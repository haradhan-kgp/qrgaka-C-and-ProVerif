/*
 * qrgaka.c - Reference implementation of QR-GAKA (Algorithms 2-3 of the paper)
 *
 * Build:  gcc -O2 -Wall qrgaka.c -o qrgaka -loqs -lcrypto
 * Needs:  liboqs >= 0.10 (ML-KEM-768), OpenSSL >= 1.1.1 (HMAC, AES-256-GCM, BIGNUM)
 *
 * What is real:   ML-KEM-768 (liboqs), AES-256-GCM, HMAC-SHA-256 (H_lbl), Shamir over
 *                 F_p with p = 2^521-1, the full message flow M0..M4 with exact sizes,
 *                 PUF-sealing of sk / shares, ledger commitments, epoch refresh, revocation.
 * What is simulated: the PUF (a per-drone secret + HMAC) and the fuzzy extractor/BCH
 *                 (the PUF output is assumed already error-free). Radio is a function call.
 *
 * The program runs a set of positive and negative tests and prints PASS/FAIL.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#ifdef OQS_KEM_alg_ml_kem_768
#define KEM_ALG OQS_KEM_alg_ml_kem_768
#else
#define KEM_ALG OQS_KEM_alg_kyber_768   /* pre-FIPS-203 name; sizes are identical */
#endif

#define PK_LEN 1184
#define SK_LEN 2400
#define CT_LEN 1088
#define SS_LEN 32
#define SH_LEN 66            /* 521-bit field element */
#define ID_LEN 8
#define MAXN   16
#define BLOB_OVH (12 + 16)   /* nonce + GCM tag */

static OQS_KEM *kem;
static BIGNUM  *P;           /* 2^521 - 1 */
static const uint8_t N0[12] = {0};  /* each channel key encrypts exactly one message */

/* ---------------------------------------------------------------- primitives */

/* H_lbl(parts...) = HMAC-SHA-256(key = label, data = concatenation of parts).
 * Call as H("lbl", out, nparts, ptr1, (size_t)len1, ptr2, (size_t)len2, ...) */
static void H(const char *lbl, uint8_t out[32], int np, ...) {
    va_list ap; size_t tot = 0;
    va_start(ap, np);
    for (int i = 0; i < np; i++) { (void)va_arg(ap, const uint8_t *); tot += va_arg(ap, size_t); }
    va_end(ap);
    uint8_t *buf = malloc(tot ? tot : 1); size_t off = 0;
    va_start(ap, np);
    for (int i = 0; i < np; i++) {
        const uint8_t *p = va_arg(ap, const uint8_t *); size_t l = va_arg(ap, size_t);
        memcpy(buf + off, p, l); off += l;
    }
    va_end(ap);
    unsigned int ol = 32;
    HMAC(EVP_sha256(), lbl, (int)strlen(lbl), buf, tot, out, &ol);
    free(buf);
}

/* out = ciphertext || 16-byte tag; returns len(pt)+16 */
static int aead_enc(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ad, size_t adl,
                    const uint8_t *pt, size_t ptl, uint8_t *out) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, tot = 0;
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(c, NULL, NULL, key, nonce);
    EVP_EncryptUpdate(c, NULL, &l, ad, (int)adl);
    EVP_EncryptUpdate(c, out, &l, pt, (int)ptl); tot = l;
    EVP_EncryptFinal_ex(c, out + tot, &l); tot += l;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out + tot);
    EVP_CIPHER_CTX_free(c);
    return tot + 16;
}
/* returns plaintext length or -1 on authentication failure */
static int aead_dec(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ad, size_t adl,
                    const uint8_t *ct, size_t ctl, uint8_t *out) {
    if (ctl < 16) return -1;
    size_t pl = ctl - 16; int l = 0, tot = 0, ok;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(c, NULL, NULL, key, nonce);
    EVP_DecryptUpdate(c, NULL, &l, ad, (int)adl);
    EVP_DecryptUpdate(c, out, &l, ct, (int)pl); tot = l;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)(ct + pl));
    ok = EVP_DecryptFinal_ex(c, out + tot, &l);
    EVP_CIPHER_CTX_free(c);
    return ok > 0 ? (int)pl : -1;
}
static void u32(uint32_t v, uint8_t b[4]) { b[0]=v>>24; b[1]=v>>16; b[2]=v>>8; b[3]=v; }
static uint32_t rd32(const uint8_t b[4]) { return ((uint32_t)b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3]; }

/* ---------------------------------------------------------------- Shamir over F_p */

static void poly_eval(BIGNUM *r, BIGNUM **a, int t, unsigned x, BN_CTX *ctx) {
    BIGNUM *X = BN_new(); BN_set_word(X, x); BN_copy(r, a[t-1]);
    for (int j = t - 2; j >= 0; j--) { BN_mod_mul(r, r, X, P, ctx); BN_mod_add(r, r, a[j], P, ctx); }
    BN_free(X);
}
/* Lagrange interpolation at 0 through k points (xs[i], ys[i]) */
static void lagrange0(BIGNUM *S, const unsigned *xs, BIGNUM **ys, int k, BN_CTX *ctx) {
    BIGNUM *num = BN_new(), *den = BN_new(), *tmp = BN_new(), *xj = BN_new(), *d = BN_new();
    BN_zero(S);
    for (int a = 0; a < k; a++) {
        BN_one(num); BN_one(den);
        for (int b = 0; b < k; b++) if (b != a) {
            BN_set_word(xj, xs[b]);
            BN_zero(tmp); BN_mod_sub(tmp, tmp, xj, P, ctx); BN_mod_mul(num, num, tmp, P, ctx);   /* -x_j */
            BN_set_word(d, xs[a]); BN_mod_sub(d, d, xj, P, ctx); BN_mod_mul(den, den, d, P, ctx); /* x_a-x_j */
        }
        BN_mod_inverse(tmp, den, P, ctx);
        BN_mod_mul(num, num, tmp, P, ctx);
        BN_mod_mul(num, num, ys[a], P, ctx);
        BN_mod_add(S, S, num, P, ctx);
    }
    BN_free(num); BN_free(den); BN_free(tmp); BN_free(xj); BN_free(d);
}

/* ---------------------------------------------------------------- drones, ledger, sealing */

typedef struct {
    uint8_t  id[ID_LEN];
    uint8_t  puf[32];                              /* simulated PUF secret; never leaves the drone */
    uint8_t  pk[PK_LEN];                           /* public */
    uint8_t  sealed_sk[BLOB_OVH + SK_LEN];
    uint8_t  sealed_sh[BLOB_OVH + 2 * SH_LEN];     /* leader: y_L||sigma_L ; member: sigma_i */
    size_t   sealed_sh_len;
    uint32_t epoch;
} Drone;

typedef struct {                                   /* the ledger holds ONLY hashes, flags, kappa */
    uint8_t cmt[MAXN][32];
    int     flag[MAXN];
    uint8_t kappa[32];
} Ledger;

static void puf_seal_key(const Drone *d, uint8_t K[32]) {      /* K_x = H_seal(FE(PUF(c))) */
    uint8_t w[32]; unsigned l = 32;
    HMAC(EVP_sha256(), d->puf, 32, (const uint8_t *)"challenge-c0", 12, w, &l);
    H("seal", K, 1, w, (size_t)32);
    OPENSSL_cleanse(w, 32);
}
static size_t seal(const Drone *d, const uint8_t *pt, size_t n, uint8_t *out) {
    uint8_t K[32]; puf_seal_key(d, K); RAND_bytes(out, 12);
    size_t r = (size_t)aead_enc(K, out, d->id, ID_LEN, pt, n, out + 12) + 12;
    OPENSSL_cleanse(K, 32); return r;
}
static int unseal(const Drone *d, const uint8_t *blob, size_t bl, uint8_t *out) {
    uint8_t K[32]; puf_seal_key(d, K);
    int r = aead_dec(K, blob, d->id, ID_LEN, blob + 12, bl - 12, out);
    OPENSSL_cleanse(K, 32); return r;
}

/* Phase 2, device side: Enroll */
static void enroll(Drone *d, const char *name, Ledger *bc, int idx) {
    uint8_t sk[SK_LEN];
    memset(d, 0, sizeof *d);
    snprintf((char *)d->id, ID_LEN, "%s", name);
    RAND_bytes(d->puf, 32);
    OQS_KEM_keypair(kem, d->pk, sk);
    seal(d, sk, SK_LEN, d->sealed_sk);
    OPENSSL_cleanse(sk, SK_LEN);
    H("cmt", bc->cmt[idx], 2, d->id, (size_t)ID_LEN, d->pk, (size_t)PK_LEN);
    bc->flag[idx] = 0;
}

/* Phase 2, GSS side: ShareGen. Leader has x = n, member i has x = i.
 * Revoked drones (flag=1) receive nothing and are excluded from the epoch. */
static void deal(Drone *L, Drone *M, int n, int t, uint32_t e, Ledger *bc) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a[MAXN];
    for (int j = 0; j < t; j++) { a[j] = BN_new(); BN_rand_range(a[j], P); }   /* a[0] = S */
    BIGNUM *mu = BN_new(), *yL = BN_new(), *sL = BN_new(), *y = BN_new(), *s = BN_new();
    BN_rand_range(mu, P);                                                      /* independent uniform mask */
    poly_eval(yL, a, t, (unsigned)n, ctx);
    BN_mod_add(sL, yL, mu, P, ctx);                                            /* sigma_L = y_L + mu */

    uint8_t buf[2 * SH_LEN];
    BN_bn2binpad(yL, buf, SH_LEN); BN_bn2binpad(sL, buf + SH_LEN, SH_LEN);
    L->sealed_sh_len = seal(L, buf, sizeof buf, L->sealed_sh); L->epoch = e;
    for (int i = 1; i < n; i++) {
        if (bc->flag[i]) continue;
        poly_eval(y, a, t, (unsigned)i, ctx);
        BN_mod_add(s, y, sL, P, ctx);                                          /* sigma_i = y_i + sigma_L */
        BN_bn2binpad(s, buf, SH_LEN);
        M[i].sealed_sh_len = seal(&M[i], buf, SH_LEN, M[i].sealed_sh); M[i].epoch = e;
    }
    uint8_t Sb[SH_LEN], e4[4]; u32(e, e4);
    BN_bn2binpad(a[0], Sb, SH_LEN);
    H("chk", bc->kappa, 2, e4, (size_t)4, Sb, (size_t)SH_LEN);                 /* kappa_e on the ledger */
    OPENSSL_cleanse(Sb, sizeof Sb); OPENSSL_cleanse(buf, sizeof buf);
    for (int j = 0; j < t; j++) BN_clear_free(a[j]);
    BN_clear_free(mu); BN_clear_free(yL); BN_clear_free(sL); BN_clear_free(y); BN_clear_free(s);
    BN_CTX_free(ctx);
}

/* ---------------------------------------------------------------- Phases 3+4: the session */

typedef struct { int tamper_tag, skip[MAXN], stale[MAXN], bad_share[MAXN]; } Scen;
typedef struct {
    int ok, nP, inP[MAXN], mok[MAXN];
    size_t bytes;
    uint8_t SK[32], mSK[MAXN][32];
    const char *why;
} Res;

static int run_session(Drone *L, Drone *M, int n, int t, const Ledger *bc,
                       uint8_t dir[][PK_LEN], const Scen *sc, Res *r) {
    memset(r, 0, sizeof *r);
    uint32_t e = L->epoch; uint8_t e4[4]; u32(e, e4);
    uint8_t skL[SK_LEN], pl[2 * SH_LEN];
    if (unseal(L, L->sealed_sk, sizeof L->sealed_sk, skL) < 0 ||
        unseal(L, L->sealed_sh, L->sealed_sh_len, pl) < 0) { r->why = "leader unseal failed"; return 0; }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *yL = BN_bin2bn(pl, SH_LEN, NULL), *sigL = BN_bin2bn(pl + SH_LEN, SH_LEN, NULL);
    BIGNUM *S = BN_new(), *ys[MAXN]; int nys = 0;
    uint8_t epk[PK_LEN], esk[SK_LEN];
    uint8_t ldn[MAXN][32], ltr2[MAXN][32], mdn[MAXN][32], mtr2[MAXN][32], sig[MAXN][SH_LEN];

    /* LeaderBegin: M0 = (ID_L, e, nu_L, epk) */
    OQS_KEM_keypair(kem, epk, esk);
    uint8_t M0[ID_LEN + 4 + 32 + PK_LEN];
    memcpy(M0, L->id, ID_LEN); memcpy(M0 + 8, e4, 4); RAND_bytes(M0 + 12, 32); memcpy(M0 + 44, epk, PK_LEN);
    r->bytes += sizeof M0;
    uint8_t tr0[32]; H("tr", tr0, 1, M0, sizeof M0);

    for (int i = 1; i < n; i++) {
        Drone *D = &M[i];
        if (sc->skip[i]) continue;
        /* --- MemberReply: unseal, epoch check, two encapsulations --- */
        uint8_t skm[SK_LEN], sgm[SH_LEN];
        if (unseal(D, D->sealed_sk, sizeof D->sealed_sk, skm) < 0 ||
            unseal(D, D->sealed_sh, D->sealed_sh_len, sgm) < 0 || D->epoch != e) {
            OPENSSL_cleanse(skm, sizeof skm); continue;
        }
        uint8_t ce[CT_LEN], ke_m[32], cL[CT_LEN], kL_m[32], M1[ID_LEN + 32 + 2 * CT_LEN];
        OQS_KEM_encaps(kem, ce, ke_m, epk);
        OQS_KEM_encaps(kem, cL, kL_m, L->pk);
        memcpy(M1, D->id, ID_LEN); RAND_bytes(M1 + 8, 32);
        memcpy(M1 + 40, ce, CT_LEN); memcpy(M1 + 40 + CT_LEN, cL, CT_LEN);
        uint8_t tr1m[32], hk_m[32];
        H("tr", tr1m, 2, tr0, (size_t)32, M1, sizeof M1);
        H("hs", hk_m, 3, ke_m, (size_t)32, kL_m, (size_t)32, tr1m, (size_t)32);

        /* --- LeaderReply: ledger check (flag + commitment), decaps, encaps to pk_i, tag --- */
        uint8_t cm[32];
        H("cmt", cm, 2, D->id, (size_t)ID_LEN, dir[i], (size_t)PK_LEN);
        if (bc->flag[i] || memcmp(cm, bc->cmt[i], 32)) { OPENSSL_cleanse(skm, sizeof skm); continue; }
        uint8_t ke_l[32], kL_l[32], tr1l[32], hk_l[32], ci[CT_LEN], ki_l[32], tr2l[32], tag[32];
        OQS_KEM_decaps(kem, ke_l, M1 + 40, esk);
        OQS_KEM_decaps(kem, kL_l, M1 + 40 + CT_LEN, skL);
        H("tr", tr1l, 2, tr0, (size_t)32, M1, sizeof M1);
        H("hs", hk_l, 3, ke_l, (size_t)32, kL_l, (size_t)32, tr1l, (size_t)32);
        OQS_KEM_encaps(kem, ci, ki_l, dir[i]);
        H("tr", tr2l, 2, tr1l, (size_t)32, ci, (size_t)CT_LEN);
        H("tagL", tag, 2, hk_l, (size_t)32, tr2l, (size_t)32);
        if (sc->tamper_tag) tag[0] ^= 1;
        r->bytes += sizeof M1 + CT_LEN + 32;

        /* --- MemberConfirm: verify tag BEFORE releasing anything; decaps; send M3 --- */
        uint8_t tr2m[32], expt[32];
        H("tr", tr2m, 2, tr1m, (size_t)32, ci, (size_t)CT_LEN);
        H("tagL", expt, 2, hk_m, (size_t)32, tr2m, (size_t)32);
        if (CRYPTO_memcmp(expt, tag, 32)) { OPENSSL_cleanse(skm, sizeof skm); continue; }
        uint8_t ki_m[32], Km[32], upm[32], dnm[32], pt[4 + SH_LEN], m3[4 + SH_LEN + 16];
        OQS_KEM_decaps(kem, ki_m, ci, skm);
        H("ses", Km, 4, ke_m, (size_t)32, kL_m, (size_t)32, ki_m, (size_t)32, tr2m, (size_t)32);
        H("up", upm, 1, Km, (size_t)32); H("dn", dnm, 1, Km, (size_t)32);
        u32(sc->stale[i] ? e - 1 : e, pt); memcpy(pt + 4, sgm, SH_LEN);
        if (sc->bad_share[i]) pt[4 + SH_LEN - 1] ^= 1;
        aead_enc(upm, N0, tr2m, 32, pt, sizeof pt, m3);
        memcpy(mdn[i], dnm, 32); memcpy(mtr2[i], tr2m, 32);
        OPENSSL_cleanse(skm, sizeof skm); OPENSSL_cleanse(sgm, sizeof sgm);
        OPENSSL_cleanse(Km, 32); OPENSSL_cleanse(ke_m, 32); OPENSSL_cleanse(kL_m, 32); OPENSSL_cleanse(ki_m, 32);

        /* --- LeaderRelease (part 1): derive keys, decrypt M3, drop on failure / epoch mismatch --- */
        uint8_t Kl[32], upl[32], pt2[4 + SH_LEN];
        H("ses", Kl, 4, ke_l, (size_t)32, kL_l, (size_t)32, ki_l, (size_t)32, tr2l, (size_t)32);
        H("up", upl, 1, Kl, (size_t)32); H("dn", ldn[i], 1, Kl, (size_t)32);
        memcpy(ltr2[i], tr2l, 32);
        if (aead_dec(upl, N0, tr2l, 32, m3, sizeof m3, pt2) < 0) continue;
        if (rd32(pt2) != e) continue;
        memcpy(sig[i], pt2 + 4, SH_LEN);
        r->inP[i] = 1; r->nP++; r->bytes += sizeof m3;
        OPENSSL_cleanse(Kl, 32); OPENSSL_cleanse(ke_l, 32); OPENSSL_cleanse(kL_l, 32); OPENSSL_cleanse(ki_l, 32);
    }

    /* LeaderRelease (part 2): quorum, interpolation, kappa check, key release */
    if (r->nP < t - 1) { r->why = "quorum too small (|P| < t-1)"; goto done; }
    {
        unsigned xs[MAXN]; int k = 0;
        xs[k] = (unsigned)n; ys[k++] = BN_dup(yL); nys = k;
        for (int i = 1; i < n && k < t; i++) if (r->inP[i]) {
            BIGNUM *s = BN_bin2bn(sig[i], SH_LEN, NULL), *y = BN_new();
            BN_nnmod(s, s, P, ctx);
            BN_mod_sub(y, s, sigL, P, ctx);                    /* y_i = sigma_i - sigma_L */
            xs[k] = (unsigned)i; ys[k++] = y; nys = k; BN_free(s);
        }
        lagrange0(S, xs, ys, t, ctx);
        uint8_t Sb[SH_LEN], ch[32];
        BN_bn2binpad(S, Sb, SH_LEN);
        H("chk", ch, 2, e4, (size_t)4, Sb, (size_t)SH_LEN);
        if (CRYPTO_memcmp(ch, bc->kappa, 32)) { r->why = "kappa mismatch (wrong or stale share)"; OPENSSL_cleanse(Sb, sizeof Sb); goto done; }

        uint8_t z[32], sidbuf[32 + MAXN + MAXN * 32], sid[32]; size_t so = 32;
        RAND_bytes(z, 32); memcpy(sidbuf, tr0, 32);
        for (int i = 1; i < n; i++) if (r->inP[i]) sidbuf[so++] = (uint8_t)i;
        for (int i = 1; i < n; i++) if (r->inP[i]) { memcpy(sidbuf + so, ltr2[i], 32); so += 32; }
        H("sid", sid, 1, sidbuf, so);
        H("grp", r->SK, 3, Sb, (size_t)SH_LEN, z, (size_t)32, sid, (size_t)32);   /* SK = H_grp(S||z||sid) */

        int all = 1;
        for (int i = 1; i < n; i++) if (r->inP[i]) {
            uint8_t pt4[64], m4[80], d4[64];
            memcpy(pt4, r->SK, 32); memcpy(pt4 + 32, sid, 32);
            aead_enc(ldn[i], N0, ltr2[i], 32, pt4, 64, m4); r->bytes += sizeof m4;
            /* MemberFinish */
            if (aead_dec(mdn[i], N0, mtr2[i], 32, m4, sizeof m4, d4) == 64) {
                memcpy(r->mSK[i], d4, 32); r->mok[i] = 1;
            } else all = 0;
        }
        r->ok = all;
        OPENSSL_cleanse(Sb, sizeof Sb); OPENSSL_cleanse(z, 32);
    }
done:
    OPENSSL_cleanse(skL, sizeof skL); OPENSSL_cleanse(esk, sizeof esk); OPENSSL_cleanse(pl, sizeof pl);
    for (int j = 0; j < nys; j++) BN_clear_free(ys[j]);
    BN_clear_free(S); BN_clear_free(yL); BN_clear_free(sigL); BN_CTX_free(ctx);
    return r->ok;
}

/* ---------------------------------------------------------------- tests */

static int fails = 0;
#define CHECK(name, cond) do { int _c = (cond); printf("  [%s] %s\n", _c ? "PASS" : "FAIL", name); if (!_c) fails++; } while (0)

static int keys_agree(const Res *r, int n) {
    for (int i = 1; i < n; i++) if (r->inP[i] && (!r->mok[i] || memcmp(r->mSK[i], r->SK, 32))) return 0;
    return 1;
}

int main(void) {
    const int n = 9, t = 5;
    kem = OQS_KEM_new(KEM_ALG);
    if (!kem || kem->length_public_key != PK_LEN || kem->length_secret_key != SK_LEN ||
        kem->length_ciphertext != CT_LEN || kem->length_shared_secret != SS_LEN) {
        fprintf(stderr, "ML-KEM-768 not available / unexpected sizes\n"); return 2;
    }
    P = BN_new(); BN_one(P); BN_lshift(P, P, 521); BN_sub_word(P, 1);

    static Ledger bc; Drone L, M[MAXN]; static uint8_t dir[MAXN][PK_LEN];
    enroll(&L, "LEADER", &bc, 0);
    for (int i = 1; i < n; i++) { char nm[8]; snprintf(nm, sizeof nm, "UAV%d", i); enroll(&M[i], nm, &bc, i); memcpy(dir[i], M[i].pk, PK_LEN); }
    deal(&L, M, n, t, 1, &bc);

    Scen sc; Res r;

    puts("T1  honest session, n=9 t=5 (epoch 1)");
    memset(&sc, 0, sizeof sc); run_session(&L, M, n, t, &bc, dir, &sc, &r);
    CHECK("session completes", r.ok);
    CHECK("all 8 members accepted", r.nP == 8);
    CHECK("every member derives the leader's SK", keys_agree(&r, n));
    CHECK("total bytes == 3502*(n-1)+1228 == 29244", r.bytes == 3502u * (n - 1) + 1228u);
    uint8_t SK1[32]; memcpy(SK1, r.SK, 32);

    puts("T2  fresh session gives a fresh key (z and ephemeral key)");
    run_session(&L, M, n, t, &bc, dir, &sc, &r);
    CHECK("SK differs from T1", r.ok && memcmp(SK1, r.SK, 32) != 0);

    puts("T3  fault tolerance: exactly t-1 = 4 members present");
    memset(&sc, 0, sizeof sc); for (int i = 5; i < n; i++) sc.skip[i] = 1;
    CHECK("session completes", run_session(&L, M, n, t, &bc, dir, &sc, &r) && r.nP == 4);

    puts("T4  quorum gate: only t-2 = 3 members present");
    memset(&sc, 0, sizeof sc); for (int i = 4; i < n; i++) sc.skip[i] = 1;
    CHECK("leader refuses to release SK", !run_session(&L, M, n, t, &bc, dir, &sc, &r) && r.SK[0] == 0 && r.nP == 3);

    puts("T5  leader authentication: tampered tag_L");
    memset(&sc, 0, sizeof sc); sc.tamper_tag = 1;
    CHECK("members abort, nobody sends a share", !run_session(&L, M, n, t, &bc, dir, &sc, &r) && r.nP == 0);

    puts("T6  stale-epoch share is dropped by the leader");
    memset(&sc, 0, sizeof sc); sc.stale[2] = 1;
    CHECK("session ok, member 2 excluded", run_session(&L, M, n, t, &bc, dir, &sc, &r) && !r.inP[2] && r.nP == 7);

    puts("T7  wrong share is caught by the ledger check value kappa_e");
    memset(&sc, 0, sizeof sc); sc.bad_share[1] = 1;
    run_session(&L, M, n, t, &bc, dir, &sc, &r);
    CHECK("session aborts with kappa mismatch", !r.ok && r.why && strstr(r.why, "kappa"));

    puts("T8  PUF binding: a cloned flash image on another PUF cannot unseal");
    { Drone saved = M[2]; RAND_bytes(M[2].puf, 32);
      memset(&sc, 0, sizeof sc);
      CHECK("clone excluded, rest completes", run_session(&L, M, n, t, &bc, dir, &sc, &r) && !r.inP[2]);
      M[2] = saved; }

    puts("T9  revocation + epoch refresh (member 3 revoked, epoch 2)");
    bc.flag[3] = 1; deal(&L, M, n, t, 2, &bc);
    memset(&sc, 0, sizeof sc);
    CHECK("session ok without member 3", run_session(&L, M, n, t, &bc, dir, &sc, &r) && !r.inP[3] && r.nP == 7);
    bc.flag[3] = 0;   /* even if the flag were cleared, member 3 still holds only an epoch-1 share */
    run_session(&L, M, n, t, &bc, dir, &sc, &r);
    CHECK("old-epoch share useless", !r.inP[3]);

    puts("T10 ledger commitment: substituted public key in the leader's directory");
    { uint8_t save[PK_LEN]; memcpy(save, dir[4], PK_LEN); dir[4][0] ^= 1;
      run_session(&L, M, n, t, &bc, dir, &sc, &r);
      CHECK("member 4 rejected", !r.inP[4]); memcpy(dir[4], save, PK_LEN); }

    puts("Benchmark: 200 full sessions, n=9 (native, software; NOT drone-class timing)");
    { struct timespec a, b; memset(&sc, 0, sizeof sc);
      bc.flag[3] = 1; deal(&L, M, n, t, 3, &bc); bc.flag[3] = 0; /* fresh shares for all but member 3 */
      for (int i = 1; i < n; i++) M[i].epoch = (i == 3) ? 2 : 3;
      clock_gettime(CLOCK_MONOTONIC, &a);
      for (int k = 0; k < 200; k++) run_session(&L, M, n, t, &bc, dir, &sc, &r);
      clock_gettime(CLOCK_MONOTONIC, &b);
      printf("  %.3f ms per session (7 members, includes PUF-unseal and all checks)\n",
             ((b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6) / 200.0); }

    printf("\n%s (%d failure%s)\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED", fails, fails == 1 ? "" : "s");
    BN_free(P); OQS_KEM_free(kem);
    return fails != 0;
}
