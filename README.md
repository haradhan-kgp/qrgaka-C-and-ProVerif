# QR-GAKA: reference implementation and symbolic model

Artifact for *QR-GAKA: Post-Quantum Leader-Mandatory Threshold Group Authentication for Drone Swarms*.

```
src/qrgaka.c                 C reference implementation + self-tests
proverif/qrgaka_lib.pvl      ProVerif library (primitives, Leader and Member roles)
proverif/qrgaka_auth.pv      authentication + forward secrecy queries
proverif/qrgaka_leader.pv    leader-mandatory secrecy of the quorum secret S
results/                     outputs of the runs reported below
Makefile, Dockerfile         build and run helpers
```

## 1. C implementation

**Real:** ML-KEM-768 (liboqs), AES-256-GCM, HMAC-SHA-256 as `H_lbl`, Shamir sharing over F_p with
p = 2^521-1 (OpenSSL BIGNUM), the full message flow M0-M4 with exact sizes, PUF-sealing of the ML-KEM
secret key and of the shares, ledger commitments/flags/kappa_e, epoch refresh and revocation.

**Simulated:** the PUF (a per-drone secret processed with HMAC), the fuzzy extractor/BCH step (the PUF
output is assumed error-free), and the radio (messages are byte buffers passed in-process).

### Requirements
Linux or WSL2 (Ubuntu 22.04/24.04), `gcc`, `libssl-dev`, and
[liboqs](https://github.com/open-quantum-safe/liboqs) with ML-KEM-768 (build from source):

```bash
sudo apt install -y build-essential cmake ninja-build git libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && cd liboqs
cmake -GNinja -B build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON
ninja -C build && sudo ninja -C build install && sudo ldconfig
```

### Build and run
```bash
make run
# or manually:
gcc -O2 -Wall src/qrgaka.c -o qrgaka -I/usr/local/include -L/usr/local/lib -loqs -lcrypto
LD_LIBRARY_PATH=/usr/local/lib ./qrgaka
```
Docker alternative: `docker build -t qrgaka . && docker run --rm qrgaka`.

### Tests (`results/c_tests_output.txt`: all pass)

| Test | Checks |
|---|---|
| T1 | n=9, t=5 honest session: all 8 members accepted, all derive the leader's SK, total traffic = 3502(n-1)+1228 = **29,244 B** (matches the paper) |
| T2 | a second session yields a fresh SK |
| T3 | session completes with exactly t-1 = 4 members (fault tolerance) |
| T4 | with t-2 = 3 members the leader releases nothing (quorum gate) |
| T5 | tampered `tag_L`: every member aborts before sending a share |
| T6 | stale-epoch share is dropped by the leader |
| T7 | wrong share is detected by the ledger check value kappa_e |
| T8 | cloned flash image on a different PUF cannot unseal |
| T9 | revoked drone excluded after epoch refresh; its old-epoch share is useless |
| T10 | substituted public key in the leader's directory fails the ledger commitment |

**Timing caveat.** The benchmark line (1.416 ms/session, 200 runs, 7 active members) is a software timing
of the whole in-process simulation on a laptop under WSL2. It includes unsealing, hashing, the kappa check and
bookkeeping. It is **not** the 9-drone figure in the paper (3.89 ms, Python) and is not drone-class timing;
do not compare the two directly.

**Behaviour note.** The leader interpolates from itself plus the first t-1 accepted members. Extra accepted
members receive SK but their points are not cross-checked; a wrong share among the first t-1 aborts the session
via kappa_e.

## 2. ProVerif model

Install ProVerif (`sudo apt install proverif` or `opam install proverif`), then:

```bash
make proverif
# or:
proverif -lib proverif/qrgaka_lib.pvl proverif/qrgaka_auth.pv
proverif -lib proverif/qrgaka_lib.pvl proverif/qrgaka_leader.pv
```

### Results

`qrgaka_auth.pv` (`results/proverif_auth_results.txt`):

| Query | Result | Meaning |
|---|---|---|
| `event(BrokenL)`, `event(BrokenM)` | not reachable (true) | forward secrecy: after ALL long-term keys, sealing keys, shares and the mask leak, the attacker cannot recover the session-key canaries |
| `inj-event(MemberAccLeader) ==> inj-event(LeaderM2)` | true | injective authentication of the leader to the member |
| `inj-event(LeaderAccMember) ==> inj-event(MemberM3)` | true | injective authentication of the member to the leader |
| `inj-event(MemberAccKey) ==> inj-event(LeaderM4)` | true | a member accepts SK only if the leader released it in this session |
| `event(MemberAccKey)`, `event(LeaderAccMember)` | reachable (`not ... is false`) | sanity check: the protocol runs to completion, so the proofs are not vacuous |

`qrgaka_leader.pv` (`results/proverif_leader_results.txt`):

| Query | Result | Meaning |
|---|---|---|
| `attacker(rec(yL,y1,y2))` | not derivable (true) | leader-mandatory secrecy: with all members corrupted and the leader's sealed non-volatile memory read out, the quorum secret S stays secret |

There is no canary query in this file: corrupted members legitimately take part in the session and learn SK.

Optional negative control: uncomment `out(c, (yL, sigL));` in `qrgaka_leader.pv` (leader state stored
unsealed) and re-run; the secrecy query is then expected to fail. This control has not been run for the
results above.

### Abstractions (the model is symbolic)
- ML-KEM is an ideal KEM; a malformed ciphertext halts the process (implicit rejection is abstracted).
- Every `H_lbl` is an independent random oracle; AES-GCM is symbolic AEAD with associated data.
- PUF sealing: shares are sealed under a drone-private key and opened only inside that drone's process;
  the ML-KEM secret key is given to the process already unsealed.
- Shamir sharing is a constructor `rec(yL,y1,y2)` with t = 3 (leader + 2 members): S is derivable only
  from all three points.
- The ledger is public read-only data (kappa); revocation is absence from the leader's directory.
- Not covered by the symbolic model (they remain paper proofs): the information-theoretic hiding of the
  masked shares (Lemma 1, Theorem 3), the reductions to ML-KEM IND-CCA, and quantum random-oracle queries.

## 3. Reproducibility
Tested on Ubuntu under WSL2 with gcc, OpenSSL 3.x, liboqs built from `main` (ML-KEM-768) and ProVerif 2.x.
Record exact versions with `gcc --version`, `openssl version` and `proverif -help | head -1`.
