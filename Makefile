CC      = gcc
CFLAGS  = -O2 -Wall
INC     = -I/usr/local/include
LIB     = -L/usr/local/lib -loqs -lcrypto

qrgaka: src/qrgaka.c
	$(CC) $(CFLAGS) $< -o $@ $(INC) $(LIB)

run: qrgaka
	LD_LIBRARY_PATH=/usr/local/lib ./qrgaka

proverif:
	proverif -lib proverif/qrgaka_lib.pvl proverif/qrgaka_auth.pv   | grep RESULT
	proverif -lib proverif/qrgaka_lib.pvl proverif/qrgaka_leader.pv | grep RESULT

clean:
	rm -f qrgaka

.PHONY: run proverif clean
