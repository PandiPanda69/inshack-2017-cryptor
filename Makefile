CC=gcc
CCFLAGS=-lssl -lcrypto -lm -s
DEBUG=
DEL=rm

BIN=cryptor
SRC=src/base64.c src/crypt.c src/comm.c src/strings.c src/main.c

$(BIN): $(SRC)
	$(CC) -o $@ $(CCFLAGS) $(DEBUG) $^

debug: clean
	make DEBUG="-DDEBUG"

encoder:
	$(CC) -o encoder tools/encoder.c
	
clean:
	$(DEL) $(BIN) encoder 2> /dev/null || [ 0 ]

ddist:
	make clean
	make debug
	make encoder
	./encoder || [ 0 ]

dist:
	make
	make encoder
	./encoder || [ 0 ]

release:
	make dist
	tar -cvzf mails.tgz mails/
	tar -cvzf dist.tgz mails.tgz the-file-to-decrypt.flag cryptor cnc/cnc

