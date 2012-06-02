CC=cc
CFLAGS=-std=c99 -lsqlite3 -lgcrypt 
DEPS=login.h 
INCDIR=-I /usr/include -I /usr/local/include
	# change this to your needs
RELEASEBUILD=./build/release/login
DEBUGBUILD=./build/debug/login
FILESET=login.c hash.c

debug: login.c hash.c
	$(CC) -o $(DEBUGBUILD) $(FILESET) $(INCDIR) $(CFLAGS) -ggdb3 -Wall
	$(CC) -o feature_test ftm.c -Os -s
	$(CC) -o hashit hashit.c hash.c $(CFLAGS) -Os -s -Wno-unused-result
	# we dont need to know about the signedness... working with bytes we have to use unsigned chars 0 .. 255
	# use 'make pedantic' if you want to see everything - since gcc 4.5 compiler doesnt moan anymore
clean:
	rm -f $(RELEASEBUILD) $(DEBUGBUILD) *~ a.out *.o feature_test hashit

release: login.c hash.c
	$(CC) -o $(RELEASEBUILD) $(FILESET) $(INCDIR) $(CFLAGS) -O3 -s -funsigned-char 
		
pedantic: login.c hash.c
	$(CC) -o $(DEBUGBUILD) $(FILESET) $(INCDIR) $(CFLAGS) -ggdb3 -Wall -pedantic
	$(CC) -o feature_test ftm.c -Os -s -pedantic
	$(CC) -o hashit hashit.c hash.c $(CFLAGS) -Os -s -pedantic -Wno-unused-result
	# shows really all warnings

feature: ftm.c
	$(CC) -o feature_test ftm.c -Os -s
	# feature tests with GNU extensions
hash: hashit.c hash.c
	$(CC) -o hashit hashit.c hash.c $(CFLAGS) -Os -s -Wno-unused-result
	# small utility that can make use of all hashing algorithms (e.g. to fill your db)

