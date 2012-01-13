CC=cc
CFLAGS=-std=c99 -lsqlite3 -lgcrypt 
DEPS=login.h 
INCDIR=-I /usr/include -I /usr/local/include
	# change this to your needs
RELEASEBUILD=./app
DEBUGBUILD=./app
FILESET=login.c hash.c

debug: login.c hash.c
	$(CC) -o $(DEBUGBUILD) $(FILESET) $(INCDIR) $(CFLAGS) -ggdb3 -Wall -Wno-pointer-sign -funsigned-char
	$(CC) -o feature_test ftm.c 
	# we dont need to know about the signedness... working with bytes we have to use unsigned chars 0 .. 255
	# use 'make pedantic' if you want to see everything
clean:
	rm -f $(RELEASEBUILD) $(DEBUGBUILD) *~ a.out *.o feature_test

release: login.c hash.c
	$(CC) -o $(RELEASEBUILD) $(FILESET) $(INCDIR) $(CFLAGS) -O3 -s -funsigned-char 
		
pedantic: login.c hash.c
	$(CC) -o $(DEBUGBUILD) $(FILESET) $(INCDIR) $(CFLAGS) -ggdb3 -Wall -pedantic
	$(CC) -o feature_test ftm.c 
	# shows really all warnings

feature: ftm.c
	$(CC) -o feature_test ftm.c 
	# feature tests with GNU extensions

