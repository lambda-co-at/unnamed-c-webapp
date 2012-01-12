CC=gcc
CFLAGS=-std=c99 -lsqlite3 -lgcrypt
DEPS=login.h 
INCDIR=-L/usr/local/lib/ -I /usr/include -I /usr/local/include
REL=main
FILESET=main.c hash.c

default:
release: main.c hash.c
	$(CC) -o $(RELEASEBUILD) $(FILESET) $(INCDIR) $(CFLAGS) -O3 -s 
		
pedantic: main.c hash.c
	$(CC) -o $(DEBUGBUILD) $(FILESET) $(INCDIR) $(CFLAGS) -ggdb3 -Wall -pedantic
	$(CC) -o feature_test ftm.c 
	# shows really all warnings

feature: ftm.c
	$(CC) -o feature_test ftm.c 
	# feature tests with GNU extensions

