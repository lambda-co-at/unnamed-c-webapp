/* 
 * C to sqlite DB interface (for logins)
 * with hashing mechanisms using gcrypt
 * written by oMeN23 in 2011
 * If you think this is useful, use it!
 * copyleft, open and free!
 * file: login.h (headerfile)
 */
#ifndef _LOGIN_H_
#define _LOGIN_H_
#pragma once // NOTE: does this work on our compiler (gcc) ? (back of my mind tells me only msvc supports this) 

/* This code conforms to the ISO C99 standard and makes heavy use of GNU extensions */
#define _GNU_SOURCE


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <gcrypt.h>
#include <errno.h>
#include <time.h>


#ifndef _GNU_SOURCE
#warning "Using GNU EXTENSIONS highly improves security \
of this program, the other features are deprecated! \
Tried to define GNU extensions, if this fails \
change login.h."
#endif // ifndef _GNU_SOURCE

#define GCRYPT_NO_DEPRECATED // we dont want to use old library routines
#define HASH	/* IF THIS TOKEN IS UNDEF'D YOU HAVE A SQLITE INTERFACE PROGRAM WITHOUT HASHING CAPABILITIES (pass match is done plain-text - so dont undef this) */
#define DATABASE	"ex1.db"	/* path to a sqlite3 database - specify full db path if db is not in binary's folder or launch binary from db's folder */

/* multi-platform string routines */
#if defined _GNU_SOURCE
 size_t strnlen(const char* string, size_t maxlen);
 #define stringlength(x)        strnlen(x, USERBUF)
 #define longstringlength(x)    strnlen(x, LARGEBUF + 40)
 #define stringconcat(s1, s2)   strncat(s1, s2, USERBUF)
 #define stringcompare(s1, s2)  strncmp(s1, s2, USERBUF*2)
#elif _BSD_SOURCE
 #define stringconcat(s1, s2)   strncat(s1, s2, USERBUF)
 #define longstringlength(x)    strlen(x)
 #define stringlength(x)        strlen(x) 
 #define stringcompare(s1, s2)  strncmp(s1, s2, USERBUF*2)
#else	/* !_GNU_SOURCE && !_BSD_SOURCE */
 #define longstringlength(x)    strlen(x)
 #define stringlength(x)        strlen(x)
 #define stringconcat(s1, s2)   strcat(s1, s2)
 #define stringcompare(s1, s2)  strcmp(s1, s2) 
#endif

/* buffers */
#define LARGEBUF	(1 << 12) // 4096
#define USERBUF		(1 << 8) // 256

/* user data definitions - mostly hidden - only in use in the interior of the login func */
typedef struct login_data {
    char* username;    
    char* hash;
} *login_data_t;


/* function prototypes */
/* in this function im trying to handle the login event and interface with sqlite
 * this will result in return values true as ok and false otherwise
 * arg 1 and 2 are self explanatory (arg2 gets zero'd out in the process)
 * arg3 is a bool asking if you want to supply your own SQL
 * if arg3 is true supply your SQL statement as arg4 else NULL */
bool login(const char* username, char* password, bool own_sql_statement_on, const char* sql_statement);
/* small function to build the matching
 * sql string for our purposes
 * arg1 is the username
 * arg2 is to where to write the string */
void build_sql_string(char* dest, const char* username);
/* this function calculates a string which represents
 * the hash of the user's password
 * digest has to be min. gcry_md_get_algo_dlen(algo)*2
 */
void hash_func(int algo, char* digest, const void* value, size_t len);
void gcrypt_init(void);
#endif // _LOGIN_H_
