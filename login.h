/* C to sqlite DB interface (for logins)
 * with hashing mechanisms using gcrypt
 * written by oMeN23 in 2011/2012
 * If you think this is useful, use it!
 * copyleft, open and free!
 * file: login.h (headerfile)
 * Written by David Schuster -- contact david [dot] schuster [at] kdemail [dot] net 
 */
#ifndef _LOGIN_H_
#define _LOGIN_H_
#pragma once

#define _ISOC99_SOURCE

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#else
#warning "Using GNU EXTENSIONS highly improves security \
of this program, the other features are deprecated! \
Trying to define GNU extensions, if this fails \
change login.h."
#endif // ifndef _GNU_SOURCE

#define GCRYPT_NO_DEPRECATED
#define HASH	/* IF THIS TOKEN IS UNDEF'D YOU HAVE A SQLITE INTERFACE PROGRAM WITHOUT HASHING CAPABILITIES */
#define DATABASE	"ex1.db"	/* specify full db path if db is not in binary's folder or launch binary from db's folder */

#if defined _GNU_SOURCE
 size_t strnlen(const char* string, size_t maxlen);
 #define stringlength(x)	strnlen(x, USERBUF)
 #define longstringlength(x)	strnlen(x, LARGEBUF + 40)
 #define stringconcat(s1, s2)	strncat(s1, s2, USERBUF) 
#elif _BSD_SOURCE
 #define stringconcat(s1, s2)	strncat(s1, s2, USERBUF)
 #define longstringlength(x)	strlen(x)
 #define stringlength(x)	strlen(x) 
#else	/* !_GNU_SOURCE && !_BSD_SOURCE */
 #define longstringlength(x)	strlen(x)
 #define stringlength(x)	strlen(x)
 #define stringconcat(s1, s2)	strcat(s1, s2) 
#endif

/* buffers */
#define LARGEBUF	640
#define USERBUF		64

/* user data definitions - mostly hidden - only in use in the interior of the login func */
typedef struct {
    char* username;
    char* password;
    char* hash;
} login_data;
typedef login_data* login_data_t;

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
void build_sql_string(const char* username, char* destination);
/* this function calculates a string which represents
 * the hash of the user's password */
void hash_func(const char* value, char* destination, int algo, unsigned int flags);

#endif // _LOGIN_H_
