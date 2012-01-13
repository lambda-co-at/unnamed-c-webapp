/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 *
 *											-- unnamed C webapp --
 *
 *
 *	ISC License (ISCL)
 *	
 *	Copyright (c) 2011, written by < xxx  >
 *
 *	Permission to use, copy, modify, and/or distribute this software for any purpose 
 *	with or without fee is hereby granted, provided that the above copyright notice 
 * 	and this permission notice appear in all copies.
 *
 *	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD 
 *	TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN 
 *	NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL 
 *	DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER 
 *	IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN 
 *	CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 *	----------------------------------------------------------------------------------
 * 	 "THE BEERWARE LICENSE" (Revision 4.2.5.23):
 *	 < xxx > wrote this file. As long as you retain this notice 
 *	 you can do whatever you want with this stuff. If we meet some day, and you think
 *	 this stuff is worth it, you can buy us a few beers in return. 
 *	----------------------------------------------------------------------------------
 *
 *	
 * 	      ___________________________
 *	 ____| authors note (READ THIS!) |______________________________________________________________
 *	|																								|
 *	| yea. this shit is dual licensed. :D															|
 *	|																								|
 *	| ..and; if you aren't an asshole, dont make money from our code, use your own brain instead! 	|
 *	| if you want to profit from something, profit from your own shit. write free code, contribute 	|
 *	| to the community. give back. dont be a fucking corporate lemming. hacking is about more than	|
 *	| computers, programming languages and IRC-channels, and you should know that..					|
 *	|_______________________________________________________________________________________________|
 *
 * 
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * /
 
 
/*	 ------------- 
	| dev. notes: |
	 -------------

	TODO:
		o - use isLogged var. in for CGI handling of (jQuery/Ajax) editable content 
			fields (in xml or xhtml) and for session handling (if possible?).
		
	NOTE: XXX denotes a text-search pattern for bugs - in script comments e.g. / * bla bla XXX: will change soon * /
		  or / * XXX: attention: not secure yet, dont use function * /, and so on.. this technique actually copied 
		  from M$ dev. (funny fact: remember the leaked windows source? a friend grabbed '| wc -l' for "XXX" - the 
		  result was quite facinating, somewhere in the hundered thousands? iirc.)
		
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <gcrypt.h>
#include <errno.h>
#include "login.h"

#DEFINE		SOFTWARE_LICENSE	ISCL
#DEFINE		SOFTWARE_VERSION	0.1




/* C to sqlite DB interface (for logins)
 * with hashing mechanisms using gcrypt
 * written by oMeN23 in 2011
 */

/* does the user exist in the db */
bool isRegistered = false;
/* global of the login function */
bool isLoggedOn = false;

/* this function-signature is defined by the sqlite3 interface, it is our callback handler
 * it gets called by sqlite loaded with info from the DB in its arg list 
 */
static int callback (void* logindata,	/* sql_exec passes its forth argument in here - THNX sqlite3 interface - userdata pointer */
                     int numArgs,	/* number of not NULL columns in this row - recieved from DB/SQLITE3 (not passed by me) */
                     char** Db_entries,	/* array of strings which represent the indiviual entries of this row ![REMEMBER the callback gets called for every ROW] */
                     char** azColName)	/* the matching row name for the above strings eg.: azColname[0] = "username", Db_entries[0] = "man" in the last call */
{
    bool	usr1 = false;
    bool	pw1  = false;
    login_data_t	userdata = (login_data_t)logindata;
    /* basically iterate over the data we get - check for match
     * thats why we gotta return 0 if we have no match
     * the callback wouldnt get called again for the next row
     */
    for (int i = 0 ; i < numArgs; i++) {
        if (Db_entries[i] != NULL) {
            if (strcmp(Db_entries[i], userdata->username) == 0) {
                usr1 = true;
                isRegistered = true; /* username found in db (as we got a callback) -> search for matching pw */
            }
            if (strcmp(Db_entries[i], userdata->hash) == 0)
                pw1 = true;
        }
    }
    if (usr1 && pw1) {	/* successfully logged in */
        isLoggedOn = true;
        return 1; /* ABORT match found */
    } else {
        printf("No match found!\n");
        return 0;		/* no match found */
    }
}

/* in this function im trying to handle the login event and interface with sqlite
 * this will result in return values true as ok and false otherwise
 */
bool login(const char* username,	/* username */
           char* password,		/* password -> gets deleted for security reasons */
           bool own_sql,		/* indicates if you want your own sql statement executed against the DB */
           const char* sql_statement)	/* the sql statement to be executed against the Database or NULL */
{
    /* check for user overflow attempts */
    if (stringlength(username) > USERBUF - 8 || stringlength(password) > USERBUF - 8) {
        printf("Username and/or password too long! Max. %d characters.\n", USERBUF - 8);
        printf("Make a different choice, please.\n");
        abort();
    }
    else if (stringlength(username) < 4 || stringlength(password) < 5) {
        printf("Username min. 4 characters and password min. 5 characters.\n"); /* XXX: ADJUST THIS IS FOR THE FINAL - done! 4 and 5 chars is should be enough.*/
        abort();
    }
    /* turn own SQL off if a null ptr or empty string is supplied */
    if (sql_statement == NULL || strcmp(sql_statement, "") == 0)
      own_sql = false;


    /* PREREQUESITES AND MEM ALLOC */
    sqlite3*	Db_object = NULL;
    char*		errormsg;

    login_data_t container = gcry_malloc_secure(sizeof(login_data_t));

    if (container == NULL) {
        printf("Could not allocate memory!\n");
        abort();
    }
	
    container->username = gcry_malloc_secure(USERBUF);
    container->password = gcry_malloc_secure(USERBUF);
	
    container->hash = gcry_malloc_secure(USERBUF * 2); /* XXX: why * 2?! hex notation needs 2 chars per byte */

    if (!gcry_is_secure(container->hash) || !gcry_is_secure(container) || !gcry_is_secure(container->password)) {
        printf("Could not allocate in secure memory!\n");
        abort();
    }

    strcpy(container->username, username);  /* copy userdata in secure mem */
    strcpy(container->password, password);
#ifndef HASH
    strcpy(container->hash, password); /* SO IF SOMEBODY TURNS OFF HASHING IT WILL STILL WORK - XXX: security bug?! wtf?! copied here for plaintext check if hashing is off */
#endif
    memset((void*)password, 0, stringlength(password)); /* fill the parameter with zeroes - its not secure - then it is */

    int err = sqlite3_open(DATABASE,	/* const char *filename - Database filename (UTF-8), defined in the header MACRO USED */
                           &Db_object);	/* sqlite3 **ppDb - OUT: SQLite db handle */

    if (err != SQLITE_OK) {
        printf("Database connection failed, something went wrong.\n");
        abort();
    }

    /* HASHING FUNCTION
     * assign the hash to its field
     * arg1 = pw/value
     * arg2 = dest
     * arg3 = algo -> look up in gcrypt-doc
     * arg4 = flags -> 
     * 0 = none, 
     * GCRY_MGCRY_MD_FLAG_SECURE = 1,   Allocate all buffers in "secure" memory.  XXX: ""!? what the fuck is GCRY_(MGCRY_)MD?! - whats that flag?, cant find appr. doc. on google!
     * GCRY_MD_FLAG_HMAC = 2,   Make an HMAC out of this algorithm. XXX: what value is 2 - result? which HMAC?! - please document important shit like this! we just use tzhe secure flag for the secure malloc */
#ifdef HASH
    hash_func(container->password, container->hash, GCRY_MD_TIGER, GCRY_MD_FLAG_SECURE);
    printf("Trying to log in as '%s' with hashed-pw '%s'\n", container->username, container->hash);
#else
    printf("Trying to log in as '%s'\n", container->username);
#endif

    /* SQL STUFF AND BUILDER */
    char sql[LARGEBUF];
    if (own_sql)  {
        if (longstringlength(sql_statement) >= LARGEBUF) { /* FUNC MACRO USED */
            printf("SQL statement too long. Max. %d characters.\n", LARGEBUF);
            abort();
        }
        /*if (sql_statement == NULL) {
            fprintf(stderr, "Cannot pass NULL Pointer as SQL statement!\n");
            abort(); not possible as for convenience, this is turned off if a null ptr is supplied
        }*/
        if (stringlength(sql_statement) < 6) { /* FUNC MACRO USED */
            printf("Cannot pass empty or nonsensical string as SQL statement!\n");
            abort();
        }
        /* SQL OK copy it into our string - dest array should be clean so string isnt garbage */
	memset((void*)sql, 0, sizeof(sql));
        strcpy(sql, sql_statement);
    }
    else /* use default sql string builder mechanism (fast and convenient and safe) 1 call per login/username */
        build_sql_string((const char*)container->username, sql);

    /* DATABASE CALL */
    err = sqlite3_exec(Db_object,		/* An open database ![IMPORTANT -> callback is called for every ROW]! XXX: any way around this? caching? dunno. sampling rows at once each time is a bit bloated on big db lookups, done by sqlite3 exec does 1 step per result */
                       sql,			/* SQL to be evaluated */
                       callback,		/* Callback function */
                       /* int (*callback)(void* freeSlot, int numDbEntries, char** DBEntries, char** ColumnName) -
                        * arg1 is a free pointer specified by the sqlite3 calling convention interface -
                        * I put the data to compare against in here (could be unused too)
                        * arg2 NumDbEntries retrieves the count of entries in that row,
                        * arg3 DBEntries is an array of strings of the data in that row and
                        * arg4 ColumnName is an array of strings representing the column. */
                       (void*)container,	/* 1st argument to callback */
                       &errormsg);		/* Error msg written here */

    
    if (err != SQLITE_OK) {
        if (err == SQLITE_ABORT) /* callback req'd abort -> user found - not every error is an error :) */
            printf("SQL notice: callback requested query abort because a match was found.\n");
        else
        {
            printf("SQL error: %s\n", errormsg);
            printf("SQL error: %s\n", sqlite3_errmsg(Db_object));
        }

        sqlite3_free(errormsg);
    }
    /* clean up the DB connection */
    sqlite3_close(Db_object);

    /* BUFFER FLUSH */
    memset(container->hash, 0, USERBUF * 2);
    memset(container->password, 0, USERBUF);
    memset(container->username, 0, USERBUF);
    /* fprintf(stderr, "VAR TEST usr1: %s %s %s %s %s\n", username, password, container->username,
     * container->password, container->hash); // MEM TEST FUNC to see if mem was overwritten */

    /* release the memory - no data left in RAM */
    gcry_free(container->hash);
    gcry_free(container->password);
    gcry_free(container->username);
    gcry_free(container);
    container->password = NULL;
    container->hash = NULL;
    container->username = NULL;
    container = NULL;
    /* set ptrs null, username is the only variable left intact -> see above
     * the whole login_data_t container is now overwritten - also the passed password argument (around line 99) */

    /* print messages concerning status */
    if (!isRegistered)
        fprintf(stderr, "Username '%s' not found in DB.\n", username);
    /* if someone is found in the DB, but not logged in he can only have supplied a wrong password */
    if (isRegistered && !isLoggedOn)
        fprintf(stderr, "Wrong password for user '%s'.\n", username);
    /* msg for logon for logfile and display, watch the supplied stream args */
    if (isLoggedOn) {
        fprintf(stderr, "User '%s' logged on succesful!\n", username);
        fprintf(stdout, "Welcome %s!\n", username);
        fprintf(stdout, "Have a nice stay.\n");
    }

    /* magic global indicating our successful login (gets set in the callback) */
    return isLoggedOn;
}

/* small function to build the matching
 * sql string for our purposes
 * arg1 is the username
 * arg2 is to where to write the string
 * already in auto use of the login function if third param is false (of the login func)
 */
void build_sql_string(const char* username, char* dest)
{
    char sql_string[LARGEBUF] = "";
    strcpy(sql_string, "select * from users where username = '"); /* users is the name of the SQL table */
    stringconcat(sql_string, username); /* FUNC MACRO USED */
    stringconcat(sql_string, "';");
    memset((void*)dest, 0, sizeof(dest)); /* clear mem where sql string is to be written - so theres no garbage */
    strcpy(dest, sql_string);
}

/* function for file inclusion - XXX:soon obsolete!*/
void include_file(char *file) {
	FILE *inc = fopen (file, "r");
	if (inc != NULL) {
		int c;
		c = getc(inc);
		while (c != EOF) {
			putchar(c);
			c = getc(inc);
		}
		fclose(inc);		
	} else {
		printf("<p style=\"text-align: center; font-size: 14px;\"><strong style=\"color: #ffd71b;\">Internal Error:</strong> File inclusion of << %s >> failed!</p>", file);
	}
}


int main() {	

/* Example main ... this is intented to be a "library" - only a glue code
 * main will exit with retval 0 if everything is ok */

    /* get user data - change this so it suits your needs - try to use secure storage */
    if (!argv[1] || !argv[2]) abort();
    char* user = argv[1];
    char* pass = argv[2];
    
    /* login -> returns a bool indicating success */
    bool logged_on = login(user,	/* self expl this variable will come back unchanged */
                           pass,	/* this variable will be garbage after the login */
                           false,	/* own sql statement suppplied as arg4(true) or default func(false), I'd go with this setting */
                           NULL);	/* sql string like "select * from users;" or NULL pointer for default func */
/* end example */


    if (logged_on)
    {
        /* log-in succeeded - do what you like here */
        return 0;
    }
    else
    {
        /* log-in didnt succeed, handle it how you like ... (call main again whatever) */
        return 1;
    }

	/* get QUERY_STRING env */
	char *qstring_data;
	qstring_data = getenv("QUERY_STRING");
	
	/* content type & charset */
	printf("Content-Type: text/html; charset=ISO-8859-1\n\n");
	
	include_file("inc/header.inc.html");
	/* switch through pages.. */
	char *filename = NULL; 
	if(qstring_data == NULL) {
		filename = "inc/index.inc.html";
	} else if (strcmp(qstring_data, "1") == 0) {
		filename = "inc/contact.inc.html";		
	} else if (strcmp(qstring_data, "2") == 0) {
		filename = "inc/news.inc.html";		
	} else if (strcmp(qstring_data, "src") == 0) {
		printf("<p style=\"text-align: center; font-size: 14px;\"><a href=\"list_src\" alt=\"source\">show source of web project</a></p>");
	} else {
		filename = "index.inc.html";
	}
	
	/* include the actual content file */
	if(filename != NULL) {
		include_file(filename);
	}
	/* webpage footer */ 
	include_file("footer.inc.html");
	
	return 0;
	exit(0);
}
