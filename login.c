/* C to sqlite DB interface (for logins)
 * with hashing mechanisms using gcrypt
 * written by oMeN23 aka David Schuster © 2011-2016
 * If you think this is useful, use it!  
 * file: login.c (main)
 */

#include "login.h"

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
  login_data_t userdata = (login_data_t)logindata;
  /* basically iterate over the data we get - check for match
   * thats why we gotta return 0 if we have no match
   * the callback wouldnt get called again for the next row
   */
  for (int i = 0 ; i < numArgs; i++) {
    if (/*Db_entries[i] != NULL &&*/ !strcmp(azColName[0], "username")) {
      if (!strcmp(Db_entries[0], userdata->username)) {        
        isRegistered = true; /* username found in db (if check) -> search for matching pw */
      }
    } if (/*Db_entries[i] != NULL &&*/ !strcmp(azColName[1], "password")) {
        if (isRegistered && !strcmp(Db_entries[1], userdata->hash)) {
          isLoggedOn = true; 
          return 0;
        }      
      }   
    }
  return 0;
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
  if (stringlength(username) > USERBUF - 6 || stringlength(password) > USERBUF - 6) {
    fprintf(stderr, "Username and/or password too long! Max. %d characters.\n", USERBUF - 6);
    fprintf(stderr, "Make a different choice, please.\n");
    exit(1);
  }
  else if (stringlength(username) < 2 || stringlength(password) < 4) {
    fprintf(stderr, "Username min. 3 characters and password min. 4 characters.\n"); /* TODO ADJUST THIS IS FOR THE FINAL */
    exit(1);
  }   
  
  /* PREREQUESITES AND MEM ALLOC */
  sqlite3*	Db_object = NULL;
  char*		errormsg;
  gcrypt_init(); /* initialize mem manager and stuff so lib doesnt complain */
  
  login_data_t container = gcry_malloc_secure(sizeof *container);
  
  if (container == NULL) {
    fprintf(stderr, "Could not allocate memory!\n");
    abort();
  }
  container->username = gcry_malloc_secure(USERBUF);
  container->password = gcry_malloc_secure(USERBUF);
  container->hash = gcry_malloc_secure(USERBUF * 2);
  
  if (!gcry_is_secure(container->hash) || !gcry_is_secure(container) || !gcry_is_secure(container->password)) {
    fprintf(stderr, "Could not allocate in secure memory!\n");
    exit(2);
  }
  
  strcpy(container->username, username);  /* copy userdata in secure mem */
  strcpy(container->password, password);
#ifndef HASH
  strcpy(container->hash, password); /* SO IF SOMEBODY TURNS OFF HASHING IT WILL STILL WORK */
#endif
  memset((void*)password, 0, stringlength(password)); /* fill the parameter with zeroes - its not secure - then it is */
  
  int err = sqlite3_open(DATABASE,	/* const char *filename - Database filename (UTF-8), defined in the header MACRO USED */
                         &Db_object);	/* sqlite3 **ppDb - OUT: SQLite db handle */
  
  if (err != SQLITE_OK) {
    fprintf(stderr, "Database connection failed, something went wrong.\n");
    exit(3);
  }    
  
#ifdef HASH /* call of the hashing function  -> hash.c .. change to GCRY_MD_TIGER1  */
  hash_func(GCRY_MD_TIGER, container->hash, container->password, strlen(container->password));  // TODO XXX change 6 with 306 see above for enum decl
  fprintf(stderr, "Trying to log in as \n'%s' \nwith hashed-pw \n'%s'\n", container->username, container->hash);
#else
  fprintf(stderr, "Trying to log in as '%s'\n", container->username);
#endif
  /* turn off self-supplied SQL if a null ptr or empty string is supplied */
  
  /* SQL STUFF AND BUILDER */
  char sql[LARGEBUF];
  if (own_sql)  {
    if (longstringlength(sql_statement) >= LARGEBUF) { /* FUNC MACRO USED */
      fprintf(stderr, "SQL statement too long. Max. %d characters.\n", LARGEBUF);
      exit(4);
    }
    if (sql_statement == NULL || strcmp(sql_statement, "") == 0) {
      own_sql = false;
      fprintf(stderr, "login(...) called with wrong args - arg3 is true and arg4 is NULL or empty!\n");
    }
    
    /*if (sql_statement == NULL) {
     *            fprintf(stderr, "Cannot pass NULL Pointer as SQL statement!\n");
     *            abort(); not possible as for convenience, this is turned off if a null ptr is supplied
  }*/
    if (stringlength(sql_statement) < 6) { /* FUNC MACRO USED */
      fprintf(stderr, "Cannot pass empty or nonsensical string as SQL statement!\n");
      exit(5);
    }
    /* SQL OK copy it into our string - dest array should be clean so string isnt garbage */
    memset((void*)sql, 0, sizeof sql);
    strcpy(sql, sql_statement);
  }
  else /* use default sql string builder mechanism (fast and convenient and safe) 1 call per login/username */
    build_sql_string(sql, container->username);
  
  /* DATABASE CALL */
  err = sqlite3_exec(Db_object,		/* An open database ![IMPORTANT -> callback is called for every ROW]! */
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
    //	    ^^ er == 4 ? callback returned 1 (or any nonzero value)			
    //      fprintf(stderr, "SQL notice: callback requested query abort because a match was found.\n"); old logic part          
    fprintf(stderr, "SQL error: %s\n", errormsg ); // sqlite3_errmsg(Db_object)
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
   * the whole login_data_t container is now overwritten - also the passed password argument (around line 104) */
  
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
void build_sql_string(char* dest, const char* username)
{
  char sql_string[LARGEBUF] = "";
  strcpy(sql_string, "select * from users where username = '"); /* users is the name of the SQL table */
  stringconcat(sql_string, username); /* FUNC MACRO USED */
  stringconcat(sql_string, "';");
  memset(dest, 0, LARGEBUF-1); /* clear mem where sql string is to be written - so theres no garbage */
  strcpy(dest, sql_string);
}

/* Example main ... this is intented to be a "library" - only a glue code
 * main will exit with retval 0 if everything is ok
 */
int main(int argc, char* argv[])
{
  
  /* get user data - change this so it suits your needs - try to use secure storage */
  if (!argv[1] || !argv[2]) { printf("please supply two args\n"); exit(-1); }
  char* user = argv[1];
  char* pass = argv[2];
  
  /* login -> returns a bool indicating success */
  bool logged_on = login(user,	/* self expl this variable will come back unchanged */
                         pass,	/* this variable will be garbage after the login */
                         false,	/* own sql statement suppplied as arg4(true) or default func(false), I'd go with this setting */
                         NULL);	/* sql string like "select * from users;" or NULL pointer for default func */
  
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
}

