/* C to sqlite DB interface (for logins)
 * with hashing mechanisms using gcrypt
 * written by oMeN23 in 2011-2016
 * If you think this is useful, use it!
 * copyleft, open and free!
 * file: hashit.c (hashing-utility)
 */

#define _GNU_SOURCE
#include "login.h"

int main(int argc, char* argv[]) 
{
  time_t thetime = time(NULL);

  printf("hashit v0.25 - %s", ctime(&thetime));  
  gcrypt_init();
  int algo;
  
start:
  printf("These are the available algorithms: \n\
  GCRY_MD_MD5     = 1,\n\
  GCRY_MD_SHA1    = 2,\n\
  GCRY_MD_RMD160  = 3,\n\
  GCRY_MD_TIGER   = 6,   /* TIGER/192 as used by gpg <= 1.3.2. */\n\
  GCRY_MD_SHA256  = 8,\n\
  GCRY_MD_SHA384  = 9,\n\
  GCRY_MD_SHA512  = 10,\n\
  GCRY_MD_SHA224  = 11,\n\
  GCRY_MD_MD4     = 301,\n\
  GCRY_MD_CRC32   = 302,\n\
  GCRY_MD_CRC32_RFC1510 = 303,\n\
  GCRY_MD_CRC24_RFC2440 = 304,\n\
  GCRY_MD_WHIRLPOOL = 305,\n\
  GCRY_MD_TIGER1  = 306, /* TIGER fixed.  */\n\
  GCRY_MD_TIGER2  = 307  /* TIGER2 variant.   */\n");
  
  printf("Please enter the number of the desired algorithm: ");
  scanf("%i", &algo),
  getchar(); // fall thru without this call 
  bool rangeOk = false;
  if ((algo > 0 && algo < 12 && (algo != 4 && algo != 5 && algo != 7)) || (algo > 300 && algo < 308))
    rangeOk = true;
  
  if (!rangeOk) { 
    printf("Select a valid algorithm please.\n");
    goto start;   
  }
  char* final = gcry_malloc_secure((gcry_md_get_algo_dlen(algo)*2)+1);
  char* ptr = gcry_malloc_secure(4096);
  
  printf("What value do you want to hash? ");  
  fgets(ptr, 4096, stdin);  
  ptr[ strlen(ptr) - 1 ] = '\0'; // remove '\n' of fgets    
  
  hash_func(algo, final, ptr, strlen(ptr));
  printf("%s\n", final);
  
  gcry_free(final);
  gcry_free(ptr); 

  return 0;    
}
