/* C to sqlite DB interface (for logins)
 * with hashing mechanisms using gcrypt
 * written by oMeN23 in 2011-2012
 * If you think this is useful, use it!
 * copyleft, open and free!
 * file: hash.c (hashing)
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

/* this function calculates a hex-string which represents
 * the hash of the user's password or any value
 * arg1 = the value
 * arg2 = the destination (caller has to allocate dynamic or automatic memory and free it eventually after) - min. (gcry_md_get_algo_dlen(algo)*4) for hex notation
 * arg3 = the algorithm (see libgcrypt docs)
 * arg4 = some flags (see below)
 * 0 = none, 
 * GCRY_MGCRY_MD_FLAG_SECURE = 1,   Allocate all buffers in "secure" memory.  
 * GCRY_MD_FLAG_HMAC = 2,   Make an HMAC out of this algorithm.  
 */
char* hash_func(const char* value, char* dest, int algo, unsigned int flags) {
  
    gcrypt_init();
    gcry_md_hd_t	Crypto_handle; /* crypto context handle */
    gcry_error_t	Crypto_error = 0;

    /* determine pw length + 1 (macro handles it), max USERBUF , not overflowable MACRO USED */
    size_t text_length = stringlength(value) + 1; /* terminating null, shouldnt make a diff, sys dependend,  this is correct */
    /* check if the library is working as it should .. */
    Crypto_error = gcry_md_open(&Crypto_handle, algo, flags);
    if (Crypto_error || Crypto_handle == NULL)
        fprintf(stderr, "Failure: %s\t/\t%s\n",
                gcry_strsource(Crypto_error),
                gcry_strerror(Crypto_error)
               );
    Crypto_error = gcry_md_enable(Crypto_handle, algo);
    if (Crypto_error)
        fprintf(stderr, "Failure: %s\t/\t%s\n",
                gcry_strsource(Crypto_error),
                gcry_strerror(Crypto_error)
               );
    if (Crypto_error || !gcry_md_is_enabled(Crypto_handle, algo)) {
        fprintf(stderr, "Failure: %s\t/\t%s\n",
                gcry_strsource(Crypto_error),
                gcry_strerror(Crypto_error)
               );
        abort();
    }
    /* if algo works start the hashing */
    if (gcry_md_test_algo(algo) == GPG_ERR_NO_ERROR) {

        /* pass pw into hash function bytewise (unsigned char) */
        for (int x = 0 ; x < text_length; x++) {
            gcry_md_putc(Crypto_handle, (unsigned char)value[x]);
        }
        /* finalize calculation */
        gcry_md_final(Crypto_handle);
        /* allocate (secure) heap memory for the hash */
        unsigned char* byte_result = gcry_malloc_secure(gcry_md_get_algo_dlen(algo)*4); // NOTE: we actually ran out of space here once
        /* helpers to make them human readable and comparable */
        unsigned char* helper = gcry_malloc_secure(16); /* actually only need 1 char */
	unsigned char* final = gcry_malloc_secure(gcry_md_get_algo_dlen(algo)*4);
        if ( !gcry_is_secure(helper)|| !gcry_is_secure(byte_result) || !gcry_is_secure(final)) {
            fprintf(stderr, "Could not allocate in secure memory!\n");
            abort();
        }
	// NOTE: 10.6.2012 fixed a strcpy issue - where digests with a value of zer0 [00] in the middle would be 
	// cut off - using memcpy instead
        /* copy hash into a RAW string */
        memcpy(byte_result, gcry_md_read(Crypto_handle, algo), gcry_md_get_algo_dlen(algo)*2); /* read in the raw byte string - size times two for hex notation */
		
        
        
        

        /* format the raw string to hex notation and
         * pass it piece by piece into our char *dest
         * and concatenate */
        for (int i = 0; i < gcry_md_get_algo_dlen(algo); i++)  {
          sprintf((char*)helper, "%02x", (unsigned char)byte_result[i]);
          stringconcat((char*)final, (const char*)helper);
        }
        
	
	if (dest == NULL) { /* the caller has to allocate the destination memory */
          fprintf(stderr, " ---- [%s] ----\n\t  Hashing-Function: destination memory adress is not valid!\n\
          The caller of this function is responsible\n\t  for allocating a destination buffer that is large enough\n\
          for holding the digest value.\n\t  Returning as function return variable ...\n\t  This can lead to security problems\n\t  or memory leaks.\n", program_invocation_short_name);
          errno = -EINVAL;
          return (char*)final;
        }
	
	
	memset((void*)dest, 0, 48); /* clear memory where hash is to be written */
	strncpy((void*)dest, (char*)final, strlen((char*)final));
        dest[ strlen( dest ) ] = '\0';
        /* generally clean up after ourselves ... */
        gcry_md_close(Crypto_handle); /* releases all security relevant information */
	gcry_free(Crypto_handle);	
        gcry_free(byte_result);
        gcry_free(helper);
	gcry_free(final);
	final = NULL;
	Crypto_error = 0;
	Crypto_handle = NULL;
	byte_result = NULL;
	helper = NULL;
	return dest;
	
    } else	/* if the hash mechanism isnt working abort */
        abort();
}

void gcrypt_init() {
  static bool initialized = false;
  if (gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P) || initialized)
    return;
  
  if (!gcry_check_version(GCRYPT_VERSION)) {
    fprintf(stderr, "fatal error: libgcrypt version mismatch\n");
    abort();
  }  
  /* this is the actual library initialization
   * with a sec mem starting pool of 64k */
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN),
  gcry_control(GCRYCTL_INIT_SECMEM, 16384*4, 0),
  gcry_control(GCRYCTL_RESUME_SECMEM_WARN),
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
  initialized = true;
}
