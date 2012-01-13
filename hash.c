/* C to sqlite DB interface (for logins)
 * with hashing mechanisms using gcrypt
 * written by oMeN23 in 2011/2012
 * If you think this is useful, use it!
 * copyleft, open and free!
 * file: hash.c (hashing)
 * Written by David Schuster -- contact david [dot] schuster [at] kdemail [dot] net 
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

/* this function calculates a string which represents
 * the hash of the user's password
 */
void hash_func(const char* value, char* dest, int algo, unsigned int flags) {
  
   /* if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) { 
      gcrypt_init();
      fputs("Had to re-initialize gcrypt library ...", stderr);
    }
    */

    gcry_md_hd_t	Crypto_handle = NULL; /* crypto context handle */
    gcry_error_t	Crypto_error = 0;

    /* determine pw length + 1 (macro handles it), max USERBUF , not overflowable MACRO USED */
    size_t text_length = stringlength(value) + 1; /* terminating null, shouldnt make a diff, sys dependend,  this is correct */
    /* check if the library is working as it should .. */
    Crypto_error = gcry_md_open(&Crypto_handle, algo, flags); /* FIXME let go of this mem when finished */
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
        unsigned char* byte_result = gcry_malloc_secure(gcry_md_get_algo_dlen(algo));
        /* helpers to make them human readable and comparable */
        unsigned char* helper = gcry_malloc_secure(gcry_md_get_algo_dlen(algo) / 2);

        if (!gcry_is_secure(byte_result) || !gcry_is_secure(helper)) {
            fprintf(stderr, "Could not allocate in secure memory!\n");
            abort();
        }

        /* copy hash into a RAW string [ignore warnings from here until the string concat] - the compiler will moan about the signedness */
        strcpy((char*)byte_result, (char*)gcry_md_read(Crypto_handle, algo)); /* only one algo in the obj, pass 0 for default */
        memset((void*)dest, 0, sizeof(dest)); /* clear memory where hash is to be written, THIS IS REALLY IMPORTANT */
        if (dest == NULL) abort(); /* the caller has to allocate the destination memory */

        /* format the raw string to hex notation and
         * pass it piece by piece into our char *dest
         * and concatenate */
        for (int i = 0; i < stringlength((const char*)byte_result); i++) {
            sprintf((char*)helper, "%02x", (unsigned char)byte_result[i]);
            stringconcat(dest, (const char*)helper);
        }
        dest[ strlen( dest ) ] = 0;
        /* generally clean up after ourselves ... */
        gcry_md_close(Crypto_handle); /* releases all security relevant information */
	Crypto_handle = NULL;
        gcry_free(byte_result);
        gcry_free(helper);
	Crypto_error = 0;
	byte_result = NULL;
	helper = NULL;
	
    } else	/* if the hash mechanism isnt working abort */
        abort();
}
