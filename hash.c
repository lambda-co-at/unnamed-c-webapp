/*
 * new modular hash function for the sqlite3 interface
 * by David Schuster © 2016   
 */

#define _GNU_SOURCE
#include "login.h"

void hash_func(int algo, char* digest, const void* value, size_t len)
{
  size_t algolen  = gcry_md_get_algo_dlen(algo);
  char* rawResult = gcry_malloc_secure(algolen);
  
  gcry_md_hash_buffer(algo, rawResult, value, len);
  
  for (int i = 0; i < algolen; i++) {
    sprintf(digest+(i*2), "%02x", (unsigned char)rawResult[i]); /* pointer magic */ 
  }
  gcry_free(rawResult);
}

void gcrypt_init()
{
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
  gcry_control(GCRYCTL_INIT_SECMEM, 65536, 0),
  gcry_control(GCRYCTL_RESUME_SECMEM_WARN),
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0),
  initialized = true;
}
