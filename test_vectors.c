/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#include "test_vectors.h"

int test_vector(glp_test_vec_t vec){
  int success = 1;
    
  /*check that public key is derived from signing key*/
  glp_public_key_t pk_test;
  glp_gen_pk(&pk_test, vec.sk);
  for(int i = 0; i < N; i++){
    if((pk_test.t)[i] != (vec.pk.t)[i]){
      printf("failed to derive public key from signing key\n");
      success = 0;
      break;
    }
  }
  
  /*check that supplied signature verifies correctly*/
  if(!glp_verify(vec.sig, vec.pk, (unsigned char*)(vec.message), strlen(vec.message))
     ){
      printf("failed to verify test vector with supplied signatures!\n");
      success = 0;
    }

  /*check that computed signature matches provided one*/
  glp_signature_t sig_test;
  if(!glp_deterministic_sign(&sig_test, vec.y1,vec.y2, vec.sk, (unsigned char *)vec.message, strlen(vec.message))){
    printf("failed to sign message!\n");
  }
#if NISPOWEROFTWO
  for(int i = 0; i < N; i++){
#else
  for(int i = 0; i < N-1; i++){
#endif

    if(((sig_test.z1)[i] != (vec.sig.z1)[i])||((sig_test.z2)[i] != (vec.sig.z2)[i])){
      printf("failed to produce signature from test vector!\n");
      success = 0;
      break;
    }    
  }
  for(int i = 0; i < OMEGA; i++){
    if( ((sig_test.c.pos)[i] != (vec.sig.c.pos)[i])||((sig_test.c.sign)[i] != (vec.sig.c.sign)[i])){
      printf("failed to produce signature from test vector!\n");
      success = 0;
      break;
    }
    
  }

  return success;
}
