/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */


#include "glp.h"
#include "glp_utils.h"
#include "test_vectors.h"
#define SIGN_TRIALS 1000


int main(){

  glp_signing_key_t sk;
  glp_public_key_t pk;
  char *message = "testtest";
  glp_signature_t sig;

  /*print a single example*/
  printf("example signature");
  printf("\nmessage:\n");
  printf("%s\n",message);
  glp_gen_sk(&sk);
  glp_gen_pk(&pk, sk);
  printf("\nsigning key:\n");
  print_sk(sk);
  printf("\npublic key:\n");
  print_pk(pk);
  glp_sign(&sig, sk,(unsigned char *)message,strlen(message));
  printf("\nsignature:\n");
  print_sig(sig);
  
uint16_t i;

  
  printf("******************************************************************************************************\n");


  /*run test vectors*/
  for(i = 0; i < N_GLP_TEST_VECS;i++){
    printf("running test vector %d of %d\n",i+1,N_GLP_TEST_VECS);
    if(test_vector(glp_test_vecs[i])) printf("passed\n");
    else printf("failed\n");
  }

  printf("******************************************************************************************************\n");

  /*test a lot of verifications*/
  printf("trying %d independent keygen/sign/verifies\n", SIGN_TRIALS);
  for(i=0; i < SIGN_TRIALS; i++){
    glp_gen_sk(&sk);
    glp_gen_pk(&pk,sk);
    if(!glp_sign(&sig, sk,(unsigned char *)message,strlen(message))){
      printf("signature failure round %d!\n",i);
    }
    if(!glp_verify(sig, pk,(unsigned char *)message,strlen(message))){
      printf("verification failure round %d!\n",i);
      return 1;
    }
    if(!(i % 100)){
      printf("passed trial %d\n",i);
    }
  }
  printf("signature scheme validates across %d independent trials\n", SIGN_TRIALS);
  printf("******************************************************************************************************\n");

  
  return 0;
}
