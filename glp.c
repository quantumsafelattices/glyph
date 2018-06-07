/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#include <string.h>

#include "glp.h"
#include "glp_rand_openssl_aes.h"
#include "glp_utils.h"


/***********************************************SIGNING KEY GENERATION********************************/

/*generates signing key (s1,s2), stored in physical form */
void glp_gen_sk(glp_signing_key_t *sk){    
    sample_glp_secret(sk->s1);
    sample_glp_secret(sk->s2);
}


/***********************************************PUBLIC KEY GENERATION********************************/

/*takes a signing key stored in physical space and computes the public key in physical space */
/*points a1, a2 are stored in FFT space */
void glp_gen_pk(glp_public_key_t *pk, glp_signing_key_t sk){
  FFT_FORWARD(sk.s1);
  FFT_FORWARD(sk.s2);
  POINTWISE_MUL_ADD(pk->t, a, sk.s1, sk.s2, N, Q);
  FFT_BACKWARD(sk.s1);
  FFT_BACKWARD(sk.s2);
  FFT_BACKWARD(pk->t);
}


/**********************************************SIGNING*********************************************/

#if NISPOWEROFTWO
#define N_LIMIT N
#else
#define N_LIMIT N-1
#endif

#define MAXSIGNITERS 1000

/*signs a message as (z,c) where z is a ring elt in physical form, and c is a hash output encoded as a sparse poly */
int glp_sign(glp_signature_t *sig,
              const glp_signing_key_t sk, 
              const unsigned char *message_digest,
              const size_t dgst_len){
  RINGELT y1[N]={0}, y2[N] ={0};
  int success = 0;
  uint16_t i, sign_iters = 0;
 
  /*initialise random sampling for y1,y2*/
  RANDOM_VARS
  /*sample y1,y2 randomly, and repeat until they pass rejection sampling*/
  while(!success && (sign_iters < MAXSIGNITERS)){
    sign_iters += 1;
#if !NISPOWEROFTWO
    y1[N-1] = 0;
    y2[N-1] = 0;
#endif
  for(i = 0; i < N_LIMIT; i++){
    while(1){
      y1[i] = RANDOM32; /*get 32 bits of random */
      y1[i] &= ~(~0 << (B_BITS + 1)); /*take bottom (B_BITS + 1) bits */
      if(y1[i] <= 2*B + 1) break;
    }
    while(1){
      y2[i] = RANDOM32; /*get 32 bits of random */
      y2[i] &= ~(~0 << (B_BITS + 1)); /*take bottom (B_BITS + 1) bits */
      if(y2[i] <= 2*B + 1)   break;
    }    
    y1[i] = (y1[i] <= B)? y1[i] : Q - (y1[i] - B); 
    y2[i] = (y2[i] <= B)? y2[i] : Q - (y2[i] - B); 
  }
  success = glp_deterministic_sign(sig, y1,y2, sk, message_digest, dgst_len);
  }
  return success;
}


/*signs a message for a fixed choice of ephemeral secret y in physcial space
 returns 1 or 0 according to success or failure in doing so (due to rejection sampling)*/
int glp_deterministic_sign(glp_signature_t *signature, 
                           const RINGELT y1[N],
                           const RINGELT y2[N],
                           const glp_signing_key_t sk, 
                           const unsigned char *message_digest,
                           const size_t dgst_len){
  RINGELT ay1_y2[N], ay1_y2_rounded[N], y1_fft[N], y2_fft[N];
  unsigned char hash_output[GLP_DIGEST_LENGTH];
  copy_poly(y1_fft,y1);
  copy_poly(y2_fft,y2);
  FFT_FORWARD(y1_fft);
  FFT_FORWARD(y2_fft);

  /*ay1_y2 = a y1 + y2*/
  POINTWISE_MUL_ADD(ay1_y2,a,y1_fft,y2_fft,N,Q);
  FFT_BACKWARD(ay1_y2);
  MAPTOCYCLOTOMIC(ay1_y2,N,Q);

  /*round and hash u*/
  copy_poly(ay1_y2_rounded,ay1_y2);
  K_floor(ay1_y2_rounded);
  if(!hash(hash_output, ay1_y2_rounded, message_digest,dgst_len)) return 0;
  if(!encode_sparse(&(signature->c), hash_output)) return 0;

  /*z_1 = y_1 + s_1 c*/
  sparse_mul(signature->z1, sk.s1, signature->c);
  POINTWISE_ADD(signature->z1,signature->z1,y1,N,Q);
  MAPTOCYCLOTOMIC(signature->z1,N,Q);

  /*rejection sampling on z_1*/
  for(uint16_t i = 0; i < N_LIMIT; i++) if(ABS(signature->z1[i]) > (B-OMEGA) ) return 0;

  /*z_2 = y_2 + s_2 c*/
  sparse_mul(signature->z2, sk.s2, signature->c);
  POINTWISE_ADD(signature->z2,signature->z2,y2,N,Q);
  MAPTOCYCLOTOMIC(signature->z2,N,Q);

  /*rejection sampling on z_2*/
  for(uint16_t i = 0; i < N_LIMIT; i++) if(ABS(signature->z2[i]) > (B-OMEGA) ) return 0;

  /*compression of a*z1 - t*c = (a*y1+y2) - z2*/
  RINGELT az1_tc[N];
  POINTWISE_SUB(az1_tc,ay1_y2,signature->z2, N, Q);
  MAPTOCYCLOTOMIC(az1_tc,N,Q);

   /*signature compression*/
  for(uint16_t i = 0; i < N_LIMIT; i++){
    signature->z2[i] = compress_coefficient(az1_tc[i], signature->z2[i]);
  }

  return 1;
}



/**********************************************VERIFICATION*********************************************/

int glp_verify(glp_signature_t sig, 
               const glp_public_key_t pk, 
               const unsigned char *message_digest,
               const size_t dgst_len){
  RINGELT h[N],tc[N];  
  sparse_poly_t c_test;
  unsigned char hash_output[GLP_DIGEST_LENGTH];
  uint16_t i;
  for(i = 0; i < N_LIMIT; i++){
    if(ABS(sig.z1[i]) > (B-OMEGA) ) return 0;
    if(ABS(sig.z2[i]) > (B-OMEGA) ) return 0;
  }
  FFT_FORWARD(sig.z1);
  FFT_FORWARD(sig.z2);
  POINTWISE_MUL_ADD(h,a,sig.z1,sig.z2,N,Q);
  FFT_BACKWARD(h);
  sparse_mul(tc,pk.t,sig.c);
  POINTWISE_SUB(h,h,tc,N,Q);
  MAPTOCYCLOTOMIC(h,N,Q);
  K_floor(h);
  if(!hash(hash_output, h, message_digest, dgst_len))return 0;
  if(!encode_sparse(&c_test,hash_output))return 0;
  for(i = 0; i < OMEGA; i++){
    if(c_test.pos[i] != sig.c.pos[i]) return 0;
    if(c_test.sign[i] != sig.c.sign[i])return 0;
  }
    
  return 1;
}
