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
  RINGELT u[N],u_rounded[N], y1_fft[N], y2_fft[N];
  unsigned char hash_output[GLP_DIGEST_LENGTH];
  copy_poly(y1_fft,y1);
  copy_poly(y2_fft,y2);
  FFT_FORWARD(y1_fft);
  FFT_FORWARD(y2_fft);

  /*u = a y1 + y2*/
  POINTWISE_MUL_ADD(u,a,y1_fft,y2_fft,N,Q);
  FFT_BACKWARD(u);
  MAPTOCYCLOTOMIC(u,N,Q);

  /*round and hash u*/
  copy_poly(u_rounded,u);
  round_poly(u_rounded,B - OMEGA);
  if(!hash(hash_output, u_rounded, message_digest,dgst_len)) return 0;
  if(!encode_sparse(&(signature->c), hash_output)) return 0;

  /*z_1 = y_1 + s_1 c*/
  sparse_mul(signature->z1, sk.s1, signature->c);
  POINTWISE_ADD(signature->z1,signature->z1,y1,N,Q);
  MAPTOCYCLOTOMIC(signature->z1,N,Q);

  /*rejection sampling on z_1*/
  for(uint16_t i = 0; i < N_LIMIT; i++) if(ABS(signature->z1[i]) > (B - OMEGA) ) return 0;

  /*z_2 = y_2 + s_2 c*/
  sparse_mul(signature->z2, sk.s2, signature->c);
  POINTWISE_ADD(signature->z2,signature->z2,y2,N,Q);
  MAPTOCYCLOTOMIC(signature->z2,N,Q);

  /*rejection sampling on z_2*/
  for(uint16_t i = 0; i < N_LIMIT; i++) if(ABS(signature->z2[i]) > (B - OMEGA) ) return 0;

  /*compression rounding_target = a*z1 - t*c = u - z2*/
  RINGELT approx_u[N], rounding_target[N];
  POINTWISE_SUB(rounding_target,u,signature->z2, N, Q);
  MAPTOCYCLOTOMIC(rounding_target,N,Q);

  copy_poly(approx_u,rounding_target);
  round_poly(approx_u,B -OMEGA);

  /*signature compression*/
  for(uint16_t i = 0; i < N_LIMIT; i++){
    if(approx_u[i] == u_rounded[i]) signature->z2[i] = 0;

    else if(rounding_target[i] <= (B-OMEGA)){
      if(2*(Q%(2*(B-OMEGA) + 1)) >= (B-OMEGA)){
        if((SIGN(signature->z2[i]) < 0) && (SIGN((rounding_target[i] + signature->z2[i]) %Q) <0)) signature->z2[i] = NEG(B-OMEGA);
        else signature->z2[i] = B-OMEGA;
      }
    }

    else if(rounding_target[i] >= Q - (B-OMEGA)){
      if((SIGN(signature->z2[i]) > 0) && (rounding_target[i] + signature->z2[i] >= Q))signature->z2[i] = (B-OMEGA);
      else if(approx_u[i] == u_rounded[i] + 1) signature->z2[i] = NEG(B-OMEGA);
    }

    else if(approx_u[i] == u_rounded[i] + 1) signature->z2[i] = NEG(B-OMEGA);
    else signature->z2[i] = B-OMEGA;
  }
  return 1;
}



/**********************************************VERIFICATION*********************************************/

int glp_verify(glp_signature_t sig, 
               const glp_public_key_t pk, 
               const unsigned char *message_digest,
               const size_t dgst_len){
  RINGELT u[N],v[N];  
  sparse_poly_t c_test;
  unsigned char hash_output[GLP_DIGEST_LENGTH];
  uint16_t i;
  for(i = 0; i < N_LIMIT; i++){
    if(ABS(sig.z1[i]) > (B - OMEGA) ) return 0;
    if(ABS(sig.z2[i]) > (B - OMEGA) ) return 0;
  }
  FFT_FORWARD(sig.z1);
  FFT_FORWARD(sig.z2);
  POINTWISE_MUL_ADD(u,a,sig.z1,sig.z2,N,Q);
  FFT_BACKWARD(u);
  sparse_mul(v,pk.t,sig.c);
  POINTWISE_SUB(u,u,v,N,Q);
  MAPTOCYCLOTOMIC(u,N,Q);
  round_poly(u, B-OMEGA);
  if(!hash(hash_output, u, message_digest, dgst_len))return 0;
  if(!encode_sparse(&c_test,hash_output))return 0;
  for(i = 0; i < OMEGA; i++){
    if(c_test.pos[i] != sig.c.pos[i]) return 0;
    if(c_test.sign[i] != sig.c.sign[i])return 0;
  }
    
  return 1;
}

