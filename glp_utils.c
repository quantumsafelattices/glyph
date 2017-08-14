/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */


#include "glp_utils.h"
#include "glp_rand_openssl_aes.h"


/**************************************************************PRINTING AND COPYING******************************************************/

void copy_poly(RINGELT f[N], const RINGELT g[N]){
  uint16_t i;
  for(i = 0; i < N; i++) f[i] = g[i];
}

void print_poly(const RINGELT f[N]){
  uint16_t i;
  for(i = 0; i < N ; i++){
    printf("%ld ", 2*f[i] < Q ? f[i] : f[i] - Q );
  }
  printf("\n");
}


void print_sk(const glp_signing_key_t sk){
  printf("s1:");
  print_poly(sk.s1);
  printf("\n");
  printf("s2:");
  print_poly(sk.s2);
}


void print_pk(const glp_public_key_t pk){
  printf("t:");
  print_poly(pk.t);
}

void print_sparse(const sparse_poly_t s){
  uint16_t i;
  for(i = 0; i < OMEGA; i++) printf("(%d,%d)",s.pos[i],s.sign[i]);
  printf("\n");
}

void print_sig(const glp_signature_t sig){
  printf("z1:");
  print_poly(sig.z1);
  printf("\n");
  printf("z2:");
  print_poly(sig.z2);
  printf("\n");
  printf("c:");
  print_sparse(sig.c);
  printf("\n");
}



/***************************************************************HASH ROUTINE*************************************/
void poly2bytes(unsigned char *y, RINGELT f[N]){
  RINGELT x;
  uint16_t i,j;
  for(i = 0; i < N; i++){
    x = f[i];
#if !NISPOWEROFTWO 
    if (i == N-1)
      x = 0;
#endif
    for(j = 0; j < Q_BYTES; j++){
      y[Q_BYTES*i + j] = x & 0xff;
      x >>= 8;
    }
  }
}

/*hash function */
/*input: one polynomial, mu (usually itself a message digest),
         and the length of mu in bytes*/
/*output: a 256-bit hash */

int hash(unsigned char hash_output[GLP_DIGEST_LENGTH],
	  RINGELT u[N],
	  const unsigned char* mu,
	  const size_t mulen){
  int ret;
  #if NISPOWEROFTWO
  uint64_t bytesPerPoly = N * Q_BYTES;
  #else
  uint64_t bytesPerPoly = (N-1) * Q_BYTES;
  #endif
  uint64_t hash_input_bytes = bytesPerPoly+ mulen;
  uint16_t i;
  unsigned char *hash_input;
  if ((hash_input = (unsigned char *)malloc(hash_input_bytes)) == NULL) return 0;
  poly2bytes(hash_input,u);
  for(i = 0; i < mulen; i++) hash_input[i + bytesPerPoly] = mu[i];
  SHA256_CTX sha256;
  ret = 1;
  ret &= SHA256_Init(&sha256);
  ret &= SHA256_Update(&sha256, hash_input, hash_input_bytes);
  ret &= SHA256_Final(hash_output, &sha256);
  free(hash_input);
  return ret;
}



  
/***************************************************************SPARSE POLY MULTIPLICATION*************************/
void sparse_mul(RINGELT v[N], const RINGELT a[N], const sparse_poly_t b){

  RINGELT v_aux[2*N];
  uint16_t i,j;
  /*zero the output*/
  for(i = 0; i < 2*N; i++) v_aux[i] = 0;

  /*multiply in Z[x]*/
  for(i = 0; i < OMEGA; i++) {
    for(j = 0; j < N; j++) {
      if(b.sign[i] == 1) ADD_MOD(v_aux[b.pos[i] + j], v_aux[b.pos[i] + j], a[j],Q);
      else SUB_MOD(v_aux[b.pos[i] + j], v_aux[b.pos[i] + j], a[j],Q);   
    }
  }
#if NISPOWEROFTWO
  /*reduce mod x^n + 1*/
  for(i = 0; i < N; i++) SUB_MOD(v[i], v_aux[i], v_aux[i+N], Q);
#else
  /*reduce mod x^n - 1*/
  for(i = 0; i < N; i++) ADD_MOD(v[i], v_aux[i], v_aux[i+N], Q);
#endif
}

/**************************************************************ENCODE ROUTINES*************************************/
int encode_sparse(sparse_poly_t *encode_output,
                  const unsigned char hash_output[GLP_DIGEST_LENGTH]){
  
 /*key AES on hash output*/
  AES_KEY aes_key;
  if (AES_set_encrypt_key(hash_output,8*GLP_DIGEST_LENGTH,&aes_key) < 0)return 0;
  /*initialise AES */
  unsigned char aes_ivec[AES_BLOCK_SIZE];
  memset(aes_ivec, 0, AES_BLOCK_SIZE); 
  unsigned char aes_ecount_buf[AES_BLOCK_SIZE]; 
  memset(aes_ecount_buf, 0, AES_BLOCK_SIZE); 
  unsigned int aes_num = 0; 
  unsigned char aes_in[AES_BLOCK_SIZE]; 
  memset(aes_in, 0, AES_BLOCK_SIZE);

  /*get OMEGA values in [0,n), each with a 0 or 1 to indicate sign*/
  uint64_t rand64 = randomplease(&aes_key, aes_ivec, aes_ecount_buf, &aes_num, aes_in);
  uint16_t rand_bits_used = 0;
  uint16_t pos,sign,i,j;
  for(i=0; i<OMEGA; i++){
    while(1){
      if(rand_bits_used >= (62 - NBITS)){
        rand64 = (uint32_t) randomplease(&aes_key, aes_ivec, aes_ecount_buf, &aes_num, aes_in);
        rand_bits_used = 0;
      }
   
      /*get random bits for this coefficient */
      sign = rand64&1;
      rand64 >>= 1;
      rand_bits_used += 1;
      pos = rand64 & (~((~0)<<NBITS));
      rand64 >>= NBITS;
      rand_bits_used += NBITS;

      /*get position from random*/
#if NISPOWEROFTWO
      if(pos < N)
#else
      if(pos < N-1)
#endif
        {
          /*check we are not using this position already */
          int success=1;
          for(j = 0; j < i; j++) if(pos == encode_output->pos[j]) success = 0;
          if(success) break;
        }
    }
    (encode_output->sign)[i] = sign;
    (encode_output->pos)[i] = pos;
  } 
  return 1;
}


/***********************************************ROUNDING***********************/
void round_poly(RINGELT f[N], RINGELT K){
  uint16_t i;
  for(i = 0; i < N; i++){
    f[i] = high_bits(f[i],K);
  }
}

/*high bits of z*/
RINGELT high_bits(RINGELT z, RINGELT K){
  return z/(RINGELT)(2*K + 1);
}

/*low bits of z, represented in [-K,K) mod Q */
RINGELT low_bits(RINGELT z, RINGELT K){
  RINGELT out = z - (high_bits(z,K))*(2*K+1);
  return out <= K ? out : NEG(2*K + 1 - z);
}
