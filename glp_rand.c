/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */


#include "glp_rand.h"
#include "glp_rand_openssl_aes.h"


void sample_glp_secret(RINGELT f[N]){
  uint64_t rand64;
  uint16_t rand2;
  uint16_t rand_bits_used = 0;
  uint16_t i;
  RANDOM_VARS
  rand64 = RANDOM64;
    
#if NISPOWEROFTWO
  for(i = 0; i < N; i++){
#else
  f[N-1] = 0;
  for(i = 0; i < N-1; i++){
#endif

    while(1){
      if(rand_bits_used >= 63){
        rand64 = RANDOM64;
        rand_bits_used = 0;
      }
      rand2 = (uint16_t) rand64 & (uint16_t)3;
      rand64 >>= 2;
      rand_bits_used += 2;
      if(3!= rand2) break;
    }
    if(0 == rand2) f[i] = 0;
    else if(1 == rand2) f[i] = 1;
    else if(2 == rand2) f[i] = Q - 1;
    else printf("ERROR in secret sampling %d should only equal 0,1 or 2!\n",rand2);
  }
}
  

