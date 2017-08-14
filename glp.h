/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef HEADER_GLP_H
#define HEADER_GLP_H

#include "glp_consts.h"
#include "glp_rand.h"

#define GLP_DIGEST_LENGTH 32
  
#ifndef RINGELT
#define RINGELT uint32_t
#endif


/*signature structs */
struct glp_public_key_st{
  RINGELT t[N];
};

struct glp_signing_key_st{
  RINGELT s1[N];
  RINGELT s2[N];
};

struct sparse_poly_st{
  uint16_t pos[OMEGA];
  uint16_t sign[OMEGA];
};

typedef struct sparse_poly_st sparse_poly_t;

struct glp_signature_st{
  RINGELT z1[N];
  RINGELT z2[N];
  sparse_poly_t c;
};


typedef struct glp_public_key_st glp_public_key_t;
typedef struct glp_signing_key_st glp_signing_key_t;
typedef struct glp_signature_st glp_signature_t; 

/*macros for working mod q */
#define SIGN(A) (0 == (A))? 0 : ((2*(A) <= Q) ? 1 : -1) 
#define ABS(A) (2*(A) <= Q ? (A) : Q - (A))
#define NEG(A) ((Q - (A)) % Q)

/* Internal function prototypes */
void glp_gen_sk(glp_signing_key_t *sk);
void glp_gen_pk(glp_public_key_t *pk,glp_signing_key_t sk);
RINGELT abs_low_bits(RINGELT x);
int glp_sign(glp_signature_t *sig,
              const glp_signing_key_t sk,  
              const unsigned char *message_digest,
              const size_t dlen);
int glp_verify(glp_signature_t sig, 
               const glp_public_key_t pk, 
               const unsigned char *message_digest,
               const size_t dgst_len);
int glp_deterministic_sign(glp_signature_t *signature, 
                           const RINGELT y1[N],
                           const RINGELT y2[N],
                           const glp_signing_key_t sk,
                           const unsigned char *message_digest,
                           const size_t dgst_len);





#endif /* HEADER_GLP_H */


