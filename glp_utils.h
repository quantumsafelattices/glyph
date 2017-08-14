/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef GLP_UTILS_H
#define GLP_UTILS_H

#include "glp_rand.h"

void copy_poly(RINGELT f[N],
	       const RINGELT g[N]);
void print_poly(const RINGELT f[N]);
void print_sparse(const sparse_poly_t s);
void print_pk(const glp_public_key_t pk);
void print_sk(const glp_signing_key_t sk);
void print_sig(const glp_signature_t sig);

int hash(unsigned char hash_output[GLP_DIGEST_LENGTH],
	 RINGELT u[N],
	 const unsigned char* mu,
	 const size_t mulen);
void sparse_mul(RINGELT v[N],
                const RINGELT a[N],
                const sparse_poly_t b);
int encode_sparse(sparse_poly_t * encode_output,
		  const unsigned char hash_output[GLP_DIGEST_LENGTH]);
void round_poly(RINGELT f[N],RINGELT K);
RINGELT high_bits(RINGELT z, RINGELT K);
RINGELT low_bits(RINGELT z, RINGELT K);
#endif
