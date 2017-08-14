/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef GLP_TEST_VECTORS_H
#define GLP_TEST_VECTORS_H

#include "glp.h"
#include "glp_utils.h"

struct glp_test_vec_st{
  glp_public_key_t pk;
  glp_signing_key_t sk;
  RINGELT y1[N];
  RINGELT y2[N];
  glp_signature_t sig;
  char *message;
};

typedef struct glp_test_vec_st glp_test_vec_t;

#if GLP_N == 1024
#include "test_vectors_1024.h"
#endif

int test_vector(glp_test_vec_t vec);
#endif
