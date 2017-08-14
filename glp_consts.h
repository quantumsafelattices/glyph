/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef HEADER_GLP_CONSTS_H
#define HEADER_GLP_CONSTS_H

#ifndef RINGELT
#define RINGELT uint_fast16_t
#endif

#define RINGELT_BYTES 2

#undef VALID_N

#if GLP_N == 1024
#include "glp_consts_1024.h"
#define VALID_N
#endif

#endif /* HEADER_GLP_CONSTS_H */
