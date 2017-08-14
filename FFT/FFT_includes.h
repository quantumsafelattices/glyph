/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#ifndef FFT_INCLUDES_H
#define FFT_INCLUDES_H

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define FFTLONG uint_fast64_t
#define PRIuFFTLONG PRIuFAST64
#define FFTSHORT uint_fast32_t
#define PRIuFFTSHORT PRIuFAST32

#define ADD(x, a, b) \
do {\
        x = (a) + (b);\
} while (0)

#define MUL_MOD(x, a, b, q) \
do {\
        FFTLONG x64 = ((FFTLONG)(a) * (FFTLONG)(b));	\
        x64 = x64 % (q);\
        x = (FFTSHORT) x64;\
} while(0)


#define MUL_MOD_LONG(x_long,a_short,b_short,q_long) \
do {\
        x_long = ((FFTLONG)(a_short) * (b_short));\
        x_long %= q_long;\
} while (0)


#define ADD_MOD(x, a, b, q) \
do {\
        x = (a) + (b);\
        x -= (x >= (q)) ? (q) : 0;\
} while (0)


#define ADD_MOD_LONG(x,a,b,q) \
do {\
	x = (a) + (b);\
	x -= (x >= (q)) ? (q) : 0;\
} while (0)


#define SUB_MOD(x, a, b, q) \
do {\
        x = (a) + ((q) - (b));\
        x -= (x >= (q)) ? (q) : 0;\
} while (0)


#define SUB_MOD_LONG(x,a,b,q) \
do {\
	x = (a) + ((q) - (b));\
	x -= (x >= (q)) ? (q) : 0;\
} while (0)


/*Needed for indexing in the FFT*/
#define SUB_MODn(x, a, b, n)			\
do {\
        x = (a) + (n-(b));\
        x -= (x >= n) ? n : 0;\
} while (0)

/* Pointwise multiplication in the ring */
#define POINTWISE_MUL(v, b, e0, m, q)		\
  do {   uint16_t _i;\
	for (_i = 0; _i < m; ++_i) {\
		MUL_MOD((v)[_i], (e0)[_i], (b)[_i], (q));\
	}\
} while(0)

/* Pointwise addition in the ring */
#define POINTWISE_ADD(v, b, e0, m, q)		\
    do {  uint16_t _i;\
	for (_i = 0; _i < m; ++_i) {\
		ADD_MOD((v)[_i], (e0)[_i], (b)[_i], (q));\
	}\
} while(0)


/* Pointwise subtraction in the ring */
#define POINTWISE_SUB(v, b, e0, m, q)		\
    do {  uint16_t _i;\
	for (_i = 0; _i < m; ++_i) {\
		SUB_MOD((v)[_i], (b)[_i], (e0)[_i], (q));\
	}\
} while(0)


/* Pointwise multiplication and addition in the ring.
   All done in the FFT / CRT domain. */
#define POINTWISE_MUL_ADD(v, b, e0, e1, m, q)	\
    do {  uint16_t _i;\
	for (_i = 0; _i < m; ++_i) {\
		MUL_MOD((v)[_i], (e0)[_i], (b)[_i], (q));\
		ADD_MOD((v)[_i], (v)[_i], (e1)[_i], (q));\
	}\
} while(0)



/*Map a length m object in the ring F_q[x]/<x^m-1> to a length m-1 object in the ring F_q[x]/<1+x+...+x^{m-1}>*/
#if NISPOWEROFTWO
#define MAPTOCYCLOTOMIC(v, m, q)
#else
#define MAPTOCYCLOTOMIC(v, m, q)		\
    do {  uint16_t _i;\
        for (_i = 0; _i < m-1; ++_i) {				\
			SUB_MOD((v)[_i], (v)[_i], (v)[m-1], q);\
		}\
		v[m-1] = 0;\
	} while(0)
#endif


#endif /* FFT_INCLUDES_H */



