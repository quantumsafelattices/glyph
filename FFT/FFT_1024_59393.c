
/* Code to compute a Number Theoretic Transform for multiplication in the ring 
F_q[x] / <x^n+1>.
	n = 1024, q = 59393	*/

	
#include "FFT_1024_59393.h"

#ifdef TESTFFT
#include <stdio.h>
#include <sys/time.h>
#endif

/*Set n and q*/
static const FFTSHORT n = 1024;
static const FFTSHORT q = 59393;

	
#include "FFT_1024_59393_constants.c"


/*
We use Gentleman-Sande, decimation-in-frequency FFT, for the forward FFT.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will invert 
the fourier transform using decimation-in-time.
*/
void FFT_forward_1024_59393(FFTSHORT x[1024]) {
	FFTSHORT index, step;
	FFTSHORT i,j,m;
	FFTSHORT t0,t1;

	step = 1;
	for (m = n>>1; m >= 1; m=m>>1) {
		index = 0;
		for (j = 0 ; j < m; ++j) {
			for (i = j; i < n; i += (m<<1)) {
				ADD_MOD(t0, x[i], x[i+m], q);
				ADD(t1, x[i], q - x[i+m]);
				MUL_MOD(x[i+m], t1, W[index], q);				
				x[i] = t0;				
			}
			SUB_MODn(index, index, step);
		}
		step = step << 1;
	}	 
}

/*
We use Cooley-Tukey, decimation-in-time FFT, for the inverse FFT.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will the forward
fourier transform is using decimation-in-frequency.
*/
void FFT_backward_1024_59393(FFTSHORT x[1024]) {
	FFTSHORT index, step;
	FFTSHORT i,j,m;
	FFTSHORT t0,t1;

	step = n>>1;
	for (m = 1; m < n; m=m<<1) {
		index = 0;
		for (j = 0 ; j < m; ++j) {
			for (i = j; i < n; i += (m<<1)) {							
				t0 = x[i];
				t0 -= (t0 >= q) ? q : 0;
				MUL_MOD(t1, x[i+m], W_rev[index], q);				
				ADD(x[i], t0, t1);
				ADD(x[i+m], t0, q - t1);
				
			}
			SUB_MODn(index, index, step);
		}
		step = step >> 1;
	}	
	for (i = 0; i < n; ++i) {
		x[i] -= (x[i] >= q) ? q : 0;
	}
}

	
/*
We use Gentleman-Sande, decimation-in-frequency FFT, for the forward FFT.
We premultiply x by the 2n'th roots of unity to affect a Discrete Weighted Fourier Transform, 
so when we apply pointwise multiplication we obtain the negacyclic convolution, i.e. multiplication 
modulo x^n+1.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will invert 
the fourier transform using decimation-in-time.
*/
void FFT_twisted_forward_1024_59393(FFTSHORT x[1024]) {
	FFTSHORT index, step;
	FFTSHORT i,j,m;
	FFTSHORT t0,t1;

	//Pre multiplication for twisted FFT
	j = 0;
	for (i = 0; i < n>>1; ++i) {
		MUL_MOD(x[j], x[j], W[i], q);
		j++;	
		MUL_MOD(x[j], x[j], W_sqrt[i], q);	
		j++;
	}

	step = 1;
	for (m = n>>1; m >= 1; m=m>>1) {
		index = 0;
		for (j = 0 ; j < m; ++j) {
			for (i = j; i < n; i += (m<<1)) {				
				ADD_MOD(t0, x[i], x[i+m], q);
				ADD(t1, x[i], q - x[i+m]);
				MUL_MOD(x[i+m], t1, W[index], q);				
				x[i] = t0;						
			}
			SUB_MODn(index, index, step);
		}
		step = step << 1;
	}	 
}

/*
We use Cooley-Tukey, decimation-in-time FFT, for the inverse FFT.
We postmultiply x by the inverse of the 2n'th roots of unity * n^-1 to affect a Discrete Weighted Fourier Transform, 
so when we apply pointwise multiplication we obtain the negacyclic convolution, i.e. multiplication 
modulo x^n+1.
Note that we will not perform the usual scambling / bit-reversal procedure here because we will the forward
fourier transform is using decimation-in-frequency.
*/
void FFT_twisted_backward_1024_59393(FFTSHORT x[1024]) {
	FFTSHORT index, step;
	FFTSHORT i,j,m;
	FFTSHORT t0,t1;

	step = n>>1;
	for (m = 1; m < n; m=m<<1) {
		index = 0;
		for (j = 0 ; j < m; ++j) {
			for (i = j; i < n; i += (m<<1)) {							
				t0 = x[i];
				t0 -= (t0 >= q) ? q : 0;
				MUL_MOD(t1, x[i+m], W_rev[index], q);				
				ADD(x[i], t0, t1);
				ADD(x[i+m], t0, q - t1);
			}
			SUB_MODn(index, index, step);
		}
		step = step >> 1;
	}

	//Post multiplication for twisted FFT
	j = 0;
	for (i = 0; i < n>>1; ++i) {
		MUL_MOD(x[j], x[j], W_rev[i], q);
		j++;	
		MUL_MOD(x[j], x[j], W_sqrt_rev[i], q);
		j++;
	} 
}

void _FFT_forward_1024_59393(FFTSHORT *x) {
  FFT_twisted_forward_1024_59393(x);
}

void _FFT_backward_1024_59393(FFTSHORT *x) {
  int i;
  FFT_twisted_backward_1024_59393(x);
  for (i=0; i<1024; ++i)
    MUL_MOD(x[i], x[i], 59335, 59393);
}
