CC=gcc
CCFLAGS=-O3 -Wall -Wextra -std=gnu99 -pedantic -Wfatal-errors -funroll-all-loops 

all: test_1024 

test_1024: test.c glp_test_vectors_1024.o glp_1024.o glp_utils_1024.o glp_rand_1024.o glp_rand_openssl_aes_1024.o FFT/FFT_1024_59393.o 
	$(CC) $(CCFLAGS) -D GLP_N=1024  -o $@ $^ -lm -lcrypto

glp_1024.o: glp.c
	$(CC)  $(CCFLAGS) -c -D GLP_N=1024  -o $@ $^ 

glp_test_vectors_1024.o: test_vectors.c
	$(CC) $(CCFLAGS) -c -D GLP_N=1024  -o $@ $^

glp_utils_1024.o: glp_utils.c
	$(CC) $(CCFLAGS) -c -D GLP_N=1024  -o $@ $^ 

glp_rand_1024.o: glp_rand.c
	$(CC) $(CCFLAGS) -c -D GLP_N=1024  -o $@ $^ 

glp_rand_openssl_aes_1024.o: glp_rand_openssl_aes.c
	$(CC) $(CCFLAGS) -c -D GLP_N=1024  -o $@ $^ 


clean: 
	rm -f FFT/*.o *.o test_1024 write_test_1024 


