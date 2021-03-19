//http://www.cs.yale.edu/homes/aspnes/pinewiki/C(2f)Randomization.html

/**

If you really need actual random numbers and are on a Linux or BSD-like operating system, you can use the special device files /dev/random and /dev/urandom. These can be opened for reading like ordinary files, but the values read from them are a random sequence of bytes (including null characters). 

Both /dev/random and /dev/urandom derive their random bits from physically random properties of the computer, like time between keystrokes or small variations in hard disk rotation speeds. 

The difference between the two is that /dev/urandom will always give you some random-looking bits, even if it has to generate extra ones using a cryptographic pseudo-random number generator, while /dev/random will only give you bits that it is confident are in fact random. 

Since your computer only generates a small number of genuinely random bits per second, this may mean that /dev/random will exhaust its pool if read too often. In this case, a read on /dev/random will block (just like reading a terminal with no input on it) until the pool has filled up again. 


*/
#include <stdio.h>
#include <stdint.h>
//#include "sodium.h"

 int main(int argc, char **argv)
{
    unsigned int randval[3];
    FILE *f;
    f = fopen("/dev/random", "r");
    fread(&randval, sizeof(unsigned int), 3, f);
    fclose(f);

      printf("%u\n", randval);

	char ran1[32];
	uint32_t myint;
	if(sodium_init()< 0 ) return 1;

	randombytes_buf(ran1,32);
	myint = randombytes_uniform(10);
	printf("\n%hhu",myint);

   return 0;
}
