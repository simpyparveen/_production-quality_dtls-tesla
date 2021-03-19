// main.c
// 20 Dec2018, Simpy Parveen
// Inut : Secret key(1024bits = 128 bytes)
//Output : Public Key (512 bits= 64bytes) K2SN has each public key of 576 bits and so we had to XOR 


#include <immintrin.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sha3.h"
// read a hex string, return byte length or -1 on error.

static int test_hexdigit(char ch)
{
    if (ch >= '0' && ch <= '9')
        return  ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return  ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return  ch - 'a' + 10;
    return -1;
}

static int test_readhex(uint8_t *buf, const char *str, int maxbytes)
{
    int i, h, l;

    for (i = 0; i < maxbytes; i++) {
        h = test_hexdigit(str[2 * i]);
        if (h < 0)
            return i;
        l = test_hexdigit(str[2 * i + 1]);
        if (l < 0)
            return i;
        buf[i] = (h << 4) + l;
    }

    return i;
}

// returns zero on success, nonzero + stderr messages on failure

void test_sha3()
{
    int seed_len, K_len;
    uint8_t K[10][32], seed[32];
     FILE *f;
    //Clearing the memory
       
        
        memset(seed, 0, sizeof(seed));               //Original message to be hashed

        seed_len = 32;                            // Input bytes to the hash
        K_len = 32;                             // Output bytes from the hash
	
	printf("\n Seed length %d \n",seed_len);
	printf("Key length %d \n",K_len);



//for(int i=0;i<msg_len;i++)msg[i] = rand()%255;  // Input is taken randomly using rand()

    f = fopen("/dev/urandom", "r");
    fread(&seed, sizeof(unsigned int),seed_len, f);
    fclose(f);




for(int k=0;k<10;k++){

	sha3(seed, seed_len, K[k], K_len);		//sha3(msg, msg_len, buf, sha_len);             // Calculates Sha3 hash of the msg and saves it into buf
        
	printf("\n\nSeed : ");
	for(int i=0;i<seed_len;i++)printf("%hhu ",seed[i]);
		
	
	
	printf("\n\Sha key K[k][32] : ");
	for(int i=0;i<K_len;i++)printf("%hhu ",K[k][i]);

  	memset(seed,0,32);

	memcpy(&seed,K[k],32);
}
}

int main(int argc, char **argv)
{
        test_sha3(); //&& test_shake() == 0)
        printf("\n Finished !\n");
    //test_speed();

    return 0;
}

