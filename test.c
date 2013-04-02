#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#include "SHA3api_ref.h"

#define HbLEN 1024
#define HBLEN (HbLEN/8)

#define CHUNKSIZE 16

typedef BitSequence hashval_t[HBLEN];

static const hashval_t target = {
	0x5b, 0x4d, 0xa9, 0x5f, 0x5f, 0xa0, 0x82, 0x80,
	0xfc, 0x98, 0x79, 0xdf, 0x44, 0xf4, 0x18, 0xc8,
	0xf9, 0xf1, 0x2b, 0xa4, 0x24, 0xb7, 0x75, 0x7d,
	0xe0, 0x2b, 0xbd, 0xfb, 0xae, 0x0d, 0x4c, 0x4f,
	0xdf, 0x93, 0x17, 0xc8, 0x0c, 0xc5, 0xfe, 0x04,
	0xc6, 0x42, 0x90, 0x73, 0x46, 0x6c, 0xf2, 0x97,
	0x06, 0xb8, 0xc2, 0x59, 0x99, 0xdd, 0xd2, 0xf6,
	0x54, 0x0d, 0x44, 0x75, 0xcc, 0x97, 0x7b, 0x87,
	0xf4, 0x75, 0x7b, 0xe0, 0x23, 0xf1, 0x9b, 0x8f,
	0x40, 0x35, 0xd7, 0x72, 0x28, 0x86, 0xb7, 0x88,
	0x69, 0x82, 0x6d, 0xe9, 0x16, 0xa7, 0x9c, 0xf9,
	0xc9, 0x4c, 0xc7, 0x9c, 0xd4, 0x34, 0x7d, 0x24,
	0xb5, 0x67, 0xaa, 0x3e, 0x23, 0x90, 0xa5, 0x73,
	0xa3, 0x73, 0xa4, 0x8a, 0x5e, 0x67, 0x66, 0x40,
	0xc7, 0x9c, 0xc7, 0x01, 0x97, 0xe1, 0xc5, 0xe7,
	0xf9, 0x02, 0xfb, 0x53, 0xca, 0x18, 0x58, 0xb6,
};

static int compare_hash(hashval_t h)
{
	int i, count = 0;
	unsigned long long* lh = (unsigned long long*)h;
	unsigned long long* lt = (unsigned long long*)target;

	for (i = 0; i < HBLEN/(sizeof(lh[0])/sizeof(h[0])); i++) {
		count += __builtin_popcountll(lt[i] ^ lh[i]);
	}

	return count;
}
static const char hex[] = "0123456789abcdef";

static void hexify(const void* input, size_t inlen, char* output)
{
	int i;

	for (i = 0; i < inlen; i++) {
		output[i*2] = hex[((unsigned char*)input)[i] >> 4];
		output[i*2 + 1] = hex[((unsigned char*)input)[i] & 0xf];
	}
}

typedef BitSequence input_t[32];

static int score_hash(char* str, hashval_t hash)
{
	HashReturn ret;
	size_t dlen = strlen(str);

	ret = Hash(HbLEN, (const BitSequence*)str, dlen * CHAR_BIT, hash);
	if (ret != SUCCESS) {
		fprintf(stderr, "Error: %s\n", ret == FAIL ? "FAIL" \
		        : ret == BAD_HASHLEN ? "BAD_HASHLEN"
		        : (abort(), (char*)NULL));
		return -1;
	}

	return compare_hash(hash);
}

static FILE* input;

static unsigned long count = 0;
static int best = 1024;
static hashval_t hash;

static struct timeval starttime;

static void do_input(void)
{
	int i, tmp;
	unsigned char change;
	char hashtext[256+1];
	char raw_input[CHUNKSIZE];
	char hex_input[CHUNKSIZE*2 + 1];
	hex_input[CHUNKSIZE*2] = '\0';
	hashtext[256] = '\0';

	if (fread(raw_input, CHUNKSIZE, 1, input) != 1) {
		perror("read");
		abort();
	}

	hexify(raw_input, CHUNKSIZE, hex_input);

	for (i = 0; i < CHUNKSIZE; i++) {
		tmp = score_hash(hex_input, hash);

		if (tmp < best) {
			best = tmp;
			hexify(hash, HBLEN, hashtext);
			printf("score(\"%s\") = %d\n%256s\n", hex_input, tmp, hashtext);
			fflush(stdout);
			fsync(fileno(stdout));
		}

		count += 1;

		change = ~raw_input[i];
		hex_input[i*2] = hex[change >> 4];
		hex_input[i*2+1] = hex[change & 0xf];
	}
}

static void sigint(int sig)
{
	struct timeval endtime, elapsed;
	if (gettimeofday(&endtime, NULL))
		abort();
	fclose(input);
	timersub(&endtime, &starttime, &elapsed);
	printf("\n%lu hashes in %ld.%06ld seconds\n", count, elapsed.tv_sec, elapsed.tv_usec);
	printf("(%g hashes per second)\n",
	       (double)count / ((double)elapsed.tv_sec + ((double)elapsed.tv_usec/1000000)));
	exit(0);
}

int main(int argc, char** argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s SOURCE\n", argv[0]);
		exit(1);
	}

	if (!(input = fopen(argv[1], "r"))) {
		perror(argv[1]);
		exit(1);
	}

	if (signal(SIGINT, sigint) == SIG_ERR) {
		perror("signal(SIGINT)");
		exit(1);
	}

	if (gettimeofday(&starttime, NULL))
		abort();

	for (;;)
		do_input();

	return 0;
}
