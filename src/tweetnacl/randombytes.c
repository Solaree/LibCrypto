#ifdef WIN32
#include "Windows.h"
#endif
#include <stdio.h>
#include <stdlib.h>

void randombytes(unsigned char *buf, unsigned int buf_len) {
	char failed = 0;
#ifdef WIN32
	static HCRYPTPROV prov = 0;
	if (prov == 0) {
		if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, 0)) {
			failed = 1;
		}
	} if (!failed && !CryptGenRandom(prov, buf_len, buf))
		failed = 1;
#else
	FILE *fd = fopen("/dev/urandom", "rb");

	if (fd != NULL) {
		if (fread(buf, buf_len, 1, fd) == 0)
			failed = 1;
		fclose(fd);
	} else {
		failed = 1;
	}

	if (failed) {
		perror("Failed to create randombytes.");
		exit(EXIT_FAILURE);
	}
#endif
}