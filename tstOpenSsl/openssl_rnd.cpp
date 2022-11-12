#include <openssl/rand.h>

int GenerateRandom(unsigned char* buf, int bufSize)
{
    return RAND_bytes(buf, bufSize);
}
