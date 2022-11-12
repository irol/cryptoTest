#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int decrypt_AES256ECB(unsigned char *key, unsigned char *cipher, int cipherLength, unsigned char *plain, int plainLength)
{
    AES_KEY deckey;

    if(0 != (cipherLength % AES_BLOCK_SIZE)) {
        //printf("Cypher length should be a multiple of AES_BLOCK_SIZE\n");
        return -1;
    }

    if(plainLength != cipherLength)
    {
        //printf("Cypher length should be same as plain length\n");
        return -2;
    }

    if (AES_set_decrypt_key(key, 256, &deckey) < 0) {
        //printf("Set decryption key in AES failed\n");
        return -3;
    }

    while(cipherLength > 0) {
        AES_ecb_encrypt(cipher, plain, &deckey, AES_DECRYPT);
        cipherLength -= AES_BLOCK_SIZE;
        cipher += AES_BLOCK_SIZE;
        plain += AES_BLOCK_SIZE;
    }

    return 0;
}

int encrypt_AES256ECB(unsigned char *key, unsigned char *plain, int plainLength,  unsigned char *cipher, int cipherLength)
{
    AES_KEY encKey;

    if(0 != (plainLength % AES_BLOCK_SIZE)) {
        //printf("Cypher length should be a multiple of AES_BLOCK_SIZE\n");
        return -1;
    }

    if(plainLength != cipherLength)
    {
        //printf("Cypher length should be same as plain length\n");
        return -2;
    }

    if (AES_set_encrypt_key(key, 256, &encKey) < 0) {
        //printf("Set encryption key in AES failed\n");
        return -3;
    }

    while(plainLength > 0) {
        AES_ecb_encrypt(plain, cipher, &encKey, AES_ENCRYPT);
        plainLength -= AES_BLOCK_SIZE;
        cipher += AES_BLOCK_SIZE;
        plain += AES_BLOCK_SIZE;
    }

    return 0;
}
