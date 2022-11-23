#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

RSA* CreatePublicKeyFromModulusExponent(const char* modulusHex, const char* exponentHex);
RSA* CreatePrivateKeyFromPemString(const char* privateKeyStr);
RSA* CreatePublicKeyFromPemString(const char* publicKeyStr);

int EncryptRsa(const char* modulusHex, const char* exponentHex,
               unsigned char* dataIn, unsigned int dataInLength, unsigned char* dataOut, int& dataOutLength) {
    int rc = -1;
    RSA *publicRsaKey = CreatePublicKeyFromModulusExponent(modulusHex,exponentHex);
    if (publicRsaKey) {
        dataOutLength = RSA_public_encrypt(dataInLength, dataIn, dataOut, publicRsaKey, RSA_PKCS1_PADDING);
        RSA_free(publicRsaKey);
        rc = 0;
    }
    return rc;
}

int EncryptRsa(const char* publicKeyPem, unsigned char* dataIn, unsigned int dataInLength, unsigned char* dataOut, int& dataOutLength) {
    int rc = -1;
    RSA *publicRsaKey = CreatePublicKeyFromPemString(publicKeyPem);
    if (publicRsaKey) {
        dataOutLength = RSA_public_encrypt(dataInLength, dataIn, dataOut, publicRsaKey, RSA_PKCS1_PADDING);
        RSA_free(publicRsaKey);
        rc = 0;
    }
    return rc;
}


int DecryptRsa(const char* privateKeyPem, unsigned char* dataIn, unsigned int dataInLength, unsigned char* dataOut, int& dataOutLength){
    int rc = -1;
    RSA* privateRsaKey = CreatePrivateKeyFromPemString(privateKeyPem);//, strlen(privateKeyPem));
    if(privateRsaKey){
        dataOutLength = RSA_private_decrypt(dataInLength, dataIn, dataOut, privateRsaKey, RSA_PKCS1_PADDING);
        RSA_free(privateRsaKey);
        rc = 0;
    }
    return rc;
}

int SignRsa(const char* privateKeyPem, const unsigned char* message, unsigned int messageLength, unsigned char* signature, unsigned int& signatureLength)
{
    int rc = -1;
    RSA* privateRsaKey = CreatePrivateKeyFromPemString(privateKeyPem);//, strlen(privateKeyPem));
    if(privateRsaKey){
        if(RSA_sign(NID_sha256, message, messageLength, signature, &signatureLength, privateRsaKey) == 1)
        {
            rc = 0;
        }
        RSA_free(privateRsaKey);
    }
    return rc;
}

int VerifyRsa(const char* modulusHex, const char* exponentHex, const unsigned char* message, unsigned int messageLength, const unsigned char* signature, unsigned int signatureLength, bool& verified)
{
    verified = false;
    int rc = -1;
    RSA *publicRsaKey = CreatePublicKeyFromModulusExponent(modulusHex,exponentHex);
    if(publicRsaKey){
        verified = (RSA_verify(NID_sha256, message, messageLength, signature, signatureLength, publicRsaKey) == 1);
        RSA_free(publicRsaKey);
        rc = 0;
    }
    return rc;
}


RSA* CreatePrivateKeyFromPemString(const char* privateKeyStr)
{
    BIO *bio = BIO_new_mem_buf( (void*)privateKeyStr, -1 );
    //BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
    RSA* rsaPrivateKey = NULL;
    auto pKey = PEM_read_bio_RSAPrivateKey(bio, &rsaPrivateKey, NULL, NULL ) ;

    if (!rsaPrivateKey)
        printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));

    BIO_free( bio ) ;
    return rsaPrivateKey ;
}

RSA* CreatePublicKeyFromPemString(const char* publicKeyStr)
{
    BIO *bio = BIO_new_mem_buf( (void*)publicKeyStr, -1 );
    //BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
    RSA* rsaPublicKey = NULL;
    auto pKey = PEM_read_bio_RSAPublicKey(bio, &rsaPublicKey, NULL, NULL ) ;

    if (!rsaPublicKey) {
        printf("ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSAPublicKey FAILED(1): %s\n",
               ERR_error_string(ERR_get_error(), NULL));

        if(bio) {
            BIO_free(bio);
            bio=NULL;
        }

        bio = BIO_new(BIO_s_mem());
        int len = BIO_write(bio, publicKeyStr, strlen(publicKeyStr) + 1);

        EVP_PKEY* evp_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        if(evp_key) {
            rsaPublicKey = EVP_PKEY_get1_RSA(evp_key);

            if (!rsaPublicKey) {
                printf("ERROR: Could not load PUBLIC KEY!  EVP_PKEY_get1_RSA FAILED(2): %s\n",
                       ERR_error_string(ERR_get_error(), NULL));
            }
        }
        else {
            printf("ERROR: Could not load PUBLIC KEY!  PEM_read_bio_PUBKEY FAILED(3): %s\n",
                   ERR_error_string(ERR_get_error(), NULL));
        }
    }

    if(bio) {
        BIO_free(bio);
        bio=NULL;
    }
    return rsaPublicKey ;
}

RSA* CreatePublicKeyFromModulusExponent(const char* modulusHex, const char* exponentHex)
{
    bool freeNE = true;
    RSA *publicRsaKey = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    int rc = BN_hex2bn(&n, modulusHex);
    if(rc > 0){
        if(rc > 0) {
            rc = BN_hex2bn(&e, exponentHex);
            if(rc > 0) {
                publicRsaKey = RSA_new();
                rc = RSA_set0_key(publicRsaKey, n, e, NULL);
                if (rc != 1){
                    RSA_free(publicRsaKey);
                    publicRsaKey = NULL;
                }
                else {
                    freeNE = false;
                }
            }
        }
    }
    if(freeNE) {
        if (n) BN_free(n);
        if (e) BN_free(e);
    }
    return publicRsaKey;
}

int ReadModulusAndExponent(const RSA* publicKey, unsigned char* modulus, int& modulusLength, unsigned char* exponent, int& exponentLength){
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    RSA_get0_key(publicKey, &n, &e, &d);

    modulusLength = BN_bn2bin(n, modulus);
    exponentLength = BN_bn2bin(e, exponent);

    return exponentLength > 0 && modulusLength > 0 ? 0 : -1;
}