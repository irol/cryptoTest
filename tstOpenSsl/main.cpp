#include <iostream>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rsa.h>

extern int GenerateRandom(unsigned char* buf, int bufSize);
extern std::ostream& PrintBuf(const char* bufName, unsigned char* buf, long bufLen, std::ostream& o);
extern int encrypt_AES256ECB(unsigned char *key, unsigned char *plain, int plainLength,  unsigned char *cipher, int cipherLength);
extern int decrypt_AES256ECB(unsigned char *key, unsigned char *cipher, int cipherLength, unsigned char *plain, int plainLength);
extern int EncryptRsa(const char* modulusHex, const char* exponentHex, unsigned char* dataIn, unsigned int dataInLength, unsigned char* dataOut, int& dataOutLength);
extern int EncryptRsa(const char* publicKeyPem, unsigned char* dataIn, unsigned int dataInLength, unsigned char* dataOut, int& dataOutLength);
extern int DecryptRsa(const char* privateKeyPem, unsigned char* dataIn, unsigned int dataInLength, unsigned char* dataOut, int& dataOutLength);
extern int SignRsa(const char* privateKeyPem, const unsigned char* message, unsigned int messageLength, unsigned char* signature, unsigned int& signatureLength);
extern int VerifyRsa(const char* modulusHex, const char* exponentHex, const unsigned char* message, unsigned int messageLength, const unsigned char* signature, unsigned int signatureLength, bool& verified);
extern int TestAes();
extern int TestRsa();
extern RSA* CreatePublicKeyFromPemString(const char* publicKeyStr);
extern int ReadModulusAndExponent(const RSA* publicKey, unsigned char* modulus, int& modulusLength, unsigned char* exponent, int& exponentLength);

int main(){
    TestAes();
    std::cout << std::endl << std::endl;
    TestRsa();
}

int TestRsa(){
    const char* modulusHex = "db09c54207e27d6c89e1e2ddca038dc2e77fe98efe121fb037cd7e7681c71bf172279be9e090bf4b65ae5076834f67b517bfdd774486accb1a910d09b4adb0331016fd557a3c60a0909f1c942894441d2b6ca215720d98849450b0f5ccaec1baf6c84a2a9c259ee4e8949b989a414ecdd5213a680dd6f83a20aed2c1a161d863";
    const char* exponentHex = "010001";
    const char* plainText = "Plain text to cipher";
    const char* privateRsaPem = "-----BEGIN RSA PRIVATE KEY-----\n"
                             "MIICXwIBAAKBgQDbCcVCB+J9bInh4t3KA43C53/pjv4SH7A3zX52gccb8XInm+ng\n"
                             "kL9LZa5QdoNPZ7UXv913RIasyxqRDQm0rbAzEBb9VXo8YKCQnxyUKJREHStsohVy\n"
                             "DZiElFCw9cyuwbr2yEoqnCWe5OiUm5iaQU7N1SE6aA3W+DogrtLBoWHYYwIDAQAB\n"
                             "AoGBAMvvSuNxp+STG8VejpU5vdFL7QIuCkwhiNZL04TOy+0uXdSXC6fz3Md8QlHU\n"
                             "JenWavtTvgT/nkxfRbrrYrAATt1jCsKTLNjTl31P37IH3SejmJxPIRsLlnOPK25K\n"
                             "QAyabFSlpaxWpBcrBdJbiYhsgWp3Fa/cX9hIbw3zIoS2p2UhAkEA8JC/TqImMr78\n"
                             "hBg3K+7FykcbcpnhTBxYsBRtIex5zZXWs80VFURtatVFDjhkR6TFp/0AsIsjJOee\n"
                             "AiihavqdSQJBAOkXcPGCHwV+foSr/5ScO15+2p0jZp0LkXljmqRUx2qBCzqD31hX\n"
                             "cIfBx0CIJMPlQnup3UpC64G7OD7s73KbpEsCQQCHvtYE1CDD39tz2oo/YyP/CXLm\n"
                             "jwh/vzsYWN5gFyWAKb4WhXIRJySq9R9bb9y+RK84JN7fwBObvor94tl7GWHpAkEA\n"
                             "2Tb4EIezAvqzSk3CuimxhcjvTvqbeIQ8SAQTK0q6Hz0sSpZzvy6U9l4VocR9hnSS\n"
                             "NQ3B459jOp1OuA0ywvnZ6wJBAKe8vxXeC60BjCYi7iUCuAmckekHEIusIiQ6zR5f\n"
                             "UKKBD1CV7vl4cgnwi3TgEaqBSezce34Coa+8PjfSfIxYd7s=\n"
                             "-----END RSA PRIVATE KEY-----\n";
    const char* publicRsaPem = "-----BEGIN PUBLIC KEY-----\n"
                               "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbCcVCB+J9bInh4t3KA43C53/p\n"
                               "jv4SH7A3zX52gccb8XInm+ngkL9LZa5QdoNPZ7UXv913RIasyxqRDQm0rbAzEBb9\n"
                               "VXo8YKCQnxyUKJREHStsohVyDZiElFCw9cyuwbr2yEoqnCWe5OiUm5iaQU7N1SE6\n"
                               "aA3W+DogrtLBoWHYYwIDAQAB\n"
                               "-----END PUBLIC KEY-----";
    int bufferLength = 8*1024;
    int outputLength = 0;
    unsigned char* bufEncrypt = new unsigned char [bufferLength];
    memset(bufEncrypt, '\0', bufferLength);
    int ret = EncryptRsa(modulusHex, exponentHex, (unsigned char *) plainText, strlen(plainText)+1,
                         bufEncrypt, outputLength);
    std::cout << "ret: " << ret << std::endl;
    PrintBuf("bufEncrypt", bufEncrypt, outputLength, std::cout);
    if(!ret)
    {
        unsigned char* outBuf = new unsigned char [bufferLength];
        int oLength = 0;
        ret = DecryptRsa(privateRsaPem, bufEncrypt, outputLength, outBuf, oLength);
        std::cout << "ret: " << ret << std::endl;
        PrintBuf("outBuf", outBuf, oLength, std::cout);
        if(!ret){
            if(outputLength > 0 && outBuf){
                std::cout << "outBuf: " << (char*)outBuf << std::endl;
            }
        }
        delete [] outBuf;
    }

    unsigned int signatureLength = 0;
    ret = SignRsa(privateRsaPem, (const unsigned char *)plainText, strlen(plainText) + 1, bufEncrypt, signatureLength);
    std::cout << "ret: " << ret << std::endl;
    if(!ret){
        PrintBuf("signature", bufEncrypt, signatureLength, std::cout);
    }

    bool verified = false;
    ret = VerifyRsa(modulusHex, exponentHex, (const unsigned char *)plainText, strlen(plainText) + 1, bufEncrypt, signatureLength, verified);
    std::cout << "ret: " << ret << " Verified: " << (verified ? "true" : "false") << std::endl;

    const char* plainText1 = "Plain text to cipher --- to check";
    ret = VerifyRsa(modulusHex, exponentHex, (const unsigned char *)plainText1, strlen(plainText1) + 1, bufEncrypt, signatureLength, verified);
    std::cout << "ret: " << ret << " Verified: " << (verified ? "true" : "false") << std::endl;


    std::cout << std::endl << std::endl;
    std::cout << "===== ENCRYPT FROM PEM =====" << std::endl;

    outputLength = 0;
    ret = EncryptRsa(publicRsaPem, (unsigned char *) plainText, strlen(plainText)+1,
                     bufEncrypt, outputLength);

    std::cout << "ret: " << ret << std::endl;
    PrintBuf("bufEncrypt", bufEncrypt, outputLength, std::cout);
    if(!ret)
    {
        unsigned char* outBuf = new unsigned char [bufferLength];
        int oLength = 0;
        ret = DecryptRsa(privateRsaPem, bufEncrypt, outputLength, outBuf, oLength);
        std::cout << "ret: " << ret << std::endl;
        PrintBuf("outBuf", outBuf, oLength, std::cout);
        if(!ret){
            if(outputLength > 0 && outBuf){
                std::cout << "outBuf: " << (char*)outBuf << std::endl;
            }
        }
        delete [] outBuf;
    }

    std::cout << "===== MODULUS & EXPONENT FROM PEM =====" << std::endl;
    RSA *publicRsaKey = CreatePublicKeyFromPemString(publicRsaPem);
    if(publicRsaKey){
        int modulusLength = 0;
        int exponentLength = 0;
        unsigned char exponent[20] = {0};
        unsigned char* modulus = new unsigned char [bufferLength];
        memset(modulus, '\0', bufferLength);
        int ret = ReadModulusAndExponent(publicRsaKey, modulus, modulusLength, exponent, exponentLength);
        std::cout << "ret: " << ret << std::endl;
        PrintBuf("modulus", modulus, modulusLength, std::cout);
        PrintBuf("exponent", exponent, exponentLength, std::cout);

        RSA_free(publicRsaKey);
        delete [] modulus;
    }

    delete [] bufEncrypt;
    return 0;
}

int TestAes() {
    const char* plainText = "Plain text to cipher";
    unsigned char fillChar = '\0';

    unsigned char rnd[32] = {0};

    unsigned char* plainBuf = nullptr;
    int origLen = strlen(plainText) + 1;
    std::cout << "origLen: " << origLen << std::endl;
    int plainBufLen = 0;
    if(origLen <= AES_BLOCK_SIZE)
        plainBufLen = AES_BLOCK_SIZE;
    else {
        plainBufLen = (1+(origLen/AES_BLOCK_SIZE))*AES_BLOCK_SIZE;
    }

    std::cout << "plainBufLen: " << plainBufLen << std::endl;
    plainBuf = new unsigned char [plainBufLen];
    memset(plainBuf, fillChar, plainBufLen);
    memcpy(plainBuf, plainText, origLen);

    int result = GenerateRandom(rnd, sizeof(rnd)/sizeof(rnd[0]));
    std::cout << "GenerateRandom result: " << result << std::endl;
    PrintBuf("rnd", rnd, sizeof(rnd)/sizeof(rnd[0]), std::cout);

    unsigned char *cipher = new unsigned char [plainBufLen];
    memset(cipher, '\0', plainBufLen);
    result = encrypt_AES256ECB(rnd, plainBuf, plainBufLen,  cipher, plainBufLen);
    std::cout << "encrypt_AES256ECB result: " << result << std::endl;
    PrintBuf("cipher", cipher, plainBufLen, std::cout);

    memset(plainBuf, '\0', plainBufLen);
    result = decrypt_AES256ECB(rnd, cipher, plainBufLen, plainBuf, plainBufLen);
    std::cout << "decrypt_AES256ECB result: " << result << std::endl;
    PrintBuf("plainBuf", plainBuf, plainBufLen, std::cout);
    if(!result)
    {
        std::cout << "len: " << origLen << std::endl;
        std::cout << "plain: [" << (char*)plainBuf << "]" << std::endl;
    }

    delete [] plainBuf;
    delete [] cipher;
    return 0;
}
