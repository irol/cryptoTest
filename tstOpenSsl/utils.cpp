#include <iostream>
#include <sstream>
#include <string.h>

int Bin2Hex(const unsigned char* bin, char* hex, int maxHexLen)
{
    hex[maxHexLen] = '\0';
    const char xx[]= "0123456789ABCDEF";
    while (--maxHexLen >= 0) hex[maxHexLen] = xx[(bin[maxHexLen>>1] >> ((1 - (maxHexLen&1)) << 2)) & 0xF];
    return 0;
}
short hex2int(const char c)
{
    if(c >= '0' && c <= '9')
        return c-'0';
    if(c >= 'A' && c <= 'F')
        return 10+c-'A';
    if(c >= 'a' && c <= 'f')
        return 10+c-'a';
    return -1;
}
int Hex2Bin(const char* hex, unsigned char* bin, int maxBinLen)
{
    short c1, c2;
    if(strlen(hex) < 2*maxBinLen)
        return 1;

    for(int i=0, j=0; i<maxBinLen; i++, j+=2){
        c1 = hex2int(hex[j]);
        if(c1 < 0)
            return 2;
        c2 = hex2int(hex[j+1]);
        if(c1 < 0)
            return 3;
        bin[i] = (((c1 << 4) & 0xf0) | (c2 & 0x0f)) & 0xff;
    }

    return 0;
}
std::ostream& PrintBuf(const char* bufName, unsigned char* buf, long bufLen, std::ostream& o)
{
    o << bufName << "[" << bufLen << "]#";
    if(buf != NULL && bufLen > 0){
        char* str = new char[2*bufLen + 1];
        memset(str,'\0', 2*bufLen + 1);
        Bin2Hex(buf, str, 2*bufLen);
        o << str;
        delete [] str;
    }
    o << std::endl;
    return o;
}

unsigned int HexToUInt(char* hexString){
    unsigned int x= 0;
    if(strlen(hexString) > 0) {
        std::stringstream ss;
        ss << std::hex << hexString;
        ss >> x;
    }
    return x;
}

// hexStringLength = hexStrlen+1
void UIntToHex(unsigned int x , char* hexString, int hexStrlen){
    memset(hexString, 0, hexStrlen + 1);
    sprintf(hexString, "%0*X", hexStrlen, x);
}

// C like
// free buffer outside
char* ReadAllFromTextFile(const char* filePath)
{
    char* buffer = NULL;
    FILE* f = fopen(filePath, "r");
    if(f) {
        fseek(f, 0, SEEK_END);
        size_t size = ftell(f);
        buffer = (char*)malloc(size);
        rewind(f);
        fread(buffer, sizeof(char), size, f);
        fclose(f);
    }
    return buffer;
}