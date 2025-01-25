#ifndef _ENC_
 #define _ENC_ 0

#define BUF_SIZE 16 
_declspec(dllexport) unsigned char* encryptXor(unsigned char*, unsigned char*);
_declspec(dllexport)unsigned char* decryptXor(unsigned char*, unsigned char*);
_declspec(dllexport)unsigned char*   xorArray(unsigned char*, unsigned char*, unsigned int);

#endif