#ifndef _ENC_
 #define _ENC_ 0

#define BUF_SIZE 16 
_declspec(dllimport) unsigned char* encryptXor(unsigned char*, unsigned char*);
_declspec(dllimport) unsigned char* decryptXor(unsigned char*, unsigned char*);
_declspec(dllimport) unsigned char*   xorArray(unsigned char*, unsigned char*, unsigned int);

#endif