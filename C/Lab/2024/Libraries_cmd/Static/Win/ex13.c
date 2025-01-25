#include "xor.h"
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>

// Compile consumer app by considering the static library
//			cl.exe /FoUseCrypto ex12.lib ex13.c

int main(int argc, char* argv[]) {
    char opt[3];
    char mode[10];
    char fIn[200];
    char fOut[200];
    int i = 0, j = 0;
    int ch, numRead;

    unsigned char pass[ BUF_SIZE ]; //pass 128 bits
    unsigned char buff[ BUF_SIZE ]; // BUF_SIZE defined in xor.h

    unsigned char* buffW = (unsigned char*)malloc(( BUF_SIZE )*sizeof(unsigned char));
    
    unsigned char* iVector = (unsigned char*)malloc(( BUF_SIZE )*sizeof(unsigned char));
    for (i = 0; i < BUF_SIZE; i++) iVector[i] = 0x00; //or MD5 of the pass

    unsigned char* xorVector = (unsigned char*)malloc(( BUF_SIZE )*sizeof(unsigned char));

    if (argc < 4) {
        printf("\n Wrong number of parameters \n Example: UseCrypto.exe -e -ecb fSrc fDst");
        return 1;
    } else {
        strcpy(opt, argv[1]);
        strcpy(mode, argv[2]);
        strcpy(fIn, argv[3]);
        strcpy(fOut, argv[4]);

        printf("\n Enter pass please (16 chars):"); 
        /* Read in single line from "stdin": */
        for( i = 0; (i <  BUF_SIZE ) && ((ch = getchar()) != EOF) && (ch != '\n'); i++ )
            pass[i] = (unsigned char)ch;

        /* Terminate string with null character: */
        //pass[i] = '\0';
        printf("\n pass received:%s", pass);
        //printf("\n pass received");
        
        FILE* fSrc, *fDst;
        fSrc = fopen(fIn, "rb");
        fDst = fopen(fOut, "wb");

        if (strcmp(opt, "-e") == 0) { // this is an encryption
            if (strcmp(mode, "-ecb") == 0) {
                while ((numRead = (int)fread(buff, 1, BUF_SIZE, fSrc)) > 0) {
                    
                    buffW = encryptXor(buff, pass); // call function encryptXor from ex12.lib
                    fwrite(buffW, 1, numRead, fDst);
                    fflush(fDst);
                }
            } else {
                //assumes that it is cbc = cyphering block chaining
                while ((numRead = (int)fread(buff, 1, BUF_SIZE, fSrc)) > 0) {

                    xorVector = xorArray(iVector, buff, numRead);
                    buffW = encryptXor(xorVector, pass); 
                    fwrite(buffW, 1, numRead, fDst);
                    fflush(fDst);
                    for (j = 0; j < numRead; j++) iVector[j] = buffW[j];
                }                 
            }
        } else { // this is a decryption
            if (strcmp(opt, "-d") == 0) {
                if (strcmp(mode, "-ecb") == 0) {
                    while ((numRead = (int)fread(buff, 1, BUF_SIZE, fSrc)) > 0) {
                    
                        buffW = decryptXor(buff, pass);
                        fwrite(buffW, 1, numRead, fDst);
                        fflush(fDst);
                    }
                } else {
                    //assumes that it is cbc = cyphering block chaining
                    int kChunks = 0;
                    while ((numRead = (int)fread(buff, 1, BUF_SIZE, fSrc)) > 0) {
                    
                        buffW = decryptXor(buff, pass);
                        if (kChunks == 0) {
                            for (j = 0; j < numRead; j++) iVector[j] = 0x00;
                        }                    
                        xorVector = xorArray(iVector, buffW, numRead);                         
                        fwrite(xorVector, 1, numRead, fDst);
                        fflush(fDst);
                        for (j = 0; j < numRead; j++) iVector[j] = buff[j];
                        kChunks++;
                    }
                }
            } else {
                printf("\n Unknown option \n Example: UseCrypto.exe -e -ecb fSrc fDst");
                return 2;
            }
        }
        fclose(fDst);
        fclose(fSrc);
    }
    
    return 0;
}