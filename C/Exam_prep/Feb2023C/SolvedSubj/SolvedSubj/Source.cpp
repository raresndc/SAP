#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#define MAX_LINE_LENGTH 1024

void compute_sha_for_each_line_write_in_file(const char* input_filename, const char* output_filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char output_sha256[SHA256_DIGEST_LENGTH];

    FILE* input_file = fopen(input_filename, "r");
    FILE* output_file = fopen(output_filename, "w");

    if (!input_file || !output_file) {
        perror("Failed to open file");
        return;
    }

    while (fgets(line, sizeof(line), input_file)) {
        size_t len = strlen(line);

        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        SHA256_CTX context_sha256;
        SHA256_Init(&context_sha256);
        SHA256_Update(&context_sha256, line, len);
        SHA256_Final(output_sha256, &context_sha256);

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            fprintf(output_file, "%02X ", output_sha256[i]);
        }

        fprintf(output_file, "\n");
    }

    fclose(input_file);
    fclose(output_file);
}

int encryptFileCBC(const char* inputFilename,
    const char* outputFilename,
    const unsigned char* key,
    size_t keySize,
    const unsigned char* iv)
{
    if (!inputFilename || !outputFilename || !key || !iv) {
        fprintf(stderr, "Invalid parameters provided to encryptFileCBC.\n");
        return 1;
    }
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16 (128-bit), 24 (192-bit), or 32 (256-bit) bytes.\n");
        return 2;
    }

    FILE* fIn = fopen(inputFilename, "rb");
    if (!fIn) {
        perror("Failed to open input file");
        return 3;
    }

    fseek(fIn, 0, SEEK_END);
    long fileSize = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);

    if (fileSize <= 0) {
        fprintf(stderr, "Input file is empty or error reading size.\n");
        fclose(fIn);
        return 4;
    }

    unsigned char* plaintext = (unsigned char*)malloc(fileSize);
    if (!plaintext) {
        fprintf(stderr, "Failed to allocate memory for plaintext.\n");
        fclose(fIn);
        return 5;
    }
    if (fread(plaintext, 1, fileSize, fIn) != (size_t)fileSize) {
        fprintf(stderr, "Error reading input file.\n");
        free(plaintext);
        fclose(fIn);
        return 6;
    }
    fclose(fIn);

    size_t partial_block = (fileSize % AES_BLOCK_SIZE) ? 1 : 0;
    size_t blocks = (fileSize / AES_BLOCK_SIZE) + partial_block;
    size_t ciphertextSize = blocks * AES_BLOCK_SIZE;

    unsigned char* ciphertext = (unsigned char*)malloc(ciphertextSize);
    if (!ciphertext) {
        fprintf(stderr, "Failed to allocate memory for ciphertext.\n");
        free(plaintext);
        return 7;
    }

    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        fprintf(stderr, "Failed to set encrypt key.\n");
        free(plaintext);
        free(ciphertext);
        return 8;
    }

    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    AES_cbc_encrypt(plaintext, ciphertext, fileSize, &aesKey, ivCopy, AES_ENCRYPT);

    FILE* fOut = fopen(outputFilename, "wb");
    if (!fOut) {
        perror("Failed to open output file");
        free(plaintext);
        free(ciphertext);
        return 9;
    }

    fwrite(ciphertext, 1, ciphertextSize, fOut);
    fclose(fOut);

    free(plaintext);
    free(ciphertext);

    printf("File '%s' encrypted successfully into '%s'\n", inputFilename, outputFilename);
    return 0;
}

int main()
{
    compute_sha_for_each_line_write_in_file("wordlist.txt", "hashes.txt");



    encryptFileCBC("hashes.txt", "aes-cbc.bin", keySize, iv);

	return 0;
}