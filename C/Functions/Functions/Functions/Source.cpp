#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/aes.h>

#define INPUT_BLOCK_LENGTH 15
#define MAX_LINE_LENGTH 1024  // Maximum length of a line
#define IV_SIZE 16
#define KEY_SIZE 32  // Adjust based on AES-128 (16), AES-192 (24), or AES-256 (32)
#define AES_BLOCK_SIZE 16


//read ANY type of file into a variable
char* read_from_file(const char* filename) {
    FILE* f = fopen(filename, "rb");  

    if (!f) {
        perror("Failed to open file");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);  

    char* content = (char*)malloc(file_size + 1);
    if (!content) {
        perror("Memory allocation failed");
        fclose(f);
        return NULL;
    }

    fread(content, 1, file_size, f);
    content[file_size] = '\0';  

    fclose(f);
    return content;  
}

void write_in_file(const char* filename) {

    //wb for binary writing
    FILE* f = fopen(filename, "w");

    if (!f) {
        perror("Failed to open file");
        return;
    }

    fprintf(f, "%s", "Nedelcu Rares");

    printf("Name written successfully!\n");

    fclose(f);
}

//will save the iv in iv parameter (txt must be 0xFF, 0X1A etc)
int read_iv_from_file(const char* filename, unsigned char iv[IV_SIZE]) {
    FILE* ivFile = fopen(filename, "r");
    if (!ivFile) {
        perror("Failed to open IV file");
        return 1;
    }

    char buffer[128]; 
    int i = 0;

    if (fgets(buffer, sizeof(buffer), ivFile) == NULL) {
        perror("Error reading file");
        fclose(ivFile);
        return 1;
    }
    fclose(ivFile);

    char* ptr = buffer;
    while (*ptr && i < IV_SIZE) {
        if (*ptr == ',' || isspace((unsigned char)*ptr)) {
            ptr++;  
            continue;
        }

        if (*ptr == '0' && (*(ptr + 1) == 'x' || *(ptr + 1) == 'X')) {
            iv[i] = (unsigned char)strtol(ptr, &ptr, 16);
            i++;
        }
        else {
            ptr++;  
        }
    }

    if (i != IV_SIZE) {
        fprintf(stderr, "Error: IV file contains insufficient or excessive data\n");
        return 1;
    }

    return 0;
}

//will save the aes key in the parameter (adjust the KEY_SIZE defined)
int read_aes_key(const char* filename, unsigned char* key) {
    FILE* keyFile = fopen(filename, "rb");
    if (!keyFile) {
        perror("Failed to open key file");
        return 1;  // Return error
    }

    size_t bytesRead = fread(key, 1, KEY_SIZE, keyFile);
    fclose(keyFile);

    if (bytesRead != KEY_SIZE) {
        fprintf(stderr, "Error: Expected %d bytes but read %zu bytes.\n", KEY_SIZE, bytesRead);
        return 1;  // Return error
    }

    return 0;  // Success
}

//read iv and key from the same file
int read_iv_and_aes_key(const char* filename, unsigned char* iv, unsigned char* key, size_t key_size) {
    FILE* keyFile = fopen(filename, "rb");
    if (!keyFile) {
        return 1;  // Return error
    }

    // Read IV
    size_t bytesRead = fread(iv, 1, IV_SIZE, keyFile);
    if (bytesRead != IV_SIZE) {
        fclose(keyFile);
        return 1;  // Return error
    }

    // Read AES key
    bytesRead = fread(key, 1, key_size, keyFile);
    fclose(keyFile);

    if (bytesRead != key_size) {
        return 1;  // Return error
    }

    return 0;  // Success
}

void hex_to_bytes(const char* hex, unsigned char* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
}

void compute_sha_for_all_file(const char* filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char output[SHA_DIGEST_LENGTH];  // SHA-1 output (20 bytes)
    unsigned char output_sha256[SHA256_DIGEST_LENGTH];  // SHA-256 output (32 bytes)

    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file");
        return;
    }

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Initialize SHA-1 context
    SHA_CTX context_sha1;
    SHA1_Init(&context_sha1);

    // Initialize SHA-256 context
    SHA256_CTX context_sha256;
    SHA256_Init(&context_sha256);

    // Process the file in 15-byte chunks
    while (remaining_length > 0) {
        size_t bytes_to_read = (remaining_length > INPUT_BLOCK_LENGTH) ? INPUT_BLOCK_LENGTH : remaining_length;
        fread(input, sizeof(unsigned char), bytes_to_read, f);
        SHA1_Update(&context_sha1, input, bytes_to_read);    // SHA-1 Update
        SHA256_Update(&context_sha256, input, bytes_to_read);  // SHA-256 Update
        remaining_length -= bytes_to_read;
    }

    fclose(f);

    // Finalize SHA-1 hash
    SHA1_Final(output, &context_sha1);
    // Finalize SHA-256 hash
    SHA256_Final(output_sha256, &context_sha256);

    // Print the SHA-1 hash
    printf("SHA-1 for all file:\n");
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02X ", output[i]);
    }
    printf("\n");

    // Print the SHA-256 hash
    printf("SHA-256 for all file:\n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02X ", output_sha256[i]);
    }
    printf("\n");
}

void compute_sha_for_all_file_and_write_in_txt_file(const char* input_filename, const char* output_filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char output[SHA_DIGEST_LENGTH];  // SHA-1 output (20 bytes)
    unsigned char output_sha256[SHA256_DIGEST_LENGTH];  // SHA-256 output (32 bytes)

    FILE* f = fopen(input_filename, "r");
    FILE* output_file = fopen(output_filename, "w");

    if (!f || !output_file) {
        perror("Failed to open file");
        return;
    }

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Initialize SHA-1 context
    SHA_CTX context_sha1;
    SHA1_Init(&context_sha1);

    // Initialize SHA-256 context
    SHA256_CTX context_sha256;
    SHA256_Init(&context_sha256);

    // Process the file in 15-byte chunks
    while (remaining_length > 0) {
        size_t bytes_to_read = (remaining_length > INPUT_BLOCK_LENGTH) ? INPUT_BLOCK_LENGTH : remaining_length;
        fread(input, sizeof(unsigned char), bytes_to_read, f);
        SHA1_Update(&context_sha1, input, bytes_to_read);    // SHA-1 Update
        SHA256_Update(&context_sha256, input, bytes_to_read);  // SHA-256 Update
        remaining_length -= bytes_to_read;
    }

    fclose(f);

    // Finalize SHA-1 hash
    SHA1_Final(output, &context_sha1);
    // Finalize SHA-256 hash
    SHA256_Final(output_sha256, &context_sha256);

    // Write the SHA-1 hash
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        fprintf(output_file, "%02X ", output[i]);
    }
    fprintf(output_file, "\n");

    // Write the SHA-256 hash
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(output_file, "%02X ", output_sha256[i]);
    }
    fprintf(output_file, "\n");

    fclose(output_file);
}

void compute_sha_for_each_line(const char* filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char output[SHA_DIGEST_LENGTH];  // SHA-1 output (20 bytes)
    unsigned char output_sha256[SHA256_DIGEST_LENGTH];  // SHA-256 output (32 bytes)

    FILE* f = fopen(filename, "r");

    if (!f) {
        perror("Failed to open file");
        return;
    }

    printf("\nSHA-1 for each line:\n");

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        // Initialize SHA-1 context
        SHA_CTX context_sha1;
        SHA1_Init(&context_sha1);
        SHA1_Update(&context_sha1, line, len);
        SHA1_Final(output, &context_sha1);

        // Initialize SHA-256 context
        SHA256_CTX context_sha256;
        SHA256_Init(&context_sha256);
        SHA256_Update(&context_sha256, line, len);
        SHA256_Final(output_sha256, &context_sha256);

        // Print SHA-1 hash of the current line
        printf("SHA-1: ");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            printf("%02X", output[i]);
        }

        // Print SHA-256 hash of the current line
        printf("  SHA-256: ");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02X", output_sha256[i]);
        }

        printf("  <- \"%s\"\n", line);  // Show the original line for reference
    }

    fclose(f);
}

void compute_sha_for_each_line_write_in_txt_file(const char* input_filename, const char* output_filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char output[SHA_DIGEST_LENGTH];  // SHA-1 output (20 bytes)
    unsigned char output_sha256[SHA256_DIGEST_LENGTH];  // SHA-256 output (32 bytes)

    FILE* input_file = fopen(input_filename, "r");
    FILE* output_file = fopen(output_filename, "w");

    if (!input_file || !output_file) {
        perror("Failed to open file");
        return;
    }

    while (fgets(line, sizeof(line), input_file)) {
        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        // Compute SHA-1 hash for the line
        SHA_CTX context_sha1;
        SHA1_Init(&context_sha1);
        SHA1_Update(&context_sha1, line, len);
        SHA1_Final(output, &context_sha1);

        // Compute SHA-256 hash for the line
        SHA256_CTX context_sha256;
        SHA256_Init(&context_sha256);
        SHA256_Update(&context_sha256, line, len);
        SHA256_Final(output_sha256, &context_sha256);

        // Write SHA-1 hash
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            fprintf(output_file, "%02X ", output[i]);
        }

        fprintf(output_file, "\n");

        // Write SHA-256 hash
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            fprintf(output_file, "%02X ", output_sha256[i]);
        }

        fprintf(output_file, "\n");
    }

    fclose(input_file);
    fclose(output_file);
}

void compute_md5_for_all_file(const char* filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char output[MD5_DIGEST_LENGTH];  // MD5 output (16 bytes)

    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file");
        return;
    }

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Initialize MD5 context
    MD5_CTX context_md5;
    MD5_Init(&context_md5);

    // Process the file in 15-byte chunks
    while (remaining_length > 0) {
        size_t bytes_to_read = (remaining_length > INPUT_BLOCK_LENGTH) ? INPUT_BLOCK_LENGTH : remaining_length;
        fread(input, sizeof(unsigned char), bytes_to_read, f);
        MD5_Update(&context_md5, input, bytes_to_read);  // MD5 Update
        remaining_length -= bytes_to_read;
    }

    fclose(f);

    // Finalize MD5 hash
    MD5_Final(output, &context_md5);

    // Print the MD5 hash
    printf("MD5 for all file:\n");
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02X ", output[i]);
    }
    printf("\n");
}

void compute_md5_for_all_file_and_write_in_txt_file(const char* input_filename, const char* output_filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char output[MD5_DIGEST_LENGTH];  // MD5 output (16 bytes)

    FILE* f = fopen(input_filename, "r");
    FILE* output_file = fopen(output_filename, "w");

    if (!f || !output_file) {
        perror("Failed to open file");
        return;
    }

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Initialize MD5 context
    MD5_CTX context_md5;
    MD5_Init(&context_md5);

    // Process the file in 15-byte chunks
    while (remaining_length > 0) {
        size_t bytes_to_read = (remaining_length > INPUT_BLOCK_LENGTH) ? INPUT_BLOCK_LENGTH : remaining_length;
        fread(input, sizeof(unsigned char), bytes_to_read, f);
        MD5_Update(&context_md5, input, bytes_to_read);  // MD5 Update
        remaining_length -= bytes_to_read;
    }

    fclose(f);

    // Finalize MD5 hash
    MD5_Final(output, &context_md5);

    // Write the MD5 hash
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        fprintf(output_file, "%02X ", output[i]);
    }
    fprintf(output_file, "\n");

    fclose(output_file);
}

void compute_md5_for_each_line(const char* filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char output[MD5_DIGEST_LENGTH];  // MD5 output (16 bytes)

    FILE* f = fopen(filename, "r");

    if (!f) {
        perror("Failed to open file");
        return;
    }

    printf("\nMD5 for each line:\n");

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        // Initialize MD5 context
        MD5_CTX context_md5;
        MD5_Init(&context_md5);
        MD5_Update(&context_md5, line, len);
        MD5_Final(output, &context_md5);

        // Print MD5 hash of the current line
        printf("MD5: ");
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02X", output[i]);
        }

        printf("  <- \"%s\"\n", line);  // Show the original line for reference
    }

    fclose(f);
}

void compute_md5_for_each_line_write_in_txt_file(const char* input_filename, const char* output_filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char output[MD5_DIGEST_LENGTH];  // MD5 output (16 bytes)

    FILE* input_file = fopen(input_filename, "r");
    FILE* output_file = fopen(output_filename, "w");

    if (!input_file || !output_file) {
        perror("Failed to open file");
        return;
    }

    while (fgets(line, sizeof(line), input_file)) {
        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        // Compute MD5 hash for the line
        MD5_CTX context_md5;
        MD5_Init(&context_md5);
        MD5_Update(&context_md5, line, len);
        MD5_Final(output, &context_md5);

        // Write MD5 hash
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            fprintf(output_file, "%02X ", output[i]);
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
    // Sanity checks:
    if (!inputFilename || !outputFilename || !key || !iv) {
        fprintf(stderr, "Invalid parameters provided to encryptFileCBC.\n");
        return 1;
    }
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16 (128-bit), 24 (192-bit), or 32 (256-bit) bytes.\n");
        return 2;
    }

    // Open the input file for reading
    FILE* fIn = fopen(inputFilename, "rb");
    if (!fIn) {
        perror("Failed to open input file");
        return 3;
    }

    // Determine the size of the input file
    fseek(fIn, 0, SEEK_END);
    long fileSize = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);

    if (fileSize <= 0) {
        fprintf(stderr, "Input file is empty or error reading size.\n");
        fclose(fIn);
        return 4;
    }

    // Read the entire file into plaintext buffer
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

    // Compute size for ciphertext buffer
    // Similar to your snippet, it doesn't do official padding but does block rounding.
    size_t partial_block = (fileSize % AES_BLOCK_SIZE) ? 1 : 0;
    size_t blocks = (fileSize / AES_BLOCK_SIZE) + partial_block;
    size_t ciphertextSize = blocks * AES_BLOCK_SIZE;

    unsigned char* ciphertext = (unsigned char*)malloc(ciphertextSize);
    if (!ciphertext) {
        fprintf(stderr, "Failed to allocate memory for ciphertext.\n");
        free(plaintext);
        return 7;
    }

    // Prepare the AES key structure
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        fprintf(stderr, "Failed to set encrypt key.\n");
        free(plaintext);
        free(ciphertext);
        return 8;
    }

    // Copy IV locally, because AES_cbc_encrypt modifies the IV
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    // Encrypt (CBC)
    AES_cbc_encrypt(plaintext, ciphertext, fileSize, &aesKey, ivCopy, AES_ENCRYPT);

    // Write the ciphertext to the output file
    FILE* fOut = fopen(outputFilename, "wb");
    if (!fOut) {
        perror("Failed to open output file");
        free(plaintext);
        free(ciphertext);
        return 9;
    }

    fwrite(ciphertext, 1, ciphertextSize, fOut);
    fclose(fOut);

    // Cleanup
    free(plaintext);
    free(ciphertext);

    printf("File '%s' encrypted successfully into '%s'\n", inputFilename, outputFilename);
    return 0;
}

void encryptAndPrintCBC(const unsigned char* plaintext,
    size_t plaintextSize,
    const unsigned char* key,
    size_t keySize,
    const unsigned char* iv)
{
    if (!plaintext || !key || !iv) {
        fprintf(stderr, "Invalid parameters provided to encryptAndPrintCBC.\n");
        return;
    }
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16, 24, or 32 bytes.\n");
        return;
    }

    // Compute size for ciphertext (same partial-block approach)
    size_t partial_block = (plaintextSize % AES_BLOCK_SIZE) ? 1 : 0;
    size_t blocks = (plaintextSize / AES_BLOCK_SIZE) + partial_block;
    size_t ciphertextSize = blocks * AES_BLOCK_SIZE;

    unsigned char* ciphertext = (unsigned char*)malloc(ciphertextSize);
    if (!ciphertext) {
        fprintf(stderr, "Failed to allocate memory for ciphertext.\n");
        return;
    }

    // Prepare AES key
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        fprintf(stderr, "Failed to set encrypt key.\n");
        free(ciphertext);
        return;
    }

    // Copy IV, because AES_cbc_encrypt will modify it
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    // Encrypt
    AES_cbc_encrypt(plaintext, ciphertext, plaintextSize, &aesKey, ivCopy, AES_ENCRYPT);

    // Print ciphertext in hex
    printf("Ciphertext: ");
    for (size_t i = 0; i < ciphertextSize; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    free(ciphertext);
}

int encryptFileECB(const char* inputFilename,
    const char* outputFilename,
    const unsigned char* key,
    size_t keySize)
{
    // Validate arguments
    if (!inputFilename || !outputFilename || !key) {
        fprintf(stderr, "Invalid parameters to encryptFileECB.\n");
        return 1;
    }

    // Check key size
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16 (128-bit), 24 (192-bit), or 32 (256-bit) bytes.\n");
        return 2;
    }

    // Open input file
    FILE* fIn = fopen(inputFilename, "rb");
    if (!fIn) {
        perror("Failed to open input file");
        return 3;
    }

    // Determine file size
    fseek(fIn, 0, SEEK_END);
    long fileSize = ftell(fIn);
    fseek(fIn, 0, SEEK_SET);

    if (fileSize < 0) {
        fclose(fIn);
        fprintf(stderr, "Error determining file size or file is empty.\n");
        return 4;
    }

    // Allocate buffer to hold the file data (plaintext)
    unsigned char* plaintext = (unsigned char*)malloc(fileSize);
    if (!plaintext) {
        fclose(fIn);
        fprintf(stderr, "Failed to allocate memory for plaintext.\n");
        return 5;
    }

    // Read plaintext from file
    if (fread(plaintext, 1, fileSize, fIn) != (size_t)fileSize) {
        fclose(fIn);
        free(plaintext);
        fprintf(stderr, "Error reading input file.\n");
        return 6;
    }
    fclose(fIn);

    // Prepare the AES key
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        free(plaintext);
        fprintf(stderr, "Failed to set AES encryption key.\n");
        return 7;
    }

    // Calculate number of blocks (handle partial block)
    size_t partial_block = fileSize % AES_BLOCK_SIZE ? 1 : 0;
    size_t totalBlocks = (fileSize / AES_BLOCK_SIZE) + partial_block;
    size_t ciphertextSize = totalBlocks * AES_BLOCK_SIZE;

    // Allocate buffer for ciphertext
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertextSize);
    if (!ciphertext) {
        free(plaintext);
        fprintf(stderr, "Failed to allocate memory for ciphertext.\n");
        return 8;
    }

    // Encrypt block by block
    for (size_t offset = 0; offset < (size_t)fileSize; offset += AES_BLOCK_SIZE) {
        // For the last partial block, we only have leftover bytes
        unsigned char block[AES_BLOCK_SIZE] = { 0 };
        size_t bytesLeft = fileSize - offset;
        size_t blockSize = (bytesLeft < AES_BLOCK_SIZE) ? bytesLeft : AES_BLOCK_SIZE;

        // Copy only what's left of plaintext into a full-sized block buffer
        memcpy(block, plaintext + offset, blockSize);

        // Encrypt one block at a time
        AES_encrypt(block, ciphertext + offset, &aesKey);
    }

    // Write ciphertext to the output file
    FILE* fOut = fopen(outputFilename, "wb");
    if (!fOut) {
        perror("Failed to open output file");
        free(plaintext);
        free(ciphertext);
        return 9;
    }

    fwrite(ciphertext, 1, ciphertextSize, fOut);
    fclose(fOut);

    // Cleanup
    free(plaintext);
    free(ciphertext);

    printf("File '%s' encrypted successfully into '%s' using AES-ECB.\n",
        inputFilename, outputFilename);
    return 0;
}

void encryptAndPrintECB(const unsigned char* plaintext,
    size_t plaintextSize,
    const unsigned char* key,
    size_t keySize)
{
    if (!plaintext || !key) {
        fprintf(stderr, "Invalid parameters to encryptAndPrintECB.\n");
        return;
    }
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16, 24, or 32 bytes.\n");
        return;
    }

    // Prepare AES key
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        fprintf(stderr, "Failed to set AES encryption key.\n");
        return;
    }

    // Determine number of blocks (including partial)
    size_t partial_block = (plaintextSize % AES_BLOCK_SIZE) ? 1 : 0;
    size_t totalBlocks = (plaintextSize / AES_BLOCK_SIZE) + partial_block;
    size_t ciphertextSize = totalBlocks * AES_BLOCK_SIZE;

    // Allocate ciphertext buffer
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertextSize);
    if (!ciphertext) {
        fprintf(stderr, "Failed to allocate memory for ciphertext.\n");
        return;
    }
    memset(ciphertext, 0, ciphertextSize);

    // Encrypt block-by-block
    size_t offset = 0;
    while (offset < plaintextSize) {
        unsigned char block[AES_BLOCK_SIZE] = { 0 };
        size_t bytesLeft = plaintextSize - offset;
        size_t blockSize = (bytesLeft < AES_BLOCK_SIZE) ? bytesLeft : AES_BLOCK_SIZE;

        memcpy(block, plaintext + offset, blockSize);
        AES_encrypt(block, ciphertext + offset, &aesKey);

        offset += blockSize;
    }

    // Print the ciphertext (in hex)
    printf("Ciphertext (AES-ECB): ");
    for (size_t i = 0; i < ciphertextSize; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    free(ciphertext);
}

int encryptFileCBCLineByLine(const char* inputFilename,
    const char* outputFilename,
    const unsigned char* key,
    size_t keySize,
    const unsigned char* iv)
{
    // Basic checks
    if (!inputFilename || !outputFilename || !key || !iv) {
        fprintf(stderr, "Invalid parameters.\n");
        return 1;
    }
    // Validate key size
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16, 24, or 32 bytes.\n");
        return 2;
    }

    // Open input file
    FILE* fIn = fopen(inputFilename, "r");
    if (!fIn) {
        perror("Failed to open input file");
        return 3;
    }

    // Open output file
    FILE* fOut = fopen(outputFilename, "wb");
    if (!fOut) {
        perror("Failed to open output file");
        fclose(fIn);
        return 4;
    }

    // Initialize the AES encryption key
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        fprintf(stderr, "Failed to set AES encryption key.\n");
        fclose(fIn);
        fclose(fOut);
        return 5;
    }

    // Copy IV because AES_cbc_encrypt modifies it
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    // Buffer to read lines
    // Increase this size if you expect very long lines
    char lineBuffer[1024];

    while (fgets(lineBuffer, sizeof(lineBuffer), fIn)) {
        size_t lineLen = strlen(lineBuffer);
        // Note: This line length includes the newline character if present
        // unless the line exactly filled the buffer (no newline until next iteration).

        // We will zero-pad any partial block just like the original code
        // Determine how many blocks we need for this line
        size_t partialBlock = (lineLen % AES_BLOCK_SIZE) ? 1 : 0;
        size_t blocks = (lineLen / AES_BLOCK_SIZE) + partialBlock;
        size_t encSize = blocks * AES_BLOCK_SIZE;

        // Prepare plaintext buffer (zero it out for padding)
        unsigned char* plaintext = (unsigned char*)calloc(encSize, 1);
        if (!plaintext) {
            fprintf(stderr, "Memory allocation error.\n");
            fclose(fIn);
            fclose(fOut);
            return 6;
        }
        memcpy(plaintext, lineBuffer, lineLen);

        // Allocate ciphertext buffer
        unsigned char* ciphertext = (unsigned char*)malloc(encSize);
        if (!ciphertext) {
            fprintf(stderr, "Memory allocation error.\n");
            free(plaintext);
            fclose(fIn);
            fclose(fOut);
            return 7;
        }

        // Encrypt using CBC
        AES_cbc_encrypt(plaintext, ciphertext, encSize, &aesKey, ivCopy, AES_ENCRYPT);

        // Write encrypted data to output
        fwrite(ciphertext, 1, encSize, fOut);

        // Clean up this iteration
        free(plaintext);
        free(ciphertext);
    }

    fclose(fIn);
    fclose(fOut);

    printf("File '%s' encrypted line-by-line (CBC) into '%s'.\n",
        inputFilename, outputFilename);
    return 0;
}

int encryptFileECBLineByLine(const char* inputFilename,
    const char* outputFilename,
    const unsigned char* key,
    size_t keySize)
{
    // Basic checks
    if (!inputFilename || !outputFilename || !key) {
        fprintf(stderr, "Invalid parameters.\n");
        return 1;
    }

    // Validate key size
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16, 24, or 32 bytes.\n");
        return 2;
    }

    // Open input file
    FILE* fIn = fopen(inputFilename, "r");
    if (!fIn) {
        perror("Failed to open input file");
        return 3;
    }

    // Open output file
    FILE* fOut = fopen(outputFilename, "wb");
    if (!fOut) {
        perror("Failed to open output file");
        fclose(fIn);
        return 4;
    }

    // Initialize AES key
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        fprintf(stderr, "Failed to set AES encryption key.\n");
        fclose(fIn);
        fclose(fOut);
        return 5;
    }

    // Buffer to read lines
    char lineBuffer[1024];

    while (fgets(lineBuffer, sizeof(lineBuffer), fIn)) {
        size_t lineLen = strlen(lineBuffer);

        // Calculate the block-aligned size for this line
        size_t partialBlock = (lineLen % AES_BLOCK_SIZE) ? 1 : 0;
        size_t blocks = (lineLen / AES_BLOCK_SIZE) + partialBlock;
        size_t encSize = blocks * AES_BLOCK_SIZE;

        // Prepare plaintext buffer (zero-pad)
        unsigned char* plaintext = (unsigned char*)calloc(encSize, 1);
        if (!plaintext) {
            fprintf(stderr, "Memory allocation error.\n");
            fclose(fIn);
            fclose(fOut);
            return 6;
        }
        memcpy(plaintext, lineBuffer, lineLen);

        // Allocate ciphertext buffer
        unsigned char* ciphertext = (unsigned char*)malloc(encSize);
        if (!ciphertext) {
            fprintf(stderr, "Memory allocation error.\n");
            free(plaintext);
            fclose(fIn);
            fclose(fOut);
            return 7;
        }

        // Encrypt each block
        for (size_t offset = 0; offset < encSize; offset += AES_BLOCK_SIZE) {
            AES_encrypt(plaintext + offset, ciphertext + offset, &aesKey);
        }

        // Write to output
        fwrite(ciphertext, 1, encSize, fOut);

        // Clean up
        free(plaintext);
        free(ciphertext);
    }

    fclose(fIn);
    fclose(fOut);

    printf("File '%s' encrypted line-by-line (ECB) into '%s'.\n",
        inputFilename, outputFilename);
    return 0;
}

int main() {
#ifdef TEST_SHA_FUNCTIONS

    compute_sha_for_all_file("wordlist.txt");

    compute_sha_for_all_file_and_write_in_txt_file("wordlist.txt", "hash.txt");

    compute_sha_for_each_line("wordlist.txt");

    compute_sha_for_each_line_write_in_txt_file("wordlist.txt", "hashes.txt");
#endif

#ifdef TEST_MD5_FUNCTIONS
    compute_md5_for_all_file("wordlist.txt");

    compute_md5_for_all_file_and_write_in_txt_file("wordlist.txt", "md5_hash.txt");

    compute_md5_for_each_line("wordlist.txt");

    compute_md5_for_each_line_write_in_txt_file("wordlist.txt", "md5_hashes.txt");
#endif

#ifdef TEST_CBC_FUNCTIONS
    //test cbc with given plaintext
    unsigned char plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xaa, 0x0b, 0x0c, 0xdd, 0x0e, 0x0f,
                     0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xba, 0x0b, 0x0c, 0xdd, 0x0e };
    unsigned char key[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99, 0x88, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x9a, 0x8b };
    unsigned char IV[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    size_t plaintextSize = sizeof(plaintext) / sizeof(plaintext[0]);
    size_t keySize = sizeof(key) / sizeof(key[0]);
    encryptAndPrintCBC(plaintext, plaintextSize, key, keySize, IV);
#endif

#ifdef TEST_IV_READING_FROM_TXT
    //read iv from txt file
    printf("\n\nIV read from text file: ");
    unsigned char iv[16];
    read_iv_from_file("iv.txt", iv);
    for (int i = 0; i < 16; i++) {
        printf("%02X ", iv[i]);
    }
#endif

#ifdef TEST_READING_FROM_ANY_TYPE_OF_FILE
    //read from any type of file (doesn t work for iv)
    printf("\n\n");
    char* content = read_from_file("wordlist.txt");

    if (content) {
        printf("File Contents:\n%s\n", content);
        free(content);  // Free allocated memory
    }
#endif

#ifdef TEST_ECB_FUNCTIONS
    unsigned char plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xaa, 0x0b, 0x0c, 0xdd, 0x0e, 0x0f,
                         0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xba, 0x0b, 0x0c, 0xdd, 0x0e };
    unsigned char key_128[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99, 0x88, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x9a, 0x8b };

    size_t plaintextSize = sizeof(plaintext) / sizeof(plaintext[0]);

    encryptAndPrintECB(plaintext, plaintextSize, key_128, sizeof(key_128));
#endif

#ifdef TEST_AES_KEY_READING
    unsigned char aes_key[KEY_SIZE];

    if (read_aes_key("aes.key", aes_key) != 0) {
        return 1;  // Handle error
    }

    printf("AES key read successfully!\n");

    printf("AES Key: ");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02X ", aes_key[i]);
    }
    printf("\n");
#endif

#ifdef TEST_READING_THE_IV_AND_AES_KEY_FROM_THE_SAME_FILE
    unsigned char iv[IV_SIZE];
    unsigned char key[KEY_SIZE];

    const char* filename = "keyfile.bin";

    if (read_iv_and_aes_key(filename, iv, key, KEY_SIZE) != 0) {
        fprintf(stderr, "Failed to read IV and AES key from file.\n");
        return 1;
    }
#endif

#ifdef TEST_ECB_AND_CBC_ENCRYPTION_LINE_BY_LINE
    unsigned char key[16] = "0123456789ABCDEF";  // 128-bit example
    unsigned char iv[16] = "IV_IS_16_BYTES!!";  // 16 bytes for CBC

    // Encrypt line-by-line with CBC
    int resultCBC = encryptFileCBCLineByLine(
        "plaintext.txt",
        "ciphertext_cbc.bin",
        key,
        sizeof(key),
        iv
    );
    if (resultCBC != 0) {
        fprintf(stderr, "CBC line-by-line encryption failed.\n");
    }

    // Encrypt line-by-line with ECB
    int resultECB = encryptFileECBLineByLine(
        "plaintext.txt",
        "ciphertext_ecb.bin",
        key,
        sizeof(key)
    );
    if (resultECB != 0) {
        fprintf(stderr, "ECB line-by-line encryption failed.\n");
    }
#endif

    return 0;
}
