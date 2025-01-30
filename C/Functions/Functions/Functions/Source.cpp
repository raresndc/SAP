#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <openssl/aes.h>

#define INPUT_BLOCK_LENGTH 15
#define MAX_LINE_LENGTH 1024  // Maximum length of a line
#define AES_BLOCK_SIZE 16

unsigned char key_128[AES_BLOCK_SIZE] = { 0x00 };  // Example key
unsigned char IV[AES_BLOCK_SIZE] = { 0x00 };

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

int main() {

    compute_sha_for_all_file("wordlist.txt");

    compute_sha_for_all_file_and_write_in_txt_file("wordlist.txt", "hash.txt");

    compute_sha_for_each_line("wordlist.txt");

    compute_sha_for_each_line_write_in_txt_file("wordlist.txt", "hashes.txt");

    compute_md5_for_all_file("wordlist.txt");

    compute_md5_for_all_file_and_write_in_txt_file("wordlist.txt", "md5_hash.txt");

    compute_md5_for_each_line("wordlist.txt");

    compute_md5_for_each_line_write_in_txt_file("wordlist.txt", "md5_hashes.txt");

    unsigned char plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xaa, 0x0b, 0x0c, 0xdd, 0x0e, 0x0f,
                     0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xba, 0x0b, 0x0c, 0xdd, 0x0e };
    unsigned char key[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99, 0x88, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x9a, 0x8b };
    unsigned char IV[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    size_t plaintextSize = sizeof(plaintext) / sizeof(plaintext[0]);
    size_t keySize = sizeof(key) / sizeof(key[0]);
    encryptAndPrintCBC(plaintext, plaintextSize, key, keySize, IV);

    return 0;
}
