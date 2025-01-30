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

void aes_cbc_encrypt_for_all_file(const char* filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char* ciphertext = NULL;
    AES_KEY aes_key;

    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file");
        return;
    }

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Compute the number of ciphertext blocks
    unsigned char partial_block = remaining_length % AES_BLOCK_SIZE ? 1 : 0;
    unsigned char ciphertext_blocks = remaining_length / AES_BLOCK_SIZE + partial_block;
    ciphertext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

    // AES CBC encryption
    AES_set_encrypt_key(key_128, 128, &aes_key);
    unsigned char IV_dec[AES_BLOCK_SIZE];
    memcpy(IV_dec, IV, AES_BLOCK_SIZE);  // Preserve IV for decryption
    AES_cbc_encrypt(input, ciphertext, remaining_length, &aes_key, IV, AES_ENCRYPT);

    // Print the ciphertext
    printf("AES-CBC ciphertext: ");
    for (unsigned int i = 0; i < ciphertext_blocks * AES_BLOCK_SIZE; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    free(ciphertext);
    fclose(f);
}

// AES CBC encryption for the entire file with output written to a text file
void aes_cbc_encrypt_for_all_file_and_write_in_txt_file(const char* input_filename, const char* output_filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char* ciphertext = NULL;
    AES_KEY aes_key;

    FILE* f = fopen(input_filename, "rb");
    FILE* output_file = fopen(output_filename, "w");

    if (!f || !output_file) {
        perror("Failed to open file");
        return;
    }

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Compute the number of ciphertext blocks
    unsigned char partial_block = remaining_length % AES_BLOCK_SIZE ? 1 : 0;
    unsigned char ciphertext_blocks = remaining_length / AES_BLOCK_SIZE + partial_block;
    ciphertext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

    // AES CBC encryption
    AES_set_encrypt_key(key_128, 128, &aes_key);
    unsigned char IV_dec[AES_BLOCK_SIZE];
    memcpy(IV_dec, IV, AES_BLOCK_SIZE);  // Preserve IV for decryption
    AES_cbc_encrypt(input, ciphertext, remaining_length, &aes_key, IV, AES_ENCRYPT);

    // Write the ciphertext to the output file
    for (unsigned int i = 0; i < ciphertext_blocks * AES_BLOCK_SIZE; i++) {
        fprintf(output_file, "%02X", ciphertext[i]);
    }
    fprintf(output_file, "\n");

    free(ciphertext);
    fclose(f);
    fclose(output_file);
}

// AES CBC encryption for each line in a file
void aes_cbc_encrypt_for_each_line(const char* filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char* ciphertext = NULL;
    AES_KEY aes_key;

    FILE* f = fopen(filename, "r");

    if (!f) {
        perror("Failed to open file");
        return;
    }

    printf("\nAES-CBC ciphertext for each line:\n");

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        // Compute the ciphertext size (ensure we handle padding)
        unsigned char partial_block = len % AES_BLOCK_SIZE ? 1 : 0;
        unsigned char ciphertext_blocks = len / AES_BLOCK_SIZE + partial_block;
        ciphertext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

        // AES CBC encryption
        AES_set_encrypt_key(key_128, 128, &aes_key);
        unsigned char IV_dec[AES_BLOCK_SIZE];
        memcpy(IV_dec, IV, AES_BLOCK_SIZE);  // Preserve IV for decryption
        AES_cbc_encrypt((unsigned char*)line, ciphertext, len, &aes_key, IV, AES_ENCRYPT);

        // Print the ciphertext
        printf("Ciphertext: ");
        for (unsigned int i = 0; i < ciphertext_blocks * AES_BLOCK_SIZE; i++) {
            printf("%02X", ciphertext[i]);
        }
        printf("  <- \"%s\"\n", line);
        free(ciphertext);
    }

    fclose(f);
}

// AES CBC encryption for each line and output written to a text file
void aes_cbc_encrypt_for_each_line_write_in_txt_file(const char* input_filename, const char* output_filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char* ciphertext = NULL;
    AES_KEY aes_key;

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

        // Compute the ciphertext size (ensure we handle padding)
        unsigned char partial_block = len % AES_BLOCK_SIZE ? 1 : 0;
        unsigned char ciphertext_blocks = len / AES_BLOCK_SIZE + partial_block;
        ciphertext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

        // AES CBC encryption
        AES_set_encrypt_key(key_128, 128, &aes_key);
        unsigned char IV_dec[AES_BLOCK_SIZE];
        memcpy(IV_dec, IV, AES_BLOCK_SIZE);  // Preserve IV for decryption
        AES_cbc_encrypt((unsigned char*)line, ciphertext, len, &aes_key, IV, AES_ENCRYPT);

        // Write the ciphertext to the output file
        for (unsigned int i = 0; i < ciphertext_blocks * AES_BLOCK_SIZE; i++) {
            fprintf(output_file, "%02X", ciphertext[i]);
        }
        fprintf(output_file, "\n");

        free(ciphertext);
    }

    fclose(input_file);
    fclose(output_file);
}

void aes_cbc_decrypt_for_all_file(const char* filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char* plaintext = NULL;
    AES_KEY aes_key;

    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file");
        return;
    }

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Compute the number of ciphertext blocks
    unsigned char partial_block = remaining_length % AES_BLOCK_SIZE ? 1 : 0;
    unsigned char plaintext_blocks = remaining_length / AES_BLOCK_SIZE + partial_block;
    plaintext = (unsigned char*)malloc(plaintext_blocks * AES_BLOCK_SIZE);

    // AES CBC decryption
    AES_set_decrypt_key(key_128, 128, &aes_key);
    unsigned char IV_dec[AES_BLOCK_SIZE];
    memcpy(IV_dec, IV, AES_BLOCK_SIZE);  // Preserve IV for decryption
    AES_cbc_encrypt(input, plaintext, remaining_length, &aes_key, IV_dec, AES_DECRYPT);

    // Print the decrypted plaintext
    printf("AES-CBC decrypted plaintext: ");
    for (unsigned int i = 0; i < plaintext_blocks * AES_BLOCK_SIZE; i++) {
        printf("%02X", plaintext[i]);
    }
    printf("\n");

    free(plaintext);
    fclose(f);
}

// AES CBC decryption for the entire file with output written to a text file
void aes_cbc_decrypt_for_all_file_and_write_in_txt_file(const char* input_filename, const char* output_filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char* plaintext = NULL;
    AES_KEY aes_key;

    FILE* f = fopen(input_filename, "rb");
    FILE* output_file = fopen(output_filename, "w");

    if (!f || !output_file) {
        perror("Failed to open file");
        return;
    }

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Compute the number of ciphertext blocks
    unsigned char partial_block = remaining_length % AES_BLOCK_SIZE ? 1 : 0;
    unsigned char plaintext_blocks = remaining_length / AES_BLOCK_SIZE + partial_block;
    plaintext = (unsigned char*)malloc(plaintext_blocks * AES_BLOCK_SIZE);

    // AES CBC decryption
    AES_set_decrypt_key(key_128, 128, &aes_key);
    unsigned char IV_dec[AES_BLOCK_SIZE];
    memcpy(IV_dec, IV, AES_BLOCK_SIZE);  // Preserve IV for decryption
    AES_cbc_encrypt(input, plaintext, remaining_length, &aes_key, IV_dec, AES_DECRYPT);

    // Write the decrypted plaintext to the output file
    for (unsigned int i = 0; i < plaintext_blocks * AES_BLOCK_SIZE; i++) {
        fprintf(output_file, "%02X", plaintext[i]);
    }
    fprintf(output_file, "\n");

    free(plaintext);
    fclose(f);
    fclose(output_file);
}

// AES CBC decryption for each line in a file
void aes_cbc_decrypt_for_each_line(const char* filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char* plaintext = NULL;
    AES_KEY aes_key;

    FILE* f = fopen(filename, "r");

    if (!f) {
        perror("Failed to open file");
        return;
    }

    printf("\nAES-CBC decrypted plaintext for each line:\n");

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        // Compute the plaintext size (ensure we handle padding)
        unsigned char partial_block = len % AES_BLOCK_SIZE ? 1 : 0;
        unsigned char plaintext_blocks = len / AES_BLOCK_SIZE + partial_block;
        plaintext = (unsigned char*)malloc(plaintext_blocks * AES_BLOCK_SIZE);

        // AES CBC decryption
        AES_set_decrypt_key(key_128, 128, &aes_key);
        unsigned char IV_dec[AES_BLOCK_SIZE];
        memcpy(IV_dec, IV, AES_BLOCK_SIZE);  // Preserve IV for decryption
        AES_cbc_encrypt((unsigned char*)line, plaintext, len, &aes_key, IV_dec, AES_DECRYPT);

        // Print the decrypted plaintext
        printf("Decrypted: ");
        for (unsigned int i = 0; i < plaintext_blocks * AES_BLOCK_SIZE; i++) {
            printf("%02X", plaintext[i]);
        }
        printf("  <- \"%s\"\n", line);
        free(plaintext);
    }

    fclose(f);
}

// AES CBC decryption for each line and output written to a text file
void aes_cbc_decrypt_for_each_line_write_in_txt_file(const char* input_filename, const char* output_filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char* plaintext = NULL;
    AES_KEY aes_key;

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

        // Calculate the size of ciphertext (it should be multiple of AES_BLOCK_SIZE)
        size_t ciphertext_len = len / 2;  // Since each byte is represented by two hex characters
        unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);

        // Convert hex string (input) to binary ciphertext
        for (size_t i = 0; i < ciphertext_len; i++) {
            sscanf(line + 2 * i, "%2hhx", &ciphertext[i]);
        }

        // Compute the plaintext size (ensure we handle padding)
        size_t plaintext_len = ciphertext_len;  // Same size for the decrypted output
        plaintext = (unsigned char*)malloc(plaintext_len);

        // AES CBC decryption
        AES_set_decrypt_key(key_128, 128, &aes_key);
        unsigned char IV_dec[AES_BLOCK_SIZE];
        memcpy(IV_dec, IV, AES_BLOCK_SIZE);  // Preserve IV for decryption
        AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &aes_key, IV_dec, AES_DECRYPT);

        // Remove padding (PKCS7)
        unsigned char padding = plaintext[plaintext_len - 1];
        plaintext_len -= padding;  // Adjust the plaintext length to remove padding

        // Write the decrypted plaintext to the output file
        fwrite(plaintext, 1, plaintext_len, output_file);
        fprintf(output_file, "\n");  // New line after each decrypted line

        free(ciphertext);
        free(plaintext);
    }

    fclose(input_file);
    fclose(output_file);
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

    aes_cbc_encrypt_for_all_file("wordlist.txt");

    aes_cbc_encrypt_for_all_file_and_write_in_txt_file("wordlist.txt", "aes_encrypted.txt");

    aes_cbc_encrypt_for_each_line("wordlist.txt");

    aes_cbc_encrypt_for_each_line_write_in_txt_file("wordlist.txt", "aes_encrypted_lines.txt");

    //aes_cbc_decrypt_for_all_file("aes_encrypted.txt");

    //aes_cbc_decrypt_for_all_file_and_write_in_txt_file("aes_encrypted.txt", "aes_decrypted.txt");

    aes_cbc_decrypt_for_each_line("aes_encrypted.txt");

    aes_cbc_decrypt_for_each_line_write_in_txt_file("aes_encrypted.txt", "aes_decrypted_lines.txt");

    return 0;
}
