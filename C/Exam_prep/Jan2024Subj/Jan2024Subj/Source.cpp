#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <ctype.h>

#define INPUT_BLOCK_LENGTH 15
#define MAX_LINE_LENGTH 1024  // Maximum length of a line
#define IV_SIZE 16
#define KEY_SIZE 16

void write_in_file(const char* filename) {

    FILE* f = fopen(filename, "w");

    if (!f) {
        perror("Failed to open file");
        return;
    }

    fprintf(f, "%s", "Nedelcu Rares");

    printf("Name written successfully!\n");

    fclose(f);
}

void compute_sha_for_all_file(const char* filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    //unsigned char output[SHA_DIGEST_LENGTH];  // SHA-1 output (20 bytes)
    unsigned char output_sha256[SHA256_DIGEST_LENGTH];  // SHA-256 output (32 bytes)

    FILE* f = fopen(filename, "r");
    if (!f) {
        perror("Failed to open file");
        return;
    }

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Initialize SHA-1 context
    //SHA_CTX context_sha1;
    //SHA1_Init(&context_sha1);

    // Initialize SHA-256 context
    SHA256_CTX context_sha256;
    SHA256_Init(&context_sha256);

    // Process the file in 15-byte chunks
    while (remaining_length > 0) {
        size_t bytes_to_read = (remaining_length > INPUT_BLOCK_LENGTH) ? INPUT_BLOCK_LENGTH : remaining_length;
        fread(input, sizeof(unsigned char), bytes_to_read, f);
        //SHA1_Update(&context_sha1, input, bytes_to_read);    // SHA-1 Update
        SHA256_Update(&context_sha256, input, bytes_to_read);  // SHA-256 Update
        remaining_length -= bytes_to_read;
    }

    fclose(f);

    // Finalize SHA-1 hash
    //SHA1_Final(output, &context_sha1);
    // Finalize SHA-256 hash
    SHA256_Final(output_sha256, &context_sha256);

    // Print the SHA-1 hash
    //printf("SHA-1 for all file:\n");
    //for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
    //    printf("%02X ", output[i]);
    //}
    //printf("\n");

    // Print the SHA-256 hash
    printf("SHA-256 for all file:\n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02X ", output_sha256[i]);
    }
    printf("\n");
}

void aes_cbc_encrypt_for_all_file_and_write_in_file(const char* input_filename, const char* output_filename, const unsigned char* key_128, unsigned char* IV) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char* ciphertext = NULL;
    AES_KEY aes_key;

    FILE* f = fopen(input_filename, "r");
    FILE* output_file = fopen(output_filename, "wb");

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
    AES_set_encrypt_key(key_128, 256, &aes_key);
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

void aes_cbc_encrypt_for_all_file(const char* filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char* ciphertext = NULL;
    AES_KEY aes_key;

    FILE* f = fopen(filename, "r");
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
    unsigned char key_128[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99, 0x88, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x9a, 0x8b };
    unsigned char IV[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

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

int main() {
    //write_in_file("name.txt");

    //compute_sha_for_all_file("name.txt");

    //FILE* ivFile = fopen("iv.txt", "r");
    //if (!ivFile) {
    //    perror("Failed to open iv file");
    //    return 1;
    //}

    //char buffer[128];  // Temporary buffer to read the file
    //unsigned char iv[IV_SIZE];
    //int i = 0;

    //// Read the entire file into buffer
    //if (fgets(buffer, sizeof(buffer), ivFile) == NULL) {
    //    perror("Error reading file");
    //    fclose(ivFile);
    //    return 1;
    //}
    //fclose(ivFile);

    //// Parse hex values, ignoring commas and spaces
    //char* ptr = buffer;
    //while (*ptr && i < IV_SIZE) {
    //    if (*ptr == ',' || isspace((unsigned char)*ptr)) {
    //        ptr++;  // Skip commas and spaces
    //        continue;
    //    }

    //    // Convert "0xff" style hex values
    //    if (*ptr == '0' && (*(ptr + 1) == 'x' || *(ptr + 1) == 'X')) {
    //        iv[i] = (unsigned char)strtol(ptr, &ptr, 16);
    //        i++;
    //    }
    //    else {
    //        ptr++;  // Move to next character
    //    }
    //}

    //// Print the IV in hex format
    //printf("IV: ");
    //for (int j = 0; j < IV_SIZE; j++) {
    //    printf("%02X", iv[j]);
    //}
    //printf("\n");

    //FILE* keyFile = fopen("aes.key", "rb");
    //if (!keyFile) {
    //    perror("Failed to open key file");
    //    return 1;
    //}

    //unsigned char key[KEY_SIZE];
    //size_t bytesRead = fread(key, 1, KEY_SIZE, keyFile);
    //fclose(keyFile);

    //if (bytesRead != KEY_SIZE) {
    //    fprintf(stderr, "Error: Expected %d bytes but read %zu bytes.\n", KEY_SIZE, bytesRead);
    //    return 1;
    //}

    //printf("AES-256 Key: ");
    //for (int i = 0; i < KEY_SIZE; i++) {
    //    printf("%02X", key[i]);
    //}
    //printf("\n");

    //aes_cbc_encrypt_for_all_file_and_write_in_file("name.txt", "enc_name.aes", key, iv);

    aes_cbc_encrypt_for_all_file("input.txt");

    return 0;
}