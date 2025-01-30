#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#define INPUT_BLOCK_LENGTH 15
#define MAX_LINE_LENGTH 1024  // Maximum length of a line

void compute_sha1_for_all_file(const char* filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char output[SHA_DIGEST_LENGTH];
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
    SHA_CTX context;
    SHA1_Init(&context);

    // Process the file in 15-byte chunks
    while (remaining_length > 0) {
        size_t bytes_to_read = (remaining_length > INPUT_BLOCK_LENGTH) ? INPUT_BLOCK_LENGTH : remaining_length;
        fread(input, sizeof(unsigned char), bytes_to_read, f);
        SHA1_Update(&context, input, bytes_to_read);
        remaining_length -= bytes_to_read;
    }

    fclose(f);

    // Finalize SHA-1 hash
    SHA1_Final(output, &context);

    // Print the hash
    printf("SHA-1 for all text file:\n");
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02X ", output[i]);
    }
    printf("\n");
}

void compute_sha1_for_all_file_and_write_in_txt_file(const char* input_filename, const char* output_filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
    unsigned char output[SHA_DIGEST_LENGTH];
    
    FILE* f = fopen(input_filename, "r");
    //FILE* f = fopen(input_filename, "rb");  // Correct mode for reading binary files
    FILE* output_file = fopen(output_filename, "w");
    //FILE* output_file = fopen(output_filename, "wb");  // Use "wb" for binary mode (optional here, for consistency)

    // Get file length
    fseek(f, 0, SEEK_END);
    unsigned int remaining_length = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Initialize SHA-1 context
    SHA_CTX context;
    SHA1_Init(&context);

    // Process the file in 15-byte chunks
    while (remaining_length > 0) {
        size_t bytes_to_read = (remaining_length > INPUT_BLOCK_LENGTH) ? INPUT_BLOCK_LENGTH : remaining_length;
        fread(input, sizeof(unsigned char), bytes_to_read, f);
        SHA1_Update(&context, input, bytes_to_read);
        remaining_length -= bytes_to_read;
    }

    fclose(f);

    // Finalize SHA-1 hash
    SHA1_Final(output, &context);

    // Print the hash
    //printf("SHA-1 for all text file:\n");
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        fprintf(output_file, "%02X ", output[i]);
    }
    fprintf(output_file, "\n");
}

void compute_sha1_for_each_line(const char* filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char output[SHA_DIGEST_LENGTH];
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
        SHA_CTX context;
        SHA1_Init(&context);
        SHA1_Update(&context, line, len);
        SHA1_Final(output, &context);

        // Print SHA-1 hash of the current line
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            printf("%02X ", output[i]);
        }
        printf("  <- \"%s\"\n", line);  // Show the original line for reference
    }

    fclose(f);
}

void compute_sha1_for_each_line_write_in_txt_file(const char* input_filename, const char* output_filename) {
    char line[MAX_LINE_LENGTH];
    unsigned char output[SHA_DIGEST_LENGTH];

    FILE* input_file = fopen(input_filename, "r");
    //FILE* f = fopen(input_filename, "rb");  // Correct mode for reading binary files
    FILE* output_file = fopen(output_filename, "w");
    //FILE* output_file = fopen(output_filename, "wb");  // Use "wb" for binary mode (optional here, for consistency)

    if (!input_file) {
        perror("Failed to open input file");
        return;
    }
    if (!output_file) {
        perror("Failed to open output file");
        fclose(input_file);
        return;
    }

    //printf("SHA-1 for each line (also written to %s):\n", output_filename);

    while (fgets(line, sizeof(line), input_file)) {
        size_t len = strlen(line);

        // Remove newline character if present
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        // Compute SHA-1 hash for the line
        SHA_CTX context;
        SHA1_Init(&context);
        SHA1_Update(&context, line, len);
        SHA1_Final(output, &context);

        // Print and write SHA-1 hash
        //printf("SHA-1: ");
        //fprintf(output_file, "SHA-1: ");
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
            //printf("%02X", output[i]);
            fprintf(output_file, "%02X ", output[i]);
        }
        //printf("  <- \"%s\"\n", line);
        //fprintf(output_file, "  <- \"%s\"\n", line);
        fprintf(output_file, "\n");
    }

    fclose(input_file);
    fclose(output_file);
}

int main() {
    compute_sha1_for_all_file("wordlist.txt");

    compute_sha1_for_all_file_and_write_in_txt_file("wordlist.txt", "hash.txt");

    compute_sha1_for_each_line("wordlist.txt");

    compute_sha1_for_each_line_write_in_txt_file("wordlist.txt", "hashes.txt");
    return 0;
}
