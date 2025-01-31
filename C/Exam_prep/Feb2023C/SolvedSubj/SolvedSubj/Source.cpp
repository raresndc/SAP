#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#define MAX_LINE_LENGTH 1024

void compute_sha_for_each_line_write_in_file(const char* input_filename, const char* output_filename) {
    char line[MAX_LINE_LENGTH];
    //unsigned char output[SHA_DIGEST_LENGTH];  // SHA-1 output (20 bytes)
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
        //SHA_CTX context_sha1;
        //SHA1_Init(&context_sha1);
        //SHA1_Update(&context_sha1, line, len);
        //SHA1_Final(output, &context_sha1);

        // Compute SHA-256 hash for the line
        SHA256_CTX context_sha256;
        SHA256_Init(&context_sha256);
        SHA256_Update(&context_sha256, line, len);
        SHA256_Final(output_sha256, &context_sha256);

        // Write SHA-1 hash
        //for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        //    fprintf(output_file, "%02X ", output[i]);
        //}

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

int main()
{
    compute_sha_for_each_line_write_in_file("wordlist.txt", "hashes.txt");

	return 0;
}