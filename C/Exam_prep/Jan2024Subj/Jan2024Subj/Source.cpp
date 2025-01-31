#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/aes.h>

#define INPUT_BLOCK_LENGTH 15
#define IV_SIZE 16
#define KEY_SIZE 32

void compute_sha_for_all_file(const char* filename) {
    unsigned char input[INPUT_BLOCK_LENGTH];
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

    // Initialize SHA-256 context
    SHA256_CTX context_sha256;
    SHA256_Init(&context_sha256);

    // Process the file in 15-byte chunks
    while (remaining_length > 0) {
        size_t bytes_to_read = (remaining_length > INPUT_BLOCK_LENGTH) ? INPUT_BLOCK_LENGTH : remaining_length;
        fread(input, sizeof(unsigned char), bytes_to_read, f);
        SHA256_Update(&context_sha256, input, bytes_to_read);  // SHA-256 Update
        remaining_length -= bytes_to_read;
    }

    fclose(f);

    // Finalize SHA-256 hash
    SHA256_Final(output_sha256, &context_sha256);


    // Print the SHA-256 hash
    printf("SHA-256 for all file:\n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02X ", output_sha256[i]);
    }
    printf("\n");
}

int read_iv_from_file_as_uint8(const char* filename, uint8_t iv[IV_SIZE]) {
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
        // Skip commas and whitespace
        if (*ptr == ',' || isspace((unsigned char)*ptr)) {
            ptr++;
            continue;
        }

        // If the token starts with "0x" or "0X", interpret as hex
        if (*ptr == '0' && (*(ptr + 1) == 'x' || *(ptr + 1) == 'X')) {
            // strtol converts the hex string to a long.
            // The (uint8_t) cast will truncate to 8 bits, which is fine for IV data.
            iv[i] = (uint8_t)strtol(ptr, &ptr, 16);
            i++;
        }
        else {
            ptr++;
        }
    }

    if (i != IV_SIZE) {
        fprintf(stderr, "Error: IV file contains insufficient or excessive data (got %d values, need %d)\n",
            i, IV_SIZE);
        return 1;
    }

    return 0;
}

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

int decryptFileCBCLineByLine(const char* inputFilename,
    const char* outputFilename,
    const unsigned char* key,
    size_t keySize,
    const unsigned char* iv)
{
    // Validate arguments
    if (!inputFilename || !outputFilename || !key || !iv) {
        fprintf(stderr, "Invalid parameters.\n");
        return 1;
    }
    // Check key size
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        fprintf(stderr, "Key size must be 16, 24, or 32 bytes.\n");
        return 2;
    }

    // Open input (ciphertext) file
    FILE* fIn = fopen(inputFilename, "rb");
    if (!fIn) {
        perror("Failed to open ciphertext file");
        return 3;
    }

    // Open output (plaintext) file
    FILE* fOut = fopen(outputFilename, "w");
    if (!fOut) {
        perror("Failed to open output file");
        fclose(fIn);
        return 4;
    }

    // Set up AES key for decryption
    AES_KEY aesKey;
    if (AES_set_decrypt_key(key, (int)(keySize * 8), &aesKey) < 0) {
        fprintf(stderr, "Failed to set AES decryption key.\n");
        fclose(fIn);
        fclose(fOut);
        return 5;
    }

    // Copy IV because AES_cbc_encrypt (AES_DECRYPT) will modify it
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    // We use the same chunk size as in the encryption function (1024).
    // Each line was read into 1024, padded to a multiple of 16, and written.
    unsigned char cipherBuffer[1024];
    unsigned char plainBuffer[1024];

    while (1) {
        // Read exactly up to 1024 bytes of ciphertext
        size_t bytesRead = fread(cipherBuffer, 1, sizeof(cipherBuffer), fIn);

        if (bytesRead == 0) {
            // No more data to read
            break;
        }

        // If the bytesRead is not a multiple of AES_BLOCK_SIZE, it indicates
        // either file corruption or mismatch with the encryption approach
        if (bytesRead % AES_BLOCK_SIZE != 0) {
            fprintf(stderr, "Ciphertext block size mismatch! Possibly corrupted.\n");
            fclose(fIn);
            fclose(fOut);
            return 6;
        }

        // Decrypt in CBC mode
        AES_cbc_encrypt(cipherBuffer, plainBuffer, bytesRead,
            &aesKey, ivCopy, AES_DECRYPT);

        // Now plainBuffer contains the original line data (zero padded).
        // We remove trailing zero bytes to restore the original line content.
        // This is purely to reconstruct the text line as it was before encryption.
        size_t realDataLen = bytesRead;
        while (realDataLen > 0 && plainBuffer[realDataLen - 1] == 0) {
            realDataLen--;
        }

        // Write the (zero-stripped) data to the output file
        // This is text data, so we can just fwrite it or fprintf it.
        fwrite(plainBuffer, 1, realDataLen, fOut);

        // If the encryption function was using fgets, each chunk was presumably one line
        // plus newline. If a newline was included, it will appear in the plainBuffer.
        // This means we don't necessarily need to write our own newline here.
        // But if you want to forcibly break lines, you could do something like:
        // fputc('\n', fOut);
        // However, that might create extra blank lines if the original line
        // already included '\n'.
    }

    fclose(fIn);
    fclose(fOut);

    printf("File '%s' decrypted line-by-line (CBC) into '%s'.\n",
        inputFilename, outputFilename);
    return 0;
}

int main() {
	
	FILE* name = fopen("name.txt", "w");
	fprintf(name, "%s", "Nedelcu Rares");
	fclose(name);

    compute_sha_for_all_file("name.txt");

    uint8_t iv[16];
    read_iv_from_file_as_uint8("iv.txt", iv);

    unsigned char aesKey[KEY_SIZE];
    read_aes_key("aes.key", aesKey);

    encryptFileCBC("name.txt", "enc_name.aes", aesKey, KEY_SIZE, iv);

    decryptFileCBCLineByLine("enc_name.aes", "test.txt", aesKey, KEY_SIZE, iv);

	return 0;
}