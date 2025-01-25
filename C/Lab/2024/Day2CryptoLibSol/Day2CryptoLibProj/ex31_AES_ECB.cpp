#include <openssl/aes.h>
#include <malloc.h>
#include <stdio.h>
#include <memory.h>

// TODO: switch to binary and text files for key, plaintext and ciphertext
// TODO: update implementation for key_192 and key_256

int main()
{
	unsigned char plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						 0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						 0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xaa, 0x0b, 0x0c, 0xdd, 0x0e, 0x0f,
						 0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xba, 0x0b, 0x0c, 0xdd, 0x0e };
	unsigned char key_128[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99, 0x88, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x9a, 0x8b };
	unsigned char *ciphertext = NULL; 

	AES_KEY aes_key;

	// AES-ECB encryption
	AES_set_encrypt_key(key_128, (sizeof(key_128) * 8), &aes_key);

	// compute the actual size of the ciphertext bytearray
	unsigned char partial_block = sizeof(plaintext) % AES_BLOCK_SIZE ? 1 : 0;
	unsigned char ciphertext_blocks = sizeof(plaintext) / AES_BLOCK_SIZE + partial_block;
	ciphertext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

	for (unsigned int plain_block_offset = 0;
		plain_block_offset < sizeof(plaintext);
		plain_block_offset += AES_BLOCK_SIZE)
	{
		// make encryption at AES block level only
		AES_encrypt((plaintext + plain_block_offset), (ciphertext + plain_block_offset), &aes_key);
	}

	printf("AES-ECB ciphertext:");
	for (unsigned int i = 0; i < (unsigned int)(ciphertext_blocks * AES_BLOCK_SIZE); i++)
		printf("%02X", ciphertext[i]);
	printf("\n");

	// AES-ECB decryption
	AES_set_decrypt_key(key_128, (sizeof(key_128) * 8), &aes_key);
	unsigned char restore[sizeof(plaintext)];

	unsigned int cipher_block_offset = 0;
	for (cipher_block_offset = 0;
		cipher_block_offset < (unsigned int)((ciphertext_blocks - 1) * AES_BLOCK_SIZE);
		cipher_block_offset += AES_BLOCK_SIZE)
	{
		// n-1 blocks processed here; decryption done at AES block level only
		AES_decrypt((ciphertext + cipher_block_offset), (restore + cipher_block_offset), &aes_key);
	}
	//process the last cipher block
	unsigned char temp[AES_BLOCK_SIZE];
	AES_decrypt((ciphertext + cipher_block_offset), temp, &aes_key);
	if (partial_block)
	{
		// the last restore data block is partial
		unsigned char keeping_bytes = sizeof(restore) % AES_BLOCK_SIZE; // compute the number of bytes to be considered as content for the last block
		memcpy(restore + sizeof(restore) - keeping_bytes, temp, keeping_bytes);
	}
	else {
		// the last block must be considere entirely (plaintext is AES block aligned)
		memcpy(restore + sizeof(restore) - AES_BLOCK_SIZE, temp, AES_BLOCK_SIZE);
	}

	printf("AES-ECB restore:");
	for (unsigned int i = 0; i < sizeof(restore); i++)
		printf("%02X", restore[i]);
	printf("\n");

	int result = memcmp(plaintext, restore, sizeof(plaintext));

	if (result)
	{
		printf("Wrong encryption/decryption operations!\n");
	}
	else
	{
		printf("Successfully encryption/decryption operations!\n");
	}

	free(ciphertext);

	return 0;
}