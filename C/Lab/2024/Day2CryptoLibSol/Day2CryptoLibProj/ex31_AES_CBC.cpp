#include <openssl/aes.h>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>

// TODO: extend implementation for binary and text files: plaintext, ciphertext, key, IV
// TODO: switch to key_192 and key_256

int main()
{
	unsigned char plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						 0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
						 0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xaa, 0x0b, 0x0c, 0xdd, 0x0e, 0x0f,
						 0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xba, 0x0b, 0x0c, 0xdd, 0x0e };
	unsigned char key_128[] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99, 0x88, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x9a, 0x8b };
	unsigned char IV[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	
	unsigned char IV_dec[sizeof(IV)];
	unsigned char* ciphertext = NULL;

	AES_KEY aes_key;

	// compute the actual size of the ciphertext bytearray
	unsigned char partial_block = sizeof(plaintext) % AES_BLOCK_SIZE ? 1 : 0;
	unsigned char ciphertext_blocks = sizeof(plaintext) / AES_BLOCK_SIZE + partial_block;
	ciphertext = (unsigned char*)malloc(ciphertext_blocks * AES_BLOCK_SIZE);

	// AES CBC encryption
	AES_set_encrypt_key(key_128, (sizeof(key_128) * 8), &aes_key);
	memcpy(IV_dec, IV, sizeof(IV)); // needed because the IV will be changed after the call to AES_cbc_encrypt
									// at decryption time, the initial IV must be the same with the initial IV used for encryption
	AES_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext), &aes_key, IV, AES_ENCRYPT);
	
	printf("AES-CBC ciphertext: ");
	for (unsigned int i = 0; i < (unsigned int)(ciphertext_blocks * AES_BLOCK_SIZE); i++)
	{
		printf("%02X", ciphertext[i]);
	}
	printf("\n\n");

	// AES CBC decryption
	AES_set_decrypt_key(key_128, (sizeof(key_128) * 8), &aes_key);
	unsigned char restore[sizeof(plaintext)];
	AES_cbc_encrypt(ciphertext, restore, sizeof(plaintext), &aes_key, IV_dec, AES_DECRYPT);

	printf("AES-CBC restore: ");
	for (unsigned int i = 0; i < sizeof(plaintext); i++)
	{
		printf("%02X", restore[i]);
	}
	printf("\n\n");

	int result = memcmp(plaintext, restore, sizeof(plaintext));
	if (result)
	{
		printf("Wrong encryption/decryption operations\n");
	}
	else
	{
		printf("Successfully encryption/decryption operations\n");
	}

	free(ciphertext);
	return 0;
}