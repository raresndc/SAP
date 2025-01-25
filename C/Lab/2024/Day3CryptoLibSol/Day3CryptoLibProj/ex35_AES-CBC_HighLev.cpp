#include <stdio.h>
#include <malloc.h>
#include <openssl/evp.h>

int main()
{

	unsigned char iv[] = {
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x02, 0x03, 0x01, 0x01, 0x01, 0xff, 0xff
	};
	unsigned char aes_key[] = {
		0x01, 0x02, 0x11, 0x21, 0x31, 0x41, 0x51, 0x61,
		0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0x01, 0x01, 0x01, 0x01,
		0x01, 0xff, 0xff, 0xff, 0xff, 0x01, 0xff, 0xff
	};

	EVP_CIPHER_CTX *context;
	// allocate the context
	context = EVP_CIPHER_CTX_new();
	// initialization of the context
	EVP_CIPHER_CTX_init(context);

	EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), NULL, aes_key, iv);

	int key_length = EVP_CIPHER_CTX_key_length(context);
	int block_size = EVP_CIPHER_CTX_block_size(context);
	int iv_size = EVP_CIPHER_CTX_iv_length(context);

	printf("AES-CBC key length: %d\n", key_length);
	printf("AES-CBC block size: %d\n", block_size);
	printf("AES-CBC IV size: %d\n", iv_size);

	FILE* fsrc = fopen("Work.cpp", "rb");
	fseek(fsrc, 0, SEEK_END);
	int file_len = ftell(fsrc);
	fseek(fsrc, 0, SEEK_SET);
	unsigned char* in_data = (unsigned char*)malloc(sizeof(unsigned char)*file_len);
	fread(in_data, sizeof(unsigned char), file_len, fsrc);
	int ciphertext_size = (file_len / block_size) * block_size;
	char partial = file_len % block_size;
	if (partial)
	{
		ciphertext_size += block_size;
	}
	unsigned char* ciphertext = (unsigned char*)malloc(sizeof(unsigned char) * ciphertext_size);

	int cipher_len = 0;
	int in_offset = 0, out_offset = 0;

	EVP_EncryptUpdate(context, ciphertext, &cipher_len, in_data, 15); // each update will encrypt block-aligned input;
	if (cipher_len > 0)
	{
		out_offset += cipher_len;
	}
	in_offset += 15;

	EVP_EncryptUpdate(context, (unsigned char*)(ciphertext + out_offset), &cipher_len, 
						(unsigned char*)(in_data + in_offset), 35); 
	if (cipher_len > 0)
	{
		out_offset += cipher_len;
	}
	in_offset += 35;

	EVP_EncryptUpdate(context, (unsigned char*)(ciphertext + out_offset), &cipher_len,
		(unsigned char*)(in_data + in_offset), (int)(file_len - in_offset));
	if (cipher_len > 0)
	{
		out_offset += cipher_len;
	}
	in_offset += file_len - in_offset;

	EVP_EncryptFinal_ex(context, (unsigned char*)(ciphertext + out_offset), &cipher_len); // the output point is at the end of the output buffer after one/many calls to EncryptUpdate

	FILE* fdst = fopen("Ciphertext.cbc", "wb+");
	fwrite(ciphertext, sizeof(unsigned char), ciphertext_size, fdst);

	free(in_data);
	free(ciphertext);
	EVP_CIPHER_CTX_free(context);

	fclose(fdst);

	return 0;
}