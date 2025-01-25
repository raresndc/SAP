#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <openssl/evp.h>

int main()
{
	unsigned char data[] = {
		0xff, 0xa4, 0xff
	};
	unsigned char* message_digest = NULL;

	EVP_MD_CTX* md_context = NULL;
	EVP_MD* digest = NULL;

	digest = (EVP_MD*)EVP_sha3_256();
	md_context = EVP_MD_CTX_new();

	EVP_DigestInit_ex(md_context, digest, NULL); // initialization of the message digest context
	EVP_DigestUpdate(md_context, data, sizeof(data));

	int digest_length = EVP_MD_size(digest);
	message_digest = (unsigned char*)malloc(digest_length);
	memset(message_digest, 0x00, digest_length); // set all bytes over message_digest to zero

	unsigned int size = 0;
	EVP_DigestFinal(md_context, message_digest, &size); // if message digest bytearray already allocated before

	printf("SHA3 result = ");
	for (unsigned char i = 0; i < size; i++)
	{
		printf("%02x", message_digest[i]);
	}
	printf("\n\n");
}