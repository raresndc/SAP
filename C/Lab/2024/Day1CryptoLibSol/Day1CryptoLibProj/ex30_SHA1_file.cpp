#include <stdio.h>
#include <openssl/sha.h>

#define INPUT_BLOCK_LENGTH 15

// TODO: add implementation for SHA-256

int main()
{
	unsigned char input[INPUT_BLOCK_LENGTH];
	FILE* f = NULL;
	SHA_CTX context;

	f = fopen("input_SHA1.bin", "rb");
	fseek(f, 0, SEEK_END);
	unsigned int remaining_length = ftell(f); // initial value: total length of the file
	fseek(f, 0, SEEK_SET);

	SHA1_Init(&context);

	while (remaining_length > 0)
	{
		if (remaining_length > INPUT_BLOCK_LENGTH)
		{
			// sha1 update done for 15-byte input 
			fread(input, sizeof(unsigned char), INPUT_BLOCK_LENGTH, f);
			SHA1_Update(&context, input, INPUT_BLOCK_LENGTH); // one data block having exactly 15 bytes is processed			
			remaining_length -= INPUT_BLOCK_LENGTH; // update the remaining length of the entire input to be processed later
		}
		else
		{
			// sha1 update done for less or equal to 15 bytes as data length
			fread(input, sizeof(unsigned char), remaining_length, f);
			SHA1_Update(&context, input, remaining_length); // remained data block is processsed
			remaining_length -= remaining_length; // remaining_length is zero; there is no more data to be processed by SHA1_Update rounds
		}
	}

	unsigned char output[SHA_DIGEST_LENGTH];
	SHA1_Final(output, &context);

	for (unsigned char i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		printf(" %02X", output[i]);
	}
	printf("\n\n");

	return 0;
}
