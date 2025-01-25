#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>

#define INPUT_BLOCK_LENGTH 15

// TODO: add implementation for SHA-256

int main()
{
	unsigned char input[INPUT_BLOCK_LENGTH];
	FILE* f = NULL;
	SHA_CTX context;

	f = fopen("input-SHA1-txtfile.txt", "rb");
	fseek(f, 0, SEEK_END);
	unsigned int remaining_length = ftell(f); // initial value: total length of the file
	fseek(f, 0, SEEK_SET);

	SHA1_Init(&context);

	while (remaining_length > 0)
	{
		unsigned char hex_pair[2];
		unsigned char i = 0;
		if (remaining_length > (INPUT_BLOCK_LENGTH * 2)) // double length because eah hex-pair means 2 bytes in text/ASCII representation
		{
			for (i = 0; i < INPUT_BLOCK_LENGTH; i++)
			{
				fread(hex_pair, sizeof(unsigned char), sizeof(hex_pair)/sizeof(unsigned char), f); // read 2 bytes from the text file corresponding to one single hex pair
				input[i] = (unsigned char)strtol((const char*)hex_pair, NULL, 16);
			}

			// sha1 update done for 15-byte input 
			SHA1_Update(&context, input, INPUT_BLOCK_LENGTH); // one data block having exactly 15 bytes is processed			
			remaining_length -= (INPUT_BLOCK_LENGTH * 2); // update the remaining length (double for text representation read from the file) of the entire input to be processed later
		}
		else
		{
			unsigned char remaining_hex_pairs = remaining_length / 2;
			for (i = 0; i < remaining_hex_pairs; i++) // 2 because the hex pair has as text has a double no of bytes
			{
				fread(hex_pair, sizeof(unsigned char), sizeof(hex_pair) / sizeof(unsigned char), f); // read 2 bytes from the text file corresponding to one single hex pair
				input[i] = (unsigned char)strtol((const char*)hex_pair, NULL, 16);
			}

			// sha1 update done for less or equal to 15 bytes as data length
			SHA1_Update(&context, input, remaining_hex_pairs); // remained data block is processsed
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
