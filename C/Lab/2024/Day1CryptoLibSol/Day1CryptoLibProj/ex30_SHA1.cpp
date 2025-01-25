#include <stdio.h>
#include <openssl/sha.h>

#define INPUT_BLOCK_LENGTH 15

// TODO: add implementation for SHA-256

int main()
{
	unsigned char input[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							 0x11, 0x02, 0x03, 0x44, 0x55, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
							 0x21, 0x02, 0x03, 0x44, 0x65, 0x06, 0x07, 0x08, 0x09, 0xaa, 0x0b, 0x0c, 0xdd, 0x0e, 0x0f,
							 0x31, 0x02, 0x03, 0x44, 0x75, 0x06, 0x07, 0x08, 0x09, 0xba, 0x0b, 0x0c, 0xdd, 0x0e };
	SHA_CTX context;

	SHA1_Init(&context);
	unsigned char input_length = sizeof(input) / sizeof(unsigned char); // total length of the bytearray input
	unsigned char remaining_length = input_length; // length of remaining data to be processed
	unsigned char input_offset = 0; // current offset of data chunk to be processed

	while (remaining_length > 0)
	{
		if (remaining_length > INPUT_BLOCK_LENGTH)
		{
			// sha1 update done for 15-byte input 
			SHA1_Update(&context, (input + input_offset), INPUT_BLOCK_LENGTH); // one data block having exactly 15 bytes is processed
			input_offset += INPUT_BLOCK_LENGTH; // update the current offset for the next data chunk to be processed later
			remaining_length -= INPUT_BLOCK_LENGTH; // update the remaining length of the entire input to be processed later
		}
		else
		{
			// sha1 update done for less or equal to 15 bytes as data length
			SHA1_Update(&context, (input + input_offset), remaining_length); // remained data block is processsed
			input_offset += remaining_length; // this update input_offset will not be used further
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
