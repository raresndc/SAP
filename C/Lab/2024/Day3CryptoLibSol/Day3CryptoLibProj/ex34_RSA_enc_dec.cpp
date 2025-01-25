#include <stdio.h>
#include <openssl/applink.c>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int main(int argc, char** argv)
{
	FILE* fsrc = NULL, * fdst = NULL, *fdstxt = NULL;

	fsrc = fopen(argv[1], "rb"); // this is the file to be encrypted with RSA public key
	fdst = fopen("encFile.bin", "wb+"); // binary file
	fdstxt = fopen("hexEncFile.txt", "w+"); // text file; binary content to be written as hex-pairs into text file

	RSA* pubkey = NULL;

	// RSA public encryption
	FILE* fkey = fopen("RSAPublicKey.pem", "rb");

	pubkey = PEM_read_RSAPublicKey(fkey, NULL, NULL, NULL);
	int key_size = RSA_size(pubkey); // RSA key size in number of bytes
	int enc_size = 0; // number of bytes for one single round of RSA encryption operation
	unsigned char* data = NULL;
	data = (unsigned char*)malloc(key_size); // buffer with the plaintext to be encrypted
	unsigned char* out = NULL;
	out = (unsigned char*)malloc(key_size); // buffer with the ciphertext after encryption

	size_t read_bytes = 0;

	while ((read_bytes = fread(data, sizeof(unsigned char), key_size, fsrc)) && 
		   (read_bytes == key_size))
	{
		enc_size = RSA_public_encrypt(key_size, data, out, pubkey, RSA_NO_PADDING); // encrypt one single full data block
		fwrite(out, sizeof(unsigned char), key_size, fdst); // write one single ciphertext block into encrypted file
		for (unsigned char i = 0; i < key_size; i++)
		{
			fprintf(fdstxt, "%02x", out[i]);
		}
	}

	if (read_bytes > 0)
	{
		enc_size = RSA_public_encrypt(read_bytes, data, out, pubkey, RSA_PKCS1_PADDING); // encrypt one single full data block
		fwrite(out, sizeof(unsigned char), key_size, fdst); // write one single ciphertext block into encrypted file
		for (unsigned char i = 0; i < key_size; i++)
		{
			fprintf(fdstxt, "%02x", out[i]);
		}
	}

	// RSA private decryption
	RSA* privkey = NULL;

	// RSA public encryption
	FILE* fprivkey = fopen("RSAPrivateKey.pem", "rb");
	privkey = PEM_read_RSAPrivateKey(fprivkey, NULL, NULL, NULL);

	int enc_file_size = ftell(fdst);
	int no_blocks = enc_file_size / key_size;
	fseek(fdst, 0, SEEK_SET);
	int dec_size = 0;

	FILE* frest = NULL;
	frest = fopen("restored.txt", "wb+");

	for (unsigned char i = 1; i < no_blocks; i++) // the first n-1 blocks were encrypted without padding
	{
		fread(data, sizeof(unsigned char), key_size, fdst);
		dec_size = RSA_private_decrypt(key_size, data, out, privkey, RSA_NO_PADDING);
		fwrite(out, sizeof(unsigned char), key_size, frest);
	}

	// decrypt the last block
	fread(data, sizeof(unsigned char), key_size, fdst);
	dec_size = RSA_private_decrypt(key_size, data, out, privkey, RSA_PKCS1_PADDING);
	fwrite(out, sizeof(unsigned char), dec_size, frest);

	// dealocations
	free(data);
	free(out);
	RSA_free(pubkey);
	RSA_free(privkey);

	fclose(fsrc);
	fclose(fdst);
	fclose(fkey);
	fclose(fprivkey);
	fclose(frest);

	return 0;
}