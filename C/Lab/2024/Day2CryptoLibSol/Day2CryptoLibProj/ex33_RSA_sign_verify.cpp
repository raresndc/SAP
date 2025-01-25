#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include <memory.h>
#include <stdio.h>

int main()
{
	RSA* rsa_public;

	// usually, the message digest SHA1 is re-computed against the restored message at destination point
	// with the receiver's private key
	unsigned char SHA1[] = { 0x2B, 0xA1, 0x7C, 0xE4, 0xAF, 0xD6, 0xCB, 0x94, 0xA2, 0xCD,
							 0xC0, 0xDA, 0x23, 0x72, 0x97, 0x75, 0xBF, 0x5C, 0x2F, 0xD8 };

	FILE* fpublic = fopen("RSAPublicKey.pem", "r");
	rsa_public = PEM_read_RSAPublicKey(fpublic, NULL, NULL, NULL);

	int rsa_size = RSA_size(rsa_public); // TODO: check if rsa_size is number of bits or bytes; it shoudl be number of bytes!!!
	unsigned char message_digest_sha1[20];

	FILE* fsign = fopen("signature.sig", "rb");
	fseek(fsign, 0, SEEK_END); // move the internal data pointer on the end of the file
	unsigned int sign_length = ftell(fsign);
	unsigned char* rsa_signature = (unsigned char*)malloc(sign_length);
	fseek(fsign, 0, SEEK_SET); // move the internal data pointer on the begining of the file signature.sig
	fread(rsa_signature, 1, sign_length, fsign); // get the signature into rsa_signature buffer

	// signature decrypted with issuer's public key
	RSA_public_decrypt(sign_length, rsa_signature, message_digest_sha1, rsa_public, RSA_PKCS1_PADDING);

	int result = memcmp(message_digest_sha1, SHA1, sizeof(message_digest_sha1));

	if (result)
	{
		printf("Wrong signature!\n");
	}
	else
	{
		printf("Signature has been verified!\n");
	}

	RSA_free(rsa_public);
	fclose(fpublic);
	fclose(fsign);
	free(rsa_signature);

	return 0;
}