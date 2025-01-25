#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>

int main()
{
	RSA* rsa_private;
	
	// usually, the message digest SHA1 is computed against the plaintext
	unsigned char SHA1[] = { 0x2B, 0xA1, 0x7C, 0xE4, 0xAF, 0xD6, 0xCB, 0x94, 0xA2, 0xCD, 
							 0xC0, 0xDA, 0x23, 0x72, 0x97, 0x75, 0xBF, 0x5C, 0x2F, 0xD8 };

	FILE* fprivate = fopen("RSAPrivateKey.pem", "r");
	rsa_private = PEM_read_RSAPrivateKey(fprivate, NULL, NULL, NULL);

	int rsa_size = RSA_size(rsa_private); // TODO: check if rsa_size is number of bits or bytes; it shoudl be number of bytes!!!
	unsigned char* rsa_signature = (unsigned char*)malloc(rsa_size);

	RSA_private_encrypt(sizeof(SHA1), SHA1, rsa_signature, rsa_private, RSA_PKCS1_PADDING); // the signature generated and saved into rsa_signature

	FILE* fsign = fopen("signature.sig", "wb+");
	fwrite(rsa_signature, rsa_size, 1, fsign); // save the signature into signature.sig

	RSA_free(rsa_private);
	fclose(fprivate);
	fclose(fsign);
	free(rsa_signature);

	return 0;
}