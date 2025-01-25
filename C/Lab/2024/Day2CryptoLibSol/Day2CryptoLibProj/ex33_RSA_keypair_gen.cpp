#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/applink.c>

int main()
{
	RSA *rsa_kp;

	rsa_kp = RSA_generate_key(1024, 65535, NULL, NULL);

	// RSA_check_key(rsa_kp); // validate the just created RSA key pair

	FILE* fprivate = fopen("RSAPrivateKey.pem", "w+");
	PEM_write_RSAPrivateKey(fprivate, rsa_kp, NULL, NULL, 0, NULL, NULL); // save the private key components in PEM format file
	FILE* fpublic = fopen("RSAPublicKey.pem", "w+");
	PEM_write_RSAPublicKey(fpublic, rsa_kp); // save the public key components in PEM format file

	RSA_free(rsa_kp);

	return 0;
}