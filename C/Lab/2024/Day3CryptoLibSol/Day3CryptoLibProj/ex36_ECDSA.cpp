#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

int main()
{
	unsigned char SHA1[] = {
		0xff, 0xa4, 0xff, 0xff, 0x77, 
		0xff, 0xab, 0xff, 0xff, 0xff, 
		0x04, 0xff, 0xff, 0xff, 0x1c, 
		0xc5, 0xff, 0xa9, 0xff, 0xff
	};
	unsigned char* signature = (unsigned char*)malloc(80); // 72 bytes is ECDSA max length for NIST P256R1
	unsigned int signature_len = 0;

	EC_KEY* ec_key = NULL;

	ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // initialize EC_KEY with NIST P256R1 curve parameters
	EC_KEY_generate_key(ec_key); // generate a NIST P256R1 key pair

	// ECDSA signature generated into signature buffer;
	// for the same EC private key, each ECDSA signature will be different for the next calls to ECDSA_sign
	// generated signature in DER format
	// first argument is ignored as API doc states
	ECDSA_sign(0, SHA1, sizeof(SHA1), signature, &signature_len, ec_key); 
	

	// ECDSA signature verification
	ECDSA_SIG* pBNSig = NULL;
	pBNSig = ECDSA_SIG_new(); // alocare storage for structure ECDSA_SIG
	// temporary change of signature content
	// signature[5] += 1; // impact on R content (signature becomes invalid)
	// signature[0] = 66; // impact the DER enconding (conversion to R and S as BIGNUM is failing)
	d2i_ECDSA_SIG(&pBNSig, (const unsigned char**)&signature, signature_len); // transform the DER bytearray into 2 BIGNUM structures
	int result = ECDSA_do_verify(SHA1, sizeof(SHA1), pBNSig, ec_key); // verify the signature

	if (result == 1)
	{
		printf("Signature is valid!\n");
	}
	else
	{
		if (result == 0)
		{
			printf("Signature is not valid!\n");
		}
		else
		{
			printf("An error has occured!\n");
		}
	}

	return 0;
}