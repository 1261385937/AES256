#include <string>
#include <vector>
#include "crypto/aes.h"
int main()
{
	//private key
	uint8_t  secret_key[32] = { 41,51,71,51,61,71,61,21,71,31,11,31,111,56,84,91,51,71,61,71,61,51,48,81,61,46,87,81,61,87,69,100 };
	uint8_t public_key_hash_first_half[16] = { 71,31,11,31,111,56,84,91,51,71,61,71,61,51,48,81 };

	AES256CBCEncrypt encrypt(secret_key, public_key_hash_first_half, true);
	const unsigned char msg[3] = { 1,2,3 };
	std::vector<unsigned char> vchCiphertext;
	vchCiphertext.resize(3 + AES_BLOCKSIZE);
	std::size_t len = encrypt.Encrypt(msg, 3, vchCiphertext.data());
	if (len < 3)
		return false;
	vchCiphertext.resize(len);



	len = vchCiphertext.size();
	std::vector<unsigned char> quondam_msg;
	quondam_msg.resize(len);
	AES256CBCDecrypt dec(secret_key, public_key_hash_first_half, true);
	len = dec.Decrypt(vchCiphertext.data(), vchCiphertext.size(), quondam_msg.data());
	if (len == 0)
		return false;
	quondam_msg.resize(len);
	return 0;
}