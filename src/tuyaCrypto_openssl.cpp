/*
 *  Crypto helper functions using OpenSSL
 *
 *  Copyright 2022-2024 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#ifndef USE_MBEDTLS

#include "tuyaAPI.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

int tuyaAPI::aes_128_ecb_encrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output, int *output_len)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	int len;

	EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
	EVP_EncryptUpdate(ctx, output, &len, input, input_len);
	*output_len = len;
	EVP_EncryptFinal_ex(ctx, output + len, &len);
	*output_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return 0;
}

int tuyaAPI::aes_128_ecb_decrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output, int *output_len)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	int len;

	EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
	EVP_DecryptUpdate(ctx, output, &len, input, input_len);
	*output_len = len;
	EVP_DecryptFinal_ex(ctx, output + len, &len);
	*output_len += len;
	EVP_CIPHER_CTX_free(ctx);

	return 0;
}

void tuyaAPI::hmac_sha256(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *output)
{
	unsigned int hmac_len;
	HMAC(EVP_sha256(), key, key_len, data, data_len, output, &hmac_len);
}

void tuyaAPI::md5_hash(const unsigned char *data, int data_len, unsigned char *output)
{
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
	EVP_DigestUpdate(ctx, data, data_len);
	EVP_DigestFinal_ex(ctx, output, nullptr);
	EVP_MD_CTX_free(ctx);
}

void tuyaAPI::random_bytes(unsigned char *buffer, int len)
{
	RAND_bytes(buffer, len);
}

#endif // USE_MBEDTLS
