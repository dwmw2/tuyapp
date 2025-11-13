/*
 *  Crypto helper functions using mbedtls
 *
 *  Copyright 2022-2024 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#ifdef USE_MBEDTLS

#include "tuyaAPI.hpp"
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <cstring>

int tuyaAPI::aes_128_ecb_encrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output, int *output_len)
{
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, key, 128);

	*output_len = 0;
	// ECB mode processes 16-byte blocks
	for (int i = 0; i < input_len; i += 16) {
		mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, input + i, output + i);
		*output_len += 16;
	}

	mbedtls_aes_free(&ctx);
	return 0;
}

int tuyaAPI::aes_128_ecb_decrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output, int *output_len)
{
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_dec(&ctx, key, 128);

	*output_len = 0;
	// ECB mode processes 16-byte blocks
	for (int i = 0; i < input_len; i += 16) {
		mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, input + i, output + i);
		*output_len += 16;
	}

	mbedtls_aes_free(&ctx);
	return 0;
}

void tuyaAPI::hmac_sha256(const unsigned char *key, int key_len, const unsigned char *data, int data_len, unsigned char *output)
{
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md_hmac(md_info, key, key_len, data, data_len, output);
}

void tuyaAPI::md5_hash(const unsigned char *data, int data_len, unsigned char *output)
{
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
	mbedtls_md(md_info, data, data_len, output);
}

void tuyaAPI::random_bytes(unsigned char *buffer, int len)
{
	static mbedtls_entropy_context entropy;
	static mbedtls_ctr_drbg_context ctr_drbg;
	static bool initialized = false;

	if (!initialized) {
		mbedtls_entropy_init(&entropy);
		mbedtls_ctr_drbg_init(&ctr_drbg);
		mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
		initialized = true;
	}

	mbedtls_ctr_drbg_random(&ctr_drbg, buffer, len);
}

#endif // USE_MBEDTLS
