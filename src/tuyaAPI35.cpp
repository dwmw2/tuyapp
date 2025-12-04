/*
 *  Client interface for local Tuya device access
 *
 *  Copyright 2022-2024 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *  Licensed under GNU General Public License 3.0 or later.
 *  Some rights reserved. See COPYING, AUTHORS.
 *
 *  @license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */


#define PROTOCOL_35_HEADER_SIZE 20
#define MESSAGE_PREFIX 0x00006699
#define MESSAGE_SUFFIX 0x00009966
#define MESSAGE_TRAILER_SIZE 4
#define GCM_TAG_SIZE 16
#define GCM_IV_SIZE 12

#include "tuyaAPI35.hpp"
#include <cstring>
#include <thread>

#ifdef DEBUG
#include <iostream>
#endif

tuyaAPI35::tuyaAPI35()
{
	m_protocol = Protocol::v35;
	m_session_established = false;
	m_seqno = 0;
}

void tuyaAPI35::SetEncryptionKey(const std::string &key)
{
	tuyaAPI::SetEncryptionKey(key);
	m_session_established = false;
	m_seqno = 0;
	random_bytes(m_local_nonce, 16);
}

int tuyaAPI35::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload)
{
	if (!m_session_established)
		return -1;

	m_seqno++;

	// For control commands (7, 13), protocol 3.5 requires "3.5" prefix + 12 null bytes
	std::string payload = szPayload;
	if (command == TUYA_CONTROL || command == TUYA_CONTROL_NEW)
	{
		payload = "3.5";
		payload.append(12, '\0');
		payload.append(szPayload);
	}

	// Generate 12-byte IV
	unsigned char iv[GCM_IV_SIZE];
	random_bytes(iv, GCM_IV_SIZE);

	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_35_HEADER_SIZE);
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	// bytes 4-7 are unknown/reserved (set to 0)
	buffer[8] = (m_seqno & 0xFF000000) >> 24;
	buffer[9] = (m_seqno & 0x00FF0000) >> 16;
	buffer[10] = (m_seqno & 0x0000FF00) >> 8;
	buffer[11] = (m_seqno & 0x000000FF);
	buffer[15] = command;
	bufferpos += (int)PROTOCOL_35_HEADER_SIZE;

#ifdef DEBUG
	std::cout << "dbg: Payload to encrypt (" << payload.length() << " bytes): " << payload << "\n";
#endif

	// Copy IV to buffer
	memcpy(&buffer[bufferpos], iv, GCM_IV_SIZE);
	bufferpos += GCM_IV_SIZE;

	unsigned char* cEncryptedPayload = &buffer[bufferpos];
	int payloadSize = (int)payload.length();
	int encryptedSize = 0;
	unsigned char tag[GCM_TAG_SIZE];

	// AAD is header bytes 4-19 (after prefix)
	if (aes_128_gcm_encrypt(m_session_key, iv, GCM_IV_SIZE,
	                        &buffer[4], PROTOCOL_35_HEADER_SIZE - 4,
	                        (unsigned char*)payload.c_str(), payloadSize,
	                        cEncryptedPayload, &encryptedSize,
	                        tag, GCM_TAG_SIZE) != 0)
		return -1;

	bufferpos += encryptedSize;

	// Append GCM tag
	memcpy(&buffer[bufferpos], tag, GCM_TAG_SIZE);
	bufferpos += GCM_TAG_SIZE;

	// Append suffix
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0x000000FF);

	int buffersize = bufferpos;
	int payload_len = buffersize - PROTOCOL_35_HEADER_SIZE - MESSAGE_TRAILER_SIZE;
	buffer[14] = (payload_len & 0x0000FF00) >> 8;
	buffer[15] = (payload_len & 0x000000FF);
	buffer[15] = command;  // restore command byte

#ifdef DEBUG
	std::cout << "dbg: normal message (size=" << buffersize << "): ";
	for(int i=0; i<buffersize; ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}


std::string tuyaAPI35::DecodeTuyaMessage(unsigned char* buffer, const int size)
{
	if (!m_session_established)
		return "{\"msg\":\"session not established\"}";

	std::string result;
	int bufferpos = 0;

	while (bufferpos < size)
	{
		unsigned char* cTuyaResponse = &buffer[bufferpos];
		int payload_len = (int)((uint8_t)cTuyaResponse[15] + ((uint8_t)cTuyaResponse[14] << 8));
		int messageSize = payload_len + PROTOCOL_35_HEADER_SIZE + MESSAGE_TRAILER_SIZE;

		// Extract IV (12 bytes after header)
		unsigned char iv[GCM_IV_SIZE];
		memcpy(iv, &cTuyaResponse[PROTOCOL_35_HEADER_SIZE], GCM_IV_SIZE);

		// Extract tag (16 bytes before suffix)
		unsigned char tag[GCM_TAG_SIZE];
		memcpy(tag, &cTuyaResponse[messageSize - MESSAGE_TRAILER_SIZE - GCM_TAG_SIZE], GCM_TAG_SIZE);

		// Encrypted payload is between IV and tag
		unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_35_HEADER_SIZE + GCM_IV_SIZE];
		int encryptedSize = payload_len - GCM_IV_SIZE - GCM_TAG_SIZE;

		unsigned char* cDecryptedPayload = new unsigned char[encryptedSize + 16];
		memset(cDecryptedPayload, 0, encryptedSize + 16);
		int decryptedSize = 0;

		// AAD is header bytes 4-19
		if (aes_128_gcm_decrypt(m_session_key, iv, GCM_IV_SIZE,
		                        &cTuyaResponse[4], PROTOCOL_35_HEADER_SIZE - 4,
		                        cEncryptedPayload, encryptedSize,
		                        tag, GCM_TAG_SIZE,
		                        cDecryptedPayload, &decryptedSize) == 0)
		{
			// Check for retcode at start of decrypted payload
			int json_start = 0;
			if (decryptedSize >= 4 && cDecryptedPayload[0] == 0 && cDecryptedPayload[1] == 0)
			{
				int retcode = (int)((uint8_t)cDecryptedPayload[3] + ((uint8_t)cDecryptedPayload[2] << 8));
				if (retcode != 0)
				{
					char cErrorMessage[50];
					sprintf(cErrorMessage, "{\"msg\":\"device returned error %d\"}", retcode);
					result.append(cErrorMessage);
					delete[] cDecryptedPayload;
					bufferpos += messageSize;
					continue;
				}
				json_start = 4;
			}

			// Strip protocol version header if present
			for (int i = json_start; i < decryptedSize - 1; i++)
			{
				if (cDecryptedPayload[i] == '{')
				{
					json_start = i;
					break;
				}
			}

			result.append((char*)cDecryptedPayload + json_start, decryptedSize - json_start);
		}
		else
		{
			result.append("{\"msg\":\"error decrypting payload\"}");
		}

		delete[] cDecryptedPayload;
		bufferpos += messageSize;
	}
	return result;
}

int tuyaAPI35::BuildSessionMessage(unsigned char *buffer)
{
	uint8_t command;
	std::string payload;

	if (m_seqno == 0)
	{
		// Send first message: local nonce
#ifdef DEBUG
		std::cout << "dbg: Starting session negotiation\n";
#endif
		m_seqno = 1;
		command = 3;
		payload = std::string((char*)m_local_nonce, 16);
	}
	else if (m_seqno == 1)
	{
		// After receiving response, send second message
		unsigned char rkey_hmac[32];
		hmac_sha256((unsigned char*)m_encryption_key.c_str(), m_encryption_key.length(),
		            m_remote_nonce, 16, rkey_hmac);

		m_seqno = 2;
		m_session_established = true;
		command = 5;
		payload = std::string((char*)rkey_hmac, 32);
	}
	else
	{
		// Session complete
		return 0;
	}

	// Generate IV
	unsigned char iv[GCM_IV_SIZE];
	random_bytes(iv, GCM_IV_SIZE);

	// Build the session message
	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_35_HEADER_SIZE);
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	buffer[8] = (m_seqno & 0xFF000000) >> 24;
	buffer[9] = (m_seqno & 0x00FF0000) >> 16;
	buffer[10] = (m_seqno & 0x0000FF00) >> 8;
	buffer[11] = (m_seqno & 0x000000FF);
	buffer[15] = command;
	bufferpos += (int)PROTOCOL_35_HEADER_SIZE;

	// Copy IV
	memcpy(&buffer[bufferpos], iv, GCM_IV_SIZE);
	bufferpos += GCM_IV_SIZE;

	unsigned char* cEncryptedPayload = &buffer[bufferpos];
	int payloadSize = (int)payload.length();
	int encryptedSize = 0;
	unsigned char tag[GCM_TAG_SIZE];

	if (aes_128_gcm_encrypt((unsigned char*)m_encryption_key.c_str(), iv, GCM_IV_SIZE,
	                        &buffer[4], PROTOCOL_35_HEADER_SIZE - 4,
	                        (unsigned char*)payload.c_str(), payloadSize,
	                        cEncryptedPayload, &encryptedSize,
	                        tag, GCM_TAG_SIZE) != 0)
		return -1;

	bufferpos += encryptedSize;

	// Append tag
	memcpy(&buffer[bufferpos], tag, GCM_TAG_SIZE);
	bufferpos += GCM_TAG_SIZE;

	// Append suffix
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	buffer[bufferpos++] = (MESSAGE_SUFFIX & 0x000000FF);

	int buffersize = bufferpos;
	int payload_len = buffersize - PROTOCOL_35_HEADER_SIZE - MESSAGE_TRAILER_SIZE;
	buffer[14] = (payload_len & 0x0000FF00) >> 8;
	buffer[15] = (payload_len & 0x000000FF);
	buffer[15] = command;  // restore command

#ifdef DEBUG
	std::cout << "dbg: session message (size=" << buffersize << "): ";
	for(int i=0; i<buffersize; ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}


std::string tuyaAPI35::DecodeSessionMessage(unsigned char* buffer, const int size)
{
	// Decrypt the session response
	std::string result;
	unsigned char* cTuyaResponse = buffer;
	int payload_len = (int)((uint8_t)cTuyaResponse[15] + ((uint8_t)cTuyaResponse[14] << 8));

	// Extract IV
	unsigned char iv[GCM_IV_SIZE];
	memcpy(iv, &cTuyaResponse[PROTOCOL_35_HEADER_SIZE], GCM_IV_SIZE);

	// Extract tag
	unsigned char tag[GCM_TAG_SIZE];
	int messageSize = payload_len + PROTOCOL_35_HEADER_SIZE + MESSAGE_TRAILER_SIZE;
	memcpy(tag, &cTuyaResponse[messageSize - MESSAGE_TRAILER_SIZE - GCM_TAG_SIZE], GCM_TAG_SIZE);

	// Encrypted payload
	unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_35_HEADER_SIZE + GCM_IV_SIZE];
	int encryptedSize = payload_len - GCM_IV_SIZE - GCM_TAG_SIZE;

	unsigned char* cDecryptedPayload = new unsigned char[encryptedSize + 16];
	memset(cDecryptedPayload, 0, encryptedSize + 16);
	int decryptedSize = 0;

	if (aes_128_gcm_decrypt((unsigned char*)m_encryption_key.c_str(), iv, GCM_IV_SIZE,
	                        &cTuyaResponse[4], PROTOCOL_35_HEADER_SIZE - 4,
	                        cEncryptedPayload, encryptedSize,
	                        tag, GCM_TAG_SIZE,
	                        cDecryptedPayload, &decryptedSize) == 0)
	{
		// Skip retcode if present
		int start = 0;
		if (decryptedSize >= 4 && cDecryptedPayload[0] == 0 && cDecryptedPayload[1] == 0)
			start = 4;

		result.append((char*)cDecryptedPayload + start, decryptedSize - start);
	}
	else
	{
		result.append("{\"msg\":\"error decrypting payload\"}");
	}

	delete[] cDecryptedPayload;

	// Process the decrypted response based on state
	if (m_seqno == 1 && result.length() >= 48)
	{
		// Extract remote_nonce (first 16 bytes)
		memcpy(m_remote_nonce, result.c_str(), 16);

		// Verify HMAC(local_key, local_nonce) matches bytes 16-47
		unsigned char hmac_check[32];
		hmac_sha256((unsigned char*)m_encryption_key.c_str(), m_encryption_key.length(),
		            m_local_nonce, 16, hmac_check);

		if (memcmp(hmac_check, (unsigned char*)result.c_str() + 16, 32) != 0)
		{
#ifdef DEBUG
			std::cout << "dbg: HMAC verification failed!\n";
#endif
			return "";
		}

		// XOR local and remote nonces
		unsigned char xor_nonce[16];
		for (int i = 0; i < 16; i++)
			xor_nonce[i] = m_local_nonce[i] ^ m_remote_nonce[i];

		// Encrypt XOR'd nonce with local_key using ECB to get session key
		int outlen;
		if (aes_128_ecb_encrypt((unsigned char*)m_encryption_key.c_str(), xor_nonce, 16, m_session_key, &outlen) != 0)
			return "";

#ifdef DEBUG
		std::cout << "dbg: Session key: ";
		for(int i=0; i<16; ++i)
			printf("%.2x", (uint8_t)m_session_key[i]);
		std::cout << "\n";
#endif
	}

	return result;
}
