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

#define SOCKET_TIMEOUT_SECS 5

#include "tuyaAPI34.hpp"
#include <netdb.h>
#include <zlib.h>
#include <sstream>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

#ifdef WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <io.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>


#define PROTOCOL_34_HEADER_SIZE 16
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 36


tuyaAPI34::tuyaAPI34()
{
	m_protocol = Protocol::v34;
	m_seqno = 0;
	m_last_response_size = 0;
	RAND_bytes(m_local_nonce, 16);
}

tuyaAPI34::~tuyaAPI34()
{
	disconnect();
}


void tuyaAPI34::setEncryptionKey(const std::string &key)
{
	m_encryption_key = key;
	m_seqno = 0;
	m_session_established = false;
	RAND_bytes(m_local_nonce, 16);
}


int tuyaAPI34::BuildSessionMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload, const std::string &encryption_key)
{
	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_34_HEADER_SIZE);
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	buffer[4] = (m_seqno & 0xFF000000) >> 24;
	buffer[5] = (m_seqno & 0x00FF0000) >> 16;
	buffer[6] = (m_seqno & 0x0000FF00) >> 8;
	buffer[7] = (m_seqno & 0x000000FF);
	buffer[11] = command;
	bufferpos += (int)PROTOCOL_34_HEADER_SIZE;

	unsigned char* cEncryptedPayload = &buffer[bufferpos];
	int payloadSize = (int)szPayload.length();
	memset(cEncryptedPayload, 0, payloadSize + 16);
	int encryptedSize = 0;
	int encryptedChars = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)encryption_key.c_str(), nullptr);
	EVP_EncryptUpdate(ctx, cEncryptedPayload, &encryptedChars, (unsigned char*)szPayload.c_str(), payloadSize);
	encryptedSize = encryptedChars;
	EVP_EncryptFinal_ex(ctx, cEncryptedPayload + encryptedChars, &encryptedChars);
	encryptedSize += encryptedChars;
	EVP_CIPHER_CTX_free(ctx);

	bufferpos += encryptedSize;
	unsigned char* cMessageTrailer = &buffer[bufferpos];

	int buffersize = bufferpos + MESSAGE_TRAILER_SIZE;
	buffer[14] = ((buffersize - PROTOCOL_34_HEADER_SIZE) & 0x0000FF00) >> 8;
	buffer[15] = (buffersize - PROTOCOL_34_HEADER_SIZE) & 0x000000FF;

	// Calculate HMAC-SHA256
	unsigned int hmac_len;
	HMAC(EVP_sha256(), (unsigned char*)encryption_key.c_str(), encryption_key.length(),
	     buffer, bufferpos, cMessageTrailer, &hmac_len);

	cMessageTrailer[32] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	cMessageTrailer[33] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	cMessageTrailer[34] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	cMessageTrailer[35] = (MESSAGE_SUFFIX & 0x000000FF);

#ifdef DEBUG
	std::cout << "dbg: session message (size=" << buffersize << "): ";
	for(int i=0; i<buffersize; ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}


std::string tuyaAPI34::DecodeSessionMessage(unsigned char* buffer, const int size, const std::string &encryption_key)
{
	std::string result;

	// Need at least header to read message size
	if (size < PROTOCOL_34_HEADER_SIZE)
		return result;

	unsigned char* cTuyaResponse = buffer;
	int messageSize = (int)((uint8_t)cTuyaResponse[15] + ((uint8_t)cTuyaResponse[14] << 8) + PROTOCOL_34_HEADER_SIZE);

	// Check we have complete message
	if (size < messageSize)
		return result;

	// Session messages have a 4-byte retcode after the header
	unsigned char *cEncryptedPayload = &cTuyaResponse[PROTOCOL_34_HEADER_SIZE + 4];
	int payloadSize = (int)(messageSize - PROTOCOL_34_HEADER_SIZE - 4 - MESSAGE_TRAILER_SIZE);

	unsigned char* cDecryptedPayload = new unsigned char[payloadSize + 16];
	memset(cDecryptedPayload, 0, payloadSize + 16);
	int decryptedSize = 0;
	int decryptedChars = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)encryption_key.c_str(), nullptr);
	EVP_DecryptUpdate(ctx, cDecryptedPayload, &decryptedChars, cEncryptedPayload, payloadSize);
	decryptedSize = decryptedChars;
	EVP_DecryptFinal_ex(ctx, cDecryptedPayload + decryptedSize, &decryptedChars);
	decryptedSize += decryptedChars;
	EVP_CIPHER_CTX_free(ctx);
	result.append((char*)cDecryptedPayload, decryptedSize);

	delete[] cDecryptedPayload;
	return result;
}


bool tuyaAPI34::NegotiateSession(const std::string &local_key)
{
	m_seqno = 0;

	if (!tuyaAPI::NegotiateSession(local_key))
		return false;

	return true;
}

int tuyaAPI34::GetNextSessionPacket(unsigned char *buffer)
{
	if (m_seqno == 0)
	{
		// Send first message: local nonce
#ifdef DEBUG
		std::cout << "dbg: Starting session negotiation\n";
#endif
		m_seqno = 1;
		return BuildSessionMessage(buffer, 3, std::string((char*)m_local_nonce, 16), m_encryption_key);
	}
	else if (m_seqno == 1)
	{
		// Process response and send second message
		std::string response = DecodeSessionMessage(m_last_response, m_last_response_size, m_encryption_key);
		if (response.length() < 48)
		{
#ifdef DEBUG
			std::cout << "dbg: Response too short: " << response.length() << " bytes\n";
#endif
			return -1;
		}

		// Extract remote_nonce and verify HMAC
		memcpy(m_remote_nonce, response.c_str(), 16);

		unsigned char hmac_check[32];
		unsigned int hmac_check_len;
		HMAC(EVP_sha256(), (unsigned char*)m_encryption_key.c_str(), m_encryption_key.length(),
		     m_local_nonce, 16, hmac_check, &hmac_check_len);

		if (memcmp(hmac_check, (unsigned char*)response.c_str() + 16, 32) != 0)
		{
#ifdef DEBUG
			std::cout << "dbg: HMAC verification failed!\n";
#endif
			return -1;
		}

		// Derive session key
		unsigned char xor_nonce[16];
		for (int i = 0; i < 16; i++)
			xor_nonce[i] = m_local_nonce[i] ^ m_remote_nonce[i];

		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		int outlen;
		EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)m_encryption_key.c_str(), nullptr);
		EVP_EncryptUpdate(ctx, m_session_key, &outlen, xor_nonce, 16);
		EVP_EncryptFinal_ex(ctx, m_session_key + outlen, &outlen);
		EVP_CIPHER_CTX_free(ctx);

#ifdef DEBUG
		std::cout << "dbg: Session key: ";
		for(int i=0; i<16; ++i)
			printf("%.2x", (uint8_t)m_session_key[i]);
		std::cout << "\n";
#endif

		// Send second message: HMAC of remote nonce
		unsigned char rkey_hmac[32];
		unsigned int hmac_len;
		HMAC(EVP_sha256(), (unsigned char*)m_encryption_key.c_str(), m_encryption_key.length(),
		     m_remote_nonce, 16, rkey_hmac, &hmac_len);

		m_seqno = 2;
		m_session_established = true;
		return BuildSessionMessage(buffer, 5, std::string((char*)rkey_hmac, 32), m_encryption_key);
	}

	// Session complete
	return 0;
}

void tuyaAPI34::StoreSessionResponse(unsigned char *buffer, int size)
{
	m_last_response_size = size;
	memcpy(m_last_response, buffer, size);
}


int tuyaAPI34::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload)
{
	if (!m_session_established)
		return -1;

	m_seqno++;

	// For control commands (7, 13), protocol 3.4 requires "3.4" prefix + 12 null bytes
	std::string payload = szPayload;
	if (command == TUYA_CONTROL || command == TUYA_CONTROL_NEW)
	{
		payload = "3.4";
		payload.append(12, '\0');
		payload.append(szPayload);
	}

	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_34_HEADER_SIZE);
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	buffer[4] = (m_seqno & 0xFF000000) >> 24;
	buffer[5] = (m_seqno & 0x00FF0000) >> 16;
	buffer[6] = (m_seqno & 0x0000FF00) >> 8;
	buffer[7] = (m_seqno & 0x000000FF);
	buffer[11] = command;
	bufferpos += (int)PROTOCOL_34_HEADER_SIZE;

#ifdef DEBUG
	std::cout << "dbg: Payload to encrypt (" << payload.length() << " bytes): " << payload << "\n";
#endif

	unsigned char* cEncryptedPayload = &buffer[bufferpos];
	int payloadSize = (int)payload.length();
	memset(cEncryptedPayload, 0, payloadSize + 16);
	int encryptedSize = 0;
	int encryptedChars = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, m_session_key, nullptr);
	EVP_EncryptUpdate(ctx, cEncryptedPayload, &encryptedChars, (unsigned char*)payload.c_str(), payloadSize);
	encryptedSize = encryptedChars;
	EVP_EncryptFinal_ex(ctx, cEncryptedPayload + encryptedChars, &encryptedChars);
	encryptedSize += encryptedChars;
	EVP_CIPHER_CTX_free(ctx);

	bufferpos += encryptedSize;
	unsigned char* cMessageTrailer = &buffer[bufferpos];

	int buffersize = bufferpos + 36;  // 32 bytes HMAC + 4 bytes suffix
	buffer[14] = ((buffersize - PROTOCOL_34_HEADER_SIZE) & 0x0000FF00) >> 8;
	buffer[15] = (buffersize - PROTOCOL_34_HEADER_SIZE) & 0x000000FF;

	// Calculate HMAC-SHA256 of header + encrypted payload
	unsigned int hmac_len;
	HMAC(EVP_sha256(), m_session_key, 16, buffer, bufferpos, cMessageTrailer, &hmac_len);

	cMessageTrailer[32] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	cMessageTrailer[33] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	cMessageTrailer[34] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	cMessageTrailer[35] = (MESSAGE_SUFFIX & 0x000000FF);

#ifdef DEBUG
	std::cout << "dbg: normal message (size=" << buffersize << "): ";
	for(int i=0; i<buffersize; ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}

int tuyaAPI34::DecodeOneMessage(unsigned char* buffer, const int size, std::string &result)
{
	if (!m_session_established)
	{
		result = "{\"msg\":\"session not established\"}";
		return -1;
	}

	// Need at least header to determine message size
	if (size < PROTOCOL_34_HEADER_SIZE)
		return 0;

	int messageSize = (int)((uint8_t)buffer[15] + ((uint8_t)buffer[14] << 8) + PROTOCOL_34_HEADER_SIZE);

	// Check if we have the complete message
	if (size < messageSize)
		return 0;

	int retcode = (int)((uint8_t)buffer[19] + ((uint8_t)buffer[18] << 8));

	if (retcode != 0)
	{
		char cErrorMessage[50];
		sprintf(cErrorMessage, "{\"msg\":\"device returned error %d\"}", retcode);
		result = cErrorMessage;
		return messageSize;
	}

	// Verify HMAC
	unsigned char hmac_sent[32];
	memcpy(hmac_sent, &buffer[messageSize - 36], 32);

	unsigned char hmac_calc[32];
	unsigned int hmac_len;
	HMAC(EVP_sha256(), m_session_key, 16, buffer, messageSize - 36, hmac_calc, &hmac_len);

	if (memcmp(hmac_sent, hmac_calc, 32) != 0)
	{
		result = "{\"msg\":\"crc error\"}";
		return messageSize;
	}

	unsigned char *cEncryptedPayload = &buffer[PROTOCOL_34_HEADER_SIZE + sizeof(retcode)];
	int payloadSize = (int)(messageSize - PROTOCOL_34_HEADER_SIZE - sizeof(retcode) - 36);

	unsigned char* cDecryptedPayload = new unsigned char[payloadSize + 16];
	memset(cDecryptedPayload, 0, payloadSize + 16);
	int decryptedSize = 0;
	int decryptedChars = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, m_session_key, nullptr);
	EVP_DecryptUpdate(ctx, cDecryptedPayload, &decryptedChars, cEncryptedPayload, payloadSize);
	decryptedSize = decryptedChars;
	EVP_DecryptFinal_ex(ctx, cDecryptedPayload + decryptedSize, &decryptedChars);
	decryptedSize += decryptedChars;
	EVP_CIPHER_CTX_free(ctx);

	// Strip protocol version header (e.g., "3.4" followed by binary data)
	// Look for the start of JSON data
	int json_start = 0;
	for (int i = 0; i < decryptedSize - 1; i++)
	{
		if (cDecryptedPayload[i] == '{')
		{
			json_start = i;
			break;
		}
	}

	result.append((char*)cDecryptedPayload + json_start, decryptedSize - json_start);
	delete[] cDecryptedPayload;

	return messageSize;
}


bool tuyaAPI34::ConnectToDevice(const std::string &hostname, const int portnumber, uint8_t retries)
{
	// Use base class connection
	if (!tuyaAPI::ConnectToDevice(hostname, portnumber, retries))
		return false;

	// Protocol 3.4 requires session negotiation
	// Session will be negotiated on first message
	m_session_established = false;
	m_seqno = 0;
	return true;
}
