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

#include "tuyaAPI33.hpp"
#include <netdb.h>
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


#define PROTOCOL_33_HEADER_SIZE 16
#define PROTOCOL_33_EXTRA_HEADER_SIZE 15
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 8


tuyaAPI33::tuyaAPI33()
{
	m_protocol = Protocol::v33;
}

tuyaAPI33::~tuyaAPI33()
{
	disconnect();
}


int tuyaAPI33::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload)
{
	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_33_HEADER_SIZE);
	// set message prefix
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	// set command code at int32 @msg[8] (single byte value @msg[11])
	buffer[11] = command;
	bufferpos += (int)PROTOCOL_33_HEADER_SIZE;

	if ((command != TUYA_DP_QUERY) && (command != TUYA_UPDATEDPS))
	{
		// add the protocol 3.3 secondary header
		unsigned char* extraHeader = &buffer[bufferpos];
		memset(extraHeader, 0, PROTOCOL_33_EXTRA_HEADER_SIZE);
		strcpy((char*)extraHeader, "3.3");
		bufferpos += PROTOCOL_33_EXTRA_HEADER_SIZE;
	}

	unsigned char* cEncryptedPayload = &buffer[bufferpos];
	int payloadSize = (int)szPayload.length();
	memset(cEncryptedPayload, 0, payloadSize + 16);
	int encryptedSize = 0;
	int encryptedChars = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)m_encryption_key.c_str(), nullptr);
	EVP_EncryptUpdate(ctx, cEncryptedPayload, &encryptedChars, (unsigned char*)szPayload.c_str(), payloadSize);
	encryptedSize = encryptedChars;
	EVP_EncryptFinal_ex(ctx, cEncryptedPayload + encryptedChars, &encryptedChars);
	encryptedSize += encryptedChars;
	EVP_CIPHER_CTX_free(ctx);

#ifdef DEBUG
	std::cout << "dbg: encrypted payload (size=" << encryptedSize << "): ";
	for(int i=0; i<encryptedSize; ++i)
		printf("%.2x", (uint8_t)cEncryptedPayload[i]);
	std::cout << "\n";
#endif

	bufferpos += encryptedSize;
	unsigned char* cMessageTrailer = &buffer[bufferpos];

	// update message size in int32 @buffer[12]
	int buffersize = bufferpos + MESSAGE_TRAILER_SIZE;
	buffer[14] = ((buffersize - PROTOCOL_33_HEADER_SIZE) & 0x0000FF00) >> 8;
	buffer[15] = (buffersize - PROTOCOL_33_HEADER_SIZE) & 0x000000FF;

	// calculate CRC
	unsigned long crc = this->crc32(0, nullptr, 0);
	crc = this->crc32(crc, buffer, bufferpos) & 0xFFFFFFFF;

	// fill the message trailer
	cMessageTrailer[0] = (crc & 0xFF000000) >> 24;
	cMessageTrailer[1] = (crc & 0x00FF0000) >> 16;
	cMessageTrailer[2] = (crc & 0x0000FF00) >> 8;
	cMessageTrailer[3] = (crc & 0x000000FF);

	cMessageTrailer[4] = (MESSAGE_SUFFIX & 0xFF000000) >> 24;
	cMessageTrailer[5] = (MESSAGE_SUFFIX & 0x00FF0000) >> 16;
	cMessageTrailer[6] = (MESSAGE_SUFFIX & 0x0000FF00) >> 8;
	cMessageTrailer[7] = (MESSAGE_SUFFIX & 0x000000FF);

#ifdef DEBUG
	std::cout << "dbg: complete message: ";
	for(int i=0; i<(int)(buffersize); ++i)
		printf("%.2x", (uint8_t)buffer[i]);
	std::cout << "\n";
#endif

	return buffersize;
}

int tuyaAPI33::DecodeOneMessage(unsigned char* buffer, const int size, std::string &result)
{
	// Need at least header to determine message size
	if (size < PROTOCOL_33_HEADER_SIZE)
		return 0;

	int messageSize = (int)((uint8_t)buffer[15] + ((uint8_t)buffer[14] << 8) + PROTOCOL_33_HEADER_SIZE);

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

	unsigned int crc_sent = ((uint8_t)buffer[messageSize - 8] << 24) + ((uint8_t)buffer[messageSize - 7] << 16) + ((uint8_t)buffer[messageSize - 6] << 8) + (uint8_t)buffer[messageSize - 5];
	unsigned int crc = this->crc32(0, nullptr, 0) & 0xFFFFFFFF;
	crc = this->crc32(crc, buffer, messageSize - 8) & 0xFFFFFFFF;

	if (crc_sent != crc)
	{
		result = "{\"msg\":\"crc error\"}";
		return messageSize;
	}

	unsigned char *cEncryptedPayload = &buffer[PROTOCOL_33_HEADER_SIZE + sizeof(retcode)];
	int payloadSize = (int)(messageSize - PROTOCOL_33_HEADER_SIZE - sizeof(retcode) - 8);

	unsigned char* cDecryptedPayload = new unsigned char[payloadSize + 16];
	memset(cDecryptedPayload, 0, payloadSize + 16);
	int decryptedSize = 0;
	int decryptedChars = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, (unsigned char*)m_encryption_key.c_str(), nullptr);
	EVP_DecryptUpdate(ctx, cDecryptedPayload, &decryptedChars, cEncryptedPayload, payloadSize);
	decryptedSize = decryptedChars;
	EVP_DecryptFinal_ex(ctx, cDecryptedPayload + decryptedSize, &decryptedChars);
	decryptedSize += decryptedChars;
	EVP_CIPHER_CTX_free(ctx);
	result.append((char*)cDecryptedPayload);
	delete[] cDecryptedPayload;

	return messageSize;
}




