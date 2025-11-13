/*
 *	Client interface for local Tuya device access
 *
 *	Copyright 2022-2024 - gordonb3 https://github.com/gordonb3/tuyapp
 *
 *	Licensed under GNU General Public License 3.0 or later.
 *	Some rights reserved. See COPYING, AUTHORS.
 *
 *	@license GPL-3.0+ <https://github.com/gordonb3/tuyapp/blob/master/LICENSE>
 */

#define SOCKET_TIMEOUT_SECS 5

#include "tuyaAPI31.hpp"
#include <netdb.h>
#include <sstream>
#include <iomanip>
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


#include <sstream>


#define PROTOCOL_31_HEADER_SIZE 16
#define MESSAGE_PREFIX 0x000055aa
#define MESSAGE_SUFFIX 0x0000aa55
#define MESSAGE_TRAILER_SIZE 8


tuyaAPI31::tuyaAPI31()
{
	m_protocol = Protocol::v31;
}

tuyaAPI31::~tuyaAPI31()
{
	disconnect();
}


int tuyaAPI31::BuildTuyaMessage(unsigned char *buffer, const uint8_t command, const std::string &szPayload)
{
	int bufferpos = 0;
	memset(buffer, 0, PROTOCOL_31_HEADER_SIZE);
	// set message prefix
	buffer[0] = (MESSAGE_PREFIX & 0xFF000000) >> 24;
	buffer[1] = (MESSAGE_PREFIX & 0x00FF0000) >> 16;
	buffer[2] = (MESSAGE_PREFIX & 0x0000FF00) >> 8;
	buffer[3] = (MESSAGE_PREFIX & 0x000000FF);
	// set command code at int32 @buffer[8] (single byte value @buffer[11])
	buffer[11] = command;
	bufferpos += (int)PROTOCOL_31_HEADER_SIZE;

	int payloadSize = (int)szPayload.length();
	if (!m_encryption_key.empty())
	{
		unsigned char* cEncryptedPayload = &buffer[bufferpos];
		memset(cEncryptedPayload, 0, payloadSize + 16);
		int encryptedSize = 0;

		aes_128_ecb_encrypt((unsigned char*)m_encryption_key.c_str(), (unsigned char*)szPayload.c_str(), payloadSize, cEncryptedPayload, &encryptedSize);

		unsigned char cBase64Payload[200];
		payloadSize = encode_base64( (unsigned char *)cEncryptedPayload, encryptedSize, &cBase64Payload[0]);

		// add 3.1 info
		std::string premd5 = "data=";
		premd5.append((char *)cBase64Payload);
		premd5.append("||lpv=3.1||");
		premd5.append(m_encryption_key);
		std::string md5str = make_md5_digest(premd5);
		std::string md5mid = (char *)&md5str[8];
		std::string header = "3.1";
		header.append(md5mid);
		bcopy(header.c_str(), &buffer[bufferpos], header.length());
		bufferpos += header.length();
		cEncryptedPayload = &buffer[bufferpos];
		strcpy((char *)cEncryptedPayload,(char *)cBase64Payload);
		bufferpos += payloadSize;

#ifdef DEBUG
		std::cout << "dbg: encrypted payload (size=" << payloadSize << "): ";
		for(int i=0; i<payloadSize; ++i)
			printf("%.2x", (uint8_t)cEncryptedPayload[i]);
		std::cout << "\n";
#endif
	}
	else
	{
		unsigned char* cPayload = &buffer[bufferpos];
		memcpy((void *)cPayload, (void *)szPayload.c_str(), payloadSize + 1);
		bufferpos += payloadSize;
	}

	unsigned char* cMessageTrailer = &buffer[bufferpos];

	// update message size in int32 @buffer[12]
	int buffersize = bufferpos + MESSAGE_TRAILER_SIZE;
	buffer[14] = ((buffersize - PROTOCOL_31_HEADER_SIZE) & 0x0000FF00) >> 8;
	buffer[15] = (buffersize - PROTOCOL_31_HEADER_SIZE) & 0x000000FF;

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

int tuyaAPI31::DecodeOneMessage(unsigned char* buffer, const int size, std::string &result)
{
	// Need at least header to determine message size
	if (size < PROTOCOL_31_HEADER_SIZE)
		return 0;

	int messageSize = (int)((uint8_t)buffer[15] + ((uint8_t)buffer[14] << 8) + PROTOCOL_31_HEADER_SIZE);

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

	// Verify CRC
	unsigned int crc_sent = ((uint8_t)buffer[messageSize - 8] << 24) + ((uint8_t)buffer[messageSize - 7] << 16) + ((uint8_t)buffer[messageSize - 6] << 8) + (uint8_t)buffer[messageSize - 5];
	unsigned int crc = this->crc32(0, nullptr, 0) & 0xFFFFFFFF;
	crc = this->crc32(crc, buffer, messageSize - 8) & 0xFFFFFFFF;

	if (crc != crc_sent)
	{
		result = "{\"msg\":\"crc error\"}";
		return messageSize;
	}

	unsigned char *cPayload = &buffer[PROTOCOL_31_HEADER_SIZE + sizeof(retcode)];
	int payloadSize = (int)(messageSize - PROTOCOL_31_HEADER_SIZE - sizeof(retcode) - MESSAGE_TRAILER_SIZE);

	result.append((const char *)cPayload, payloadSize + 1);

	return messageSize;
}


/* private */ int tuyaAPI31::encode_base64( const unsigned char *input_str, int input_size, unsigned char *output_str)
{
	// Character set of base64 encoding scheme
	char char_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	
	int index, no_of_bits = 0, padding = 0, val = 0, count = 0, temp;
	int i, j, k = 0;
	
	// Loop takes 3 characters at a time from
	// input_str and stores it in val
	for (i = 0; i < input_size; i += 3)
		{
			val = 0, count = 0, no_of_bits = 0;

			for (j = i; j < input_size && j <= i + 2; j++)
			{
				// binary data of input_str is stored in val
				val = val << 8;
				
				// (A + 0 = A) stores character in val
				val = val | input_str[j];
				
				// calculates how many time loop
				// ran if "MEN" -> 3 otherwise "ON" -> 2
				count++;
			
			}

			no_of_bits = count * 8;

			// calculates how many "=" to append after output_str.
			padding = no_of_bits % 3;

			// extracts all bits from val (6 at a time)
			// and find the value of each block
			while (no_of_bits != 0)
			{
				// retrieve the value of each block
				if (no_of_bits >= 6)
				{
					temp = no_of_bits - 6;
					
					// binary of 63 is (111111) f
					index = (val >> temp) & 63;
					no_of_bits -= 6;		
				}
				else
				{
					temp = 6 - no_of_bits;
					
					// append zeros to right if bits are less than 6
					index = (val << temp) & 63;
					no_of_bits = 0;
				}
				output_str[k++] = char_set[index];
			}
	}

	// padding is done here
	for (i = 1; i <= padding; i++)
	{
		output_str[k++] = '=';
	}

	output_str[k] = '\0';

	return k;
 }


/* private */ std::string tuyaAPI31::make_md5_digest(const std::string &str)
{
	unsigned char hash[16];
	md5_hash((unsigned char*)str.c_str(), str.size(), hash);

	std::stringstream ss;

	for(unsigned int i = 0; i < 16; i++){
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>( hash[i] );
	}
	return ss.str();
}


