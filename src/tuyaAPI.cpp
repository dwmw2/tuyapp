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

#include "tuyaAPI.hpp"
#include "tuyaAPI31.hpp"
#include "tuyaAPI33.hpp"
#include "tuyaAPI34.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <chrono>

#ifndef SOCKET_TIMEOUT_SECS
#define SOCKET_TIMEOUT_SECS 5
#endif

tuyaAPI::tuyaAPI() : m_sockfd(0)
{
}

tuyaAPI::~tuyaAPI()
{
	if (m_sockfd)
		disconnect();
}

tuyaAPI* tuyaAPI::create(const std::string &version)
{
	if (version == "3.1")
		return new tuyaAPI31();
	if (version == "3.3")
		return new tuyaAPI33();
	if (version == "3.4")
		return new tuyaAPI34();
	return nullptr;
}

bool tuyaAPI::ResolveHost(const std::string &hostname, struct sockaddr_in& serv_addr)
{
	if ((hostname[0] ^ 0x30) < 10)
	{
		serv_addr.sin_family = AF_INET;
		if (inet_pton(AF_INET, hostname.c_str(), &serv_addr.sin_addr) == 1)
			return true;
	}
	if (hostname.find(':') != std::string::npos)
	{
		serv_addr.sin_family = AF_INET6;
		if (inet_pton(AF_INET6, hostname.c_str(), &serv_addr.sin_addr) == 1)
			return true;
	}
	struct addrinfo *addr;
	if (getaddrinfo(hostname.c_str(), "0", nullptr, &addr) == 0)
	{
		struct sockaddr_in *saddr = (((struct sockaddr_in *)addr->ai_addr));
		memcpy(&serv_addr, saddr, sizeof(sockaddr_in));
		return true;
	}

	return false;
}

bool tuyaAPI::ConnectToDevice(const std::string &hostname, const int portnumber, uint8_t retries)
{
	struct sockaddr_in serv_addr;
	bzero((char*)&serv_addr, sizeof(serv_addr));
	if (!ResolveHost(hostname, serv_addr))
		return false;

	m_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (m_sockfd < 0)
		return false;

	serv_addr.sin_port = htons(portnumber);

	struct timeval timeout;
	timeout.tv_sec = SOCKET_TIMEOUT_SECS;
	timeout.tv_usec = 0;
	setsockopt(m_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);

	for (uint8_t i = 0; i < retries; i++)
	{
		if (connect(m_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0)
			return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	}
	return false;
}

int tuyaAPI::send(unsigned char* buffer, const unsigned int size)
{
	return write(m_sockfd, buffer, size);
}

int tuyaAPI::receive(unsigned char* buffer, const unsigned int maxsize, const unsigned int minsize)
{
	unsigned int numbytes = (unsigned int)read(m_sockfd, buffer, maxsize);
	
	// Handle empty ack responses - device sends ack first, then actual data
	// Empty ack is typically 40 bytes (0x28) with cmd=13 (TUYA_CONTROL_NEW)
	// Retry up to 5 times if we get a small response
	int retries = 0;
	while (numbytes > 0 && numbytes <= minsize && retries < 5)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		numbytes = (unsigned int)read(m_sockfd, buffer, maxsize);
		retries++;
	}
	return (int)numbytes;
}

void tuyaAPI::disconnect()
{
	close(m_sockfd);
	m_sockfd = 0;
}
