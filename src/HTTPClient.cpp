/*
 * This was written with the help of the following guides:
 * https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages
 */

#ifndef F_HTTPClient
#define F_HTTPClient

#include <string>
#include "./TCPServer.cpp"
#include "./http_message.cpp"

namespace HTTP {
	using string = std::string;

	struct HTTPClient : TCPClient {
		HTTPClient(): TCPClient() {}

		ERROR_CODE fetch(http_message& request, http_message& response, HeadBuffer& head_buffer) {
			const int sockfd = this->connection_info.sockfd;
			ERROR_CODE err;

			err = send_http_message(sockfd, request, MESSAGE_TYPE::REQUEST);
			if(err != ERROR_CODE::SUCCESS) return err;

			err = recv_http_message(sockfd, response, MESSAGE_TYPE::RESPONSE, head_buffer);
			if(err != ERROR_CODE::SUCCESS) return err;

			return ERROR_CODE::SUCCESS;
		}
	};
}

#endif
