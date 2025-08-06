/*
 * This was written with the help of the following guides:
 * https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages
 */

#ifndef F_HTTPClient
#define F_HTTPClient

#include <string>
#include "./TCPClient.cpp"
#include "./http_message.cpp"

namespace HTTP {
	using string = std::string;

	struct HTTPClient : TCP::TCPClient {
		HTTPClient(): TCPClient() {}

		ERROR_CODE fetch(HTTPConnection& connection, MessageBuffer& send_buffer, MessageBuffer& recv_buffer, http_response& response, size_t& response_length) {
			const int sockfd = this->connection_info.sockfd;
			ERROR_CODE err;

			err = send_http_request(connection, send_buffer);
			if(err != ERROR_CODE::SUCCESS) return err;

			err = recv_http_response(connection, recv_buffer, response, response_length);
			if(err != ERROR_CODE::SUCCESS) return err;

			return ERROR_CODE::SUCCESS;
		}
	};
}

#endif
