/*
 * This was written with the help of the following guides:
 * https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages
 */

#ifndef F_HTTPClient
#define F_HTTPClient

#include <string>
#include "./TCPServer.cpp"
#include "./http_structs.cpp"
#include "./http_message.cpp"

namespace HTTP {
	using string = std::string;

	struct HTTPClient : TCPClient {
		HTTPClient(): TCPClient() {}

		ERROR_CODE fetch(http_request& request, http_response& response) {
			const int sockfd = this->connection_info.sockfd;
			ERROR_CODE err;

			err = send_http_request(sockfd, request);
			if(err != ERROR_CODE::SUCCESS) return err;

			http_buffer buffer(1024);
			err = recv_http_response(sockfd, response, buffer);
			if(err != ERROR_CODE::SUCCESS) return err;

			return ERROR_CODE::SUCCESS;
		}
	};
}

#endif
