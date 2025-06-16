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
	using ERROR_STATUS::error_status;

	struct HTTPClient : TCPClient {
		HTTPClient(): TCPClient() {}

		error_status fetch(http_request& request, http_response& response) {
			const int sockfd = this->connection_info.sockfd;
			error_status err;
			err = send_http_request(sockfd, request);
			if(err.code != ERROR_STATUS::SUCCESS.code) return err;
			err = recv_http_response(sockfd, response);
			if(err.code != ERROR_STATUS::SUCCESS.code) return err;
			return ERROR_STATUS::SUCCESS;
		}
	};
}

#endif
