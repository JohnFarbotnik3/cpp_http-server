/*
This was written with the help of the following guides:
https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages
*/

#ifndef F_SERVER_HTTP
#define F_SERVER_HTTP

#include <cstdio>
#include <netdb.h>
#include <string>
#include "./TCPServer.cpp"
#include "./http_structs.cpp"
#include "./http_message.cpp"
#include "./definitions/mime_types.cpp"

namespace HTTP {
	using std::string;

	struct HTTPServer : TCPServer {
		HTTPServer(const char* hostname, const char* portname): TCPServer(hostname, portname) {}

		void handle_connection(accept_connection_struct connection) override {
			int fd = connection.sockfd;
			try {
				string ipstr =  get_address_string(connection.addr, connection.addrlen);
				printf("accepted HTTP connection | fd: %i, addr: %s\n", fd, ipstr.c_str());

				while(true) {
					ERROR_CODE err;

					// get request.
					http_request request;
					err = recv_http_request(fd, request);
					if(err != ERROR_CODE::SUCCESS) {
						fprintf(stderr, "error during recv_http_request(): %s\n", ERROR_MESSAGE.at(err).c_str());
						fprintf(stderr, "errno: %s\n", strerror(errno));
						break;
					}

					// generate response.
					http_response response;
					err = handle_request(connection, request, response);

					// send response.
					err = send_http_response(fd, response);
					if(err != ERROR_CODE::SUCCESS) {
						fprintf(stderr, "error during send_http_response(): %s\n", ERROR_MESSAGE.at(err).c_str());
						fprintf(stderr, "errno: %s\n", strerror(errno));
						break;
					}
				}
			} catch (const std::exception& e) {
				fprintf(stderr, "%s\n", e.what());
				try {
					// attempt to notify client of server error.
					http_response response;
					response.protocol = HTTP_PROTOCOL_1_1;
					response.status_code = 500;
					ERROR_CODE err = send_http_response(fd, response);
				} catch (const std::exception& e) {
					fprintf(stderr, "%s\n", e.what());
				}
			}
		}

		virtual ERROR_CODE handle_request(const accept_connection_struct& connection, http_request& request, http_response& response) {
			response.protocol = HTTP_PROTOCOL_1_1;
			response.status_code = 200;
			response.body = "test abc 123 :)";
			response.headers[HEADERS::content_type] = MIME_TYPES.at("txt");
			response.headers[HEADERS::content_length] = int_to_string(response.body.length());
			ERROR_CODE err = send_http_response(connection.sockfd, response);
			return err;
		}
	};
}

#endif
