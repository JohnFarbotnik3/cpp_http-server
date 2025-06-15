/*
This was written with the help of the following guides:
<Beej's networking guide (c)>
https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages
*/

#ifndef F_SERVER_HTTP
#define F_SERVER_HTTP

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include "./TCPServer.cpp"
#include "./http_structs.cpp"
#include "./http_message.cpp"
#include "./definitions/mime_types.cpp"

namespace HTTP {
	using string = std::string;

	// ============================================================
	// send + receive
	// ------------------------------------------------------------

	// ============================================================
	// server
	// ------------------------------------------------------------

	struct HTTPServer : TCPServer {
		HTTPServer(const char* hostname, const char* portname):
		TCPServer(hostname, portname) {}

		void handle_connection(accept_connection_struct connection_info) override {
			int fd = connection_info.sockfd;
			try {
				string ipstr =  get_address_string(connection_info.addr, connection_info.addrlen);
				printf("accepted HTTP connection\n");
				printf("\tsockfd: %i\n", fd);
				printf("\tipaddr: %s\n", ipstr.c_str());

				// perform request-response cycle until user closes socket.
				// TODO: automatically close after N seconds of no traffic, or after T total seconds.

				while(true) {
					ERROR_STATUS::error_status err;

					// get request.
					http_request request;
					err = recv_http_request(fd, request);
					if(err.code != ERROR_STATUS::SUCCESS.code) {
						fprintf(stderr, "error during recv_http(): %s\n", err.message.c_str());
						fprintf(stderr, "errno: %i\n", errno);
						//return;
						break;
					}
					///*
					printf("request head length: %lu\n", request.head.length());
					printf("request body length: %lu\n", request.body.length());
					//*/

					// generate response.
					http_response response = this->handle_request(request);
					// re-use socket for additional messages.
					//response.headers[HTTP::HEADERS::connection] = "keep-alive";

					// send response.
					err = send_http_response(fd, response);
					if(err.code != ERROR_STATUS::SUCCESS.code) {
						fprintf(stderr, "error during send_http(): %s\n", err.message.c_str());
						fprintf(stderr, "errno: %i\n", errno);
						//return;
						break;
					}
					///*
					printf("response head length: %lu\n", response.head.length());
					printf("response body length: %lu\n", response.body.length());
					printf("response head:\n%s\n", response.head.c_str());
					//printf("response body:\n%s\n", response.buffer_body.c_str());
					//*/
				}
			} catch (const std::exception& e) {
				fprintf(stderr, "%s\n", e.what());
				try {
					// attempt to notify client of server error.
					http_response response;
					response.protocol = HTTP_PROTOCOL_1_1;
					response.status_code = 500;
					ERROR_STATUS::error_status err = send_http_response(fd, response);
				} catch (const std::exception& e) {
					fprintf(stderr, "%s\n", e.what());
				}
			}
		}

		virtual http_response handle_request(const http_request& request) {
			http_response response;
			string& content = response.body;

			// build content.
			std::vector<string> list;
			list.push_back("==============================");
			list.push_back("start line");
			list.push_back("------------------------------");
			list.push_back(request.method);
			list.push_back(request.target);
			list.push_back(request.protocol);
			list.push_back("==============================");
			list.push_back("request headers");
			list.push_back("------------------------------");
			for(const auto& [key,val] : request.headers) {
				char temp[1024];
				int len = snprintf(temp, 1024, "%s: %s", key.c_str(), val.c_str());
				list.push_back(string(temp, len));
			}
			list.push_back("==============================");
			list.push_back("extra headers (not present in response)");
			list.push_back("------------------------------");
			header_dict extra_headers;
			{
				// milliseconds since epoch.
				char temp[256];
				const auto now = std::chrono::duration_cast<std::chrono::milliseconds, int64_t>(std::chrono::system_clock::now().time_since_epoch());
				const int64_t now_i64 = now.count();
				int len = snprintf(temp, 256, "%li", now_i64);
				extra_headers[HTTP::HEADERS::date] = string(temp, len);
			}
			for(const auto& [key,val] : extra_headers) {
				char temp[1024];
				int len = snprintf(temp, 1024, "%s: %s", key.c_str(), val.c_str());
				list.push_back(string(temp, len));
			}
			list.push_back("==============================");
			list.push_back("content");
			list.push_back("------------------------------");
			list.push_back(request.body);
			for(const string str : list) {
				content.append(str);
				content.append("\n");
			}
			content.append("EOF");

			// return response.
			response.status_code = 200;
			response.headers[HEADERS::content_type] = get_mime_type("txt");
			response.headers[HEADERS::content_length] = int_to_string(response.body.length());
			return response;
		}
	};
}

#endif
