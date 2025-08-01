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
#include "src/utils/time_util.cpp"

namespace HTTP {
	using std::string;
	using utils::time_util::timepoint_64_ns;

	// TODO - FIX MULTITHREADING HAZARD - multiple threads may read/write data in this struct at the same time!
	// NOTE ^ I've already seen multiple incorrect values of req_counter show up in logs.
	struct http_server_stats {
		// number of file-descriptors opened over lifetime of this server.
		int fd_counter = 0;
		// number of requests received.
		int req_counter = 0;
	};

	struct HTTPServer : TCPServer {
		http_server_stats stats;

		HTTPServer(const char* hostname, const char* portname): TCPServer(hostname, portname) {}

		void handle_connection(accept_connection_struct connection) override {
			int fd = connection.sockfd;
			int fd_counter = stats.fd_counter++;
			try {
				string ipstr =  get_address_string(connection.addr, connection.addrlen);
				printf("accepted HTTP connection | fd: %i, addr: %s\n", fd, ipstr.c_str());

				HeadBuffer head_buffer;
				while(true) {
					timepoint_64_ns t0;

					// get request.
					http_request request;
					timepoint_64_ns dt_recv_wait;
					timepoint_64_ns dt_recv_work;
					ERROR_CODE err = recv_http_request(fd, request, head_buffer, dt_recv_wait, dt_recv_work);
					if(err != ERROR_CODE::SUCCESS) {
						fprintf(stderr, "error during recv_http_request(): %s\n", ERROR_MESSAGE.at(err).c_str());
						fprintf(stderr, "errno: %s\n", strerror(errno));
						break;
					}

					// generate response.
					t0 = timepoint_64_ns::now();
					http_response response = handle_request(connection, request);
					timepoint_64_ns dt_handle = timepoint_64_ns::now().delta(t0);

					// send response.
					t0 = timepoint_64_ns::now();
					err = send_http_response(fd, response);
					timepoint_64_ns dt_send = timepoint_64_ns::now().delta(t0);
					if(err != ERROR_CODE::SUCCESS) {
						fprintf(stderr, "error during send_http_response(): %s\n", ERROR_MESSAGE.at(err).c_str());
						fprintf(stderr, "errno: %s\n", strerror(errno));
						break;
					}

					// push log entry.
					timepoint_64_ns t1 = timepoint_64_ns::now();
					printf("[%li] fdn=%i, reqn=%i, method=%s, status=%i, ip=%s, target=%s, reqlen=[%lu, %lu], reslen=[%lu, %lu], dt=[%li, %li, %li]\n",
						timepoint_64_ns::now().value_ms(),
						fd_counter,
						stats.req_counter,
						request.method.c_str(),
						response.status_code,
						ipstr.c_str(),
						request.target.c_str(),
						request.head.length(),
						request.body.length(),
						response.head.length(),
						response.body.length(),
						dt_recv_work.value_us(),
						dt_handle.value_us(),
						dt_send.value_us()
					);
					stats.req_counter++;
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

		virtual http_response handle_request(const accept_connection_struct& connection, const http_request& request) {
			http_response response;
			response.protocol = HTTP_PROTOCOL_1_1;
			response.status_code = 200;
			response.body = "test abc 123 :)";
			response.headers[HEADERS::content_type] = get_mime_type(".txt");
			response.headers[HEADERS::content_length] = int_to_string(response.body.length());
			ERROR_CODE err = send_http_response(connection.sockfd, response);
			return response;
		}
	};
}

#endif
