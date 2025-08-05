/*
This was written with the help of the following guides:
https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages
*/

#ifndef F_SERVER_HTTP
#define F_SERVER_HTTP

#include <cstdio>
#include <cstring>
#include <netdb.h>
#include <string>
#include "./TCPServer.cpp"
#include "./http_message.cpp"
#include "./definitions/mime_types.cpp"
#include "src/definitions/headers.cpp"
#include "src/utils/time_util.cpp"

namespace HTTP {
	using std::string;
	using utils::time_util::timepoint_64_ns;

	// TODO - FIX MULTITHREADING HAZARD - multiple threads may read/write data in this struct at the same time!
	// NOTE ^ I've already seen multiple incorrect values of req_counter show up in logs.
	// ^ use get/set functions with mutexes/lock-guards for this. (read should use weak mutex, write should use strong mutex.)
	struct http_server_stats {
		// number of file-descriptors opened over lifetime of this server.
		int fd_counter = 0;
		// number of requests received.
		int req_counter = 0;
	};

	struct HTTPServer : TCP::TCPServer {
		http_server_stats stats;

		HTTPServer(const char* hostname, const char* portname): TCPServer(hostname, portname) {}

		void on_soft_error(HTTPConnection& connection, const int response_status, const ERROR_CODE err) {
			fprintf(stderr, "soft error during handle_connection(): %s\n", ERROR_MESSAGE.at(err).c_str());
			fprintf(stderr, "most recent errno: %s\n", strerror(errno));

			// attempt to notify client of server error.
			http_response response;
			response.protocol = HTTP_PROTOCOL_1_1;
			response.status_code = response_status;
			MessageBuffer head_buffer(MAX_HEAD_LENGTH);
			MessageBuffer body_buffer(0);
			ERROR_CODE notify_err = send_http_response(connection, head_buffer, body_buffer, response);
		}

		void on_hard_error(HTTPConnection& connection, const int response_status, const ERROR_CODE err) {
			fprintf(stderr, "HARD ERROR during handle_connection(): %s\n", ERROR_MESSAGE.at(err).c_str());
			fprintf(stderr, "most recent errno: %s\n", strerror(errno));

			// attempt to notify client of server error.
			http_response response;
			response.protocol = HTTP_PROTOCOL_1_1;
			response.status_code = response_status;
			MessageBuffer head_buffer(MAX_HEAD_LENGTH);
			MessageBuffer body_buffer(0);
			ERROR_CODE notify_err = send_http_response(connection, head_buffer, body_buffer, response);
		}

		virtual ERROR_CODE handle_request(const HTTPConnection& connection, const http_request& request, http_response& response, MessageBuffer& body_buffer) {
			string data = "test abc 123 :)";
			response.protocol = HTTP_PROTOCOL_1_1;
			response.status_code = 200;
			response.headers[HEADERS::content_type] = get_mime_type(".txt");
			response.headers[HEADERS::content_length] = int_to_string(data.length());
			body_buffer.append(data);
			return ERROR_CODE::SUCCESS;
		}

		void handle_connection(TCP::tcp_connection_struct tcp_connection) override {
			HTTPConnection http_connection(tcp_connection, MAX_HEAD_LENGTH, MAX_HEAD_LENGTH, 0);
			MessageBuffer& recv_buffer = http_connection.recv_buffer;
			MessageBuffer& head_buffer = http_connection.head_buffer;
			MessageBuffer& body_buffer = http_connection.body_buffer;
			int fd_counter = stats.fd_counter++;
			ERROR_CODE err;
			try {
				string ipstr = tcp_connection.get_address_string();
				printf("accepted HTTP connection | fd: %i, addr: %s\n", tcp_connection.sockfd, ipstr.c_str());

				while(true) {
					timepoint_64_ns t0;

					// get request.
					http_request request;
					size_t request_length;
					err = recv_http_request(http_connection, recv_buffer, request, request_length);
					if(err != ERROR_CODE::SUCCESS) { on_soft_error(http_connection, 400, err); break; }

					// generate response.
					t0 = timepoint_64_ns::now();
					http_response response;
					handle_request(http_connection, request, response, body_buffer);
					if(err != ERROR_CODE::SUCCESS) { on_soft_error(http_connection, 500, err); break; }
					timepoint_64_ns dt_handle = timepoint_64_ns::now().delta(t0);

					// send response.
					t0 = timepoint_64_ns::now();
					err = send_http_response(http_connection, head_buffer, body_buffer, response);
					if(err != ERROR_CODE::SUCCESS) { on_soft_error(http_connection, 500, err); break; }
					timepoint_64_ns dt_send = timepoint_64_ns::now().delta(t0);

					// push log entry.
					timepoint_64_ns t1 = timepoint_64_ns::now();
					printf("[%li] fdn=%i, reqn=%i, method=%s, status=%i, ip=%s, target=%s, reqlen=[%lu, %lu], reslen=[%lu, %lu], dt=[%li, %li]\n",
						timepoint_64_ns::now().value_ms(),
						fd_counter,
						stats.req_counter,
						request.method.c_str(),
						response.status_code,
						ipstr.c_str(),
						request.target.c_str(),
						request.head.length(),
						request.body.length(),
						head_buffer.length,
						body_buffer.length,
						dt_handle.value_us(),
						dt_send.value_us()
					);

					recv_cleanup(recv_buffer, request_length);
					send_cleanup(head_buffer, body_buffer);

					stats.req_counter++;
				}
			} catch (const std::exception& e) {
				fprintf(stderr, "%s\n", e.what());
				try {
					on_hard_error(http_connection, 500, err);
				} catch (const std::exception& e) {
					fprintf(stderr, "%s\n", e.what());
				}
			}
		}
	};
}

#endif
