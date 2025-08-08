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
	using utils::time_util::time64_ns;

	struct HTTPServer : TCP::TCPServer {
		HTTPServer(const string hostname, const string portname): TCPServer(hostname, portname) {}

		void on_soft_error(HTTPConnection& connection, const int status_code, const ERROR_CODE err) {
			fprintf(stderr, "soft error during handle_connection(): %s\n", ERROR_MESSAGE.at(err).c_str());
			fprintf(stderr, "most recent errno: %s\n", strerror(errno));

			// attempt to notify client of server error.
			http_response response;
			response.protocol = HTTP_PROTOCOL_1_1;
			response.status_code = status_code;
			MessageBuffer headbuf(MAX_HEAD_LENGTH);
			MessageBuffer bodybuf(0);
			ERROR_CODE notify_err = send_http_response(connection, response, headbuf, bodybuf);
		}

		void on_hard_error(HTTPConnection& connection, const int status_code, const ERROR_CODE err) {
			fprintf(stderr, "HARD ERROR during handle_connection(): %s\n", ERROR_MESSAGE.at(err).c_str());
			fprintf(stderr, "most recent errno: %s\n", strerror(errno));

			// attempt to notify client of server error.
			http_response response;
			response.protocol = HTTP_PROTOCOL_1_1;
			response.status_code = status_code;
			MessageBuffer headbuf(MAX_HEAD_LENGTH);
			MessageBuffer bodybuf(0);
			ERROR_CODE notify_err = send_http_response(connection, response, headbuf, bodybuf);
		}

		virtual http_response handle_request(const http_request& request, MessageBuffer& body_buffer) {
			http_response response;
			int status_code = 200;
			string data = "test abc 123 :)";
			response.headers[HEADERS::content_type] = get_mime_type(".txt");
			response.headers[HEADERS::content_length] = int_to_string(data.length());
			body_buffer.append(data);
			return response;
		}

		void handle_connection(TCP::TCPConnection connection) override {
			HTTPConnection http_connection(connection, MAX_HEAD_LENGTH, MAX_HEAD_LENGTH, 0);
			MessageBuffer& recvbuf = http_connection.recv_buffer;
			MessageBuffer& headbuf = http_connection.head_buffer;
			MessageBuffer& bodybuf = http_connection.body_buffer;
			ERROR_CODE err;
			try {
				string ipstr = connection.get_address_string();
				printf("accepted HTTP connection | fd: %i, addr: %s\n", connection.socket.fd, ipstr.c_str());

				while(true) {
					time64_ns t0;

					// get request.
					http_request request;
					size_t request_length;
					http_connection.on_recv_starting();
					err = recv_http_request(http_connection, recvbuf, request, request_length);
					http_connection.on_recv_finished();
					if(err != ERROR_CODE::SUCCESS) { on_soft_error(http_connection, 400, err); break; }

					// generate response.
					t0 = time64_ns::now();
					http_response response = handle_request(request, bodybuf);
					if(err != ERROR_CODE::SUCCESS) { on_soft_error(http_connection, 500, err); break; }
					time64_ns dt_handle = time64_ns::now() - t0;

					// send response.
					http_connection.on_send_starting();
					err = send_http_response(http_connection, response, headbuf, bodybuf);
					http_connection.on_send_finished();
					if(err != ERROR_CODE::SUCCESS) { on_soft_error(http_connection, 500, err); break; }
					time64_ns dt_send = http_connection.send_t1 - http_connection.send_t0;

					// push log entry.
					printf("[%li] fd=%i, method=%s, status=%i, ip=%s, path=%s%s, reqlen=[%lu, %lu], reslen=[%lu, %lu], dt=[%li, %li]\n",
						time64_ns::now().value_ms(),
						connection.socket.fd,
						request.method.c_str(),
						response.status_code,
						ipstr.c_str(),
						request.path.c_str(),
						request.query.c_str(),
						request.head.length(),
						request.body.length(),
						headbuf.length,
						bodybuf.length,
						dt_handle.value_us(),
						dt_send.value_us()
					);

					recv_cleanup(recvbuf, request_length);
					send_cleanup(headbuf, bodybuf);
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
