/*
This was written with the help of the following guides:
<Beej's networking guide (c)>
https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages

*/

#include "../tcp/server_tcp.cpp"
#include "./definitions/headers.cpp"
#include "./definitions/status_codes.cpp"
#include "./definitions/content_types.cpp"
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>

namespace HTTP {
	using string = std::string;

	namespace ERROR_STATUS {
		struct error_status {
			int		code;
			string	message;
		};

		const error_status SUCCESS					{ 0, "" };

		const error_status RECV_CLOSED_DURING_HEAD	{ 1, "RECV_CLOSED_DURING_HEAD" };
		const error_status RECV_CLOSED_DURING_BODY	{ 2, "RECV_CLOSED_DURING_BODY" };
		const error_status RECV_ERR_DURING_HEAD		{ 3, "RECV_ERR_DURING_HEAD" };
		const error_status RECV_ERR_DURING_BODY		{ 4, "RECV_ERR_DURING_BODY" };
		const error_status ERR_MAXLEN_HEAD			{ 5, "ERR_MAXLEN_HEAD" };
		const error_status ERR_MAXLEN_BODY			{ 6, "ERR_MAXLEN_BODY" };
		const error_status MISSING_START_NEWLINE	{ 7, "MISSING_START_NEWLINE" };
		const error_status MISSING_HEADER_NEWLINE	{ 8, "MISSING_HEADER_NEWLINE" };
		const error_status MISSING_HEADER_COLON		{ 9, "MISSING_HEADER_COLON" };

		const error_status SEND_CLOSED_DURING_HEAD	{ 1, "SEND_CLOSED_DURING_HEAD" };
		const error_status SEND_CLOSED_DURING_BODY	{ 2, "SEND_CLOSED_DURING_BODY" };
		const error_status SEND_ERR_DURING_HEAD		{ 3, "SEND_ERR_DURING_HEAD" };
		const error_status SEND_ERR_DURING_BODY		{ 4, "SEND_ERR_DURING_BODY" };

	}

	using header_dict = std::map<string, string>;

	struct http_request {
		string		buffer;
		size_t		head_length	= 0;// length of header section.
		size_t		body_length	= 0;// length of content section (if any).
		// start line.
		string		method;
		string		target;
		string		protocol;
		// headers.
		header_dict	headers;
		// content.
		std::string_view content() const {
			return std::string_view(buffer.data() + head_length, body_length);
		}
	};

	struct http_response {
		string		buffer_head;
		string		buffer_body;
		// start line.
		string						protocol;
		HTTP::STATUS_CODES::status	status;
		// headers.
		header_dict	headers;
		// content - NOTE: this points to an associated buffer.
		char*		content_beg;
		char*		content_end;
	};

	const string	HTTP_HEADER_NEWLINE	= "\r\n";
	const string	HTTP_HEADER_END		= "\r\n\r\n";
	const int		HTTP_HEADER_MAXLEN	= 1024 * 10;// 10 KiB
	const int		HTTP_REQUEST_MAXLEN	= 1024 * 1024 * 10;// 10 MiB

	http_request
	recv_http(int fd, ERROR_STATUS::error_status& error) {
		http_request request;
		string& buffer = request.buffer;

		// receive header section.
		{
			const int MAX_HEAD_LENGTH = 1024 * 10;// 10 KiB
			// read until end of header-section is found.
			int scan_start = 0;
			while(true) {
				// read some data.
				const int chunk_sz = 512;
				char temp[chunk_sz];
				int len = recv(fd, temp, chunk_sz, 0);
				// check if connection closed or errored during recv.
				if(len == 0) {
					error = ERROR_STATUS::RECV_CLOSED_DURING_HEAD;
					return request;
				}
				if(len == -1) {
					error = ERROR_STATUS::RECV_ERR_DURING_HEAD;
					return request;
				}
				// append data to buffer.
				buffer.append(temp, len);
				// check if max length exceeded.
				if(buffer.length() > MAX_HEAD_LENGTH) {
					error = ERROR_STATUS::ERR_MAXLEN_HEAD;
					return request;
				}
				// check for end of headers.
				int pos = buffer.find(HTTP_HEADER_END, scan_start);
				if(pos != string::npos) {
					request.head_length = pos + HTTP_HEADER_END.length();
					break;
				} else {
					// move scan start to (near) end of buffer, leaving some padding in case
					// only part of end-of-header was received during this iteration.
					scan_start = buffer.length() - HTTP_HEADER_END.length();
				}
			}
		}

		// parse start line.
		{
			int end = buffer.find(HTTP_HEADER_NEWLINE);
			if(end != string::npos) {
				int a=0, b=0;
				// method.
				b = buffer.find(" ", a);
				request.method = to_lowercase_ascii(buffer.substr(a, b-a));
				// target.
				a = b + 1;
				b = buffer.find(" ", a);
				request.target = to_lowercase_ascii(buffer.substr(a, b-a));
				// protocol.
				a = b + 1;
				b = end;
				request.protocol = to_lowercase_ascii(buffer.substr(a, b-a));
			} else {
				error = ERROR_STATUS::MISSING_START_NEWLINE;
				return request;
			}
		}

		// parse header lines.
		{
			int beg = buffer.find(HTTP_HEADER_NEWLINE) + HTTP_HEADER_NEWLINE.length();
			while(true) {
				// find end of header line.
				int end = buffer.find(HTTP_HEADER_NEWLINE, beg);
				if(end == string::npos) {
					error = ERROR_STATUS::MISSING_HEADER_NEWLINE;
					return request;
				}
				// check if end of headers reached.
				if(beg == end) break;
				// find header separator.
				int mid = buffer.find(":", beg);
				if(mid == string::npos) {
					error = ERROR_STATUS::MISSING_HEADER_COLON;
					return request;
				}
				// add to header dictionary.
				const string key = buffer.substr(beg, mid-beg);
				const string val = buffer.substr(mid+1, end-(mid+1));
				request.headers[to_lowercase_ascii(key)] = trim_leading(val);
				// advance to the next line.
				beg = end + HTTP_HEADER_NEWLINE.length();
			}
		}

		// receive content section (if any).
		if(request.headers.contains(HTTP::HEADERS::content_length)) {
			// get content length.
			const string str = request.headers.at(HTTP::HEADERS::content_length);
			int content_length;
			std::from_chars(str.data(), str.data()+str.size(), content_length);
			// some of the content may have already been read into buffer when receiving headers.
			request.body_length = buffer.length() - request.head_length;
			// read content.
			const int chunk_sz = 1024 * 16;
			while(request.body_length < content_length) {
				char temp[chunk_sz];
				int len = recv(fd, temp, chunk_sz, 0);
				// check if connection closed or errored during read.
				if(len == 0) {
					error = ERROR_STATUS::RECV_CLOSED_DURING_BODY;
					return request;
				}
				if(len == -1) {
					error = ERROR_STATUS::RECV_ERR_DURING_BODY;
					return request;
				}
				// add data to buffer.
				buffer.append(temp, len);
				request.body_length += len;
			}
		}

		error = ERROR_STATUS::SUCCESS;
		return request;
	}

	void
	send_http(int fd, ERROR_STATUS::error_status& error, http_response& response) {
		string& buffer_head = response.buffer_head;
		string& buffer_body = response.buffer_body;

		// add "content-length".
		// NOTE: "content-type" header will still have to be set externally.
		if(buffer_body.length() > 0) {
			char temp[256];
			snprintf(temp, 256, "%lu", buffer_body.length());
			response.headers[HTTP::HEADERS::content_length] = string(temp);
		}

		// build start line.
		{
			char temp[256];
			snprintf(temp, 256, "%s %i %s", response.protocol.c_str(), response.status.code, response.status.text.c_str());
			buffer_head.append(string(temp));
			buffer_head.append(HTTP_HEADER_NEWLINE);
		}

		// build header lines.
		{
			for(const auto& [key,val] : response.headers) {
				buffer_head.append(key);
				buffer_head.append(": ");
				buffer_head.append(val);
				buffer_head.append(HTTP_HEADER_NEWLINE);
			}
		}

		// send headers.
		{
			int x = 0;
			while(x < buffer_head.length()) {
				// write some data.
				int len = send(fd, buffer_head.data()+x, buffer_head.length()-x, 0);
				// check if connection closed or errored.
				if(len == 0) {
					error = ERROR_STATUS::SEND_CLOSED_DURING_HEAD;
					return;
				}
				if(len == -1) {
					error = ERROR_STATUS::SEND_ERR_DURING_HEAD;
					return;
				}
				// advance.
				x += len;
			}
		}

		// send content (if any).
		if(buffer_body.length() > 0) {
			int x = 0;
			while(x < buffer_body.length()) {
				// write some data.
				int len = send(fd, buffer_body.data()+x, buffer_body.length()-x, 0);
				// check if connection closed or errored.
				if(len == 0) {
					error = ERROR_STATUS::SEND_CLOSED_DURING_BODY;
					return;
				}
				if(len == -1) {
					error = ERROR_STATUS::SEND_ERR_DURING_BODY;
					return;
				}
				// advance.
				x += len;
			}
		}

		// send 0 bytes to convince browser to behave normally.
		error = ERROR_STATUS::SUCCESS;
	}

	struct HTTPServer : TCPServer {
		HTTPServer(const char* hostname, const char* portname):
		TCPServer(hostname, portname) {}

		void handle_connection(accept_connection_struct connection_info) override {
			int fd = connection_info.sockfd;
			string ipstr =  get_address_string(connection_info.addr, connection_info.addrlen);
			printf("accepted HTTP connection\n");
			printf("\tsockfd: %i\n", fd);
			printf("\tipaddr: %s\n", ipstr.c_str());

			// perform request-response cycle until user closes socket.
			// TODO: automatically close after N seconds of no traffic, or after T total seconds.
			// TODO: figure out why putting req-res cycle in a while loop doesn't work.

			// get request.
			ERROR_STATUS::error_status err;
			http_request request = recv_http(fd, err);
			if(err.code != ERROR_STATUS::SUCCESS.code) {
				fprintf(stderr, "error during recv_http(): %s\n", err.message.c_str());
				fprintf(stderr, "errno: %i\n", errno);
				return;//break;
			}
			/*
			printf("request head length: %lu\n", request.head_length);
			printf("request body length: %lu\n", request.body_length);
			*/

			// send response.
			http_response response = this->generate_response(request);
			send_http(fd, err, response);
			if(err.code != ERROR_STATUS::SUCCESS.code) {
				fprintf(stderr, "error during send_http(): %s\n", err.message.c_str());
				fprintf(stderr, "errno: %i\n", errno);
				return;//break;
			}
			/*
			printf("response head length: %lu\n", response.buffer_head.length());
			printf("response body length: %lu\n", response.buffer_body.length());
			printf("response head:\n%s\n", response.buffer_head.c_str());
			printf("response body:\n%s\n", response.buffer_body.c_str());
			*/
		}

		virtual http_response generate_response(const http_request& request) {
			http_response response;
			string& content = response.buffer_body;

			// add extra headers.
			header_dict extra_headers;
			{
				extra_headers[HTTP::HEADERS::content_type] = HTTP::CONTENT_TYPES::text;
			}
			{
				// milliseconds since epoch.
				char temp[256];
				const auto now = std::chrono::duration_cast<std::chrono::milliseconds, int64_t>(std::chrono::system_clock::now().time_since_epoch());
				const int64_t now_i64 = now.count();
				int len = snprintf(temp, 256, "%li", now_i64);
				extra_headers[HTTP::HEADERS::date] = string(temp, len);
			}

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
				int len = snprintf(temp, 1024, "%s: %s\n", key.c_str(), val.c_str());
				list.push_back(string(temp, len));
			}
			list.push_back("==============================");
			list.push_back("extra headers");
			list.push_back("------------------------------");
			for(const auto& [key,val] : extra_headers) {
				char temp[1024];
				int len = snprintf(temp, 1024, "%s: %s\n", key.c_str(), val.c_str());
				list.push_back(string(temp, len));
			}
			list.push_back("==============================");
			list.push_back("content");
			list.push_back("------------------------------");
			list.push_back(string(request.content()));
			list.push_back("==============================");
			list.push_back("EOF");
			list.push_back("------------------------------");
			for(const string str : list) {
				content.append(str);
				content.append("\n");
			}

			// build response.
			response.protocol = request.protocol;
			response.status = HTTP::STATUS_CODES::s200;

			return response;
		}
	};
}






