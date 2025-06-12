/*
This was written with the help of the following guides:
<Beej's networking guide (c)>
https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages

*/

#include "../tcp/server_tcp.cpp"
#include "./definitions/headers.cpp"
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
		const error_status CLOSED_DURING_HEAD		{ 1, "CLOSED_DURING_HEAD" };
		const error_status CLOSED_DURING_BODY		{ 2, "CLOSED_DURING_BODY" };
		const error_status RECV_ERR_DURING_HEAD		{ 3, "RECV_ERR_DURING_HEAD" };
		const error_status RECV_ERR_DURING_BODY		{ 4, "RECV_ERR_DURING_BODY" };
		const error_status ERR_MAXLEN_HEAD			{ 5, "ERR_MAXLEN_HEAD" };
		const error_status ERR_MAXLEN_BODY			{ 6, "ERR_MAXLEN_BODY" };
		const error_status MISSING_START_NEWLINE	{ 7, "MISSING_START_NEWLINE" };
		const error_status MISSING_HEADER_NEWLINE	{ 8, "MISSING_HEADER_NEWLINE" };
		const error_status MISSING_HEADER_COLON		{ 9, "MISSING_HEADER_COLON" };
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
		// content - NOTE: this points to an associated buffer.
		char*		content_beg;
		char*		content_end;
	};

	struct http_response {
		// start line.
		string		protocol;
		int			status_code;
		string		status_text;
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

	http_request recv_http(int fd, ERROR_STATUS::error_status& error) {
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
					error = ERROR_STATUS::CLOSED_DURING_HEAD;
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
					error = ERROR_STATUS::CLOSED_DURING_BODY;
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

	int send_http(int fd, void* msg, int len, int* status, int flags=0) {
		// TODO
		return 0;
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

			// receive request.
			ERROR_STATUS::error_status err;
			http_request request = recv_http(fd, err);

			if(err.code == ERROR_STATUS::SUCCESS.code) {
				// print parsed http data.
				std::vector<string> list;
				list.push_back(request.method);
				list.push_back(request.target);
				list.push_back(request.protocol);
				printf("START OF REQUEST\n");
				for(const string  str : list) printf("%s\n", str.c_str());
				printf("REQUEST HEADERS\n");
				for(const auto& [key,val] : request.headers) printf("%s: %s\n", key.c_str(), val.c_str());
				printf("REQUEST BUFFER\n");
				printf("%s\n", request.buffer.c_str());
				printf("END OF REQUEST\n");

				// send response.
				string msg = "hello world! abc 123 :)";
				int status;
				send_all(fd, msg.data(), msg.size(), &status, 0);
			} else {
				fprintf(stderr, "error during recv_http(): %s\n", err.message.c_str());
			}
		}
	};

}






