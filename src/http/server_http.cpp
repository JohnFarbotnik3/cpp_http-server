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
#include <string_view>

using string = std::string;

const string	HTTP_HEADER_NEWLINE	= "\r\n";
const string	HTTP_HEADER_END		= "\r\n\r\n";
const int		HTTP_HEADER_MAXLEN	= 1024 * 10;// 10 KiB
const int		HTTP_REQUEST_MAXLEN	= 1024 * 1024 * 10;// 10 MiB

enum HTTP_STATUS {
	SUCCESS = 0,
	CLOSED_DURING_HEAD,
	CLOSED_DURING_BODY,
	RECV_ERR_DURING_HEAD,
	RECV_ERR_DURING_BODY,
	ERR_MAXLEN_HEAD,
	ERR_MAXLEN_BODY,
	MISSING_START_NEWLINE,
	MISSING_HEADER_NEWLINE,
	MISSING_HEADER_COLON,
};

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

http_request recv_http(int fd, int* status) {
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
				*status = HTTP_STATUS::CLOSED_DURING_HEAD;
				return request;
			}
			if(len == -1) {
				*status = HTTP_STATUS::RECV_ERR_DURING_HEAD;
				return request;
			}
			// append data to buffer.
			buffer.append(temp, len);
			// check if max length exceeded.
			if(buffer.length() > MAX_HEAD_LENGTH) {
				*status = HTTP_STATUS::ERR_MAXLEN_HEAD;
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
			request.method = to_lowercase(buffer.substr(a, b-a));
			// target.
			a = b + 1;
			b = buffer.find(" ", a);
			request.target = to_lowercase(buffer.substr(a, b-a));
			// protocol.
			a = b + 1;
			b = end;
			request.protocol = to_lowercase(buffer.substr(a, b-a));
		} else {
			*status = HTTP_STATUS::MISSING_START_NEWLINE;
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
				*status = HTTP_STATUS::MISSING_HEADER_NEWLINE;
				return request;
			}
			// check if end of headers reached.
			if(beg == end) break;
			// find header separator.
			int mid = buffer.find(":", beg);
			if(mid == string::npos) {
				*status = HTTP_STATUS::MISSING_HEADER_COLON;
				return request;
			}
			// add to header dictionary.
			const string key = buffer.substr(beg, mid-beg);
			const string val = buffer.substr(mid+1, end-(mid+1));
			request.headers[to_lowercase(key)] = val;
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
				*status = HTTP_STATUS::CLOSED_DURING_BODY;
				return request;
			}
			if(len == -1) {
				*status = HTTP_STATUS::RECV_ERR_DURING_BODY;
				return request;
			}
			// add data to buffer.
			buffer.append(temp, len);
			request.body_length += len;
		}
	}

	*status = HTTP_STATUS::SUCCESS;
	return request;
}

int send_http(int fd, void* msg, int len, int* status, int flags=0) {
	// TODO
}

// ============================================================
// server
// ------------------------------------------------------------

struct HTTPServer : TCPServer {
	HTTPServer(const char* hostname, const char* portname):
	TCPServer(hostname, portname) {}

	void handle_connection(accept_connection_struct connection_info) override {
		int fd = connection_info.sockfd;
		string ipstr =  get_address_string(connection_info.addr, connection_info.addrlen);
		printf("accepted HTTP connection\n");
		printf("\tsockfd: %i\n", fd);
		printf("\tipaddr: %s\n", ipstr.c_str());

		// TEST: print request to console.
		char buf[1024];
		int recv_length = recv(fd, buf, 1024, 0);
		printf("MESSAGE: {\n%s\n}\n", std::string_view(buf, buf+recv_length).data());

		int status;
		std::string msg = "test response. abc 123 :)";
		int send_len = send_all(fd, msg.data(), msg.size(), &status);
		if(status == 0) {
			printf("send - connection closed\n");
			return;
		}
		if(status <  0) {
			printf("send - error occurred: %i\n", errno);
			return;
		}
	}
};

// ============================================================
// main
// ------------------------------------------------------------

int main(const int argc, const char** argv) {
	if(argc <= 1) printf("missing arg[1]: portname (string)\n");
	if(argc <= 1) exit(1);
	const char* portname = argv[1];
	TCPServer server(NULL, "3490");
	server.start_listen();
}
