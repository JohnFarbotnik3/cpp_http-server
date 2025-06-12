/*
This was written with the help of the following guides:
<Beej's networking guide (c)>
https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages

*/

#include "./server_tcp.cpp"
#include <algorithm>
#include <map>
#include <string>
#include <string_view>

using string = std::string;

const string	HTTP_HEADER_NEWLINE	= "\r\n";
const string	HTTP_HEADER_END		= "\r\n\r\n";
const int		HTTP_HEADER_MAXLEN	= 1024 * 10;// 10 KiB
const int		HTTP_REQUEST_MAXLEN	= 1024 * 1024 * 10;// 10 MiB

enum HTTP_STATUS {
	CLOSED = 0,
	SUCCESS = 1,
	ERR_HEADER_READ,
	ERR_HEADER_MAXLEN,
	ERR_REQUEST_MAXLEN,
};

namespace HTTP_HEADERS {
	const string content_length = "content-length";
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
	int			status;
	string		message;
	// headers.
	header_dict	headers;
	// content - NOTE: this points to an associated buffer.
	char*		content_beg;
	char*		content_end;
};

http_request recv_http(int fd, int* status, int flags=0) {
	http_request request;
	string& buffer = request.buffer;

	// read until end of HTTP header section is found.
	{
		const int chunk_sz = 1024;
		while(buffer.length() < HTTP_HEADER_MAXLEN) {
			// read some more data.
			char temp[chunk_sz];
			int len = recv(fd, temp, chunk_sz, 0);
			// check if connection closed or errored during recv.
			if(len == 0) {
				*status = HTTP_STATUS::CLOSED;
				return request;
			}
			if(len == -1) {
				*status = HTTP_STATUS::ERR_HEADER_READ;
				return request;
			}
			// add data to buffer.
			buffer.append(temp, len);
			/*
			check if header end characters were found in new chunk of data.

			also check a few characters back in case part of the header-end
			string was read in last iteration.
			*/
			size_t end = buffer.length();
			size_t beg = std::max<size_t>(0, end - chunk_sz - HTTP_HEADER_END.length());
			size_t pos = buffer.find(HTTP_HEADER_END, beg);
			if(pos != std::string::npos) {
				request.head_length = pos;
				request.body_length = buffer.length() - request.head_length;
				break;
			}
		}
		if(buffer.length() >= HTTP_HEADER_MAXLEN) {
			*status = HTTP_STATUS::ERR_HEADER_MAXLEN;
			return request;
		}
	}

	// parse headers.
	// TODO - continue update from here. (buffer was turned into a string)
	{
		std::string_view header_str(buffer.data(), buffer.data() + head_length);
		std::string_view line;
		size_t line_pos = 0;
		size_t line_end;
		// parse first line.
		{
			line_end = header_str.find(HTTP_HEADER_NEWLINE, line_pos);
			line = header_str.substr(line_pos, line_end-line_pos);
			std::vector<string> list = split(string(line), " ");
			request.method		= to_lowercase(list[0]);
			request.target		= to_lowercase(list[1]);// TODO: are URLs case-insensitive?
			request.protocol	= to_lowercase(list[2]);
		}
		// parse following lines.
		while(line_pos < header_str.size()) {
			line_end = header_str.find(HTTP_HEADER_NEWLINE, line_pos);
			line = header_str.substr(line_pos, line_end-line_pos);
			// get header key-value pair.
			std::array<string, 2> list = split_pair(string(line), ":");
			string key = to_lowercase(list[0]);// TODO: should I trim both sides?
			string val = to_lowercase(list[1]);
			request.headers[key] = val;
			// advance to next line.
			line_pos = line_end + strlen(HTTP_HEADER_NEWLINE);
		}
	}

	// read rest of message (if content length was given).
	if(request.headers.contains(HTTP_HEADERS::content_length)) {
		// get content length.
		const string str = request.headers[HTTP_HEADERS::content_length];
		int content_length;
		std::from_chars(str.data(), str.data()+str.size(), content_length);
		// some of the content may have already been read when getting header.
		int x = request.body_length;
		request.body_length = content_length;
		// read content.
		const int chunk_sz = 1024 * 16;
		while(x < content_length) {
			char temp[chunk_sz];
			int len = recv(fd, temp, chunk_sz, 0);
			// check if connection closed or errored during recv.
			if(len == 0) {
				*status = HTTP_STATUS::CLOSED;
				return request;
			}
			if(len == -1) {
				*status = HTTP_STATUS::ERR_HEADER_READ;
				return request;
			}
			// add data to buffer.
			buffer.append(temp, len);
			x += len;
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
