/*
This was written with the help of the following guides:
<Beej's networking guide (c)>
https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages

*/

#include "./socket_types.cpp"
#include "./socket_helpers.cpp"
#include "./serialization.cpp"
#include "./string_helpers.cpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>

using string = std::string;

// ============================================================
// helpers
// ------------------------------------------------------------

string get_address_string(sockaddr_storage& addr, socklen_t& addrlen) {
	char buf[INET6_ADDRSTRLEN];
	inet_ntop(addr.ss_family, &addr, buf, sizeof(buf));
	return string(buf);
}

// ============================================================
// listen for and accept TCP connections
// ------------------------------------------------------------

static const int NONE_SOCKET_FD = -1;

struct TCPServer {

	const char*	hostname;
	const char* portname;
	int			listenfd;
	int			connection_counter;

	TCPServer(const char* hostname, const char* portname) {
		this->hostname = hostname;
		this->portname = portname;
		this->listenfd = NONE_SOCKET_FD;
		this->connection_counter = 0;
	}
	~TCPServer() {
		this->stop_listen();
	}

	/* start listening for connections. */
	int start_listen() {
		if(listenfd != NONE_SOCKET_FD) {
			fprintf(stderr, "error: server already listening.\n");
			return 1;
		}

		// get address info for localhost.
		addrinfo	hints;
		addrinfo*	results;
		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE;
		int addr_status = getaddrinfo(hostname, portname, &hints, &results);
		if (addr_status != 0) {
			fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(addr_status));
			return 1;
		}

		// create a socket (returns socket file-descriptor).
		listenfd = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
		if(listenfd == -1) {
			fprintf(stderr, "error: failed to create socket (sockfd: %i)\n", listenfd);
			return 1;
		}

		// allow reusing socket-address after closing (fixes "address already in use").
		int yes = 1;
		setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		// bind socket to address+port.
		int status = bind(listenfd, results->ai_addr, results->ai_addrlen);
		if(status == -1) {
			fprintf(stderr, "error: failed to bind socket (errno: %i)\n", errno);
			return 1;
		}

		// free address-info chain.
		freeaddrinfo(results);

		// listen for connections.
		int backlog = 5;
		status = listen(listenfd, backlog);
		if(status == -1) {
			fprintf(stderr, "error: failed to listen for connections (errno: %i)\n", errno);
			return 1;
		}
		printf("listening for connections on port %s\n", portname);

		// accept connections, spawning a worker thread for each new connection.
		accept_connection_struct connection_info;
		while(true) {
			int newfd = accept(listenfd, (sockaddr*)&connection_info.addr, &connection_info.addrlen);
			if(status == -1) {
				fprintf(stderr, "error: failed to listen for connections (errno: %i)\n", errno);
				return 1;
			}
			connection_info.sockfd = newfd;
			std::thread worker_thread(&TCPServer::accept_connection, this, connection_info);
			worker_thread.detach();
			connection_counter++;
		}

		// close listening socket.
		this->stop_listen();
		return 0;
	}

	/* stop listening for connections. */
	void stop_listen() {
		if(listenfd != NONE_SOCKET_FD) {
			close(listenfd);
			listenfd = NONE_SOCKET_FD;
		}
	}

	struct accept_connection_struct {
		sockaddr_storage	addr;
		socklen_t			addrlen;
		int					sockfd;
	};
	void accept_connection(accept_connection_struct connection_info) {
		printf("worker worker started,  sockfd: %i\n", connection_info.sockfd);
		this->handle_connection(connection_info);
		close(connection_info.sockfd);
		printf("worker worker finished, sockfd: %i\n", connection_info.sockfd);
	}
	virtual void handle_connection(accept_connection_struct connection_info) {
		// print info about accepted connection.
		int sockfd = connection_info.sockfd;
		string ipstr =  get_address_string(connection_info.addr, connection_info.addrlen);
		printf("accepted TCP connection\n");
		printf("\tsockfd: %i\n", sockfd);
		printf("\tipaddr: %s\n", ipstr.c_str());

		// echo.
		std::this_thread::sleep_for(std::chrono::milliseconds(2000));

		int status;
		int msg_length = recv_int(sockfd, &status);
		printf("message length: %i\n", msg_length);

		const int BUF_SZ = 6;
		char buf[BUF_SZ + 1];
		int x = 0;// current read position in message.
		while(x < msg_length) {
			// receive message chunk.
			int recv_len_max = std::min(BUF_SZ, msg_length - x);
			int recv_len = recv_all(sockfd, buf, recv_len_max, &status);
			if(status == 0) {
				printf("recv - connection closed\n");
				return;
			}
			if(status <  0) {
				printf("recv - error occurred: %i\n", errno);
				return;
			}
			x += recv_len;

			// print message data.
			buf[recv_len] = 0;// terminate string with 0 for printing.
			printf("%s\n", buf);
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));

			// send message chunk back.
			int send_len_max = recv_len;
			int send_len = send_all(sockfd, buf, send_len_max, &status);
			if(status == 0) {
				printf("send - connection closed\n");
				return;
			}
			if(status <  0) {
				printf("send - error occurred: %i\n", errno);
				return;
			}
		}
		printf("\n");

		std::this_thread::sleep_for(std::chrono::milliseconds(2000));
	}
};

// ============================================================
// HTTP
// ------------------------------------------------------------

const char*	HTTP_HEADER_NEWLINE	= "\r\n";
const char*	HTTP_HEADER_END		= "\r\n\r\n";
const int	HTTP_HEADER_MAXLEN	= 1024 * 10;// 10 KiB
const int	HTTP_REQUEST_MAXLEN	= 1024 * 1024 * 10;// 10 MiB
enum HTTP_ERROR {
	SUCCESS = 0,
	HEADER_MAXLEN,
	REQUEST_MAXLEN,
};

using header_dict = std::map<string, string>;

struct http_request {
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

// TODO: move this to a seperate "http_parser" file and break into functions,
// with the end goal of making this function (almost) standards compliant.
http_request recv_http(int fd, serialization::buffer_rw& buf, int* status, int flags=0) {
	http_request request;
	char* hdr_beg = buf.position_ptr();
	char* hdr_end = NULL;
	int total_message_size = 0;

	// read until end of HTTP header section is found.
	{
		const int chunk_sz = 1024;
		while(total_message_size < HTTP_HEADER_MAXLEN) {
			// read some more data.
			buf.reserve(chunk_sz);
			char* beg = buf.position_ptr();
			// TODO: check for connection closed/errored after recv.
			int len = recv(fd, beg, chunk_sz, 0);
			buf.advance(len);
			total_message_size += len;
			char* end = buf.position_ptr();
			// check if header end characters were found.
			size_t endpos = std::string_view(beg, end).rfind(HTTP_HEADER_END);
			if(endpos != std::string::npos) {
				hdr_end = beg + endpos;
				break;
			}
		}
		if(total_message_size >= HTTP_HEADER_MAXLEN) {
			fprintf(stderr, "header length exceeded HTTP_HEADER_MAXLEN\n");
			*status = HTTP_ERROR::HEADER_MAXLEN;
			return request;
		}
	}

	// parse headers.
	{
		std::string_view header_str(hdr_beg, hdr_end);
		std::string_view line;
		size_t line_pos = 0;
		size_t line_end;
		// parse first line.
		{
			line_end = header_str.find(HTTP_HEADER_NEWLINE, line_pos);
			line = header_str.substr(line_pos, line_end-line_pos);
			std::vector<string> list = split(string(line), " ");
			request.method		= to_lowercase(list[0]);
			request.target		= list[1];// TODO: are URLs case-insensitive?
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
	// NOTE: some of the content may have already been read when getting header.
	if(request.headers.contains("content-length")) {}
	// TODO
	*status = 1;
	return x;
}

int send_http(int fd, void* msg, int len, int* status, int flags=0) {
	// TODO
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
	//serialization::test();

	if(argc <= 1) printf("missing arg[1]: portname (string)\n");
	if(argc <= 1) exit(1);
	const char* portname = argv[1];
	HTTPServer server(NULL, "3490");
	server.start_listen();
}
