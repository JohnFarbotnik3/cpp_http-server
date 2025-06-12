
#include "./socket_types.cpp"
#include "./socket_helpers.cpp"
#include "../serialization.cpp"
#include "../string_helpers.cpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
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
// server
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
