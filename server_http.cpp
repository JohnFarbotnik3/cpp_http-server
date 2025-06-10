#include "./socket_types.cpp"
#include "./socket_helpers.cpp"
#include <chrono>
#include <cstdint>
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

string get_address_string(sockaddr& addr, socklen_t& addrlen) {
	char buf[INET6_ADDRSTRLEN];
	inet_ntop(addr.sa_family, &addr, buf, sizeof(buf));
	return string(buf);
}

// ============================================================
// listen for and accept connections
// ------------------------------------------------------------


struct accept_connection_struct {
	int			sockfd;
	sockaddr	addr;
	socklen_t	addrlen;
};

void accept_connection(accept_connection_struct connection_info) {
	// accept connection.
	int sockfd = connection_info.sockfd;
	string ipstr =  get_address_string(connection_info.addr, connection_info.addrlen);
	printf("accepted connection\n");
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
			exit(0);
		}
		if(status <  0) {
			printf("recv - error occurred: %i\n", status);
			exit(1);
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
			exit(0);
		}
		if(status <  0) {
			printf("send - error occurred: %i\n", status);
			exit(1);
		}
	}
	printf("\n");

	std::this_thread::sleep_for(std::chrono::milliseconds(2000));

	// exit thread.
	printf("worker thread finished\n");
}

void listen_for_connections(const char* portname) {
	// get address info for localhost.
	const char*	hostname = NULL;
	addrinfo	hints;
	addrinfo*	results;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	int addr_status = getaddrinfo(hostname, portname, &hints, &results);
	if (addr_status != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(addr_status));
		exit(1);
	}

	// create a socket (returns socket file-descriptor).
	int sockfd = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
	if(sockfd == -1) {
		fprintf(stderr, "error: failed to create socket (sockfd: %i)\n", sockfd);
		exit(1);
	}

	// bind socket to address+port.
	int status = bind(sockfd, results->ai_addr, results->ai_addrlen);
	if(status == -1) {
		fprintf(stderr, "error: failed to bind socket (errno: %i)\n", errno);
		exit(1);
	}

	// listen for connections.
	int backlog = 5;
	status = listen(sockfd, backlog);
	if(status == -1) {
		fprintf(stderr, "error: failed to listen for connections (errno: %i)\n", errno);
		exit(1);
	}
	printf("listening for connections on port %s\n", portname);

	// accept connections, spawning a worker thread for each new connection.
	accept_connection_struct connection_info;
	uint64_t connection_counter = 0;
	while(true) {
		int newfd = accept(sockfd, &connection_info.addr, &connection_info.addrlen);
		if(status == -1) {
			fprintf(stderr, "error: failed to listen for connections (errno: %i)\n", errno);
			exit(1);
		}
		connection_info.sockfd = newfd;
		std::thread worker_thread(accept_connection, connection_info);
		worker_thread.detach();
		connection_counter++;
	}
}

// ============================================================
// main
// ------------------------------------------------------------

int main(const int argc, const char** argv) {
	if(argc <= 1) printf("missing arg[1]: portname (string)\n");
	if(argc <= 1) exit(1);
	const char* portname = argv[1];
	listen_for_connections(portname);
}
