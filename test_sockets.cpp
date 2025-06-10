#include "./socket_types.cpp"
#include "./socket_helpers.cpp"
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <chrono>
#include <cassert>


std::string get_address_string(sockaddr& addr, socklen_t& addrlen) {
	char buf[INET6_ADDRSTRLEN];
	inet_ntop(addr.sa_family, &addr, buf, sizeof(buf));
	return std::string(buf);
}


void test_address_conversions() {
	// NOTE: Beej's network guides can be found here:
	// https://beej.us/guide
	// most stuff in this file is copied or paraphrased from his guides.

	// test string-to-binary address conversions.
	/*
		(paraphrased from Beej's network guide)
		The code snippet isn’t very robust because there is no error checking.
		inet_pton() returns -1 on error, or 0 if the address is messed up.
		So check to make sure the result is greater than 0 before using!
	*/
	sockaddr_in4 sa4;
	sockaddr_in6 sa6;
	const char* ip4 = "10.12.110.57";
	const char* ip6 = "2001:db8:63b3:1::3490";
	printf("initial IPv4 address: %s\n", ip4);
	printf("initial IPv6 address: %s\n", ip6);
	int result4 = inet_pton(AF_INET, ip4, &sa4.sin_addr);
	int result6 = inet_pton(AF_INET6, ip6, &sa6.sin6_addr);
	printf("successfully converted IPv4 address: %i\n", result4);
	printf("successfully converted IPv6 address: %i\n", result6);
	assert(result4 > 0);
	assert(result6 > 0);
	char buf4[INET_ADDRSTRLEN];
	char buf6[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET, &sa4.sin_addr, buf4, INET_ADDRSTRLEN);
	inet_ntop(AF_INET6, &sa6.sin6_addr, buf6, INET6_ADDRSTRLEN);
	printf("resulting IPv4 address: %s\n", buf4);
	printf("resulting IPv6 address: %s\n", buf6);
}


void test_address_info() {
	// test getting address info.
	int status;
	addrinfo hints;
	addrinfo *servinfo; // will point to the results.
	memset(&hints, 0, sizeof hints); // make sure the struct is empty.
	hints.ai_family = AF_UNSPEC; // don't care IPv4 or IPv6.
	hints.ai_socktype = SOCK_STREAM; // TCP stream sockets.
	//hints.ai_flags = AI_PASSIVE; // fill in my IP for me (localhost).
	const char* hostname = "www.example.com"; // set to NULL when getting localhost.
	const char* port = "443"; // can also be service-name, like "https".
	printf("IP addresses for: %s (port: %s)\n", hostname, port);
	if ((status = getaddrinfo(hostname, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		exit(1);
	}
	// servinfo now points to a linked list of 1 or more struct addrinfos
	for(auto p = servinfo; p != NULL; p = p->ai_next) {
		const int family = p->ai_family;
		void* addr;
		const char* ipver;
		char  ipstr[INET6_ADDRSTRLEN];
		if(family == AF_INET) {
			sockaddr_in4* ipv4 = (sockaddr_in4*)p->ai_addr;
			addr = &(ipv4->sin_addr);
			ipver = "IPv4";
		}
		if(family == AF_INET6) {
			sockaddr_in6* ipv6 = (sockaddr_in6*)p->ai_addr;
			addr = &(ipv6->sin6_addr);
			ipver = "IPv6";
		}
		inet_ntop(family, addr, ipstr, sizeof(ipstr));
		printf("%s: %s\n", ipver, ipstr);
	}
	// ... do everything until you don't need servinfo anymore ....
	freeaddrinfo(servinfo); // free the linked-list
}


struct test_socket_accept_struct {
	int			sockfd;
	sockaddr	addr;
	socklen_t	addrlen;
};
void test_socket_accept(test_socket_accept_struct* accept_data) {
	// TODO: find way to make thread self-terminate after X seconds.
	printf(
		"created worker thread | sockfd: %i, addr: [%s] \n",
		accept_data->sockfd,
		get_address_string(accept_data->addr, accept_data->addrlen).c_str()
	);
	std::this_thread::sleep_for(std::chrono::milliseconds(3000));
	printf("worker thread finished\n");
}

void test_socket_connect_or_listen(bool is_server) {
	// get address info for localhost, port 3490.
	const char* hostname = NULL;
	const char* portname = "3490";
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

	// connect socket to destination address+port.
	if(!is_server) {
		int status = connect(sockfd, results->ai_addr, results->ai_addrlen);
		if(status == -1) {
			fprintf(stderr, "error: failed to connect socket (errno: %i)\n", errno);
			exit(1);
		}
		printf("connected to destination\n");
		// send message.
		char buf[1024];
		std::string msg = "test message abc 123 :)";
		sprintf(buf, "%s", msg.c_str());
		int msg_length = msg.length();
		printf("sending length: %i\n", msg_length);
		send_int(sockfd, &status, msg_length);
		printf("sending message: %s\n", buf);
		send(sockfd, buf, msg_length, 0);
		// receive response.
		printf("receiving message.\n");
		char buf2[1024];
		recv_all(sockfd, buf2, msg_length, &status);
		buf2[msg.length()] = 0;
		printf("response:\n");
		printf("%s", buf2);
		printf("\n");
	}

	// bind socket to address+port, then listen for connections.
	if(is_server) {
		int status = bind(sockfd, results->ai_addr, results->ai_addrlen);
		if(status == -1) {
			fprintf(stderr, "error: failed to bind socket (errno: %i)\n", errno);
			exit(1);
		}

		int backlog = 5;
		status = listen(sockfd, backlog);
		if(status == -1) {
			fprintf(stderr, "error: failed to listen for connections (errno: %i)\n", errno);
			exit(1);
		}
		printf("listening for connections on port %s\n", portname);

		// accept connections, spawning worker threads for each new connection.
		test_socket_accept_struct accept_data;
		int n=0;
		while(true) {
			int newfd = accept(sockfd, &accept_data.addr, &accept_data.addrlen);
			if(status == -1) {
				fprintf(stderr, "error: failed to listen for connections (errno: %i)\n", errno);
				exit(1);
			}
			accept_data.sockfd = newfd;
			printf("accepted connection: %i\n", accept_data.addr.sa_family);
			std::thread worker(test_socket_accept, &accept_data);
			worker.detach();
		}
	}
}






