
#ifndef F_tcp_util_cpp
#define F_tcp_util_cpp

#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include "src/tcp_structs.cpp"

namespace TCP {
	using std::string;

	/* sources:
		https://en.wikipedia.org/wiki/Getaddrinfo
		...
	*/

	// get linked-list of potential socket addresses for binding.
	int get_potential_socket_addresses_for_listening(const string& portname, addrinfo*& results, bool expose_to_network) {
		addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family		= AF_UNSPEC;
		hints.ai_socktype	= SOCK_STREAM;
		hints.ai_flags		= AI_PASSIVE;
		if(expose_to_network) {
			return getaddrinfo(NULL, portname.c_str(), &hints, &results);
		} else {
			return getaddrinfo("::1", portname.c_str(), &hints, &results);
		}
	}

	// get linked-list of potential socket addresses for connecting to a peer with given hostname and port.
	int get_potential_socket_addresses_for_connecting(const string& hostname, const string& portname, addrinfo*& results) {
		addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family		= AF_UNSPEC;
		hints.ai_socktype	= SOCK_STREAM;
		int addr_status = getaddrinfo(hostname.c_str(), portname.c_str(), &hints, &results);
		return addr_status;
	}

	// loop through all the potential socket addresses and connect to the first we can.
	int try_to_connect(const addrinfo* results, TCPSocket& tcpsocket) {
		for(const addrinfo* p = results; p != NULL; p = p->ai_next) {
			const int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
			if (sockfd == -1) continue;
			if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
				close(sockfd);
				continue;
			}

			// copy connection info of successfull connection.
			tcpsocket = TCPSocket(sockfd, *((sockaddr_storage*)p->ai_addr), p->ai_addrlen);
			return EXIT_SUCCESS;
		}
		return EXIT_FAILURE;
	}

	// loop through all the potential socket addresses and connect to the first we can.
	int try_to_listen(const addrinfo* results, TCPSocket& tcpsocket, const int backlog) {
		for(const addrinfo* p = results; p != NULL; p = p->ai_next) {
			const int listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
			if (listenfd == -1) continue;

			// allow reusing socket-address after closing (fixes "address already in use").
			const int yes = 1;
			setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

			if (bind(listenfd, p->ai_addr, p->ai_addrlen) == -1) {
				close(listenfd);
				continue;
			}
			if(listen(listenfd, backlog) == -1) {
				close(listenfd);
				return EXIT_FAILURE;
			}

			// copy connection info of successfull connection.
			tcpsocket.fd = listenfd;
			memcpy(&tcpsocket.addr, p->ai_addr, p->ai_addrlen);
			tcpsocket.addrlen = p->ai_addrlen;
			return EXIT_SUCCESS;
		}
		return EXIT_FAILURE;
	}

	// accept connection.
	int try_to_accept(const TCPSocket& listen_socket, TCPSocket& new_socket) {
		// prepare connection_info struct.
		// https://stackoverflow.com/questions/24515526/error-invalid-argument-while-trying-to-accept-a-connection-from-a-client
		// https://linux.die.net/man/2/accept
		new_socket.addrlen = sizeof(new_socket.addr);

		// accept connection.
		int newfd = accept(listen_socket.fd, (sockaddr*)&new_socket.addr, &new_socket.addrlen);
		if(newfd == -1) return EXIT_FAILURE;

		new_socket.fd = newfd;
		return EXIT_SUCCESS;
	}

	int get_peer_address_from_sockfd(const int sockfd, sockaddr_storage& addr, socklen_t& addrlen) {
		addrlen = sizeof(addr);
		return getpeername(sockfd, (sockaddr*)&addr, &addrlen);
	}

	string get_address_string(const sockaddr_storage& addr) {
		char buf[INET6_ADDRSTRLEN];
		inet_ntop(addr.ss_family, &addr, buf, sizeof(buf));
		return std::string(buf);
	}

	bool set_socket_nonblocking(int fd, bool nonblocking) {
		// https://stackoverflow.com/questions/1543466/how-do-i-change-a-tcp-socket-to-be-non-blocking
		if(fd < 0) return false;
		#ifdef _WIN32
		unsigned long mode = blocking ? 0 : 1;
		return (ioctlsocket(fd, FIONBIO, &mode) == 0);
		#else
		int flags = fcntl(fd, F_GETFL, 0);
		if (flags == -1) return false;
		flags = nonblocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
		return (fcntl(fd, F_SETFL, flags) == 0);
		#endif
	}
}

#endif
