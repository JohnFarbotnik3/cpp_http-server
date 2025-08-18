
#ifndef F_tcp_util_cpp
#define F_tcp_util_cpp

#include <cstdlib>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/ssl.h>

namespace TCP {
	using std::string;

	const int NONE_SOCKET_FD = -1;

	/*
	 s t*ruct sockaddr {
	 unsigned short	sa_family;		// address family, AF_xxx
	 char			sa_data[14];	// 14 bytes of protocol address
};
struct sockaddr_in {
u_int16_t		sin4_family;	// Address family, AF_INET
u_int16_t		sin4_port;		// Port number
in4_addr		sin4_addr;		// Internet address
unsigned char	sin4_zero[8];	// Padding to ensure same size as struct sockaddr
};
struct sockaddr_in6 {
u_int16_t	sin6_family;	// address family, AF_INET6
u_int16_t	sin6_port;		// port number, Network Byte Order
u_int32_t	sin6_flowinfo;	// IPv6 flow information
in6_addr	sin6_addr;		// IPv6 address
u_int32_t	sin6_scope_id;	// Scope ID
};
*/
	using sockaddr_storage	= sockaddr_storage;
	using socklen_t			= socklen_t;

	/*
	 s t*ruct addrinfo {
	 int			ai_flags;		// AI_PASSIVE, AI_CANONNAME, etc.
	 int			ai_family;		// AF_INET, AF_INET6, AF_UNSPEC
	 int			ai_socket_type;	// SOCK_STREAM, SOCK_DGRAM
	 int			ai_protocol;	// use 0 for "any"
	 size_t		ai_addrlen;		// size of socket address struct (ai_addr) in bytes
	 sockaddr*	ai_addr;		// sockaddr_in | sockaddr_in6.
	 char*		ai_canonname;	// full canonical hostname
	 addrinfo*	ai_next;		// linked list, next node
};
*/
	using addrinfo = addrinfo;



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
	int get_ssl_error_status(SSL* ssl, int ret_code) {
		switch (SSL_get_error(ssl, ret_code)) {
			case SSL_ERROR_WANT_READ: return 1;// would block on read.
			case SSL_ERROR_WANT_WRITE: return 1;// would block on write.
			case SSL_ERROR_ZERO_RETURN: return 0;// no more data to read (but write may still be possible).
			case SSL_ERROR_SYSCALL: return -1;
			case SSL_ERROR_SSL:// SSL related error happened.
				if (SSL_get_verify_result(ssl) != X509_V_OK) printf("Verify error: %s\n", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
				return -1;
			default: return -1;
		}
	}


	struct TCPSocket {
		int					fd;
		sockaddr_storage	addr;
		socklen_t			addrlen;
	};

	struct TCPConnection {
		TCPSocket socket;
		SSL* ssl = nullptr;

		TCPConnection() = default;
		TCPConnection(const TCPSocket& socket) : socket(socket) {}
		TCPConnection(const TCPSocket& socket, SSL* ssl) : socket(socket), ssl(ssl) {}

		int send_all(const char* data, size_t& pos, const size_t size) {
			if(ssl == nullptr) {
				ssize_t len;
				while(pos < size) {
					len = ::send(socket.fd, data+pos, size-pos, 0);
					if(len > 0) pos += len; else break;
				}
				if(pos == size || errno == EWOULDBLOCK) return 1;// success or blocked.
				if(len == 0) return 0;// socket closed.
				return -1;// error.
			} else {
				int len;
				while(pos < size) {
					int len = SSL_write(ssl, data+pos, size-pos);
					if(len > 0) pos += len; else break;
				}
				if(pos == size || errno == EWOULDBLOCK) return 1;// success or blocked.
				if(len == 0) return 0;// socket closed.
				return -1;// error.
			}
		}
		int recv_all(char* data, size_t& pos, const size_t size) {
			if(ssl == nullptr) {
				ssize_t len;
				while(pos < size) {
					len = ::recv(socket.fd, data+pos, size-pos, 0);
					if(len > 0) pos += len; else break;
				}
				if(pos == size || errno == EWOULDBLOCK) return 1;// success or blocked.
				if(len == 0) return 0;// socket closed.
				return -1;// error.
			} else {
				int len;
				while(pos < size) {
					int len = SSL_read(ssl, data+pos, size-pos);
					if(len > 0) pos += len; else break;
				}
				if(pos == size || errno == EWOULDBLOCK) return 1;// success or blocked.
				if(len == 0) return 0;// socket closed.
				return -1;// error.
			}
		}

		// WARNING: do not use this with non-blocking sockets.
		ssize_t _send(const char* data, const size_t count) {
			if(ssl != nullptr) {
				/*
				size_t len = 0;
				int ret_code = SSL_write_ex(ssl, src, count, &len);
				return ret_code > 0 ? len : get_ssl_error_status(ssl, ret_code);
				*/
				int len = SSL_write(ssl, data, count);
				return len > 0 ? len : get_ssl_error_status(ssl, len);
			} else {
				return ::send(socket.fd, data, count, 0);
			}
		}

		// WARNING: do not use this with non-blocking sockets.
		ssize_t _recv(char* data, const size_t count) {
			if(ssl != nullptr) {
				/*
				size_t len = 0;
				int ret_code = SSL_read_ex(ssl, dst, count, &len);
				return ret_code > 0 ? len : get_ssl_error_status(ssl, ret_code);
				*/
				return SSL_read(ssl, data, count);
			} else {
				return ::recv(socket.fd, data, count, 0);
			}
		}

		void close() {
			if(ssl != nullptr) {
				SSL_free(ssl);
			} else {
				::close(socket.fd);
			}
		}

		bool set_nonblocking(bool non_blocking) {
			return set_socket_nonblocking(socket.fd, non_blocking);
		}
	};

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
}

#endif
