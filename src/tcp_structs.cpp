
#ifndef F_tcp_structs_cpp
#define F_tcp_structs_cpp

#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/ssl.h>


namespace TCP {
	using std::string;

	const int NONE_SOCKET_FD = -1;

	/*
	struct sockaddr {
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
	struct addrinfo {
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

		ssize_t send(const char* src, const size_t count) {
			if(ssl != nullptr) {
				size_t len;
				int status = SSL_write_ex(ssl, src, count, &len);
				return len;
			} else {
				return ::send(socket.fd, src, count, 0);
			}
		}

		ssize_t recv(char* dst, const size_t count) {
			if(ssl != nullptr) {
				size_t len;
				int status = SSL_read_ex(ssl, dst, count, &len);
				return len;
			} else {
				return ::recv(socket.fd, dst, count, 0);
			}
		}
	};
}

#endif
