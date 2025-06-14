#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

namespace HTTP {
	using string = std::string;

	// ============================================================
	// types
	// ------------------------------------------------------------

	using addr_in6 = in6_addr;
	using addr_in4 = in_addr;
	/*
	struct in4_addr {
		uint32_t		s4_addr;// IPv4 address
	};
	struct in6_addr {
		unsigned char	s6_addr[16];// IPv6 address
	};
	*/

	using sockaddr			= sockaddr;// NOTE: dont use this! use sockaddr_storage instead. (and pointer-cast as needed)
	using sockaddr_storage	= sockaddr_storage;
	using sockaddr_in6		= sockaddr_in6;
	using sockaddr_in4		= sockaddr_in;
	/*
	struct sockaddr {
		unsigned short	sa_family;		// address family, AF_xxx
		char			sa_data[14];	// 14 bytes of protocol address
	};
	struct sockaddr_in4 {
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

	using addrinfo = addrinfo;
	/*
	struct addrinfo {
		int			ai_flags;		// AI_PASSIVE, AI_CANONNAME, etc.
		int			ai_family;		// AF_INET, AF_INET6, AF_UNSPEC
		int			ai_socket_type;	// SOCK_STREAM, SOCK_DGRAM
		int			ai_protocol;	// use 0 for "any"
		size_t		ai_addrlen;		// size of socket address struct (ai_addr) in bytes
		sockaddr*	ai_addr;		// sockaddr_in, sockaddr_in6.
		char*		ai_canonname;	// full canonical hostname
		addrinfo*	ai_next;		// linked list, next node
	};
	*/


	// ============================================================
	// helper functions
	// ------------------------------------------------------------

	std::string get_address_string(sockaddr_storage& addr, socklen_t& addrlen) {
		char buf[INET6_ADDRSTRLEN];
		inet_ntop(addr.ss_family, &addr, buf, sizeof(buf));
		return std::string(buf);
	}

	/*
	returns number of bytes sent.

	status == 1: message was sent successfully.
	status == 0: connection closed.
	status <  0: an error occurred.

	if an error occurred, errno will be set.

	see "send" manpage for more info.
	*/
	int send_all(int fd, void* msg, int len, int* status, int flags=0) {
		int x = 0;
		while(x < len) {
			int num_sent = send(fd, (char*)msg+x, len-x, flags);
			if(num_sent <= 0) {
				*status = num_sent;
				return x;
			}
			x += num_sent;
		}
		*status = 1;
		return x;
	}

	/*
	returns number of bytes received.

	status == 1: message was sent successfully.
	status == 0: connection closed.
	status <  0: an error occurred.

	if an error occurred, errno will be set.

	see "recv" manpage for more info.
	*/
	int recv_all(int fd, void* msg, int len, int* status, int flags=0) {
		int x = 0;
		while(x < len) {
			int num_recv = recv(fd, (char*)msg+x, len-x, flags);
			if(num_recv <= 0) {
				*status = num_recv;
				return x;
			}
			x += num_recv;
		}
		*status = 1;
		return x;
	}

	void send_int(int fd, int* status, int value) {
		int net_value = htonl(value);
		send_all(fd, &net_value, sizeof(net_value), status);
	}

	int recv_int(int fd, int* status) {
		int net_value = 0;
		recv_all(fd, &net_value, sizeof(net_value), status);
		return ntohl(net_value);
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
				fprintf(stderr, "error: failed to listen for connections (err: %s)\n", strerror(errno));
				return 1;
			}
			printf("err: %s\n", strerror(errno));
			printf("listening for connections on port %s (listen_sockfd: %i)\n", portname, listenfd);

			// accept connections.
			while(true) {
				// prepare connection_info struct.
				// https://stackoverflow.com/questions/24515526/error-invalid-argument-while-trying-to-accept-a-connection-from-a-client
				// https://linux.die.net/man/2/accept
				accept_connection_struct connection_info;
				connection_info.addrlen = sizeof(connection_info.addr);

				// accept connection.
				int newfd = accept(listenfd, (sockaddr*)&connection_info.addr, &connection_info.addrlen);
				if(newfd == -1) {
					fprintf(stderr, "error: failed to accept connection (err: %s)\n", strerror(errno));
					continue;
				}

				// spawn worker thread.
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
			printf("worker thread started,  sockfd: %i\n", connection_info.sockfd);
			this->handle_connection(connection_info);
			close(connection_info.sockfd);
			printf("worker thread finished, sockfd: %i\n", connection_info.sockfd);
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

}



