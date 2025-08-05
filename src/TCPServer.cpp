/*
This was written with the help of the following guides:
<Beej's networking guide (c)>
*/

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
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

		/* stop listening for connections. */
		void stop_listen() {
			if(listenfd != NONE_SOCKET_FD) {
				close(listenfd);
				listenfd = NONE_SOCKET_FD;
			}
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

			// TODO - try multiple addresses instead of just the first (Beej C networking guide, pg 39).
			// create a socket (returns socket file-descriptor).
			listenfd = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
			if(listenfd == -1) {
				fprintf(stderr, "error: failed to create listener socket (sockfd: %i)\n", listenfd);
				return 1;
			}

			// allow reusing socket-address after closing (fixes "address already in use").
			int yes = 1;
			setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

			// bind listener socket to address+port.
			int status = bind(listenfd, results->ai_addr, results->ai_addrlen);
			if(status == -1) {
				fprintf(stderr, "error: failed to bind listener socket (errno: %i)\n", errno);
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

		struct accept_connection_struct {
			sockaddr_storage	addr;
			socklen_t			addrlen;
			int					sockfd;
		};
		void accept_connection(accept_connection_struct connection_info) {
			this->handle_connection(connection_info);
			close(connection_info.sockfd);
		}
		virtual void handle_connection(accept_connection_struct connection_info) {
			int sockfd = connection_info.sockfd;
			string ipstr =  get_address_string(connection_info.addr, connection_info.addrlen);
			printf("accepted TCP connection\n");
			printf("\tsockfd: %i\n", sockfd);
			printf("\tipaddr: %s\n", ipstr.c_str());
		}
	};

	struct open_connection_struct {
		sockaddr_storage	addr;
		socklen_t			addrlen;
		int					sockfd;
	};
	struct TCPClient {

		open_connection_struct connection_info;

		TCPClient() {
			connection_info.sockfd = NONE_SOCKET_FD;
		}
		~TCPClient() {
			this->close_connection();
		}

		void close_connection() {
			if(connection_info.sockfd != NONE_SOCKET_FD) {
				close(connection_info.sockfd);
				connection_info.sockfd = NONE_SOCKET_FD;
			}
		}
		int open_connection(const char* hostname, const char* portname) {
			if(connection_info.sockfd != NONE_SOCKET_FD) {
				fprintf(stderr, "error: client is already connected.\n");
				return 1;
			}

			// get address info for server.
			addrinfo	hints;
			addrinfo*	results;
			memset(&hints, 0, sizeof hints);
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			//hints.ai_flags = AI_PASSIVE;
			int addr_status = getaddrinfo(hostname, portname, &hints, &results);
			if (addr_status != 0) {
				fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(addr_status));
				return 1;
			}

			// loop through all the results and connect to the first we can.
			int sockfd;
			bool success = false;
			for(addrinfo* p = results; p != NULL; p = p->ai_next) {
				if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
					continue;
				}
				if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
					close(sockfd);
					continue;
				}
				// copy connection info of successfull connection.
				memset(&connection_info, 0, sizeof(connection_info));
				memcpy(&connection_info.addr, p->ai_addr, p->ai_addrlen);
				connection_info.addrlen = p->ai_addrlen;
				connection_info.sockfd = sockfd;
				success = true;
				break;
			}
			if(!success) {
				fprintf(stderr, "client: failed to connect\n");
				return 2;
			}

			// free address-info chain.
			freeaddrinfo(results);

			// TEST - print connection info.
			// TODO - move to HTTPClient.
			string ipstr =  get_address_string(connection_info.addr, connection_info.addrlen);
			printf("accepted TCP connection\n");
			printf("\tsockfd: %i\n", connection_info.sockfd);
			printf("\tipaddr: %s\n", ipstr.c_str());
			return 0;
		}
	};

}



