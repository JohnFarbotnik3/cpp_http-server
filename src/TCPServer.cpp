/*
This was written with the help of the following guides:
<Beej's networking guide (c)>
*/

#include "src/tcp_structs.cpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

namespace TCP {
	using string = std::string;

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
				tcp_connection_struct connection_info;
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

		void accept_connection(tcp_connection_struct connection_info) {
			this->handle_connection(connection_info);
			close(connection_info.sockfd);
		}
		virtual void handle_connection(tcp_connection_struct connection_info) {
			int sockfd = connection_info.sockfd;
			string ipstr =  connection_info.get_address_string();
			printf("accepted TCP connection\n");
			printf("\tsockfd: %i\n", sockfd);
			printf("\tipaddr: %s\n", ipstr.c_str());
		}
	};

}



