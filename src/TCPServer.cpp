/*
This was written with the help of the following guides:
<Beej's networking guide (c)>
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include "src/tcp_structs.cpp"
#include "src/tcp_util.cpp"

namespace TCP {
	using string = std::string;

	struct TCPServer {
		const string	hostname;
		const string	portname;
		TCPSocket		listen_socket;

		TCPServer(const string hostname, const string portname) :
			hostname(hostname),
			portname(portname)
		{
			listen_socket.fd = NONE_SOCKET_FD;
		}
		~TCPServer() {
			this->stop_listen();
		}

		/* stop listening for connections. */
		void stop_listen() {
			if(listen_socket.fd != NONE_SOCKET_FD) {
				close(listen_socket.fd);
				listen_socket.fd = NONE_SOCKET_FD;
			}
		}

		/* start listening for connections. */
		int start_listen() {
			if(listen_socket.fd != NONE_SOCKET_FD) {
				fprintf(stderr, "error: server already listening.\n");
				return 1;
			}

			addrinfo* results;
			const int addr_status = get_potential_socket_addresses_for_localhost(portname, results);
			if (addr_status != 0) {
				fprintf(stderr, "[get_potential_addresses_for_localhost] ERROR: %s\n", gai_strerror(addr_status));
				return EXIT_FAILURE;
			}

			if(try_to_listen(results, listen_socket, 5) != EXIT_SUCCESS) {
				fprintf(stderr, "error: failed to listen for connections (errno: %s)\n", strerror(errno));
				return EXIT_FAILURE;
			}
			printf("listening for connections on port %s (listen_sockfd: %i)\n", portname.c_str(), listen_socket.fd);
			printf("residual err: %s\n", strerror(errno));

			// free address-info chain.
			freeaddrinfo(results);

			// accept connections.
			while(true) {
				TCPConnection new_connection;
				if(try_accept(listen_socket, new_connection.socket) == EXIT_FAILURE) {
					fprintf(stderr, "error: failed to accept connection (err: %s)\n", strerror(errno));
					continue;
				}
				std::thread worker_thread(&TCPServer::accept_connection, this, new_connection);
				worker_thread.detach();
			}

			// close listening socket.
			this->stop_listen();
			return 0;
		}

		void accept_connection(TCPConnection new_connection) {
			this->handle_connection(new_connection);
			close(new_connection.socket.fd);
		}

		virtual void handle_connection(TCPConnection connection) {
			printf("accepted TCP connection\n");
			printf("\tsockfd: %i\n", connection.socket.fd);
			printf("\tipaddr: %s\n", connection.get_address_string().c_str());
		}
	};

}



