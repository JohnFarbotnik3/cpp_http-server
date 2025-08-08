
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>
#include "src/tcp_structs.cpp"
#include "src/tcp_util.cpp"

namespace TCP {
	using string = std::string;

	struct TCPClient {
		TCPClient() {}
		~TCPClient() {}

		void close_connection(TCPSocket& client_socket) {
			if(client_socket.fd != NONE_SOCKET_FD) {
				close(client_socket.fd);
				client_socket.fd = NONE_SOCKET_FD;
			}
		}

		int open_connection(const char* hostname, const char* portname, TCPConnection& connection) {
			addrinfo* results;
			const int addr_status = get_potential_socket_addresses_for_peer(hostname, portname, results);
			if (addr_status != 0) {
				fprintf(stderr, "[get_potential_addresses_for_peer] ERROR: %s\n", gai_strerror(addr_status));
				return EXIT_FAILURE;
			}

			if(try_to_connect(results, connection.socket) != EXIT_SUCCESS) {
				fprintf(stderr, "client: failed to connect\n");
				return EXIT_FAILURE;
			}

			// free address-info chain.
			freeaddrinfo(results);
			return EXIT_SUCCESS;
		}
	};
}
