
#include "src/tcp_structs.cpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

namespace TCP {
	using string = std::string;

	struct TCPClient {
		// TODO - connections should be created and returned by a function
		// (to be managed externally).
		TCPConnection connection_info;

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
			string ipstr =  connection_info.get_address_string();
			printf("accepted TCP connection\n");
			printf("\tsockfd: %i\n", connection_info.sockfd);
			printf("\tipaddr: %s\n", ipstr.c_str());
			return 0;
		}
	};
}
