/*
This was written with the help of the following guides:
https://bhch.github.io/posts/2017/11/writing-an-http-server-from-scratch/
https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages
*/

#ifndef F_SERVER_HTTP
#define F_SERVER_HTTP

#include <cstdio>
#include <cstring>
#include <netdb.h>
#include <sys/epoll.h>
#include <string>
#include <thread>
#include <filesystem>

#include "src/tcp_structs.cpp"
#include "src/tcp_util.cpp"
#include "src/http_util.cpp"
#include "src/definitions/mime_types.cpp"
#include "src/definitions/headers.cpp"
#include "src/utils/time_util.cpp"
#include "src/TaskQueue.cpp"
#include "src/SharedMap.cpp"
#include "src/SharedVectorMap.cpp"

#include <err.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace HTTP {
	using std::string;
	using utils::time_util::time64_ns;
	using TCP::TCPSocket;
	using TCP::TCPConnection;
	namespace fs = std::filesystem;

	struct HTTPServer {
		const string hostname;
		const string portname;
		SharedMap<int, HTTPConnection*> connections;
		TaskQueue<int> work_queue;
		std::vector<std::thread> worker_thread_pool;
		std::thread accept_thread;
		std::thread polling_thread;
		int polling_fd;
		int polling_timeout;
		bool shutting_down;

		HTTPServer(const string hostname, const string portname, const int n_accept_threads, const int n_worker_threads):
			hostname(hostname),
			portname(portname),
			worker_thread_pool(n_worker_threads),
			shutting_down(false)
		{}

		// connection and socket functions.
		void insert_connection_nonblocking(TCPConnection tcp_connection) {
			// make socket non-blocking.
			bool success = TCP::set_socket_nonblocking(tcp_connection.socket.fd, true);
			if (!success) {
				fprintf(stderr, "error: set_socket_nonblocking() failed (err: %s)\n", strerror(errno));
				tcp_connection.close();
				return;
			}

			HTTPConnection* http_connection = new HTTPConnection(tcp_connection, MAX_HEAD_LENGTH, MAX_HEAD_LENGTH, 0);
			const int fd = tcp_connection.socket.fd;
			connections.set(fd, http_connection);

			// add to epoll group.
			epoll_event ev;
			ev.events = EPOLL_EVENTS::EPOLLONESHOT | EPOLL_EVENTS::EPOLLIN;
			int status = epoll_ctl(polling_fd, EPOLL_CTL_ADD, fd, &ev);
			if(status == -1) fprintf(stderr, "[insert_connection] epoll_ctl: %s\n", strerror(errno));
		}
		void remove_connection(HTTPConnection* connection) {
			const int fd = connection->fd();

			// remove from epoll group.
			epoll_event ev;
			int status = epoll_ctl(polling_fd, EPOLL_CTL_DEL, fd, &ev);
			if(status == -1) fprintf(stderr, "[remove_connection] epoll_ctl: %s\n", strerror(errno));

			// close connection (if its still open).
			connection->tcp_connection.close();

			// free connection memory.
			connections.remove(fd);
			delete connection;
		}
		void close_connection(HTTPConnection* connection) {
			remove_connection(connection);
		}
		void re_arm_connection(int fd, EPOLL_EVENTS events) {
			// re-arm fd in epool group.
			epoll_event ev;
			ev.events = EPOLL_EVENTS::EPOLLONESHOT | events;
			int status = epoll_ctl(polling_fd, EPOLL_CTL_MOD, fd, &ev);
			if(status == -1) fprintf(stderr, "[re_arm_connection] epoll_ctl: %s\n", strerror(errno));
		}
		void re_arm_connection_recv(HTTPConnection& connection, HTTP_CONNECTION_STATE new_state) {
			connection.state = new_state;
			re_arm_connection(connection.fd(), EPOLL_EVENTS::EPOLLIN);
		}
		void re_arm_connection_send(HTTPConnection& connection, HTTP_CONNECTION_STATE new_state) {
			connection.state = new_state;
			re_arm_connection(connection.fd(), EPOLL_EVENTS::EPOLLOUT);
		}


		// send+recv functions.
		int recv_until_block(HTTPConnection& connection, char* data, size_t& pos, const size_t end) {
			time64_ns t0 = time64_ns::now();
			ssize_t len = 1;
			while(pos < end) {
				len = connection.recv(data + pos, end - pos);
				if(len > 0) pos += len;
				else break;
			}
			connection.dt_recv = connection.dt_recv + (time64_ns::now() - t0);
			// error.
			if(len  < 0 && errno != EWOULDBLOCK) return -1;
			// socket closed.
			if(len == 0) return 0;
			// success.
			return 1;
		}
		int send_until_block(HTTPConnection& connection, const char* data, size_t& pos, const size_t end) {
			time64_ns t0 = time64_ns::now();
			ssize_t len = 1;
			while(pos < end) {
				len = connection.send(data + pos, end - pos);
				if(len > 0) pos += len;
				else break;
			}
			connection.dt_send = connection.dt_send + (time64_ns::now() - t0);
			// error.
			if(len  < 0 && errno != EWOULDBLOCK) return -1;
			// socket closed.
			if(len == 0) return 0;
			// success.
			return 1;
		}
		void on_socket_close(HTTPConnection& connection) {
			remove_connection(&connection);
		}
		void on_socket_error(HTTPConnection& connection) {
			fprintf(stdout, "[worker_loop] socket error during send/recv.\n");
			remove_connection(&connection);
		}

		// thread functions.
		static void accept_loop(HTTPServer* server, const TCPSocket* listen_socket) {
			while(true) {
				TCPSocket new_socket;
				if(try_to_accept(*listen_socket, new_socket) == EXIT_FAILURE) {
					fprintf(stderr, "error: failed to accept connection (err: %s)\n", strerror(errno));
					continue;
				}

				TCPConnection tcp_connection(new_socket);
				server->insert_connection_nonblocking(tcp_connection);
			}
		}
		static void accept_loop_TLS(HTTPServer* server, SSL_CTX *ctx, BIO* acceptor_bio) {
			while(true) {
				/* Pristine error stack for each new connection */
				ERR_clear_error();

				/* Wait for the next client to connect */
				if (BIO_do_accept(acceptor_bio) <= 0) {
					/* Client went away before we accepted the connection */
					continue;
				}

				std::thread handshake_thread(accept_loop_TLS_handshake_func, server, ctx, acceptor_bio);
				handshake_thread.detach();
			}
		}
		static void accept_loop_TLS_handshake_func(HTTPServer* server, SSL_CTX *ctx, BIO* acceptor_bio) {
			/* Pop the client connection from the BIO chain */
			BIO* client_bio = BIO_pop(acceptor_bio);
			fprintf(stderr, "New client connection accepted\n");

			/* Associate a new SSL handle with the new connection */
			SSL* ssl = SSL_new(ctx);
			if (ssl == NULL) {
				ERR_print_errors_fp(stderr);
				warnx("Error creating SSL handle for new connection");
				BIO_free(client_bio);
				return;
			}
			SSL_set_bio(ssl, client_bio, client_bio);

			/* Attempt an SSL handshake with the client */
			if (SSL_accept(ssl) <= 0) {
				ERR_print_errors_fp(stderr);
				warnx("Error performing SSL handshake with client");
				SSL_free(ssl);
				return;
			}

			TCPSocket new_socket;
			BIO_get_fd(client_bio, &new_socket.fd);
			TCP::get_peer_address_from_sockfd(new_socket.fd, new_socket.addr, new_socket.addrlen);
			TCPConnection tcp_connection(new_socket, ssl);
			server->insert_connection_nonblocking(tcp_connection);
		}
		static void polling_loop(HTTPServer* server) {
			server->polling_fd = epoll_create1(0);
			if(server->polling_fd == -1) {
				fprintf(stderr, "[polling_loop] epoll_create1: %s\n", strerror(errno));
				return;
			}

			while(true) {
				if(server->shutting_down && server->connections.map.size() == 0) return;
				std::array<epoll_event, 64> epoll_events;
				int n_events = epoll_wait(server->polling_fd, epoll_events.data(), epoll_events.size(), server->polling_timeout);
				if(n_events == -1) fprintf(stderr, "[polling_loop] epoll_wait: %s\n", strerror(errno));
				else for(int x=0;x<n_events;x++) {
					const epoll_event& ev = epoll_events[x];
					// TODO: this loop can be sped up by getting read/write locks once per batch,
					// rather than once per event.
					server->connections.get(ev.data.fd)->recent_epoll_events = ev.events;
					server->work_queue.push(ev.data.fd);
					//if(ev.events & (EPOLL_EVENTS::EPOLLIN | EPOLL_EVENTS::EPOLLOUT | EPOLL_EVENTS::EPOLLHUP | EPOLL_EVENTS::EPOLLERR)) {}
				}
			}

			int status = close(server->polling_fd);
			if(status == -1) fprintf(stderr, "[polling_loop] close: %s\n", strerror(errno));
		}
		void worker_func_cycle_start(HTTPConnection& connection) {
			connection.head_scan_cursor = 0;
			connection.send_head_cursor = 0;
			connection.send_body_cursor = 0;
			connection.dt_recv = 0;
			connection.dt_work = 0;
			connection.dt_send = 0;
			return worker_func_recv_head(connection);
		}
		void worker_func_recv_head(HTTPConnection& connection) {
			const size_t HE_LEN = HTTP_HEADER_END.length();
			MessageBuffer& recvbuf = connection.recv_buffer;

			// check if there is already a completed head in buffer.
			size_t end_pos;
			if(recvbuf.length > HE_LEN) {
				end_pos = recvbuf.view().find(HTTP_HEADER_END, connection.head_scan_cursor);
				connection.head_scan_cursor = recvbuf.length - HE_LEN;
			}

			// if not found, recv data until MAX_HEAD_LENGTH or EWOULDBLOCK.
			if(end_pos == string::npos) {
				recvbuf.reserve(MAX_HEAD_LENGTH);
				int success = recv_until_block(connection, recvbuf.data, recvbuf.length, MAX_HEAD_LENGTH);
				if(success == 0) return on_socket_close(connection);
				if(success <  0) return on_socket_error(connection);

				// try to find end of head again.
				if(recvbuf.length > HE_LEN) {
					const size_t end_pos = recvbuf.view().find(HTTP_HEADER_END, connection.head_scan_cursor);
					connection.head_scan_cursor = recvbuf.length - HE_LEN;
				}

				// check (and return early) if head was still not found.
				if(end_pos == string::npos) {
					// check if head is too long.
					if(recvbuf.length >= MAX_HEAD_LENGTH) {
						// TODO - check if URI is too long first to give more specific status-code.
						return worker_func_init_soft_error(connection, 431);// header fields too long.
					} else {
						// wait for more data.
						return re_arm_connection_recv(connection, WAITING_FOR_HEAD);
					}
				}
			}

			// parse head.
			http_request& request = connection.request;
			request.clear();

			const size_t head_length = end_pos + HE_LEN;
			request.head = recvbuf.view(0, head_length);
			const ERROR_CODE ec = parse_head(request.head, request);
			if(ec) return worker_func_init_soft_error(connection, 400);// mal-formatted request.

			const size_t body_length = request.headers.contains(HEADERS::content_length)
				? string_to_int(request.headers.at(HEADERS::content_length))
				: 0;
			request.body = recvbuf.view(head_length, body_length);// WARNING: this is set before buffer has been allocated & populated.
			if(body_length > MAX_BODY_LENGTH) return worker_func_init_soft_error(connection, 413);// body too long.
			if(body_length > 0)	return worker_func_recv_body(connection);
			else				return worker_func_handle_request(connection);
		}
		void worker_func_recv_body(HTTPConnection& connection) {
			MessageBuffer& recvbuf = connection.recv_buffer;

			const size_t head_length = connection.request.head.length();
			const size_t body_length = connection.request.body.length();
			const size_t total_length = head_length + body_length;
			if(recvbuf.length < total_length) {
				recvbuf.reserve(total_length);
				int success = recv_until_block(connection, recvbuf.data, recvbuf.length, total_length);
				if(success == 0) return on_socket_close(connection);
				if(success <  0) return on_socket_error(connection);
			}

			if(recvbuf.length >= total_length) {
				connection.buf_shift_length = total_length;
				return worker_func_handle_request(connection);
			}
			else return re_arm_connection_recv(connection, WAITING_FOR_BODY);
		}
		void worker_func_handle_request(HTTPConnection& connection) {
			time64_ns t0 = time64_ns::now();
			handle_request(connection, connection.response, connection.body_buffer);
			connection.dt_work = connection.dt_work + (time64_ns::now() - t0);

			connection.response.head = connection.head_buffer.view();
			connection.response.body = connection.body_buffer.view();

			// OPTIMIZATION: pack start of body into head for more efficient transmission.
			if(connection.body_buffer.length > 0) {
				MessageBuffer& headbuf = connection.head_buffer;
				MessageBuffer& bodybuf = connection.body_buffer;

				// copy data from body_buffer to head_buffer.
				size_t pack_length = std::min(headbuf.length + bodybuf.length, MAX_PACK_LENGTH);
				size_t copy_length = pack_length - headbuf.length;
				headbuf.reserve(pack_length);
				memcpy(headbuf.data + headbuf.length, bodybuf.data, copy_length * sizeof(bodybuf.data[0]));

				// update cursors and lengths.
				headbuf.length += copy_length;
				connection.send_body_cursor += copy_length;
			}

			worker_func_send_head(connection);
		}
		virtual void handle_request(const HTTPConnection& connection, http_response& response, MessageBuffer& body_buffer) {
			string data = "test abc 123 :)";

			response.clear();
			body_buffer.clear();

			response.status_code = 200;
			response.headers[HEADERS::content_type] = get_mime_type(".txt");
			response.headers[HEADERS::content_length] = int_to_string(data.length());
			body_buffer.append(data);
		}
		void worker_func_send_head(HTTPConnection& connection) {
			MessageBuffer& buffer = connection.head_buffer;
			size_t& cursor = connection.send_head_cursor;
			if(buffer.length == 0) worker_func_send_body(connection);

			int success = send_until_block(connection, buffer.data, cursor, buffer.length);
			if(success == 0) return on_socket_close(connection);
			if(success <  0) return on_socket_error(connection);

			if(cursor == buffer.length) worker_func_send_body(connection);
			else re_arm_connection_send(connection, WAITING_TO_SEND_HEAD);
		}
		void worker_func_send_body(HTTPConnection& connection) {
			MessageBuffer& buffer = connection.body_buffer;
			size_t& cursor = connection.send_body_cursor;
			if(buffer.length == 0) worker_func_send_body(connection);

			int success = send_until_block(connection, buffer.data, cursor, buffer.length);
			if(success == 0) return on_socket_close(connection);
			if(success <  0) return on_socket_error(connection);

			if(cursor == buffer.length) worker_func_cycle_end(connection);
			else re_arm_connection_send(connection, WAITING_TO_SEND_BODY);
		}
		void worker_func_init_soft_error(HTTPConnection& connection, const int status_code) {
			// set shift-length to clear recv_buffer.
			connection.buf_shift_length = connection.recv_buffer.length;

			// replace head buffer contents with error response.
			http_response response;
			response.status_code = status_code;
			response.status_text = STATUS_CODES.at(status_code);
			connection.head_buffer.clear();
			append_head(connection.head_buffer, response);

			connection.send_head_cursor = 0;
			return worker_func_send_soft_error(connection);
		}
		void worker_func_send_soft_error(HTTPConnection& connection) {
			MessageBuffer& buffer = connection.head_buffer;
			size_t& cursor = connection.send_head_cursor;

			int success = send_until_block(connection, buffer.data, cursor, buffer.length);
			if(success == 0) return on_socket_close(connection);
			if(success <  0) return on_socket_error(connection);

			if(cursor == buffer.length) close_connection(&connection);
			else re_arm_connection_send(connection, SOFT_ERROR);
		}
		void worker_func_send_hard_error(HTTPConnection& connection) {
			MessageBuffer& buffer = connection.head_buffer;
			size_t cursor = 0;

			// replace head buffer contents with error response.
			http_response response;
			response.status_code = 500;
			response.status_text = STATUS_CODES.at(500);
			buffer.clear();
			append_head(buffer, response);

			int success = send_until_block(connection, buffer.data, cursor, buffer.length);
			if(success == 0) return on_socket_close(connection);
			if(success <  0) return on_socket_error(connection);

			if(cursor != buffer.length) fprintf(stderr, "failed to send full hard error message.\n");
			close_connection(&connection);
		}
		void worker_func_cycle_end(HTTPConnection& connection) {
			// push log entry.
			http_request& request = connection.request;
			http_response& response = connection.response;
			printf("[%li] fd=%i, method=%s, status=%i, ip=%s, path=%s%s, reqlen=[%lu, %lu], reslen=[%lu, %lu], dt=[%li, %li, %li]\n",
				time64_ns::now().value_ms(),
				connection.fd(),
				request.method.c_str(),
				response.status_code,
				TCP::get_address_string(connection.tcp_connection.socket.addr).c_str(),
				request.path.c_str(),
				request.query.c_str(),
				request.head.length(),
				request.body.length(),
				response.head.length(),
				response.body.length(),
				connection.dt_recv.value_us(),
				connection.dt_work.value_us(),
				connection.dt_send.value_us()
			);
			// cleanup buffers.
			MessageBuffer& recv_buffer = connection.recv_buffer;
			MessageBuffer& head_buffer = connection.head_buffer;
			MessageBuffer& body_buffer = connection.body_buffer;
			recv_buffer.shift(connection.buf_shift_length);
			head_buffer.clear();
			body_buffer.clear();
			if(recv_buffer.capacity > BUFFER_SHRINK_CAPACITY) recv_buffer.set_capacity(std::max(recv_buffer.length, BUFFER_SHRINK_CAPACITY));
			if(body_buffer.capacity > BUFFER_SHRINK_CAPACITY) body_buffer.set_capacity(BUFFER_SHRINK_CAPACITY);
			// set next state.
			connection.state = START_OF_CYCLE;
		}
		void worker_func() {
			HTTPConnection* connection_ptr = connections.get(work_queue.pop());
			HTTPConnection& connection = *connection_ptr;
			const uint32_t events = connection.recent_epoll_events;
			const int conn_fd = connection.tcp_connection.socket.fd;
			try {
				if(events & EPOLL_EVENTS::EPOLLHUP) {
					fprintf(stdout, "[worker_loop] connection closed. fd=%i\n", conn_fd);
					remove_connection(connection_ptr);
					return;
				}
				if(events & EPOLL_EVENTS::EPOLLERR) {
					fprintf(stderr, "[worker_loop] connection error occurred. fd=%i\n", conn_fd);
					remove_connection(connection_ptr);
					return;
				}

				HTTP_CONNECTION_STATE& state = connection.state;
				//if(state == START_OF_CYCLE) worker_func_cycle_start(connection);
				if(state == WAITING_FOR_HEAD) worker_func_recv_head(connection);
				if(state == WAITING_FOR_BODY) worker_func_recv_body(connection);
				if(state == WAITING_TO_SEND_HEAD) worker_func_send_head(connection);
				if(state == WAITING_TO_SEND_BODY) worker_func_send_body(connection);
				if(state == SOFT_ERROR) worker_func_send_soft_error(connection);
				while(state == START_OF_CYCLE) worker_func_cycle_start(connection);
			} catch (const std::exception& e) {
				fprintf(stderr, "%s\n", e.what());
				try {
					worker_func_send_hard_error(connection);
				} catch (const std::exception& e) {
					fprintf(stderr, "%s\n", e.what());
				}
			}
		}
		static void worker_loop(HTTPServer* server) {
			while(true) {
				if(server->shutting_down && server->connections.map.size() == 0) return;
				server->worker_func();
			}
		}
		static void housekeeping_loop(HTTPServer* server) {// TODO
			while(true) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			}
		}
		void spawn_threads() {
			polling_thread = std::thread(polling_loop, this);
			for(int x=0;x<worker_thread_pool.size();x++) worker_thread_pool[x] = std::thread(worker_loop, this);
			housekeeping_loop(this);
		}
		void shutdown() {
			printf("shutting down...\n");
			shutting_down = true;
			printf("shutting down: accept thread.\n");
			accept_thread.join();
			printf("shutting down: worker threads.\n");
			// TODO - find way to add shutdown tasks to worker thread poll.
			for(int x=0;x<worker_thread_pool.size();x++) worker_thread_pool[x].join();
			printf("shutting down: polling thread.\n");
			polling_thread.join();
			printf("shutting down: DONE.\n");
		}


		/* start listening for connections. */
		int start_listen(bool expose_to_network) {

			addrinfo* results;
			const int addr_status = TCP::get_potential_socket_addresses_for_listening(portname, results, expose_to_network);
			if (addr_status != 0) {
				fprintf(stderr, "[get_potential_addresses_for_localhost] ERROR: %s\n", gai_strerror(addr_status));
				return EXIT_FAILURE;
			}

			TCPSocket listen_socket;
			if(try_to_listen(results, listen_socket, 5) != EXIT_SUCCESS) {
				fprintf(stderr, "error: failed to listen for connections (errno: %s)\n", strerror(errno));
				return EXIT_FAILURE;
			}
			printf("listening for connections on port %s (listen_sockfd: %i)\n", portname.c_str(), listen_socket.fd);
			printf("residual err: %s\n", strerror(errno));

			// free address-info chain.
			freeaddrinfo(results);

			// accept connections.
			accept_thread = std::thread(accept_loop, this, &listen_socket);
			spawn_threads();

			// Unreachable cleanup code.
			shutdown();
			close(listen_socket.fd);
			return EXIT_SUCCESS;
		}
		/* start listening for TCP/TLS connections.
			https://docs.openssl.org/master/man7/ossl-guide-tls-server-block/#simple-blocking-tls-server-example
			[git repo]/openssl-3.5.1/demos/guide/tls-server-block.c
		*/
		int start_listen_TLS(const string x509_cert_path, const string x509_pkey_path) {
			// make sure required certificate and key files exist.
			if(!(fs::exists(x509_cert_path) && fs::is_regular_file(x509_cert_path))) {
				fprintf(stderr, "x509 cert not found: %s\n", x509_cert_path.c_str());
				return EXIT_FAILURE;
			}
			if(!(fs::exists(x509_pkey_path) && fs::is_regular_file(x509_pkey_path))) {
				fprintf(stderr, "x509 private key not found: %s\n", x509_pkey_path.c_str());
				return EXIT_FAILURE;
			}

			/*
			* An SSL_CTX holds shared configuration information for multiple
			* subsequent per-client SSL connections.
			*/
			int status = EXIT_FAILURE;
			SSL_CTX *ctx = NULL;
			ctx = SSL_CTX_new(TLS_server_method());
			if (ctx == NULL) {
				ERR_print_errors_fp(stderr);
				errx(status, "Failed to create server SSL_CTX");
			}

			/*
			* TLS versions older than TLS 1.2 are deprecated by IETF and SHOULD
			* be avoided if possible.
			*/
			if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
				SSL_CTX_free(ctx);
				ERR_print_errors_fp(stderr);
				errx(status, "Failed to set the minimum TLS protocol version");
			}

			long opts;

			/*
			* Tolerate clients hanging up without a TLS "shutdown".  Appropriate in all
			* application protocols which perform their own message "framing", and
			* don't rely on TLS to defend against "truncation" attacks.
			*/
			opts = SSL_OP_IGNORE_UNEXPECTED_EOF;

			/*
			* Block potential CPU-exhaustion attacks by clients that request frequent
			* renegotiation.  This is of course only effective if there are existing
			* limits on initial full TLS handshake or connection rates.
			*/
			opts |= SSL_OP_NO_RENEGOTIATION;

			/*
			* Most servers elect to use their own cipher or group preference rather than
			* that of the client.
			*/
			opts |= SSL_OP_CIPHER_SERVER_PREFERENCE;

			/* Apply the selection options */
			SSL_CTX_set_options(ctx, opts);

			/*
			* Load the server's certificate *chain* file (PEM format), which includes
			* not only the leaf (end-entity) server certificate, but also any
			* intermediate issuer-CA certificates.  The leaf certificate must be the
			* first certificate in the file.
			*
			* In advanced use-cases this can be called multiple times, once per public
			* key algorithm for which the server has a corresponding certificate.
			* However, the corresponding private key (see below) must be loaded first,
			* *before* moving on to the next chain file.
			*/
			//if (SSL_CTX_use_certificate_chain_file(ctx, "chain.pem") <= 0) {
			if (SSL_CTX_use_certificate_chain_file(ctx, x509_cert_path.c_str()) <= 0) {
				SSL_CTX_free(ctx);
				ERR_print_errors_fp(stderr);
				errx(status, "Failed to load the server certificate chain file");
			}

			/*
			* Load the corresponding private key, this also checks that the private
			* key matches the just loaded end-entity certificate.  It does not check
			* whether the certificate chain is valid, the certificates could be
			* expired, or may otherwise fail to form a chain that a client can validate.
			*/
			//if (SSL_CTX_use_PrivateKey_file(ctx, "pkey.pem", SSL_FILETYPE_PEM) <= 0) {
			if (SSL_CTX_use_PrivateKey_file(ctx, x509_pkey_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
				SSL_CTX_free(ctx);
				ERR_print_errors_fp(stderr);
				errx(status, "Error loading the server private key file, possible key/cert mismatch???");
			}

			/*
			* Servers that want to enable session resumption must specify a cache id
			* byte array, that identifies the server application, and reduces the
			* chance of inappropriate cache sharing.
			*/
			SSL_CTX_set_session_id_context(ctx, (const unsigned char*)hostname.c_str(), (unsigned int)hostname.length());
			SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

			/*
			* How many client TLS sessions to cache.  The default is
			* SSL_SESSION_CACHE_MAX_SIZE_DEFAULT (20k in recent OpenSSL versions),
			* which may be too small or too large.
			*/
			SSL_CTX_sess_set_cache_size(ctx, 2048);

			/*
			* Sessions older than this are considered a cache miss even if still in
			* the cache.  The default is two hours.  Busy servers whose clients make
			* many connections in a short burst may want a shorter timeout, on lightly
			* loaded servers with sporadic connections from any given client, a longer
			* time may be appropriate.
			*/
			SSL_CTX_set_timeout(ctx, 3600);

			/*
			* Clients rarely employ certificate-based authentication, and so we don't
			* require "mutual" TLS authentication (indeed there's no way to know
			* whether or how the client authenticated the server, so the term "mutual"
			* is potentially misleading).
			*
			* Since we're not soliciting or processing client certificates, we don't
			* need to configure a trusted-certificate store, so no call to
			* SSL_CTX_set_default_verify_paths() is needed.  The server's own
			* certificate chain is assumed valid.
			*/
			SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

			/*
			* Create a listener socket wrapped in a BIO.
			* The first call to BIO_do_accept() initialises the socket
			*/
			BIO* acceptor_bio;
			acceptor_bio = BIO_new_accept(portname.c_str());
			if (acceptor_bio == NULL) {
				SSL_CTX_free(ctx);
				ERR_print_errors_fp(stderr);
				errx(status, "Error creating acceptor bio");
			}

			BIO_set_bind_mode(acceptor_bio, BIO_BIND_REUSEADDR);
			if (BIO_do_accept(acceptor_bio) <= 0) {
				SSL_CTX_free(ctx);
				ERR_print_errors_fp(stderr);
				errx(status, "Error setting up acceptor socket");
			}

			int listen_fd;
			BIO_get_fd(acceptor_bio, listen_fd);
			printf("listening for connections on port %s (listen_sockfd: %i)\n", portname.c_str(), listen_fd);
			printf("residual err: %s\n", strerror(errno));

			// accept connections.
			accept_thread = std::thread(accept_loop_TLS, this, ctx, acceptor_bio);
			spawn_threads();

			/* Unreachable placeholder cleanup code, the above loop runs forever. */
			shutdown();
			SSL_CTX_free(ctx);
			return EXIT_SUCCESS;
		}
	};
}

#endif
