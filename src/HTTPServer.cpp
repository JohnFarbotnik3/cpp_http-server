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
#include <semaphore>
#include <string>
#include <thread>
#include <filesystem>

#include "src/tcp_structs.cpp"
#include "src/tcp_util.cpp"
#include "src/http_util.cpp"
#include "src/definitions/mime_types.cpp"
#include "src/definitions/headers.cpp"
#include "src/utils/time_util.cpp"
#include "src/SharedVectorSet.cpp"
#include "src/SharedQueue.cpp"
#include "src/SharedMap.cpp"

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
	namespace fs = std::filesystem;

	struct HTTPServer {
		const string hostname;
		const string portname;
		SharedMap<int, HTTPConnection*> connections;
		SharedVectorSet<int> recv_set;// list of connections blocked on recv.
		SharedVectorSet<int> send_set;// list of connections blocked on send.
		SharedQueue<int> work_queue;// list of connections ready to send, recv, or process.
		std::vector<std::thread> worker_thread_pool;
		std::thread polling_thread_accept;
		std::thread polling_thread_recv;
		std::thread polling_thread_send;
		int polling_timeout;
		bool shutting_down;

		HTTPServer(const string hostname, const string portname, const int n_accept_threads, const int n_worker_threads):
			hostname(hostname),
			portname(portname),
			worker_thread_pool(n_worker_threads),
			shutting_down(false)
		{}


		void insert_connection(TCPConnection tcp_connection) {
			HTTPConnection* http_connection = new HTTPConnection(tcp_connection, MAX_HEAD_LENGTH, MAX_HEAD_LENGTH, 0);
			const int fd = tcp_connection.socket.fd;
			connections.set(fd, http_connection);
			recv_set.insert(fd);
		}
		void remove_connection(int fd) {
			connections.remove(fd);
		}


		static void accept_loop(HTTPServer* server, const TCPSocket* listen_socket) {
			while(true) {
				TCPSocket new_socket;
				if(try_to_accept(*listen_socket, new_socket) == EXIT_FAILURE) {
					fprintf(stderr, "error: failed to accept connection (err: %s)\n", strerror(errno));
					continue;
				}

				TCPConnection tcp_connection(new_socket);
				server->insert_connection(tcp_connection);
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
			server->insert_connection(tcp_connection);
		}
		// TODO - continue from here...
		static void recv_polling_loop(HTTPServer* server) {
			while(true) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			}
		}// TODO
		static void send_polling_loop(HTTPServer* server) {
			while(true) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			}
		}// TODO
		static void worker_loop(HTTPServer* server) {
			while(true) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			}
		}// TODO
		static void housekeeping_loop(HTTPServer* server) {
			while(true) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			}
		}// TODO
		void spawn_threads() {
			polling_thread_recv = std::thread(recv_polling_loop, this);
			polling_thread_send = std::thread(send_polling_loop, this);
			for(int x=0;x<worker_thread_pool.size();x++) worker_thread_pool[x] = std::thread(worker_loop, this);
			housekeeping_loop(this);
		}
		void shutdown() {
			printf("shutting down...\n");
			shutting_down = true;
			printf("shutting down: accept thread.\n");
			polling_thread_accept.join();
			printf("shutting down: recv polling thread.\n");
			polling_thread_recv.join();
			printf("shutting down: send polling thread.\n");
			polling_thread_send.join();
			printf("shutting down: worker threads.\n");
			for(int x=0;x<worker_thread_pool.size();x++) worker_thread_pool[x].join();
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
			polling_thread_accept = std::thread(accept_loop, this, &listen_socket);
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
			polling_thread_accept = std::thread(accept_loop_TLS, this, ctx, acceptor_bio);
			spawn_threads();

			/* Unreachable placeholder cleanup code, the above loop runs forever. */
			shutdown();
			SSL_CTX_free(ctx);
			return EXIT_SUCCESS;
		}


		void accept_connection(TCPConnection new_connection) {
			this->handle_connection(new_connection);
			new_connection.close();
		}
		void accept_connection_TLS(TCPConnection new_connection) {
			this->handle_connection(new_connection);
			new_connection.close();
		}


		void on_soft_http_error(HTTPConnection& connection, const int status_code, const ERROR_CODE err) {
			fprintf(stderr, "soft error during handle_connection(): %s\n", ERROR_MESSAGE.at(err).c_str());
			fprintf(stderr, "most recent errno: %s\n", strerror(errno));

			// attempt to notify client of server error.
			http_response response;
			response.protocol = HTTP_PROTOCOL_1_1;
			response.status_code = status_code;
			MessageBuffer headbuf(MAX_HEAD_LENGTH);
			MessageBuffer bodybuf(0);
			ERROR_CODE notify_err = send_http_response(connection, response, headbuf, bodybuf);
		}
		void on_hard_http_error(HTTPConnection& connection, const int status_code, const ERROR_CODE err) {
			fprintf(stderr, "HARD ERROR during handle_connection(): %s\n", ERROR_MESSAGE.at(err).c_str());
			fprintf(stderr, "most recent errno: %s\n", strerror(errno));

			// attempt to notify client of server error.
			http_response response;
			response.protocol = HTTP_PROTOCOL_1_1;
			response.status_code = status_code;
			MessageBuffer headbuf(MAX_HEAD_LENGTH);
			MessageBuffer bodybuf(0);
			ERROR_CODE notify_err = send_http_response(connection, response, headbuf, bodybuf);
		}


		void handle_connection(TCP::TCPConnection connection) {
			HTTPConnection http_connection(connection, MAX_HEAD_LENGTH, MAX_HEAD_LENGTH, 0);
			MessageBuffer& recvbuf = http_connection.recv_buffer;
			MessageBuffer& headbuf = http_connection.head_buffer;
			MessageBuffer& bodybuf = http_connection.body_buffer;
			ERROR_CODE err;
			try {
				const string ipstr = TCP::get_address_string(connection.socket.addr);
				printf("accepted HTTP connection | fd: %i, addr: %s\n", connection.socket.fd, ipstr.c_str());

				while(true) {
					time64_ns t0;

					// get request.
					http_request request;
					size_t request_length;
					http_connection.on_recv_starting();
					err = recv_http_request(http_connection, recvbuf, request, request_length);
					http_connection.on_recv_finished();
					if(err != ERROR_CODE::SUCCESS) { on_soft_http_error(http_connection, 400, err); break; }

					// generate response.
					t0 = time64_ns::now();
					http_response response = handle_request(request, bodybuf);
					if(err != ERROR_CODE::SUCCESS) { on_soft_http_error(http_connection, 500, err); break; }
					time64_ns dt_handle = time64_ns::now() - t0;

					// send response.
					http_connection.on_send_starting();
					err = send_http_response(http_connection, response, headbuf, bodybuf);
					http_connection.on_send_finished();
					if(err != ERROR_CODE::SUCCESS) { on_soft_http_error(http_connection, 500, err); break; }
					time64_ns dt_send = http_connection.send_t1 - http_connection.send_t0;

					// push log entry.
					printf("[%li] fd=%i, method=%s, status=%i, ip=%s, path=%s%s, reqlen=[%lu, %lu], reslen=[%lu, %lu], dt=[%li, %li]\n",
						time64_ns::now().value_ms(),
						connection.socket.fd,
						request.method.c_str(),
						response.status_code,
						ipstr.c_str(),
						request.path.c_str(),
						request.query.c_str(),
						request.head.length(),
						request.body.length(),
						headbuf.length,
						bodybuf.length,
						dt_handle.value_us(),
						dt_send.value_us()
					);

					recv_cleanup(recvbuf, request_length);
					send_cleanup(headbuf, bodybuf);
				}
			} catch (const std::exception& e) {
				fprintf(stderr, "%s\n", e.what());
				try {
					on_hard_http_error(http_connection, 500, err);
				} catch (const std::exception& e) {
					fprintf(stderr, "%s\n", e.what());
				}
			}
		}
		virtual http_response handle_request(const http_request& request, MessageBuffer& body_buffer) {
			http_response response;
			int status_code = 200;
			string data = "test abc 123 :)";
			response.headers[HEADERS::content_type] = get_mime_type(".txt");
			response.headers[HEADERS::content_length] = int_to_string(data.length());
			body_buffer.append(data);
			return response;
		}
	};
}

#endif
