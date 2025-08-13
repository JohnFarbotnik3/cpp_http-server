/*
This was written with the help of the following guides:
<Beej's networking guide (c)>
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <filesystem>
#include "src/tcp_structs.cpp"
#include "src/tcp_util.cpp"

#include <err.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


namespace TCP {
	using string = std::string;
	namespace fs = std::filesystem;

	struct TCPServer {
		const string	hostname;
		const string	portname;

		TCPServer(const string hostname, const string portname) :
			hostname(hostname),
			portname(portname)
		{}

		/* start listening for connections. */
		int start_listen(bool expose_to_network) {

			addrinfo* results;
			const int addr_status = get_potential_socket_addresses_for_listening(portname, results, expose_to_network);
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
			while(true) {
				TCPSocket new_socket;
				if(try_to_accept(listen_socket, new_socket) == EXIT_FAILURE) {
					fprintf(stderr, "error: failed to accept connection (err: %s)\n", strerror(errno));
					continue;
				}

				TCPConnection new_connection(new_socket);
				std::thread worker_thread(&TCPServer::accept_connection, this, new_connection);
				worker_thread.detach();
			}

			// Unreachable cleanup code.
			close(listen_socket.fd);
			return EXIT_SUCCESS;
		}

		/*
			start listening for TCP/TLS connections.

			sources:
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
			while(true) {
				/* Pristine error stack for each new connection */
				ERR_clear_error();

				/* Wait for the next client to connect */
				if (BIO_do_accept(acceptor_bio) <= 0) {
					/* Client went away before we accepted the connection */
					continue;
				}

				/* Pop the client connection from the BIO chain */
				BIO* client_bio = BIO_pop(acceptor_bio);
				fprintf(stderr, "New client connection accepted\n");

				/* Associate a new SSL handle with the new connection */
				SSL* ssl = SSL_new(ctx);
				if (ssl == NULL) {
					ERR_print_errors_fp(stderr);
					warnx("Error creating SSL handle for new connection");
					BIO_free(client_bio);
					continue;
				}
				SSL_set_bio(ssl, client_bio, client_bio);

				/* Attempt an SSL handshake with the client */
				if (SSL_accept(ssl) <= 0) {
					ERR_print_errors_fp(stderr);
					warnx("Error performing SSL handshake with client");
					SSL_free(ssl);
					continue;
				}

				TCPSocket new_socket;
				BIO_get_fd(client_bio, &new_socket.fd);
				get_peer_address_from_sockfd(new_socket.fd, new_socket.addr, new_socket.addrlen);
				TCPConnection new_connection(new_socket, ssl);

				std::thread worker_thread(&TCPServer::accept_connection_TLS, this, new_connection);
				worker_thread.detach();
			}

			/*
			* Unreachable placeholder cleanup code, the above loop runs forever.
			*/
			SSL_CTX_free(ctx);
			return EXIT_SUCCESS;
		}

		void accept_connection(TCPConnection new_connection) {
			this->handle_connection(new_connection);
			close(new_connection.socket.fd);
		}

		void accept_connection_TLS(TCPConnection new_connection) {
			this->handle_connection(new_connection);
			SSL_free(new_connection.ssl);
		}

		virtual void handle_connection(TCPConnection connection) {
			printf("accepted TCP connection\n");
			printf("\tsockfd: %i\n", connection.socket.fd);
			printf("\tipaddr: %s\n", get_address_string(connection.socket.addr).c_str());
		}
	};

}



