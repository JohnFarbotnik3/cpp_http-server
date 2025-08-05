
#include <cstring>
#include <string>
#include <map>
#include <sys/socket.h>
#include "src/tcp_structs.cpp"

namespace HTTP {
	using std::string;
	using std::string_view;
	using TCP::tcp_connection_struct;

	const string HTTP_PROTOCOL_1_1 = "HTTP/1.1";

	using header_dict = std::map<string, string>;

	struct http_request {
		string_view	head;
		string_view	body;
		// start line.
		string		method;
		string		target;
		string		protocol;
		// headers.
		header_dict	headers;
	};

	struct http_response {
		string_view	head;
		string_view	body;
		// start line.
		string	protocol = HTTP_PROTOCOL_1_1;
		int		status_code;
		string	status_text;
		// headers.
		header_dict	headers;
	};

	struct MessageBuffer {
		char* data;
		size_t capacity;
		size_t length;

		MessageBuffer(int capacity) {
			this->data = new char[capacity];
			this->capacity = capacity;
			this->length = 0;
		}
		~MessageBuffer() {
			delete[] data;
		}

		void clear() {
			length = 0;
		}

		void set_capacity(size_t new_capacity) {
			char* new_data = new char[new_capacity];
			size_t new_length = std::min(length, new_capacity);
			memcpy(new_data, data, new_length * sizeof(data[0]));
			delete[] data;
			data		= new_data;
			capacity	= new_capacity;
			length		= new_length;
		}
		void reserve(size_t new_capacity) {
			if(new_capacity > capacity) set_capacity(new_capacity);
		}

		void resize(size_t new_length) {
			reserve(new_length);
			length = new_length;
		}

		string_view view() const {
			return string_view(data, length);
		}
		string_view view(size_t ofs, size_t len) const {
			return string_view(data+ofs, len);
		}

		void append(const string& str) {
			memcpy(data+length, str.data(), str.length() * sizeof(str[0]));
			length += str.length();
		}

		void shift(size_t count) {
			memmove(data, data+count, length-count);
			length -= count;
		}
	};

	enum HTTP_CONNECTION_STATE {
		CREATED,
		RECIEVING_REQUEST,
		HANDLING_REQUEST,
		SENDING_RESPONSE,
		THREAD_EXITED,
	};

	/*
		a struct containing sockets, buffers, and statistics associated
		with a given connection.
	*/
	struct HTTPConnection {
		tcp_connection_struct tcp_connection;
		MessageBuffer recv_buffer;
		MessageBuffer head_buffer;
		MessageBuffer body_buffer;
		size_t total_bytes_send = 0;
		size_t total_bytes_recv = 0;
		bool closed = false;// true if worker thread has exited.
		//time64_t date_created;
		//time64_t date_recent_activity;
		//time64_t keep_alive;

		HTTPConnection(tcp_connection_struct tcp_connection, size_t rbuf_size, size_t hbuf_size, size_t bbuf_size) :
			tcp_connection(tcp_connection),
			recv_buffer(rbuf_size),
			head_buffer(hbuf_size),
			body_buffer(bbuf_size)
		{}

		virtual ssize_t recv(char* dst, const size_t count) {
			ssize_t len = ::recv(tcp_connection.sockfd, dst, count, 0);
			if(len > 0) total_bytes_recv += len;
			return len;
		}
		virtual ssize_t send(const char* src, const size_t count) {
			ssize_t len = ::send(tcp_connection.sockfd, src, count, 0);
			if(len > 0) total_bytes_send += len;
			return len;
		}

		// TODO - close method to call after keep-alive time has been exeeded.
		virtual void close_timeout() {}

		// TODO - close method to call if abuse was detected by housekeeping thread.
		virtual void close_abuse() {}
	};

	/*
		a map of HTTPConnections.

		these connections are accessed and updated by worker threads,
		then marked as closed once worker thread exits.

		the Server will have a housekeeping thread which manages a vector
		(and a freelist) of HTTPConnections, removing connections
	*/
	struct HTTPConnectionMap {};

};
