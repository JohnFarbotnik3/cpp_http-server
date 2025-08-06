
#include <cstring>
#include <string>
#include <map>
#include <sys/socket.h>
#include "src/tcp_structs.cpp"
#include "src/utils/time_util.cpp"

namespace HTTP {
	using std::string;
	using std::string_view;
	using TCP::TCPConnection;
	using utils::time_util::time64_ns;

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
			reserve(length + str.length());
			memcpy(data+length, str.data(), str.length() * sizeof(str[0]));
			length += str.length();
		}

		void shift(size_t count) {
			memmove(data, data+count, length-count);
			length -= count;
		}
	};

	/*
		a struct containing sockets, buffers, and statistics associated
		with a given connection.
	*/
	struct HTTPConnection {
		TCPConnection tcp_connection;
		MessageBuffer recv_buffer;
		MessageBuffer head_buffer;
		MessageBuffer body_buffer;
		bool worker_thread_exited = false;
		bool is_sending = false;
		bool is_recving = false;
		time64_ns date_created;
		time64_ns send_t0;
		time64_ns send_t1;
		time64_ns recv_t0;
		time64_ns recv_t1;

		HTTPConnection(TCPConnection tcp_connection, size_t rbuf_size, size_t hbuf_size, size_t bbuf_size) :
			tcp_connection(tcp_connection),
			recv_buffer(rbuf_size),
			head_buffer(hbuf_size),
			body_buffer(bbuf_size),
			date_created(time64_ns::now())
		{}

		ssize_t send(const char* src, const size_t count) {
			return tcp_connection.send(src, count);
		}
		ssize_t recv(char* dst, const size_t count) {
			return tcp_connection.recv(dst, count);
		}

		void on_send_starting() { send_t0 = time64_ns::now(); is_sending = true; }
		void on_send_finished() { send_t1 = time64_ns::now(); is_sending = false; }
		void on_recv_starting() { recv_t0 = time64_ns::now(); is_recving = true; }
		void on_recv_finished() { recv_t1 = time64_ns::now(); is_recving = false; }
		bool is_send_too_slow(size_t min_rate) {
			size_t length = head_buffer.length + body_buffer.length;
			size_t rate = (length * 1000000000) / (time64_ns::now() - send_t0).value_ns();
			return rate < min_rate;
		}
		bool is_recv_too_slow(size_t min_rate, time64_ns keep_alive) {
			if(time64_ns::now() < (recv_t0 + keep_alive)) return false;
			size_t length = recv_buffer.length;
			size_t rate = (length * 1000000000) / (time64_ns::now() - keep_alive - recv_t0).value_ns();
			return rate < min_rate;
		}
	};

	/*
		a map of HTTPConnections.

		these connections are accessed and updated by worker threads,
		then marked as closed once worker thread exits.

		the Server will have a housekeeping thread which manages a vector
		(and a freelist) of HTTPConnections, removing connections
	*/
	struct HTTPConnectionMap {};// TODO

};
