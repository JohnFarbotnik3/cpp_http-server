
#include <cstring>
#include <string>
#include <map>
#include <string_view>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "src/MessageBuffer.cpp"
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
		string		path;	// target path, ex: "/files/images/image.png".
		string		query;	// target query, ex: "?abc=123&def=456".
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

	enum HTTP_CONNECTION_STATE {
		// start of request-response cycle.
		START_OF_CYCLE,
		// recv until completed head, or socket blocks.
		WAITING_FOR_HEAD,
		// (intermediate state.)
		PARSING_HEAD,
		// recv until completed body, or socket blocks.
		WAITING_FOR_BODY,
		// (intermediate state.)
		HANDLING_REQUEST,
		// send until head is sent, or socket blocks.
		WAITING_TO_SEND_HEAD,
		// send until body is sent, or socket blocks.
		WAITING_TO_SEND_BODY,
		// a soft error occurred during cycle - try to send error response.
		SOFT_ERROR,
		// a polling/worker thread discovered that socket is closed.
		CLOSED,
	};

	const size_t KB = 1024;
	const size_t MB = 1024 * 1024;
	const size_t MAX_HEAD_LENGTH = 16 * KB;
	const size_t MAX_BODY_LENGTH = 128 * MB;
	const size_t MAX_PACK_LENGTH = 64 * KB;
	const size_t BUFFER_SHRINK_CAPACITY = 64 * KB;

	/*
		a struct containing sockets, buffers, and statistics associated
		with a given connection.
	*/
	struct HTTPConnection {
		TCPConnection tcp_connection;
		uint32_t recent_epoll_events;
		HTTP_CONNECTION_STATE state = START_OF_CYCLE;
		MessageBuffer recv_buffer;
		MessageBuffer head_buffer;
		MessageBuffer body_buffer;
		size_t head_scan_cursor;// scan start-position when searching for end of message-head.
		size_t recv_length_head;// length of head.
		size_t recv_length_body;// expected length of body.
		size_t send_cursor_head;// amount of head data sent.
		size_t send_cursor_body;// amount of body data sent.
		http_request request;
		http_response response;
		time64_ns date_created = time64_ns::now();
		time64_ns dt_recv = 0;
		time64_ns dt_work = 0;
		time64_ns dt_send = 0;


		HTTPConnection(TCPConnection tcp_connection, size_t rbuf_size, size_t hbuf_size, size_t bbuf_size) :
			tcp_connection(tcp_connection),
			recv_buffer(rbuf_size),
			head_buffer(hbuf_size),
			body_buffer(bbuf_size)
		{}

		int fd() {
			return tcp_connection.socket.fd;
		}

		ssize_t send(const char* src, const size_t count) {
			return tcp_connection.send(src, count);
		}
		ssize_t recv(char* dst, const size_t count) {
			return tcp_connection.recv(dst, count);
		}

		void send_cleanup() {
			head_buffer.clear();
			body_buffer.clear();
			if(body_buffer.capacity > BUFFER_SHRINK_CAPACITY) body_buffer.set_capacity(BUFFER_SHRINK_CAPACITY);
		}
		void recv_cleanup(const size_t recv_message_length) {
			recv_buffer.shift(recv_message_length);
			if(recv_buffer.capacity > BUFFER_SHRINK_CAPACITY) recv_buffer.set_capacity(std::max(recv_buffer.length, BUFFER_SHRINK_CAPACITY));
		}
	};
};
