
#include <cstring>
#include <string>
#include <map>
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
		// recv until completed head, or socket blocks.
		WAITING_FOR_HEAD,
		// recv until completed body, or socket blocks.
		WAITING_FOR_BODY,
		// (intermediate state.)
		BEING_PROCESSED,
		// send until head is sent, or socket blocks.
		WAITING_TO_SEND_HEAD,
		// send until body is sent, or socket blocks.
		WAITING_TO_SEND_BODY,
		// a polling/worker thread discovered that socket is closed.
		CLOSED,
	};

	/*
		a struct containing sockets, buffers, and statistics associated
		with a given connection.
	*/
	struct HTTPConnection {
		TCPConnection tcp_connection;
		HTTP_CONNECTION_STATE state = WAITING_FOR_HEAD;
		MessageBuffer recv_buffer;
		MessageBuffer head_buffer;
		MessageBuffer body_buffer;
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

		ssize_t send(const char* src, const size_t count) {
			return tcp_connection.send(src, count);
		}
		ssize_t recv(char* dst, const size_t count) {
			return tcp_connection.recv(dst, count);
		}
	};
};
