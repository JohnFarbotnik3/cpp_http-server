
#ifndef F_http_message_cpp
#define F_http_message_cpp

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <map>
#include "src/utils/string_util.cpp"
#include "src/definitions/headers.cpp"
#include "src/definitions/status_codes.cpp"

//#include <sys/epoll.h>
//#include <sys/socket.h>
#include "src/MessageBuffer.cpp"
#include "src/tcp_util.cpp"
#include "src/utils/time_util.cpp"

namespace HTTP {
	using std::string;
	using std::string_view;
	using namespace utils::string_util;
	using utils::time_util::time64_ns;

	const string HTTP_HEADER_NEWLINE	= "\r\n";
	const string HTTP_HEADER_END		= "\r\n\r\n";
	const string HTTP_PROTOCOL_1_1 = "HTTP/1.1";

	const size_t KB = 1024;
	const size_t MB = 1024 * 1024;
	const size_t MAX_HEAD_LENGTH = 16 * KB;
	const size_t MAX_BODY_LENGTH = 128 * MB;
	const size_t MAX_PACK_LENGTH = 64 * KB;
	const size_t BUFFER_SHRINK_CAPACITY = 64 * KB;


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
		// recv until completed body, or socket blocks.
		WAITING_FOR_BODY,
		// send until head is sent, or socket blocks.
		WAITING_TO_SEND_HEAD,
		// send until body is sent, or socket blocks.
		WAITING_TO_SEND_BODY,
		// a soft error occurred during cycle - try to send error response.
		SOFT_ERROR,
	};
	struct HTTPConnection {
		TCP::TCPConnection tcp_connection;
		uint32_t recent_epoll_events;
		HTTP_CONNECTION_STATE state = START_OF_CYCLE;
		MessageBuffer recv_buffer;
		MessageBuffer head_buffer;
		MessageBuffer body_buffer;
		size_t head_scan_cursor;// scan start-position when searching for end of message-head.
		size_t recv_length_head;// length of head.
		size_t recv_length_body;// expected length of body.
		size_t send_head_cursor;// amount of head data sent.
		size_t send_body_cursor;// amount of body data sent.
		http_request request;
		http_response response;
		time64_ns date_created = time64_ns::now();
		//time64_ns dt_recv = 0;
		//time64_ns dt_work = 0;
		//time64_ns dt_send = 0;


		HTTPConnection(TCP::TCPConnection tcp_connection, size_t rbuf_size, size_t hbuf_size, size_t bbuf_size) :
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
	};


	enum ERROR_CODE {
		SUCCESS = 0,
		MISSING_START_NEWLINE,
		MISSING_START_DELIM,
		MISSING_HEADER_NEWLINE,
		MISSING_HEADER_DELIM,
	};
	const std::map<ERROR_CODE, string> ERROR_MESSAGE {
		{SUCCESS				, "SUCCESS"},
		{MISSING_START_NEWLINE	, "MISSING_START_NEWLINE"},
		{MISSING_START_DELIM	, "MISSING_START_DELIMITER"},
		{MISSING_HEADER_NEWLINE	, "MISSING_HEADER_NEWLINE"},
		{MISSING_HEADER_DELIM	, "MISSING_HEADER_DELIMITER"},
	};


	int64_t string_to_int(const string& str) {
		const int64_t value = std::stoll(str);
		return value;
	}
	int64_t string_to_int(const string_view& str) {
		return string_to_int(string(str));
	}
	string int_to_string(const size_t val) {
		char temp[32];
		int len = snprintf(temp, 32, "%lu", val);
		return string(temp, len);
	}
	string int_to_string(const int64_t val) {
		char temp[32];
		int len = snprintf(temp, 32, "%li", val);
		return string(temp, len);
	}
	string int_to_string(const int32_t val) {
		char temp[24];
		int len = snprintf(temp, 24, "%i", val);
		return string(temp, len);
	}


	void append_head(MessageBuffer& buffer, const http_request& request) {
		// append start line.
		buffer.append(request.method);
		buffer.append(" ");
		buffer.append(request.path);
		buffer.append(request.query);
		buffer.append(" ");
		buffer.append(request.protocol);
		buffer.append(HTTP_HEADER_NEWLINE);
		// append headers.
		for(const auto& [key,val] : request.headers) {
			buffer.append(key);
			buffer.append(": ");
			buffer.append(val);
			buffer.append(HTTP_HEADER_NEWLINE);
		}
		buffer.append(HTTP_HEADER_NEWLINE);
	}
	void append_head(MessageBuffer& buffer, const http_response& response) {
		// append start line.
		buffer.append(response.protocol);
		buffer.append(" ");
		buffer.append(int_to_string(response.status_code));
		buffer.append(" ");
		buffer.append(STATUS_CODES.at(response.status_code));
		buffer.append(HTTP_HEADER_NEWLINE);
		// append headers.
		for(const auto& [key,val] : response.headers) {
			buffer.append(key);
			buffer.append(": ");
			buffer.append(val);
			buffer.append(HTTP_HEADER_NEWLINE);
		}
		buffer.append(HTTP_HEADER_NEWLINE);
	}
	ERROR_CODE parse_head(const string_view& head, http_request& request) {
		size_t line_beg;
		size_t line_end;
		string_view line;
		line_beg = 0;
		line_end = head.find(HTTP_HEADER_NEWLINE, line_beg);
		if(line_end == string::npos) return ERROR_CODE::MISSING_START_NEWLINE;
		line = head.substr(line_beg, line_end - line_beg);

		// parse start line.
		{
			size_t a,b;
			a = 0;
			b = line.find(' ', a);
			if(b == string::npos) return ERROR_CODE::MISSING_START_DELIM;
			request.method = to_uppercase_ascii_sv(line.substr(a, b-a));
			a = b + 1;
			b = line.find(' ', a);
			if(b == string::npos) return ERROR_CODE::MISSING_START_DELIM;
			const size_t x = line.find('?', a);
			if(a < x && x < b) {
				request.path  = line.substr(a, x-a);
				request.query = line.substr(x, b-x);
			} else {
				request.path  = line.substr(a, b-a);
				request.query = "";
			}
			a = b + 1;
			b = line.length();
			request.protocol = to_uppercase_ascii_sv(line.substr(a, b-a));
		}

		// parse headers.
		while(true) {
			line_beg = line_end + HTTP_HEADER_NEWLINE.length();
			line_end = head.find(HTTP_HEADER_NEWLINE, line_beg);
			if(line_end == string::npos) return ERROR_CODE::MISSING_HEADER_NEWLINE;
			if(line_end == line_beg) break;
			line = head.substr(line_beg, line_end - line_beg);
			const size_t a = 0;
			const size_t x = line.find(':');
			const size_t b = line.length();
			if(x == string::npos) return ERROR_CODE::MISSING_HEADER_DELIM;
			const string key = string(line.substr(a, x-a));
			const string val = string(line.substr(x+1, b-(x+1)));
			request.headers[to_lowercase_ascii(key)] = val;
		}

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE parse_head(const string_view& head, http_response& response) {
		size_t line_beg;
		size_t line_end;
		string_view line;
		line_beg = 0;
		line_end = head.find(HTTP_HEADER_NEWLINE, line_beg);
		if(line_end == string::npos) return ERROR_CODE::MISSING_START_NEWLINE;
		line = head.substr(line_beg, line_end - line_beg);

		// parse start line.
		{
			size_t a,b;
			a = 0;
			b = line.find(' ', a);
			if(b == string::npos) return ERROR_CODE::MISSING_START_DELIM;
			response.protocol = to_uppercase_ascii_sv(line.substr(a, b-a));
			a = b + 1;
			b = line.find(' ', a);
			if(b == string::npos) return ERROR_CODE::MISSING_START_DELIM;
			response.status_code = string_to_int(line.substr(a, b-a));
			a = b + 1;
			b = line.length();
			response.status_text = to_uppercase_ascii_sv(line.substr(a, b-a));
		}

		// parse headers.
		while(true) {
			line_beg = line_end + HTTP_HEADER_NEWLINE.length();
			line_end = head.find(HTTP_HEADER_NEWLINE, line_beg);
			if(line_end == string::npos) return ERROR_CODE::MISSING_HEADER_NEWLINE;
			if(line_end == line_beg) break;
			line = head.substr(line_beg, line_end - line_beg);
			const size_t a = 0;
			const size_t x = line.find(':');
			const size_t b = line.length();
			if(x == string::npos) return ERROR_CODE::MISSING_HEADER_DELIM;
			const string key = string(line.substr(a, x-a));
			const string val = string(line.substr(x+1, b-(x+1)));
			response.headers[to_lowercase_ascii(key)] = val;
		}

		return ERROR_CODE::SUCCESS;
	}

}

#endif
