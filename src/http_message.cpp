#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
namespace sys {
	#include <sys/socket.h>
}
#include "src/utils/string_util.cpp"
#include "src/definitions/headers.cpp"
#include "src/definitions/status_codes.cpp"

namespace HTTP {
	using std::string;
	using std::string_view;
	using namespace utils::string_util;

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
		// headers.
		header_dict	headers;
	};

	enum ERROR_CODE {
		SUCCESS = 0,
		UNKNOWN_ERROR,
		SEND_CLOSED,
		SEND_ERROR,
		RECV_CLOSED_DURING_HEAD,
		RECV_CLOSED_DURING_BODY,
		RECV_ERROR_DURING_HEAD,
		RECV_ERROR_DURING_BODY,
		ERR_MAXLEN_HEAD,
		ERR_MAXLEN_BODY,
		MISSING_START_NEWLINE,
		MISSING_START_DELIMITER,
		MISSING_HEADER_NEWLINE,
		MISSING_HEADER_COLON,
	};
	const std::map<ERROR_CODE, string> ERROR_MESSAGE {
		{SUCCESS				, "SUCCESS"},
		{SEND_CLOSED			, "SEND_CLOSED"},
		{SEND_ERROR				, "SEND_ERROR"},
		{RECV_CLOSED_DURING_HEAD, "RECV_CLOSED_DURING_HEAD"},
		{RECV_CLOSED_DURING_BODY, "RECV_CLOSED_DURING_BODY"},
		{RECV_ERROR_DURING_HEAD	, "RECV_ERROR_DURING_HEAD"},
		{RECV_ERROR_DURING_BODY	, "RECV_ERROR_DURING_BODY"},
		{ERR_MAXLEN_HEAD		, "ERR_MAXLEN_HEAD"},
		{ERR_MAXLEN_BODY		, "ERR_MAXLEN_BODY"},
		{MISSING_START_NEWLINE	, "MISSING_START_NEWLINE"},
		{MISSING_START_DELIMITER, "MISSING_START_DELIMITER"},
		{MISSING_HEADER_NEWLINE	, "MISSING_HEADER_NEWLINE"},
		{MISSING_HEADER_COLON	, "MISSING_HEADER_COLON"},
	};

	const string	HTTP_HEADER_NEWLINE	= "\r\n";
	const string	HTTP_HEADER_END		= "\r\n\r\n";
	const size_t	MAX_HEAD_LENGTH = 1024 * 16;		// 16 KiB
	const size_t	MAX_BODY_LENGTH = 1024 * 1024 * 128;// 128 MiB

	struct MessageSocket {
		int fd;

		virtual ssize_t recv(char* dst, const size_t count) {
			return sys::recv(this->fd, dst, count, 0);
		}
		virtual ssize_t send(const char* src, const size_t count) {
			return sys::send(this->fd, src, count, 0);
		}
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

		void reserve_force(size_t new_capacity) {
			char* new_data = new char[new_capacity];
			size_t new_length = std::min(length, new_capacity);
			memcpy(new_data, data, new_length * sizeof(data[0]));
			delete[] data;
			data		= new_data;
			capacity	= new_capacity;
			length		= new_length;
		}
		void reserve(size_t new_capacity) {
			if(new_capacity > capacity) reserve_force(new_capacity);
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

		void shift(size_t pos) {
			memmove(data, data+pos, length-pos);
			length -= pos;
		}
	};


	ERROR_CODE recv_http_message_head(MessageSocket& socket, MessageBuffer& buffer, size_t& head_length) {
		buffer.reserve(MAX_HEAD_LENGTH);
		size_t scan_pos = 0;
		while(true) {
			// check for end of headers.
			if(buffer.length >= HTTP_HEADER_END.length()) {
				const size_t end_pos = buffer.view().find(HTTP_HEADER_END, scan_pos);
				if(end_pos != string::npos) {
					head_length = end_pos + HTTP_HEADER_END.length();
					return ERROR_CODE::SUCCESS;
				}
				scan_pos = buffer.length - HTTP_HEADER_END.length();
			}
			// check if max length exceeded.
			if(buffer.length >= MAX_HEAD_LENGTH) return ERROR_CODE::ERR_MAXLEN_HEAD;
			// read some data.
			const size_t count = MAX_HEAD_LENGTH - buffer.length;
			const ssize_t len = socket.recv(buffer.data + buffer.length, count);
			if(len == 0) return ERROR_CODE::RECV_CLOSED_DURING_HEAD;
			if(len <  0) return ERROR_CODE::RECV_ERROR_DURING_HEAD;
			buffer.length += len;
		}
		return ERROR_CODE::UNKNOWN_ERROR;
	}
	ERROR_CODE recv_http_message_body(MessageSocket& socket, MessageBuffer& buffer, const size_t head_length, const size_t content_length) {
		// check if content length is within bounds.
		if(content_length > MAX_BODY_LENGTH) return ERROR_CODE::ERR_MAXLEN_BODY;
		// read content.
		buffer.reserve(head_length + content_length);
		size_t count = content_length - (buffer.length - head_length);
		while(count > 0) {
			ssize_t len = socket.recv(buffer.data + buffer.length, count);
			if(len == 0) return ERROR_CODE::RECV_CLOSED_DURING_BODY;
			if(len <  0) return ERROR_CODE::RECV_ERROR_DURING_BODY;
			buffer.length += len;
			count -= len;
		}
		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE send_http_message(MessageSocket& socket, const char* data, const size_t size) {
		int x = 0;
		while(x < size) {
			ssize_t len = socket.send(data+x, size-x);
			if(len ==  0) return ERROR_CODE::SEND_CLOSED;
			if(len == -1) return ERROR_CODE::SEND_ERROR;
			x += len;
		}
		return ERROR_CODE::SUCCESS;
	}


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


	bool find_start_line_delims(const string_view& head, const size_t end, size_t& d0, size_t& d1) {
		d0 = string::npos;
		d1 = string::npos;
		size_t x = 0;
		while(x < end) if(head[x++] == ' ') { d0=x; break; }
		while(x < end) if(head[x++] == ' ') { d1=x; break; }
		bool success = (d0 != string::npos) & (d1 != string::npos);
		return success;
	}
	void		append_start_line_request (MessageBuffer& buffer, http_request& request) {
		buffer.append(request.method);
		buffer.append(" ");
		buffer.append(request.target);
		buffer.append(" ");
		buffer.append(request.protocol);
		buffer.append(HTTP_HEADER_NEWLINE);
	}
	void		append_start_line_response(MessageBuffer& buffer, http_response& response) {
		buffer.append(response.protocol);
		buffer.append(" ");
		buffer.append(int_to_string(response.status_code));
		buffer.append(" ");
		buffer.append(STATUS_CODES.at(response.status_code));
		buffer.append(HTTP_HEADER_NEWLINE);
	}
	ERROR_CODE	parse_start_line_request (const MessageBuffer& buffer, http_request& request) {
		const string_view head = buffer.view();

		// find end of start-line.
		int end = head.find(HTTP_HEADER_NEWLINE);
		if(end == string::npos) return ERROR_CODE::MISSING_START_NEWLINE;
		// get positions of start line delimiters.
		size_t d0, d1;
		if(!find_start_line_delims(head, end, d0, d1)) return ERROR_CODE::MISSING_START_DELIMITER;

		// parse start-line parts.
		size_t a=0, b=d0;
		request.method = to_uppercase_ascii_sv(head.substr(a, b-a));
		a=d0+1; b=d1;
		request.target = head.substr(a, b-a);
		a=d1+1; b=end;
		request.protocol = to_uppercase_ascii_sv(head.substr(a, b-a));

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE	parse_start_line_response(const MessageBuffer& buffer, http_response& response) {
		const string_view head = buffer.view();

		// find end of start-line.
		int end = head.find(HTTP_HEADER_NEWLINE);
		if(end == string::npos) return ERROR_CODE::MISSING_START_NEWLINE;
		// get positions of start line delimiters.
		size_t d0, d1;
		if(!find_start_line_delims(head, end, d0, d1)) return ERROR_CODE::MISSING_START_DELIMITER;

		// parse line parts.
		size_t a=0, b=d0;
		response.protocol = to_uppercase_ascii_sv(head.substr(a, b-a));
		a=d0+1; b=d1;
		response.status_code = string_to_int(head.substr(a, b-a));

		return ERROR_CODE::SUCCESS;
	}


	ERROR_CODE append_headers(MessageBuffer& buffer, const header_dict& headers) {
		for(const auto& [key,val] : headers) {
			buffer.append(key);
			buffer.append(": ");
			buffer.append(val);
			buffer.append(HTTP_HEADER_NEWLINE);
		}
		buffer.append(HTTP_HEADER_NEWLINE);
		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE parse_headers(const MessageBuffer& buffer, header_dict& headers) {
		const string_view head = buffer.view();
		int beg = head.find(HTTP_HEADER_NEWLINE) + HTTP_HEADER_NEWLINE.length();
		while(true) {
			// find end of header line.
			int end = head.find(HTTP_HEADER_NEWLINE, beg);
			if(end == string::npos) return ERROR_CODE::MISSING_HEADER_NEWLINE;
			// check if end of headers reached.
			if(beg == end) break;
			// find header separator.
			int mid = head.find(':', beg);
			if(mid == string::npos) return ERROR_CODE::MISSING_HEADER_COLON;
			// add to header dictionary.
			const string key = string(head.substr(beg, mid-beg));
			const string val = string(head.substr(mid+1, end-(mid+1)));
			headers[to_lowercase_ascii(key)] = trim_leading(val);
			// advance to the next line.
			beg = end + HTTP_HEADER_NEWLINE.length();
		}
		return ERROR_CODE::SUCCESS;
	}


	ERROR_CODE send_http_request(MessageSocket& socket, MessageBuffer& head_buf, MessageBuffer& body_buf, http_request& request) {
		append_start_line_request(head_buf, request);
		append_headers(head_buf, request.headers);
		request.head = head_buf.view();
		request.body = body_buf.view();

		ERROR_CODE err;
		err = send_http_message(socket, head_buf.data, head_buf.length);
		if(err != ERROR_CODE::SUCCESS) return err;

		if(body_buf.length > 0) err = send_http_message(socket, body_buf.data, body_buf.length);
		if(err != ERROR_CODE::SUCCESS) return err;

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE send_http_response(MessageSocket& socket, MessageBuffer& head_buf, MessageBuffer& body_buf, http_response& response) {
		append_start_line_response(head_buf, response);
		append_headers(head_buf, response.headers);
		response.head = head_buf.view();
		response.body = body_buf.view();

		ERROR_CODE err;
		err = send_http_message(socket, head_buf.data, head_buf.length);
		if(err != ERROR_CODE::SUCCESS) return err;

		if(body_buf.length > 0) err = send_http_message(socket, body_buf.data, body_buf.length);
		if(err != ERROR_CODE::SUCCESS) return err;

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE recv_http_request(MessageSocket& socket, MessageBuffer& buffer, http_request& request) {
		ERROR_CODE err;

		size_t head_length;
		err = recv_http_message_head(socket, buffer, head_length);
		if(err != ERROR_CODE::SUCCESS) return err;
		request.head = buffer.view(0, head_length);

		err = parse_start_line_request(buffer, request);
		if(err != ERROR_CODE::SUCCESS) return err;
		err = parse_headers(buffer, request.headers);
		if(err != ERROR_CODE::SUCCESS) return err;

		if(request.headers.contains(HTTP::HEADERS::content_length)) {
			size_t content_length = string_to_int(request.headers.at(HTTP::HEADERS::content_length));
			err = recv_http_message_body(socket, buffer, head_length, content_length);
			if(err != ERROR_CODE::SUCCESS) return err;
			request.body = buffer.view(head_length, content_length);
		}

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE recv_http_response(MessageSocket& socket, MessageBuffer& buffer, http_response& response) {
		ERROR_CODE err;

		size_t head_length;
		err = recv_http_message_head(socket, buffer, head_length);
		if(err != ERROR_CODE::SUCCESS) return err;
		response.head = buffer.view(0, head_length);

		err = parse_start_line_response(buffer, response);
		if(err != ERROR_CODE::SUCCESS) return err;
		err = parse_headers(buffer, response.headers);
		if(err != ERROR_CODE::SUCCESS) return err;

		if(response.headers.contains(HTTP::HEADERS::content_length)) {
			size_t content_length = string_to_int(response.headers.at(HTTP::HEADERS::content_length));
			err = recv_http_message_body(socket, buffer, head_length, content_length);
			if(err != ERROR_CODE::SUCCESS) return err;
			response.body = buffer.view(head_length, content_length);
		}

		return ERROR_CODE::SUCCESS;
	}
}
