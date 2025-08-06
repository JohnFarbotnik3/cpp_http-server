#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include "src/utils/string_util.cpp"
#include "src/definitions/headers.cpp"
#include "src/definitions/status_codes.cpp"
#include "src/http_structs.cpp"

namespace HTTP {
	using std::string;
	using std::string_view;
	using namespace utils::string_util;

	const string	HTTP_HEADER_NEWLINE	= "\r\n";
	const string	HTTP_HEADER_END		= "\r\n\r\n";
	const size_t	MAX_HEAD_LENGTH = 1024 * 16;		// 16 KiB
	const size_t	MAX_BODY_LENGTH = 1024 * 1024 * 128;// 128 MiB
	const size_t	BUFFER_SHRINK_CAPACITY = 1024 * 64;// 64 KiB

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
		while(x < end) if(head[x++] == ' ') { d0=x-1; break; }
		while(x < end) if(head[x++] == ' ') { d1=x-1; break; }
		bool success = (d0 != string::npos) & (d1 != string::npos);
		return success;
	}
	void		append_start_line_request (MessageBuffer& buffer, const http_request& request) {
		buffer.append(request.method);
		buffer.append(" ");
		buffer.append(request.target);
		buffer.append(" ");
		buffer.append(request.protocol);
		buffer.append(HTTP_HEADER_NEWLINE);
	}
	void		append_start_line_response(MessageBuffer& buffer, const http_response& response) {
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
		a=d1+1; b=end;
		response.status_text = to_uppercase_ascii_sv(head.substr(a, b-a));

		return ERROR_CODE::SUCCESS;
	}


	void append_headers(MessageBuffer& buffer, const header_dict& headers) {
		for(const auto& [key,val] : headers) {
			buffer.append(key);
			buffer.append(": ");
			buffer.append(val);
			buffer.append(HTTP_HEADER_NEWLINE);
		}
		buffer.append(HTTP_HEADER_NEWLINE);
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
			headers[to_lowercase_ascii(key)] = trim_leading(val);// TODO: remove trim call - trimming whitespace shouldnt be necessary.
			// advance to the next line.
			beg = end + HTTP_HEADER_NEWLINE.length();
		}
		return ERROR_CODE::SUCCESS;
	}
	size_t get_content_length(const header_dict& headers) {
		if(headers.contains(HTTP::HEADERS::content_length)) {
			return string_to_int(headers.at(HTTP::HEADERS::content_length));
		} else {
			return 0;
		}
	}


	void send_cleanup(MessageBuffer& head_buf, MessageBuffer& body_buf) {
		head_buf.clear();
		body_buf.clear();
		if(body_buf.capacity > BUFFER_SHRINK_CAPACITY) body_buf.set_capacity(BUFFER_SHRINK_CAPACITY);
	}
	void recv_cleanup(MessageBuffer& buffer, const size_t message_length) {
		buffer.shift(message_length);
		if(buffer.capacity > BUFFER_SHRINK_CAPACITY) buffer.set_capacity(buffer.length);
	}


	ERROR_CODE send_http_message(HTTPConnection& connection, const char* data, const size_t size) {
		size_t x = 0;
		while(x < size) {
			ssize_t len = connection.send(data+x, size-x);
			if(len ==  0) return ERROR_CODE::SEND_CLOSED;
			if(len == -1) return ERROR_CODE::SEND_ERROR;
			x += len;
		}
		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE recv_http_message_head(HTTPConnection& connection, MessageBuffer& buffer, size_t& head_length) {
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
			const ssize_t len = connection.recv(buffer.data + buffer.length, count);
			if(len == 0) return ERROR_CODE::RECV_CLOSED_DURING_HEAD;
			if(len <  0) return ERROR_CODE::RECV_ERROR_DURING_HEAD;
			buffer.length += len;
		}
		return ERROR_CODE::UNKNOWN_ERROR;
	}
	ERROR_CODE recv_http_message_body(HTTPConnection& connection, MessageBuffer& buffer, const size_t head_length, const size_t content_length) {
		// check if content length is within bounds.
		if(content_length > MAX_BODY_LENGTH) return ERROR_CODE::ERR_MAXLEN_BODY;
		// read content.
		buffer.reserve(head_length + content_length);
		size_t count = content_length - (buffer.length - head_length);
		while(count > 0) {
			ssize_t len = connection.recv(buffer.data + buffer.length, count);
			if(len == 0) return ERROR_CODE::RECV_CLOSED_DURING_BODY;
			if(len <  0) return ERROR_CODE::RECV_ERROR_DURING_BODY;
			buffer.length += len;
			count -= len;
		}
		return ERROR_CODE::SUCCESS;
	}


	ERROR_CODE send_http_request (HTTPConnection& connection, MessageBuffer& head_buf, const MessageBuffer& body_buf, const http_request& request) {
		append_start_line_request(head_buf, request);
		append_headers(head_buf, request.headers);

		ERROR_CODE err;
		err = send_http_message(connection, head_buf.data, head_buf.length);
		if(err != ERROR_CODE::SUCCESS) return err;

		if(body_buf.length > 0) err = send_http_message(connection, body_buf.data, body_buf.length);
		if(err != ERROR_CODE::SUCCESS) return err;

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE send_http_response(HTTPConnection& connection, MessageBuffer& head_buf, const MessageBuffer& body_buf, const http_response& response) {
		append_start_line_response(head_buf, response);
		append_headers(head_buf, response.headers);

		ERROR_CODE err;
		err = send_http_message(connection, head_buf.data, head_buf.length);
		if(err != ERROR_CODE::SUCCESS) return err;

		if(body_buf.length > 0) err = send_http_message(connection, body_buf.data, body_buf.length);
		if(err != ERROR_CODE::SUCCESS) return err;

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE recv_http_request (HTTPConnection& connection, MessageBuffer& buffer, http_request& request, size_t& request_length) {
		request_length = 0;
		ERROR_CODE err;

		size_t head_length;
		err = recv_http_message_head(connection, buffer, head_length);
		if(err != ERROR_CODE::SUCCESS) return err;
		request.head = buffer.view(0, head_length);

		err = parse_start_line_request(buffer, request);
		if(err != ERROR_CODE::SUCCESS) return err;
		err = parse_headers(buffer, request.headers);
		if(err != ERROR_CODE::SUCCESS) return err;

		const size_t content_length = get_content_length(request.headers);
		if(content_length > 0) {
			err = recv_http_message_body(connection, buffer, head_length, content_length);
			if(err != ERROR_CODE::SUCCESS) return err;
		}
		request.body = buffer.view(head_length, content_length);

		request_length = head_length + content_length;
		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE recv_http_response(HTTPConnection& connection, MessageBuffer& buffer, http_response& response, size_t& response_length) {
		response_length = 0;
		ERROR_CODE err;

		size_t head_length;
		err = recv_http_message_head(connection, buffer, head_length);
		if(err != ERROR_CODE::SUCCESS) return err;
		response.head = buffer.view(0, head_length);

		err = parse_start_line_response(buffer, response);
		if(err != ERROR_CODE::SUCCESS) return err;
		err = parse_headers(buffer, response.headers);
		if(err != ERROR_CODE::SUCCESS) return err;

		const size_t content_length = get_content_length(response.headers);
		if(content_length > 0) {
			err = recv_http_message_body(connection, buffer, head_length, content_length);
			if(err != ERROR_CODE::SUCCESS) return err;
		}
		response.body = buffer.view(head_length, content_length);

		response_length = head_length + content_length;
		return ERROR_CODE::SUCCESS;
	}
}
