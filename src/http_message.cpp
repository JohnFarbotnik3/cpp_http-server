#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include "./http_structs.cpp"
#include "src/utils/string_util.cpp"
#include "src/definitions/headers.cpp"
#include "src/definitions/status_codes.cpp"

namespace HTTP {
	using std::string;
	using std::string_view;
	using namespace utils::string_util;

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
	const size_t	MAX_HEAD_LENGTH = 1024 * 10;// 10 KiB
	const size_t	MAX_BODY_LENGTH = 1024 * 1024 * 1024;// 1 GiB
	const size_t	BUFFER_SHRINK_THRESHOLD = 1024 * 1024;

	ERROR_CODE recv_message_head(int fd, string& buffer, string& head) {
		size_t scan_start = 0;
		while(true) {
			// check for end of headers.
			if(buffer.length() > HTTP_HEADER_END.length()) {
				size_t pos = buffer.find(HTTP_HEADER_END, scan_start);
				if(pos != string::npos) {
					size_t len = pos + HTTP_HEADER_END.length();
					head = buffer.substr(0, len);
					buffer = buffer.substr(len);
					return ERROR_CODE::SUCCESS;
				} else {
					// move scan start to (near) end of buffer, leaving some padding in case
					// only part of end-of-header was received during previous iteration.
					scan_start = buffer.length() - HTTP_HEADER_END.length();
				}
			}
			// check if max length exceeded.
			if(buffer.length() > MAX_HEAD_LENGTH) return ERROR_CODE::ERR_MAXLEN_HEAD;
			// read some more data.
			char temp[1024];
			ssize_t len = recv(fd, temp, 1024, 0);
			if(len == 0) return ERROR_CODE::RECV_CLOSED_DURING_HEAD;
			if(len <  0) return ERROR_CODE::RECV_ERROR_DURING_HEAD;
			buffer.append(temp, len);
		}
		return ERROR_CODE::UNKNOWN_ERROR;
	}
	ERROR_CODE recv_message_body(int fd, string& buffer, string& body, const size_t content_length) {
		// check if content length is within bounds.
		if(content_length > MAX_BODY_LENGTH) return ERROR_CODE::ERR_MAXLEN_BODY;
		// check if body has already been read into buffer.
		// NOTE: in theory, the buffer is currently small so this isnt very expensive.
		if(buffer.length() >= content_length) {
			body = buffer.substr(0, content_length);
			buffer = buffer.substr(content_length);
			return ERROR_CODE::SUCCESS;
		}
		// read rest of content.
		// NOTE: it is read directly into body to avoid expensive allocate+copy on large content.
		body = buffer;
		buffer.resize(0);
		body.reserve(content_length);
		while(body.length() < content_length) {
			char temp[8192];
			size_t remaining = content_length - body.length();
			size_t count = std::min<size_t>(remaining, 8192);
			ssize_t len = recv(fd, temp, count, 0);
			if(len == 0) return ERROR_CODE::RECV_CLOSED_DURING_BODY;
			if(len <  0) return ERROR_CODE::RECV_ERROR_DURING_BODY;
			body.append(temp, len);
		}
		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE send_message(int fd, const char* data, const size_t size) {
		int x = 0;
		while(x < size) {
			int len = send(fd, data+x, size-x, 0);
			if(len ==  0) return ERROR_CODE::SEND_CLOSED;
			if(len == -1) return ERROR_CODE::SEND_ERROR;
			x += len;
		}
		return ERROR_CODE::SUCCESS;
	}


	int64_t string_to_int(const string str) {
		const int64_t value = std::stoll(str);
		return value;
	}
	string int_to_string(const int64_t val) {
		char temp[64];
		snprintf(temp, 64, "%li", val);
		return string(temp);
	}


	ERROR_CODE build_request_start(string& buffer, const http_request& request) {
		buffer.append(request.method);
		buffer.append(" ");
		buffer.append(request.target);
		buffer.append(" ");
		buffer.append(request.protocol);
		buffer.append(HTTP_HEADER_NEWLINE);
		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE parse_request_start(const string& buffer, http_request& request) {
		int end = buffer.find(HTTP_HEADER_NEWLINE);
		if(end != string::npos) {
			// method.
			int a=0, b=0;
			b = buffer.find(" ", a);
			if((b == string::npos) | (b > end)) return ERROR_CODE::MISSING_START_DELIMITER;
			request.method = to_uppercase_ascii(buffer.substr(a, b-a));
			// target.
			a = b + 1;
			b = buffer.find(" ", a);
			if((b == string::npos) | (b > end)) return ERROR_CODE::MISSING_START_DELIMITER;
			request.target = buffer.substr(a, b-a);
			// protocol.
			a = b + 1;
			b = end;
			request.protocol = to_uppercase_ascii(buffer.substr(a, b-a));
		} else {
			return ERROR_CODE::MISSING_START_NEWLINE;
		}
		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE build_response_start(string& buffer, const http_response& response) {
		char status_cstr[32];
		snprintf(status_cstr, 32, "%i", response.status_code);
		buffer.append(response.protocol);
		buffer.append(" ");
		buffer.append(string(status_cstr));
		buffer.append(" ");
		buffer.append(STATUS_CODES.at(response.status_code));
		buffer.append(HTTP_HEADER_NEWLINE);
		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE parse_response_start(const string& buffer, http_response& response) {
		int end = buffer.find(HTTP_HEADER_NEWLINE);
		if(end != string::npos) {
			// protocol.
			int a=0, b=0;
			b = buffer.find(" ", a);
			if((b == string::npos) | (b > end)) return ERROR_CODE::MISSING_START_DELIMITER;
			response.protocol = to_uppercase_ascii(buffer.substr(a, b-a));
			// status_code.
			a = b + 1;
			b = buffer.find(" ", a);
			if((b == string::npos) | (b > end)) return ERROR_CODE::MISSING_START_DELIMITER;
			response.status_code = string_to_int(buffer.substr(a, b-a));
		} else {
			return ERROR_CODE::MISSING_START_NEWLINE;
		}
		return ERROR_CODE::SUCCESS;
	}


	ERROR_CODE build_header_lines(string& head, const header_dict& headers) {
		for(const auto& [key,val] : headers) {
			head.append(key);
			head.append(": ");
			head.append(val);
			head.append(HTTP_HEADER_NEWLINE);
		}
		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE parse_header_lines(const string& head, header_dict& headers) {
		int beg = head.find(HTTP_HEADER_NEWLINE) + HTTP_HEADER_NEWLINE.length();
		while(true) {
			// find end of header line.
			int end = head.find(HTTP_HEADER_NEWLINE, beg);
			if(end == string::npos) return ERROR_CODE::MISSING_HEADER_NEWLINE;
			// check if end of headers reached.
			if(beg == end) break;
			// find header separator.
			int mid = head.find(":", beg);
			if(mid == string::npos) return ERROR_CODE::MISSING_HEADER_COLON;
			// add to header dictionary.
			const string key = head.substr(beg, mid-beg);
			const string val = head.substr(mid+1, end-(mid+1));
			headers[to_lowercase_ascii(key)] = trim_leading(val);
			// advance to the next line.
			beg = end + HTTP_HEADER_NEWLINE.length();
		}
		return ERROR_CODE::SUCCESS;
	}


	ERROR_CODE send_http_request(const int fd, http_request& request) {
		string& head = request.head;
		string& body = request.body;

		build_request_start(head, request);
		build_header_lines(head, request.headers);
		head.append(HTTP_HEADER_NEWLINE);

		// send headers.
		const ERROR_CODE err = send_message(fd, head.data(), head.size());
		if(err != ERROR_CODE::SUCCESS) return err;

		// send content (if any).
		if(body.length() > 0) {
			const ERROR_CODE err = send_message(fd, body.data(), body.size());
			if(err != ERROR_CODE::SUCCESS) return err;
		}

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE send_http_response(const int fd, http_response& response) {
		string& head = response.head;
		string& body = response.body;

		build_response_start(head, response);
		build_header_lines(head, response.headers);
		head.append(HTTP_HEADER_NEWLINE);

		// send headers.
		const ERROR_CODE err = send_message(fd, head.data(), head.size());
		if(err != ERROR_CODE::SUCCESS) return err;

		// send content (if any).
		if(body.length() > 0) {
			const ERROR_CODE err = send_message(fd, body.data(), body.size());
			if(err != ERROR_CODE::SUCCESS) return err;
		}

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE recv_http_request(const int fd, http_request& request, string& buffer) {
		string& head = request.head;
		string& body = request.body;
		ERROR_CODE err;

		if(buffer.capacity() > BUFFER_SHRINK_THRESHOLD) buffer.shrink_to_fit();

		err = recv_message_head(fd, buffer, head);
		if(err != ERROR_CODE::SUCCESS) return err;

		err = parse_request_start(head, request);
		if(err != ERROR_CODE::SUCCESS) return err;

		err = parse_header_lines(head, request.headers);
		if(err != ERROR_CODE::SUCCESS) return err;

		// receive message body (if any).
		if(request.headers.contains(HTTP::HEADERS::content_length)) {
			size_t content_length = string_to_int(request.headers.at(HTTP::HEADERS::content_length));
			err = recv_message_body(fd, buffer, body, content_length);
			if(err != ERROR_CODE::SUCCESS) return err;
		}

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE recv_http_response(const int fd, http_response& response, string& buffer) {
		string& head = response.head;
		string& body = response.body;
		ERROR_CODE err;

		if(buffer.capacity() > BUFFER_SHRINK_THRESHOLD) buffer.shrink_to_fit();

		err = recv_message_head(fd, buffer, head);
		if(err != ERROR_CODE::SUCCESS) return err;

		err = parse_response_start(head, response);
		if(err != ERROR_CODE::SUCCESS) return err;

		err = parse_header_lines(head, response.headers);
		if(err != ERROR_CODE::SUCCESS) return err;

		// receive message body (if any).
		if(response.headers.contains(HTTP::HEADERS::content_length)) {
			size_t content_length = string_to_int(response.headers.at(HTTP::HEADERS::content_length));
			err = recv_message_body(fd, buffer, body, content_length);
			if(err != ERROR_CODE::SUCCESS) return err;
		}

		return ERROR_CODE::SUCCESS;
	}
}
