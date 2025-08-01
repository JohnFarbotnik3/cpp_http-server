#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include "./http_structs.cpp"
#include "src/utils/string_util.cpp"
#include "src/definitions/headers.cpp"
#include "src/definitions/status_codes.cpp"
#include "src/utils/time_util.cpp"

namespace HTTP {
	using std::string;
	using std::string_view;
	using namespace utils::string_util;
	using utils::time_util::timepoint_64_ns;

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
	const size_t	MAX_HEAD_LENGTH = 1024 * 16;// 16 KiB
	const size_t	MAX_BODY_LENGTH = 1024 * 1024 * 128;// 128 MiB

	struct HeadBuffer {
		char* data;
		size_t length;

		HeadBuffer() {
			data = new char[MAX_HEAD_LENGTH];
			length = 0;
		}
		~HeadBuffer() {
			delete[] data;
		}

		size_t find(const string& str, const size_t pos) {
			return string_view(data, length).find(str, pos);
		}

		string extract(const size_t n) {
			const string dst = string(data, n);
			memmove(data, data+n, length-n);
			length -= n;
			return dst;
		}
	};
	ERROR_CODE recv_message_head(int fd, HeadBuffer& head_buffer, string& head) {
		size_t scan_pos = 0;
		while(true) {
			// check for end of headers.
			if(head_buffer.length >= HTTP_HEADER_END.length()) {
				const size_t end_pos = head_buffer.find(HTTP_HEADER_END, scan_pos);
				if(end_pos != string::npos) {
					const size_t head_len = end_pos + HTTP_HEADER_END.length();
					head = head_buffer.extract(head_len);
					return ERROR_CODE::SUCCESS;
				} else {
					scan_pos = head_buffer.length - HTTP_HEADER_END.length();
				}
			}
			// check if max length exceeded.
			if(head_buffer.length >= MAX_HEAD_LENGTH) return ERROR_CODE::ERR_MAXLEN_HEAD;
			// read some data.
			const size_t count = MAX_HEAD_LENGTH - head_buffer.length;
			const ssize_t len = recv(fd, head_buffer.data + head_buffer.length, count, 0);
			if(len == 0) return ERROR_CODE::RECV_CLOSED_DURING_HEAD;
			if(len <  0) return ERROR_CODE::RECV_ERROR_DURING_HEAD;
			head_buffer.length += len;
		}
		return ERROR_CODE::UNKNOWN_ERROR;
	}
	ERROR_CODE recv_message_body(int fd, HeadBuffer& head_buffer, string& body, const size_t content_length) {
		// check if content length is within bounds.
		if(content_length > MAX_BODY_LENGTH) return ERROR_CODE::ERR_MAXLEN_BODY;
		// get body content that may have already been read into head_buffer.
		body = head_buffer.extract(std::min<size_t>(content_length, head_buffer.length));
		// allocate memory for content. NOTE: string::resize() also zero-fills memory.
		size_t read_sum = body.length();
		body.resize(content_length);// WARNING: easy DOS method - spawn many connections with large content length.
		// read content.
		while(read_sum < content_length) {
			size_t count = content_length - read_sum;
			ssize_t len = recv(fd, body.data()+read_sum, count, 0);
			if(len == 0) return ERROR_CODE::RECV_CLOSED_DURING_BODY;
			if(len <  0) return ERROR_CODE::RECV_ERROR_DURING_BODY;
			read_sum += len;
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
	ERROR_CODE recv_http_request(const int fd, http_request& request, HeadBuffer& head_buffer, timepoint_64_ns& dt_us_wait, timepoint_64_ns& dt_us_work) {
		string& head = request.head;
		string& body = request.body;
		ERROR_CODE err;
		timepoint_64_ns t0;

		t0 = timepoint_64_ns::now();
		err = recv_message_head(fd, head_buffer, head);
		dt_us_wait.value += timepoint_64_ns::now().delta(t0).value;
		if(err != ERROR_CODE::SUCCESS) return err;

		t0 = timepoint_64_ns::now();
		err = parse_request_start(head, request);
		dt_us_work.value += timepoint_64_ns::now().delta(t0).value;
		if(err != ERROR_CODE::SUCCESS) return err;

		t0 = timepoint_64_ns::now();
		err = parse_header_lines(head, request.headers);
		dt_us_work.value += timepoint_64_ns::now().delta(t0).value;
		if(err != ERROR_CODE::SUCCESS) return err;

		// receive message body (if any).
		if(request.headers.contains(HTTP::HEADERS::content_length)) {
			size_t content_length = string_to_int(request.headers.at(HTTP::HEADERS::content_length));
			t0 = timepoint_64_ns::now();
			err = recv_message_body(fd, head_buffer, body, content_length);
			dt_us_wait.value += timepoint_64_ns::now().delta(t0).value;
			if(err != ERROR_CODE::SUCCESS) return err;
		}

		return ERROR_CODE::SUCCESS;
	}
	ERROR_CODE recv_http_response(const int fd, http_response& response, HeadBuffer& head_buffer) {
		string& head = response.head;
		string& body = response.body;
		ERROR_CODE err;

		err = recv_message_head(fd, head_buffer, head);
		if(err != ERROR_CODE::SUCCESS) return err;

		err = parse_response_start(head, response);
		if(err != ERROR_CODE::SUCCESS) return err;

		err = parse_header_lines(head, response.headers);
		if(err != ERROR_CODE::SUCCESS) return err;

		// receive message body (if any).
		if(response.headers.contains(HTTP::HEADERS::content_length)) {
			size_t content_length = string_to_int(response.headers.at(HTTP::HEADERS::content_length));
			err = recv_message_body(fd, head_buffer, body, content_length);
			if(err != ERROR_CODE::SUCCESS) return err;
		}

		return ERROR_CODE::SUCCESS;
	}
}
