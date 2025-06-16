#include <cstdint>
#include <string>
#include <sys/socket.h>
#include "./http_structs.cpp"
#include "./utils/string_helpers.cpp"
#include "./definitions/headers.cpp"
#include "./definitions/status_codes.cpp"

namespace HTTP {
	using std::string;

	namespace ERROR_STATUS {
		struct error_status {
			int		code;
			string	message;
		};

		const error_status SUCCESS					{ 0, "" };

		const error_status RECV_CLOSED_DURING_HEAD	{  1, "RECV_CLOSED_DURING_HEAD" };
		const error_status RECV_CLOSED_DURING_BODY	{  2, "RECV_CLOSED_DURING_BODY" };
		const error_status RECV_ERR_DURING_HEAD		{  3, "RECV_ERR_DURING_HEAD" };
		const error_status RECV_ERR_DURING_BODY		{  4, "RECV_ERR_DURING_BODY" };
		const error_status ERR_MAXLEN_HEAD			{  5, "ERR_MAXLEN_HEAD" };
		const error_status ERR_MAXLEN_BODY			{  6, "ERR_MAXLEN_BODY" };
		const error_status MISSING_START_NEWLINE	{  7, "MISSING_START_NEWLINE" };
		const error_status MISSING_START_DELIMITER	{  8, "MISSING_START_DELIMITER" };
		const error_status MISSING_HEADER_NEWLINE	{  9, "MISSING_HEADER_NEWLINE" };
		const error_status MISSING_HEADER_COLON		{ 10, "MISSING_HEADER_COLON" };

		const error_status SEND_CLOSED_DURING_HEAD	{ 1, "SEND_CLOSED_DURING_HEAD" };
		const error_status SEND_CLOSED_DURING_BODY	{ 2, "SEND_CLOSED_DURING_BODY" };
		const error_status SEND_ERR_DURING_HEAD		{ 3, "SEND_ERR_DURING_HEAD" };
		const error_status SEND_ERR_DURING_BODY		{ 4, "SEND_ERR_DURING_BODY" };

	}
	using ERROR_STATUS::error_status;

	const string	HTTP_HEADER_NEWLINE	= "\r\n";
	const string	HTTP_HEADER_END		= "\r\n\r\n";
	const int		HTTP_HEADER_MAXLEN	= 1024 * 10;// 10 KiB
	const int		HTTP_REQUEST_MAXLEN	= 1024 * 1024 * 10;// 10 MiB
	const size_t	MAX_HEAD_LENGTH = 1024 * 10;// 10 KiB
	const size_t	MAX_BODY_LENGTH = 1024 * 1024 * 1024;// 1 GiB

	/*
		WARNING: with really small messages, it is possible for this function to read the entirety
		of this http request, plus some of the next (an example of "http request pipelining").

		this implementation would dump this into the body of the current request (even if content-length = 0),
		losing part of the next request and likely jamming up the pipeline.

		HTTP-1.1 pipelining was obsoleted by HTTP-2, and most browsers & servers dont bother with pipelining,
		so it doesnt make sense to worry about here.
	*/
	error_status recv_message_head(int fd, string& buffer, size_t& head_length, const size_t max_head_length) {
		// read until end of header-section is found.
		int scan_start = 0;
		while(true) {
			// read some data.
			const int chunk_sz = 512;
			char temp[chunk_sz];
			int len = recv(fd, temp, chunk_sz, 0);
			// check if connection closed or errored during recv.
			if(len ==  0) return ERROR_STATUS::RECV_CLOSED_DURING_HEAD;
			if(len == -1) return ERROR_STATUS::RECV_ERR_DURING_HEAD;
			// append data to buffer.
			buffer.append(temp, len);
			// check if max length exceeded.
			if(buffer.length() > max_head_length) return ERROR_STATUS::ERR_MAXLEN_HEAD;
			// check for end of headers.
			int pos = buffer.find(HTTP_HEADER_END, scan_start);
			if(pos != string::npos) {
				head_length = pos + HTTP_HEADER_END.length();
				break;
			} else {
				// move scan start to (near) end of buffer, leaving some padding in case
				// only part of end-of-header was received during this iteration.
				scan_start = buffer.length() - HTTP_HEADER_END.length();
			}
		}
		return ERROR_STATUS::SUCCESS;
	}
	error_status recv_message_body(int fd, string& buffer, size_t& body_length, const size_t content_length) {
		// check if content length is within bounds.
		if(content_length > MAX_BODY_LENGTH) return ERROR_STATUS::ERR_MAXLEN_BODY;
		// read content.
		while(body_length < content_length) {
			const size_t remaining = content_length - body_length;
			const size_t chunk_sz = 1024 * 16;
			char temp[chunk_sz];
			size_t len = recv(fd, temp, std::min(chunk_sz, remaining), 0);
			// check if connection closed or errored during read.
			if(len ==  0) return ERROR_STATUS::RECV_CLOSED_DURING_BODY;
			if(len == -1) return ERROR_STATUS::RECV_ERR_DURING_BODY;
			// add data to buffer.
			buffer.append(temp, len);
			body_length += len;
		}
		return ERROR_STATUS::SUCCESS;
	}
	error_status send_message_head(int fd, const char* data, const size_t size) {
		int x = 0;
		while(x < size) {
			// write some data.
			int len = send(fd, data+x, size-x, 0);
			// check if connection closed or errored.
			if(len ==  0) return ERROR_STATUS::SEND_CLOSED_DURING_HEAD;
			if(len == -1) return ERROR_STATUS::SEND_ERR_DURING_HEAD;
			// advance.
			x += len;
		}
		return ERROR_STATUS::SUCCESS;
	}
	error_status send_message_body(int fd, const char* data, const size_t size) {
		int x = 0;
		while(x < size) {
			// write some data.
			int len = send(fd, data+x, size-x, 0);
			// check if connection closed or errored.
			if(len ==  0) return ERROR_STATUS::SEND_CLOSED_DURING_BODY;
			if(len == -1) return ERROR_STATUS::SEND_ERR_DURING_BODY;
			// advance.
			x += len;
		}
		return ERROR_STATUS::SUCCESS;
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


	error_status build_request_start(string& buffer, const http_request& request) {
		buffer.append(request.method);
		buffer.append(" ");
		buffer.append(request.target);
		buffer.append(" ");
		buffer.append(request.protocol);
		buffer.append(HTTP_HEADER_NEWLINE);
		return ERROR_STATUS::SUCCESS;
	}
	error_status parse_request_start(const string& buffer, http_request& request) {
		int end = buffer.find(HTTP_HEADER_NEWLINE);
		if(end != string::npos) {
			// method.
			int a=0, b=0;
			b = buffer.find(" ", a);
			if((b == string::npos) | (b > end)) return ERROR_STATUS::MISSING_START_DELIMITER;
			request.method = to_uppercase_ascii(buffer.substr(a, b-a));
			// target.
			a = b + 1;
			b = buffer.find(" ", a);
			if((b == string::npos) | (b > end)) return ERROR_STATUS::MISSING_START_DELIMITER;
			request.target = buffer.substr(a, b-a);
			// protocol.
			a = b + 1;
			b = end;
			request.protocol = to_uppercase_ascii(buffer.substr(a, b-a));
		} else {
			return ERROR_STATUS::MISSING_START_NEWLINE;
		}
		return ERROR_STATUS::SUCCESS;
	}
	error_status build_response_start(string& buffer, const http_response& response) {
		char status_cstr[32];
		snprintf(status_cstr, 32, "%i", response.status_code);
		buffer.append(response.protocol);
		buffer.append(" ");
		buffer.append(string(status_cstr));
		buffer.append(" ");
		buffer.append(STATUS_CODES.at(response.status_code));
		buffer.append(HTTP_HEADER_NEWLINE);
		return ERROR_STATUS::SUCCESS;
	}
	error_status parse_response_start(const string& buffer, http_response& response) {
		int end = buffer.find(HTTP_HEADER_NEWLINE);
		if(end != string::npos) {
			// protocol.
			int a=0, b=0;
			b = buffer.find(" ", a);
			if((b == string::npos) | (b > end)) return ERROR_STATUS::MISSING_START_DELIMITER;
			response.protocol = to_uppercase_ascii(buffer.substr(a, b-a));
			// status_code.
			a = b + 1;
			b = buffer.find(" ", a);
			if((b == string::npos) | (b > end)) return ERROR_STATUS::MISSING_START_DELIMITER;
			response.status_code = string_to_int(buffer.substr(a, b-a));
		} else {
			return ERROR_STATUS::MISSING_START_NEWLINE;
		}
		return ERROR_STATUS::SUCCESS;
	}


	error_status build_header_lines(string& buffer, const header_dict& headers) {
		for(const auto& [key,val] : headers) {
			buffer.append(key);
			buffer.append(": ");
			buffer.append(val);
			buffer.append(HTTP_HEADER_NEWLINE);
		}
		return ERROR_STATUS::SUCCESS;
	}
	error_status parse_header_lines(const string& buffer, header_dict& headers) {
		int beg = buffer.find(HTTP_HEADER_NEWLINE) + HTTP_HEADER_NEWLINE.length();
		while(true) {
			// find end of header line.
			int end = buffer.find(HTTP_HEADER_NEWLINE, beg);
			if(end == string::npos) return ERROR_STATUS::MISSING_HEADER_NEWLINE;
			// check if end of headers reached.
			if(beg == end) break;
			// find header separator.
			int mid = buffer.find(":", beg);
			if(mid == string::npos) return ERROR_STATUS::MISSING_HEADER_COLON;
			// add to header dictionary.
			const string key = buffer.substr(beg, mid-beg);
			const string val = buffer.substr(mid+1, end-(mid+1));
			headers[to_lowercase_ascii(key)] = trim_leading(val);
			// advance to the next line.
			beg = end + HTTP_HEADER_NEWLINE.length();
		}
		return ERROR_STATUS::SUCCESS;
	}


	error_status send_http_request(const int fd, http_request& request) {
		string& buffer_head = request.head;
		string& buffer_body = request.body;

		build_request_start(buffer_head, request);
		build_header_lines(buffer_head, request.headers);
		buffer_head.append(HTTP_HEADER_NEWLINE);

		// send headers.
		const error_status err = send_message_head(fd, buffer_head.data(), buffer_head.size());
		if(err.code != ERROR_STATUS::SUCCESS.code) return err;

		// send content (if any).
		if(buffer_body.length() > 0) {
			const error_status err = send_message_body(fd, buffer_body.data(), buffer_body.size());
			if(err.code != ERROR_STATUS::SUCCESS.code) return err;
		}

		return ERROR_STATUS::SUCCESS;
	}
	error_status recv_http_request(const int fd, http_request& request) {
		string& buffer_head = request.head;
		string& buffer_body = request.body;
		error_status err;

		size_t head_length = 0;
		err = recv_message_head(fd, buffer_head, head_length, MAX_HEAD_LENGTH);
		if(err.code != ERROR_STATUS::SUCCESS.code) return err;

		// move partially read body from head-buffer to body-buffer (if any).
		if(buffer_head.length() > head_length) {
			buffer_body = buffer_head.substr(head_length, buffer_head.length() - head_length);
			buffer_head.resize(head_length);
		}

		err = parse_request_start(buffer_head, request);
		if(err.code != ERROR_STATUS::SUCCESS.code) return err;

		err = parse_header_lines(buffer_head, request.headers);
		if(err.code != ERROR_STATUS::SUCCESS.code) return err;

		// receive message body (if any).
		if(request.headers.contains(HTTP::HEADERS::content_length)) {
			size_t content_length = string_to_int(request.headers.at(HTTP::HEADERS::content_length));
			size_t body_length = buffer_body.length();
			err = recv_message_body(fd, buffer_body, body_length, content_length);
			if(err.code != ERROR_STATUS::SUCCESS.code) return err;
		}

		return ERROR_STATUS::SUCCESS;
	}
	error_status send_http_response(const int fd, http_response& response) {
		string& buffer_head = response.head;
		string& buffer_body = response.body;

		build_response_start(buffer_head, response);
		build_header_lines(buffer_head, response.headers);
		buffer_head.append(HTTP_HEADER_NEWLINE);

		// send headers.
		const error_status err = send_message_head(fd, buffer_head.data(), buffer_head.size());
		if(err.code != ERROR_STATUS::SUCCESS.code) return err;

		// send content (if any).
		if(buffer_body.length() > 0) {
			const error_status err = send_message_body(fd, buffer_body.data(), buffer_body.size());
			if(err.code != ERROR_STATUS::SUCCESS.code) return err;
		}

		return ERROR_STATUS::SUCCESS;
	}
	error_status recv_http_response(const int fd, http_response& response) {
		string& buffer_head = response.head;
		string& buffer_body = response.body;
		error_status err;

		size_t head_length = 0;
		err = recv_message_head(fd, buffer_head, head_length, MAX_HEAD_LENGTH);
		if(err.code != ERROR_STATUS::SUCCESS.code) return err;

		// move partially read body from head-buffer to body-buffer (if any).
		if(buffer_head.length() > head_length) {
			buffer_body = buffer_head.substr(head_length, buffer_head.length() - head_length);
			buffer_head.resize(head_length);
		}

		err = parse_response_start(buffer_head, response);
		if(err.code != ERROR_STATUS::SUCCESS.code) return err;

		err = parse_header_lines(buffer_head, response.headers);
		if(err.code != ERROR_STATUS::SUCCESS.code) return err;

		// receive message body (if any).
		if(response.headers.contains(HTTP::HEADERS::content_length)) {
			size_t content_length = string_to_int(response.headers.at(HTTP::HEADERS::content_length));
			size_t body_length = buffer_body.length();
			err = recv_message_body(fd, buffer_body, body_length, content_length);
			if(err.code != ERROR_STATUS::SUCCESS.code) return err;
		}

		return ERROR_STATUS::SUCCESS;
	}
}
