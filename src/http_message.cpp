#include <string>
#include <sys/socket.h>
#include <charconv>
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

		const error_status RECV_CLOSED_DURING_HEAD	{ 1, "RECV_CLOSED_DURING_HEAD" };
		const error_status RECV_CLOSED_DURING_BODY	{ 2, "RECV_CLOSED_DURING_BODY" };
		const error_status RECV_ERR_DURING_HEAD		{ 3, "RECV_ERR_DURING_HEAD" };
		const error_status RECV_ERR_DURING_BODY		{ 4, "RECV_ERR_DURING_BODY" };
		const error_status ERR_MAXLEN_HEAD			{ 5, "ERR_MAXLEN_HEAD" };
		const error_status ERR_MAXLEN_BODY			{ 6, "ERR_MAXLEN_BODY" };
		const error_status MISSING_START_NEWLINE	{ 7, "MISSING_START_NEWLINE" };
		const error_status MISSING_HEADER_NEWLINE	{ 8, "MISSING_HEADER_NEWLINE" };
		const error_status MISSING_HEADER_COLON		{ 9, "MISSING_HEADER_COLON" };

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

	// TODO - break build/parse into seperate functions, since client & server message formats are very similar,
	// only really differing in start-line implementation.
	//parse_x()
	//build_x()
	//parse_start_line()
	//build_start_line()
	//...

	error_status recv_message_head(int fd, string& buffer, size_t& head_length, const int MAX_HEAD_LENGTH) {
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
			if(buffer.length() > MAX_HEAD_LENGTH) return ERROR_STATUS::ERR_MAXLEN_HEAD;
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
	error_status recv_message_body(int fd, string& buffer, size_t& body_length, const int content_length) {
		// read content.
		while(body_length < content_length) {
			const int remaining = content_length - body_length;
			const int chunk_sz = 1024 * 16;
			char temp[chunk_sz];
			int len = recv(fd, temp, std::min(chunk_sz, remaining), 0);
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


	error_status recv_http_request(int fd, http_request& request) {
		string& buffer = request.buffer;

		// receive header section.
		{
			const int MAX_HEAD_LENGTH = 1024 * 10;// 10 KiB
			const error_status err = recv_message_head(fd, buffer, request.head_length, MAX_HEAD_LENGTH);
			if(err.code != ERROR_STATUS::SUCCESS.code) return err;
		}

		// parse start line.
		{
			int end = buffer.find(HTTP_HEADER_NEWLINE);
			if(end != string::npos) {
				int a=0, b=0;
				// method.
				b = buffer.find(" ", a);
				request.method = to_uppercase_ascii(buffer.substr(a, b-a));
				// target.
				a = b + 1;
				b = buffer.find(" ", a);
				request.target = buffer.substr(a, b-a);
				// protocol.
				a = b + 1;
				b = end;
				request.protocol = to_uppercase_ascii(buffer.substr(a, b-a));
			} else {
				return ERROR_STATUS::MISSING_START_NEWLINE;
			}
		}

		// parse header lines.
		{
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
				request.headers[to_lowercase_ascii(key)] = trim_leading(val);
				// advance to the next line.
				beg = end + HTTP_HEADER_NEWLINE.length();
			}
		}

		// receive content section (if any).
		if(request.headers.contains(HTTP::HEADERS::content_length)) {
			// get content length.
			const string str = request.headers.at(HTTP::HEADERS::content_length);
			int content_length;
			std::from_chars(str.data(), str.data()+str.size(), content_length);
			// some of the content may have already been read into buffer when receiving headers.
			request.body_length = buffer.length() - request.head_length;
			// receive body.
			const error_status err = recv_message_body(fd, buffer, request.body_length, content_length);
			if(err.code != ERROR_STATUS::SUCCESS.code) return err;
		}

		return ERROR_STATUS::SUCCESS;
	}
	error_status send_http_response(int fd, http_response& response) {
		string& buffer_head = response.buffer_head;
		string& buffer_body = response.buffer_body;

		// add "content-length".
		// NOTE: "content-type" header will still have to be set externally.
		if(buffer_body.length() > 0) {
			char temp[256];
			snprintf(temp, 256, "%lu", buffer_body.length());
			response.headers[HTTP::HEADERS::content_length] = string(temp);
		}

		// build start line.
		{
			char temp[256];
			snprintf(temp, 256, "%s %i %s", response.protocol.c_str(), response.status_code, STATUS_CODES.at(response.status_code).c_str());
			buffer_head.append(string(temp));
			buffer_head.append(HTTP_HEADER_NEWLINE);
		}

		// build header lines.
		{
			for(const auto& [key,val] : response.headers) {
				buffer_head.append(key);
				buffer_head.append(": ");
				buffer_head.append(val);
				buffer_head.append(HTTP_HEADER_NEWLINE);
			}
		}

		// add blank header line (to indicate end of header section).
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

}
