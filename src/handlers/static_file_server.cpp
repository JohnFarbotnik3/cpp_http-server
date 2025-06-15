#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include "../http_structs.cpp"
#include "../definitions/methods.cpp"
#include "../definitions/headers.cpp"
#include "../definitions/mime_types.cpp"

namespace HTTP::Handlers::static_file_server {
	using std::string;
	using std::filesystem::path;

	struct config {
		// prefix to append to target filepaths.
		// requested files should be inside this directory.
		path prefix;
	};

	bool is_path_inside_prefix_directory(const path target, const path prefix) {
		path abs_p = std::filesystem::absolute(prefix);
		path abs_t = std::filesystem::absolute(target);
		return abs_t.string().contains(abs_p.string());
	}

	bool can_read_file(const path target) {
		return std::filesystem::exists(target) && std::filesystem::is_regular_file(target);
	}
	bool can_write_file(const path target) {
		return !std::filesystem::exists(target) || std::filesystem::is_regular_file(target);
	}
	bool can_delete_file(const path target) {
		return std::filesystem::exists(target) && std::filesystem::is_regular_file(target);
	}

	string read_file(const path target, int& status) {
		std::ifstream file(target, std::ios::binary | std::ios::ate);
		if (!file.is_open()) {
			fprintf(stderr, "failed to open file for reading: %s\n", target.c_str());
			status = -1;
			return "";
		} else {
			const size_t filesize = file.tellg();
			string buffer(filesize, '\0');
			file.seekg(0);
			file.read(buffer.data(), filesize);
			status = 0;
			return buffer;
		}
	}

	void write_file(const path target, int& status, const char* data, const size_t size) {
		std::ofstream file(target, std::ios::binary);
		if (!file.is_open()) {
			fprintf(stderr, "failed to open file for writing: %s\n", target.c_str());
			status = -1;
		} else {
			file.write(data, size);
			status = 0;
		}
	}

	void delete_file(const path target, int& status) {
		std::error_code ec;
		bool success = std::filesystem::remove(target, ec);
		if(!success) {
			fprintf(stderr, "failed to delete file: %s (error: %s)\n", target.c_str(), ec.message().c_str());
			status = -1;
		} else {
			status = 0;
		}
	}

	http_response handle_request(const http_request& request, const config& conf) {
		http_response response;

		// get target file path.
		path target = conf.prefix;
		target.concat(request.target);

		// security: ensure target file is within prefix directory.
		if(!is_path_inside_prefix_directory(target, conf.prefix)) {
			response.status_code = 404;
			return response;
		}

		if(request.method == HTTP::METHODS::GET) {
			if(!can_read_file(target)) {
				response.status_code = 404;
				return response;
			}
			int status;
			const string content = read_file(target, status);
			if(status == 0) {
				response.status_code = 200;
				response.buffer_body = content;
				// set content type.
				string ext = target.extension();
				string mmt = HTTP::MIME_TYPES.at("");
				if(HTTP::MIME_TYPES.contains(ext)) mmt = HTTP::MIME_TYPES.at(ext);
				response.headers[HTTP::HEADERS::content_type] = mmt;
				response.headers[HTTP::HEADERS::content_length] = content.length();
			} else {
				response.status_code = 500;
			}
			return response;
		}

		if(request.method == HTTP::METHODS::PUT) {
			if(!can_write_file(target)) {
				response.status_code = 403;
				return response;
			}
			int status;
			const std::string_view& content = request.content();
			write_file(target, status, content.data(), content.size());
			response.status_code = (status == 0) ? 200 : 500;
			return response;
		}

		if(request.method == HTTP::METHODS::DELETE) {
			if(!can_delete_file(target)) {
				response.status_code = 404;
				return response;
			}
			int status;
			delete_file(target, status);
			response.status_code = (status == 0) ? 200 : 500;
			return response;
		}

		response.status_code = 501;
		return response;
	}
}
