#include <filesystem>
#include <fstream>
#include <string>
#include "../http_structs.cpp"
#include "../definitions/methods.cpp"
#include "../definitions/headers.cpp"
#include "../definitions/mime_types.cpp"
#include "../HTTPServer.cpp"

namespace HTTP::Handlers::static_file_server {
	using std::string;
	namespace fs = std::filesystem;
	using fs::path;

	struct config {
		// prefix to append to target filepaths.
		// requested files should be inside this directory.
		path prefix;
	};

	bool can_read_file(const path target) {
		return fs::exists(target) && fs::is_regular_file(target);
	}
	bool can_write_file(const path target) {
		return !fs::exists(target) || fs::is_regular_file(target);
	}
	bool can_delete_file(const path target) {
		return fs::exists(target) && fs::is_regular_file(target);
	}

	void make_dir(const path target, int& status) {
		std::error_code ec;
		fs::create_directories(target, ec);
		if(ec) {
			fprintf(stderr, "failed to make directory: %s (error: %s)\n", target.c_str(), ec.message().c_str());
			status = -1;
		} else {
			status = 0;
		}
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
		make_dir(target.parent_path(), status);
		if(status != 0) return;

		std::ofstream file(target, std::ios::binary);
		if (!file.is_open()) {
			fprintf(stderr, "failed to open file for writing: %s\n", target.c_str());
			status = -1;
		} else {
			file.write(data, size);
			status = 0;
			errno = 0;
		}
	}

	void delete_file(const path target, int& status) {
		std::error_code ec;
		bool success = fs::remove(target, ec);
		if(!success) {
			fprintf(stderr, "failed to delete file: %s (error: %s)\n", target.c_str(), ec.message().c_str());
			status = -1;
		} else {
			status = 0;
		}
	}

	http_response handle_request(const http_request& request, const config& conf) {
		http_response response;

		// by default no content is returned (overwrite header as needed).
		response.headers[HTTP::HEADERS::content_length] = "0";

		// get target file path.
		path target;
		if(request.target == "/") {
			target = path(conf.prefix / "index.html");
		} else {
			string str = request.target;
			if(str.starts_with("/")) str = str.substr(1);
			target = path(conf.prefix / str);
		}

		// security: ensure target file is within prefix directory.
		{
			std::error_code ec;
			path abs_p = fs::canonical(conf.prefix, ec);
			path abs_t = fs::canonical(target.parent_path(), ec);
			bool is_safe = abs_t.string().append("/").contains(abs_p.string());
			if(!is_safe) {
				printf("SECURITY: target outside of prefix directory:\n");
				printf("\ttarget: %s\n", target.c_str());
				printf("\tabs_p: %s\n", abs_p.c_str());
				printf("\tabs_t: %s\n", abs_t.c_str());
				if(ec) printf("\tec: %s\n", ec.message().c_str());
				response.status_code = 404;
				return response;
			} else {
				printf("\ttarget: %s\n", target.c_str());
			}
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
				response.body = content;
				// set content type.
				string ext = target.extension();
				response.headers[HTTP::HEADERS::content_type] = get_mime_type(ext);
				response.headers[HTTP::HEADERS::content_length] = int_to_string(content.length());
				return response;
			} else {
				response.status_code = 500;
				return response;
			}
		}

		if(request.method == HTTP::METHODS::PUT) {
			if(!can_write_file(target)) {
				response.status_code = 403;
				return response;
			}
			int status;
			bool file_exists = fs::is_regular_file(target);
			write_file(target, status, request.body.data(), request.body.size());
			response.status_code = (status != 0) ? 500 : (file_exists ? 204 : 201);
			return response;
		}

		if(request.method == HTTP::METHODS::DELETE) {
			if(!can_delete_file(target)) {
				response.status_code = 404;
				return response;
			}
			int status;
			delete_file(target, status);
			response.status_code = (status != 0) ? 500 : 204;
			return response;
		}

		response.status_code = 501;
		return response;
	}

	// example server.
	struct HTTPFileServer : HTTP::HTTPServer {
		config conf;

		HTTPFileServer(const char* hostname, const char* portname, config conf) : HTTPServer(hostname, portname) {
			this->conf = conf;
		}

		ERROR_CODE handle_request(const accept_connection_struct& connection, http_request& request, http_response& response) override {
			response = static_file_server::handle_request(request, conf);
			return ERROR_CODE::SUCCESS;
		}
	};
}
