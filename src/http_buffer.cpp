
#include <cstddef>
#include <cstring>
#include <string>
#include <sys/socket.h>

namespace HTTP {
	using std::string;

	/*
	 a * buffer structure strictly for use inside this namespace.

	 when used correctly, this allows me to reduce the number of times
	 I am copying data, as well as potentially supporting request-pipelining.

	 typical buffer layout:
	 |....R-----W.........|
	 - data is written at write position W.
	 - data is read from read position R.
	 */
	struct http_buffer {
		char*	data;
		size_t	capacity;
	//private:
		size_t	write_position;
		size_t	read_position;

	public:
		http_buffer(size_t initial_capacity) {
			data = new char[initial_capacity];
			capacity = initial_capacity;
			write_position = 0;
			read_position = 0;
		}
		~http_buffer() {
			delete[] data;
		}

		// length of string between read_position and write_position.
		size_t length() {
			return write_position - read_position;
		}

		// amount of writable space left in buffer.
		size_t capacity_remaining() {
			return capacity - write_position;
		}

		// shift data so that read_position starts at 0.
		void shift_to_start() {
			const size_t len = this->length();
			memmove(data+0, data+read_position, len);
			read_position = 0;
			write_position = len;
		}

		// resize and shift data to start.
		void resize(size_t new_capacity, bool force=false) {
			if(new_capacity <= capacity && !force) return;
			const size_t len = this->length();
			char* new_data = new char[new_capacity];
			memcpy(new_data, data+read_position, len);
			delete[] data;
			data = new_data;
			read_position = 0;
			write_position = len;
		}

		// truncate to length.
		void truncate() {
			resize(this->length(), true);
		}

		// reserve space for N additional characters.
		void reserve(size_t req_capacity) {
			if(write_position + req_capacity > capacity) resize((capacity * 3) / 2 + req_capacity);
		}

		// extract first N characters from buffer - advances read position.
		string read(size_t len) {
			len = std::min(len, this->length());
			size_t pos;
			string str(data + read_position, len);
			read_position += len;
			return str;
		}

		// write N characters into buffer - advances write position.
		size_t write(char* src, size_t len) {
			len = std::min(len, this->capacity_remaining());
			memcpy(data + write_position, src, len);
			write_position += len;
			return len;
		}

		// append N characters to buffer - reserving more space as needed.
		void append(char* src, size_t len) {
			if(this->capacity_remaining() < len) this->reserve(len);
			memcpy(data + write_position, src, len);
			write_position += len;
		}

		std::string_view string_view() {
			return std::string_view(data + read_position, this->length());
		}

		// search for substring - indexed relative to read_position.
		size_t find(const string& str, size_t pos) {
			return this->string_view().find(str, pos);
		}

		// receive into buffer - advances write position.
		ssize_t buffer_recv(int fd, int count) {
			ssize_t len = recv(fd, data + write_position, count, 0);
			if(len > 0) write_position += len;
			return len;
		}
		// TODO - send



	};
}
