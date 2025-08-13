
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>

using std::string;
using std::string_view;

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

	void set_capacity(size_t new_capacity) {
		char* new_data = new char[new_capacity];
		size_t new_length = std::min(length, new_capacity);
		memcpy(new_data, data, new_length * sizeof(data[0]));
		delete[] data;
		data		= new_data;
		capacity	= new_capacity;
		length		= new_length;
	}
	void reserve(size_t new_capacity) {
		if(new_capacity > capacity) set_capacity(new_capacity);
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
		reserve(length + str.length());
		memcpy(data+length, str.data(), str.length() * sizeof(str[0]));
		length += str.length();
	}

	void shift(size_t count) {
		memmove(data, data+count, length-count);
		length -= count;
	}
};

