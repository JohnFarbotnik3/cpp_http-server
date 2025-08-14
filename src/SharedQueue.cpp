
#include <mutex>
#include <queue>

template<typename T>
struct SharedQueue {
	std::queue<T> queue;
	std::mutex mutex;

	void push(T value) {
		std::lock_guard lock(mutex);
		queue.push(value);
	}

	T pop() {
		std::lock_guard lock(mutex);
		T value = queue.front();
		queue.pop();
		return value;
	}
};
