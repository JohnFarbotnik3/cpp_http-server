
#include <mutex>
#include <queue>
#include <semaphore>

template<typename T>
struct SharedQueue {
	std::queue<T> queue;
	std::mutex mutex;
	std::counting_semaphore<1000000> semaphore = std::counting_semaphore<1000000>(0);

	void push(T value) {
		std::lock_guard lock(mutex);
		queue.push(value);
		semaphore.release();
	}

	T pop() {
		semaphore.acquire();
		std::lock_guard lock(mutex);
		T value = queue.front();
		queue.pop();
		return value;
	}
};
