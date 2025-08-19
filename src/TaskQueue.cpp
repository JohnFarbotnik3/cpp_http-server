
#include <mutex>
#include <queue>
#include <semaphore>

template<typename T>
struct TaskQueue {
	std::queue<T> queue;
	std::mutex mutex;
	std::counting_semaphore<1000000> semaphore = std::counting_semaphore<1000000>(0);

	void push(T value) {
		{
			std::unique_lock lock(mutex);
			queue.push(value);
		}
		semaphore.release();
	}

	void push_array(const T* data, int size) {
		{
			std::unique_lock lock(mutex);
			for(int x=0;x<size;x++) queue.push(data[x]);
		}
		semaphore.release(size);
	}

	T pop() {
		semaphore.acquire();
		std::unique_lock lock(mutex);
		T value = queue.front();
		queue.pop();
		return value;
	}
};
