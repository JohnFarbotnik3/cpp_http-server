
#include <mutex>
#include <shared_mutex>
#include <map>

template<typename K, typename V>
struct SharedMap {
	std::map<K, V> map;
	std::shared_mutex mutex;

	bool contains(K key) {
		std::shared_lock<std::shared_mutex> lock(mutex);
		return map.contains(key);
	}

	V& get(K key) {
		std::shared_lock<std::shared_mutex> lock(mutex);
		return map.at(key);
	}

	void set(K key, V value) {
		std::unique_lock<std::shared_mutex> lock(mutex);
		map[key] = value;
	}

	void remove(K key) {
		std::unique_lock<std::shared_mutex> lock(mutex);
		map.erase(key);
	}
};
