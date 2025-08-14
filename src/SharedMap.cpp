
#include <mutex>
#include <shared_mutex>
#include <map>

template<typename K, typename V>
struct SharedMap {
	std::map<K, V> map;
	std::shared_mutex mutex;

	V& get(K key) {
		std::shared_lock lock(mutex);
		return map.at(key);
	}

	void set(K key, V value) {
		std::unique_lock lock(mutex);
		map[key] = value;
	}

	void remove(K key) {
		std::unique_lock lock(mutex);
		map.erase(key);
	}
};
