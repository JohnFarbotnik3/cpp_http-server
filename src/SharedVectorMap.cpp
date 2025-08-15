
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <map>

template<typename K, typename V>
struct SharedVectorMap {
	std::shared_mutex mutex;
	std::map<K, int> key_index_map;
	std::vector<K> keys;
	std::vector<V> vals;

	void clear() {
		key_index_map.clear();
		keys.clear();
		vals.clear();
	}

	bool contains(K key) {
		return key_index_map[key].contains(key);
	}

	V get(K key) {
		int index = key_index_map.at(key);
		return vals[index];
	}

	void set(K key, V value) {
		std::unique_lock lock(mutex);
		if(contains(key)) {
			int index = key_index_map.at(key);
			vals[index] = value;
		} else {
			key_index_map[key] = keys.size();
			keys.push_back(key);
			vals.push_back(value);
		}
	}

	void remove(K key) {
		std::unique_lock lock(mutex);
		if(!contains(key)) return;
		int ind = key_index_map[key];
		key_index_map[keys.back()] = ind;
		std::swap(keys.back(), keys[ind]);
		std::swap(vals.back(), vals[ind]);
		keys.pop_back();
		vals.pop_back();
		key_index_map.erase(key);
	}

	std::shared_lock<std::shared_mutex> read_lock() {
		return std::shared_lock(mutex);
	}
};
