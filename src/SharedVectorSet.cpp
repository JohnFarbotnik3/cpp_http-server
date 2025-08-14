
#include <mutex>
#include <shared_mutex>
#include <vector>
#include <map>

template<typename K>
struct SharedVectorSet {
	std::shared_mutex mutex;
	std::map<K, int> key_index_map;
	std::vector<K> keys;

	void clear() {
		key_index_map.clear();
		keys.clear();
	}

	bool contains(K key) {
		return key_index_map[key].contains(key);
	}

	void insert(K key) {
		std::unique_lock<std::shared_mutex> lock(mutex);
		if(contains(key)) return;
		key_index_map[key] = keys.size();
		keys.push_back(key);
	}

	void remove(K key) {
		std::unique_lock<std::shared_mutex> lock(mutex);
		if(!contains(key)) return;
		int ind = key_index_map[key];
		key_index_map[keys.back()] = ind;
		std::swap(keys.back(), keys[ind]);
		keys.pop_back();
		key_index_map.erase(key);
	}

	std::shared_lock<std::shared_mutex> read_lock() {
		return std::shared_lock<std::shared_mutex>(mutex);
	}
};
