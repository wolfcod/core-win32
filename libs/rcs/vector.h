#pragma once

namespace rcs {
	struct vector {
		~vector();

		vector();	// create an empty buffer
		vector(size_t reserve);	// create an empty buffer with a reserved capacity

		size_t size();
		size_t capacity();
		const void* buffer();

		void reserve(size_t new_cap);
		
		void clear();
		void clear(int pattern);

		template<typename T>
		void write(T value)
		{
			if (pos_ + sizeof(T) < size_) {
				memcpy((char*)buffer_ + pos_, &value, sizeof(T));
				pos_ += sizeof(T);
			}
		}

		template<typename T>
		void write(T* array, size_t length)
		{
			if ((pos_ + sizeof(T) * length) < size_) {
				memcpy((char*)buffer_ + pos_, array, length * sizeof(T));
				pos_ += length * sizeof(T);
			}
		}
	private:
		int flags;
		void* buffer_;
		size_t size_;
		size_t pos_;
	};
}