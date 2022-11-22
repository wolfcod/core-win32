#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include "vector.h"

namespace rcs {
	vector::~vector()
	{
		if (flags == 0 && buffer_ != nullptr)
			free(buffer_);
	}

	vector::vector()
		: buffer_(nullptr), pos_(0), size_(0), flags(0)
	{

	}

	vector::vector(size_t capacity)
		: vector()
	{
		reserve(capacity);
	}

	const void* vector::buffer()
	{
		return buffer_;
	}

	size_t vector::capacity()
	{
		return size_;
	}

	size_t vector::size()
	{
		return pos_;
	}


	void vector::reserve(size_t new_cap)
	{
		if (size_ >= new_cap)
			return;

		void* tmp = realloc(buffer_, new_cap);
		if (tmp != NULL) {
			buffer_ = tmp;
			memset((char*)(buffer_)+size_, 0, new_cap - size_);
			size_ = new_cap;
		}
	}

	void vector::clear(int pattern)
	{
		if (buffer_ != nullptr)
			memset(buffer_, pattern, size_);
	}

	void vector::clear()
	{
		clear(0);
	}

}