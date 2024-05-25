#pragma once

namespace rcs {
	struct lock_guard;

	struct lock {
		lock(lock_guard &obj);
		~lock();

		void* guard_ptr;
	};
}