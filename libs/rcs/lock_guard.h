#pragma once

namespace rcs {
	struct lock_guard {
		CRITICAL_SECTION cs;
		BOOL init;

		operator void* ()
		{
			return (void*)&cs;
		}
	};
}