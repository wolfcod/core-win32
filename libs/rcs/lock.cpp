#include <Windows.h>
#include "lock_guard.h"
#include "lock.h"

namespace rcs {
	
	lock::lock(lock_guard& guard)
	{
		if (guard.init == FALSE)
			InitializeCriticalSection(&guard.cs);

		guard_ptr = (void *) &guard.cs;

		EnterCriticalSection(&guard.cs);
	}

	lock::~lock()
	{
		LeaveCriticalSection((LPCRITICAL_SECTION)guard_ptr);
	}
}