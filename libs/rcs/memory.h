#pragma once

#ifndef __RCS_MEMORY_H
#define __RCS_MEMORY_H

template<typename ...Args>
void* mmemcpy(void* dst, const void* src, size_t size, Args... args)
{
	memcpy(dst, src, size);
	return mmemcpy((uint8_t*)dst + size, args...);
}

template<>
void* mmemcpy(void* dst, const void* src, size_t size)
{
	memcpy(dst, src, size);
	return (uint8_t*)dst + size;
}

#endif
