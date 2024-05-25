#pragma once

LIST_ENTRY* InitializeListHead(LIST_ENTRY* ListHead);
LIST_ENTRY* InsertHeadList(LIST_ENTRY* ListHead, LIST_ENTRY* Entry);
LIST_ENTRY* InsertTailList(LIST_ENTRY* ListHead, LIST_ENTRY* Entry);
BOOL IsListEmpty(LIST_ENTRY* ListHead);
LIST_ENTRY* RemoveEntryList(LIST_ENTRY* Entry);
size_t list_size(LIST_ENTRY* head);

namespace rcs
{
	template<typename Key, typename Value>
	struct hash_map
	{


	};
}

template<typename T, typename Fn, typename... Args>
T* find_entry_in_list(LIST_ENTRY* head, Fn f, Args... args)
{
	LIST_ENTRY* entry = head->Flink;

	while (entry != head)
	{
		T* curr = CONTAINING_RECORD(entry, T, entry);
		if (f(curr, args...))
			return curr;

		entry = entry->Flink;
	}

	return NULL;
}

template<typename T, typename Fn>
void apply_in_list(LIST_ENTRY* head, Fn f)
{
	LIST_ENTRY* entry = head->Flink;

	while (entry != head)
	{
		T* curr = CONTAINING_RECORD(entry, T, entry);
		f(curr);
		entry = entry->Flink;
	}

	return;
}

template<typename T, typename Fn>
void reverse_apply_in_list(LIST_ENTRY* head, Fn f)
{
	LIST_ENTRY* entry = head->Blink;

	while (entry != head)
	{
		T* curr = CONTAINING_RECORD(entry, T, entry);
		f(curr);
		entry = entry->Blink;
	}

	return;
}

template<typename T, typename Fn>
void search_and_change(LIST_ENTRY* head, Fn search, Fn transform)
{
	LIST_ENTRY* entry = head->Flink;

	while (entry != head)
	{
		T* curr = CONTAINING_RECORD(entry, T, entry);
		if (search(curr))
			transform(curr);

		entry = entry->Flink;
	}

	return;
}


template<typename T, typename Fn>
void remove_all(LIST_ENTRY* head, Fn dealloc)
{
	LIST_ENTRY* entry = head->Flink;

	while (entry != head)
	{
		T* curr = CONTAINING_RECORD(entry, T, entry);

		RemoveEntryList(entry);
		dealloc((void*)curr);
	}
}

template<typename T>
void insert(LIST_ENTRY* head, T* value)
{
	LIST_ENTRY* entry = head->Flink;

	while (entry != head)
	{
		InsertTailList(head, &value->entry);
	}
}

template<typename T>
T* alloc_entry()
{
	return (T*)calloc(1, sizeof(T));
}

template<typename T>
T* get_head_list(LIST_ENTRY* head)
{
	LIST_ENTRY* entry = head->Flink;

	while (entry != head)
	{
		T* curr = CONTAINING_RECORD(entry, T, entry);
		return curr;
	}

	return NULL;
}
