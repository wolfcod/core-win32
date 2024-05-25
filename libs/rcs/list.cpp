#include <Windows.h>

#include "list.h"
LIST_ENTRY* InitializeListHead(LIST_ENTRY* ListHead)
{
	if (ListHead->Blink == NULL && ListHead->Flink == NULL)
	{
		ListHead->Blink = ListHead;
		ListHead->Flink = ListHead;
	}

	return ListHead;
}

LIST_ENTRY* InsertHeadList(LIST_ENTRY* ListHead, LIST_ENTRY* Entry)
{
	Entry->Flink = ListHead->Flink;
	Entry->Blink = ListHead;
	Entry->Flink->Blink = Entry;
	ListHead->Flink = Entry;

	return ListHead;
}

LIST_ENTRY* InsertTailList(LIST_ENTRY* ListHead, LIST_ENTRY* Entry)
{
	Entry->Flink = ListHead;
	Entry->Blink = ListHead->Blink;
	Entry->Blink->Flink = Entry;
	ListHead->Blink = Entry;
	return Entry;
}

BOOL IsListEmpty(LIST_ENTRY* ListHead)
{
	return (BOOL)(ListHead->Flink == ListHead);
}

LIST_ENTRY* RemoveEntryList(LIST_ENTRY* Entry)
{
	if (IsListEmpty(Entry))
		return NULL;

	Entry->Flink->Blink = Entry->Blink;
	Entry->Blink->Flink = Entry->Flink;
	return Entry->Flink;
}

size_t list_size(LIST_ENTRY* head)
{
	size_t i = 0;

	LIST_ENTRY* entry = head->Flink;

	while (entry != head)
	{
		i++;
		entry = entry->Flink;
	}

	return i;
}