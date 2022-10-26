#pragma once

#ifndef __LISTENTRY_H
#define __LISTENTRY_H

static __forceinline  LIST_ENTRY* InitializeListHead(LIST_ENTRY* ListHead)
{
	if (ListHead->Blink == NULL && ListHead->Flink == NULL) {
		ListHead->Blink = ListHead;
		ListHead->Flink = ListHead;
	}

	return ListHead;
}

static __forceinline LIST_ENTRY* InsertHeadList(LIST_ENTRY* ListHead, LIST_ENTRY* Entry)
{
	Entry->Flink = ListHead->Flink;
	Entry->Blink = ListHead;
	Entry->Flink->Blink = Entry;
	ListHead->Flink = Entry;

	return ListHead;
}

static __forceinline LIST_ENTRY* InsertyTailList(LIST_ENTRY* ListHead, LIST_ENTRY* Entry)
{
	Entry->Flink = ListHead;
	Entry->Blink = ListHead->Blink;
	Entry->Blink->Flink = Entry;
	ListHead->Blink = Entry;
	return Entry;
}

static __forceinline BOOL IsListEmpty(LIST_ENTRY* ListHead)
{
	return (BOOL)(ListHead->Flink == ListHead);
}

static __forceinline LIST_ENTRY* RemoveEntryList(LIST_ENTRY* Entry)
{
	if (IsListEmpty(Entry))
		return NULL;

	Entry->Flink->Blink = Entry->Blink;
	Entry->Blink->Flink = Entry->Flink;
	return Entry->Flink;
}

#endif
