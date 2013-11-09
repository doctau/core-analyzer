/*
 * stl_container.h
 * 		A wrapper of stl tree/vector/list etc. because gdb is a c program
 */
#ifndef _STL_CONTAINER_H
#define _STL_CONTAINER_H

#include "x_type.h"

typedef CA_BOOL (*CA_CompareFunctionType)(void *, void *);
struct CA_SET;
struct CA_LIST;

struct CA_SET* ca_set_new(CA_CompareFunctionType comp);
void ca_set_delete(struct CA_SET*);
void* ca_set_find(struct CA_SET*, void*);
void  ca_set_insert(struct CA_SET*, void*);
void  ca_set_clear(struct CA_SET*);
void  ca_set_traverse_start(struct CA_SET*);
void* ca_set_traverse_next(struct CA_SET*);

void  ca_list_traverse_start(struct CA_LIST*);
void* ca_list_traverse_next(struct CA_LIST*);
void* ca_list_find(struct CA_LIST*, void*);
void  ca_list_clear(struct CA_LIST*);
void  ca_list_push_front(struct CA_LIST*, void*);
void  ca_list_push_back(struct CA_LIST*, void*);
void  ca_list_pop_front(struct CA_LIST*);
struct CA_LIST* ca_list_new();
void ca_list_delete(struct CA_LIST*);
CA_BOOL ca_list_empty(struct CA_LIST*);
size_t ca_list_size(struct CA_LIST*);

#endif // _STL_CONTAINER_H
