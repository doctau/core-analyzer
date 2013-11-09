/*
 * x_dep.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_DEP_H_
#define X_DEP_H_

#include "x_type.h"

struct object_reference;
struct reg_value;
struct ca_segment;
struct CA_LIST;

struct ca_debug_context
{
	int tid;
	int frame_level;
	address_t sp;
};

extern CA_BOOL update_memory_segments_and_heaps(void);

extern CA_BOOL inferior_memory_read (address_t addr, void* buffer, size_t sz);

extern void print_register_ref(const struct object_reference* ref);
extern void print_stack_ref(const struct object_reference* ref);
extern void print_global_ref(const struct object_reference* ref);
extern void print_heap_ref(const struct object_reference* ref);

extern CA_BOOL known_global_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz);
extern CA_BOOL known_stack_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz);

extern address_t get_var_addr_by_name(const char*);

extern void print_func_locals (void);
extern void print_type_layout (char*);

extern CA_BOOL get_vtable_from_exp(const char*, struct CA_LIST*, char*, size_t, size_t*);

extern CA_BOOL user_request_break(void);

extern CA_BOOL g_debug_core;

extern unsigned int g_ptr_bit;

extern struct ca_debug_context g_debug_context;

#endif // X_DEP_H_
