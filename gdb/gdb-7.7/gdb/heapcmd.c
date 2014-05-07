/*
 * heapcmd.c
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include "ref.h"
#include "heap.h"
#include "segment.h"
#include "search.h"
#include "stl_container.h"

static unsigned int g_num_adjacent_blocks = 10;

unsigned int get_num_adjacent_blocks_to_display (void)
{
	return g_num_adjacent_blocks;
}

/***************************************************************************
* gdb commands
***************************************************************************/
static void
block_command (char *arg, int from_tty)
{
	address_t addr;
	struct heap_block heap_block;

	if (!arg)
		error_no_arg (_("address"));
	addr = parse_and_eval_address (arg);

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	if (get_heap_block_info(addr, &heap_block))
	{
		if (heap_block.inuse)
			printf_filtered(_("\t[In-use]\n"));
		else
			printf_filtered(_("\t[Free]\n"));

		printf_filtered(_("\t[Address] 0x%lx\n"), heap_block.addr);
		printf_filtered(_("\t[Size]    %ld\n"), heap_block.size);
		printf_filtered(_("\t[Offset]  %+ld\n"), addr - heap_block.addr);
	}
	else
	{
		printf_filtered(_("[Error] Failed to query the memory block\n"));
	}
}

static void
heap_command (char *args, int from_tty)
{
	address_t addr = 0;
	CA_BOOL verbose = CA_FALSE;
	CA_BOOL check_leak = CA_FALSE;

	if (args && *args != '\0')
	{
		char *exp = args;
		char *end = args + strlen(args);
		while (exp < end)
		{
			char* rest;
			/* Find the 1st optional argument (address).  */
			while (exp < end && isspace(*exp))
				exp++;
			if (exp < end)
			{
				rest = exp;
				while (rest < end && *rest && !isspace(*rest))
					rest++;
				*rest = '\0';
				// argument is either an address or /v or /leak
				if (strcmp(exp, "/leak") == 0)
				{
					check_leak = CA_TRUE;
					break;
				}
				else if (exp[0] == '/' && exp[1] == 'v')
					verbose = CA_TRUE;
				else if (addr == 0)
					addr = parse_and_eval_address (exp);
				else if (isdigit(*exp))
				{
					int n = atoi(exp);
					if (n > 0)
						g_num_adjacent_blocks = n;
				}
				exp = rest + 1;
			}
		}
	}

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	if (check_leak)
		display_heap_leak_candidates();
	else if (!heap_walk(addr, verbose))
		printf_filtered(_("[Error] Failed to walk heap\n"));
}

static void
ref_command (char *args, int from_tty)
{
	int rc;
	address_t addr;
	size_t size = -1;
	size_t depth = 1;

	char *addr_exp = NULL;
	char *size_exp = NULL;
	char *depth_exp = NULL;
	char *end;
	struct cleanup *old_chain;

	if (args == NULL || *args == '\0')
		error (_("Missing object address."));
	end = args + strlen(args);

	/* Find the 1st argument (address).  */
	addr_exp = args;
	while (isspace(*addr_exp) && addr_exp < end)
		addr_exp++;
	if (addr_exp >= end)
		error (_("Missing object address."));
	else
		size_exp = addr_exp;

	while (!isspace(*size_exp) && size_exp < end)
		size_exp++;
	*size_exp = '\0';

	/* Find the 2nd argument (object size) */
	size_exp++;
	while (size_exp < end && isspace(*size_exp))
		size_exp++;

	/* The rest is the 3rd argument (reference depth to search) */
	depth_exp = size_exp;
	while (depth_exp < end && !isspace(*depth_exp))
		depth_exp++;
	*depth_exp = '\0';
	depth_exp++;

	addr = parse_and_eval_address (addr_exp);
	if (size_exp < end)
		size = parse_and_eval_address (size_exp);
	if (depth_exp < end)
		depth = parse_and_eval_address (depth_exp);

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	old_chain = make_cleanup_restore_current_thread ();
	if (size == -1)
	{
		printf_filtered(_("Search for object type associated with 0x%lx\n"), addr);
		rc = find_object_type(addr);
	}
	else
	{
		printf_filtered(_("Search for references to 0x%lx size %ld up to %ld levels of indirection\n"), addr, size, depth);
		rc = find_object_refs(addr, size, depth);
	}
	if (!rc)
		printf_filtered(_("No result found\n"));
	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
tref_command (char *args, int from_tty)
{
	int rc;
	address_t addr;
	size_t size  = 1;
	size_t depth = 1;

	char *addr_exp = NULL;
	char *size_exp = NULL;
	char *depth_exp = NULL;
	char *end;
	struct cleanup *old_chain;

	if (args == NULL || *args == '\0')
		error (_("Missing object address."));
	end = args + strlen(args);

	/* Find the 1st argument (address).  */
	addr_exp = args;
	while (isspace(*addr_exp) && addr_exp < end)
		addr_exp++;
	if (addr_exp >= end)
		error (_("Missing object address."));
	else
		size_exp = addr_exp;

	while (!isspace(*size_exp) && size_exp < end)
		size_exp++;
	*size_exp = '\0';

	/* Find the 2nd argument (object size) */
	size_exp++;
	while (size_exp < end && isspace(*size_exp))
		size_exp++;

	/* The rest is the 3rd argument (reference depth to search) */
	depth_exp = size_exp;
	while (depth_exp < end && !isspace(*depth_exp))
		depth_exp++;
	*depth_exp = '\0';
	depth_exp++;

	addr = parse_and_eval_address (addr_exp);
	if (size_exp < end)
		size = parse_and_eval_address (size_exp);
	if (depth_exp < end)
		depth = parse_and_eval_address (depth_exp);

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	old_chain = make_cleanup_restore_current_thread ();
	printf_filtered(_("Search for thread references to 0x%lx size %ld up to %ld levels of indirection\n"),
					addr, size, depth);
	rc = find_object_refs_on_threads(addr, size, depth);
	if (!rc)
		printf_filtered(_("No result found\n"));
	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
pattern_command (char *args, int from_tty)
{
	address_t lo, hi;
	char *lo_exp;
	char *hi_exp;
	char *end;
	struct cleanup *old_chain;

	if (args == NULL || *args == '\0')
		error (_("Missing start address."));
	end = args + strlen(args);

	/* Find the low address.  */
	lo_exp = args;
	while (isspace(*lo_exp) && lo_exp < end)
		lo_exp++;
	if (lo_exp >= end)
		error (_("Missing start address."));
	else
		hi_exp = lo_exp;

	while (!isspace(*hi_exp) && hi_exp < end)
		hi_exp++;
	if (hi_exp < end)
		*hi_exp = '\0';
	else
		error (_("Missing end address."));

	/* Find the second address - rest of line.  */
	hi_exp++;
	while (isspace(*hi_exp) && hi_exp < end)
		hi_exp++;
	if (hi_exp >= end)
		error (_("Missing end address."));

	lo = parse_and_eval_address (lo_exp);
	hi = parse_and_eval_address (hi_exp);
	if (hi <= lo)
		error (_("Invalid memory address range (start >= end)."));

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	old_chain = make_cleanup_restore_current_thread ();

	print_memory_pattern(lo, hi);

	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
print_segment(struct ca_segment* segment)
{
	printf_filtered(_("[0x%lx - 0x%lx] %6ldK  %c%c%c "),
		segment->m_vaddr, segment->m_vaddr+segment->m_vsize,
		segment->m_vsize/1024,
		segment->m_read?'r':'-', segment->m_write?'w':'-', segment->m_exec?'x':'-');
	if (segment->m_type == ENUM_MODULE_TEXT)
		printf_filtered(_("[.text/.rodata] [%s]"), segment->m_module_name);
	else if (segment->m_type == ENUM_MODULE_DATA)
		printf_filtered(_("[.data/.bss] [%s]"), segment->m_module_name);
	else if (segment->m_type == ENUM_STACK)
		printf_filtered(_("[stack] [tid=%d]"), segment->m_thread.tid);
	else if (segment->m_type == ENUM_HEAP)
		printf_filtered(_("[heap]"));
	printf_filtered(_("\n"));
}

static void
segment_command (char *arg, int from_tty)
{
	struct ca_segment* segment;

	if (!update_memory_segments_and_heaps())
		return;

	if (arg)
	{
		address_t addr = parse_and_eval_address (arg);
		segment = get_segment(addr, 0);
		if (segment)
		{
			printf_filtered(_("Address 0x%lx belongs to segment:\n"), addr);
			print_segment(segment);
		}
		else
			printf_filtered(_("Address 0x%lx doesn't belong to any segment\n"), addr);
	}
	else
	{
		unsigned int i;
		printf_filtered(_("vaddr                         size      perm     name\n"));
		printf_filtered(_("=====================================================\n"));
		for (i=0; i<g_segment_count; i++)
		{
			struct ca_segment* segment = &g_segments[i];
			printf_filtered(_("[%4d] "), i);
			print_segment(segment);
		}
	}
}

static void
include_free_command (char *arg, int from_tty)
{
	g_skip_free = CA_FALSE;
	printf_filtered(_("Reference search will now include free heap memory blocks\n"));
}

static void
ignore_free_command (char *arg, int from_tty)
{
	g_skip_free = CA_TRUE;
	printf_filtered(_("Reference search will now exclude free heap memory blocks (default)\n"));
}

static void
include_unknown_command (char *arg, int from_tty)
{
	g_skip_unknown = CA_FALSE;
	printf_filtered(_("Reference search will now include all memory\n"));
}

static void
ignore_unknown_command (char *arg, int from_tty)
{
	g_skip_unknown = CA_TRUE;
	printf_filtered(_("Reference search will now exclude memory with unknown storage type (default)\n"));
}

static void
assign_command (char *args, int from_tty)
{
	address_t addr, value;
	char *first_exp = NULL;
	char *second_exp = NULL;
	char *end;

	if (args)
	{
		end = args + strlen(args);

		/* Find the low address.  */
		first_exp = args;
		/* skip white space */
		while (first_exp < end && *first_exp && isspace(*first_exp))
			first_exp++;

		/* walk to the end of the first expression until we see a white space */
		second_exp = first_exp;
		while (second_exp < end && *second_exp && !isspace(*second_exp) )
			second_exp++;
		/* put NULL terminator at the end of the first expression */
		*second_exp = '\0';
		second_exp++;
		if (second_exp > end)
			second_exp = end;
		/* skip white spaces before the second expression  */
		while (second_exp < end && *second_exp && isspace(*second_exp))
			second_exp++;
	}

	if (second_exp && strlen(second_exp) > 0)
	{
		addr = parse_and_eval_address (first_exp);
		value = parse_and_eval_address (second_exp);
		set_value (addr, value);
	}
	else if (first_exp && strlen(first_exp))
		error (_("Second argument is expected for the value at the input address"));
	else
		print_set_values ();
}

static void
unassign_command (char *arg, int from_tty)
{
	address_t addr;

	if (!arg)
		error_no_arg (_("address"));
	addr = parse_and_eval_address (arg);
	unset_value (addr);
}

static void
info_local_command (char *arg, int from_tty)
{
	print_func_locals ();
}

static void
dt_command (char *arg, int from_tty)
{
	char* type_or_expr;

	if (!arg)
		error_no_arg (_("type or variable name"));
	type_or_expr = strdup(arg);
	print_type_layout (type_or_expr);
	free (type_or_expr);
}

static void
obj_command (char *arg, int from_tty)
{
	struct cleanup *old_chain;

	if (!arg)
		error_no_arg (_("type or variable name"));

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	old_chain = make_cleanup_restore_current_thread ();
	search_cplusplus_objects_and_references(arg);
	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
shrobj_level_command (char *arg, int from_tty)
{
	unsigned int level = 0;
	if (arg)
		level = parse_and_eval_address (arg);

	set_shared_objects_indirection_level(level);
}

static void
max_indirection_level_command (char *arg, int from_tty)
{
	unsigned int level = 0;
	if (arg)
		level = parse_and_eval_address (arg);

	set_max_indirection_level(level);
}

#define IS_BLANK(c) ((c)==' ' || (c)=='\t')

static void
shrobj_command (char *arg, int from_tty)
{
	struct CA_LIST* threads = NULL;
	int* p;
	struct cleanup *old_chain;

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	threads = ca_list_new();
	if (arg)
	{
		const char* exp = arg;
		while(*exp)
		{
			const char* remainder;
			// skip blanks
			while (*exp && IS_BLANK(*exp))
				exp++;
			// get the remainder
			remainder = exp;
			while (*remainder && !IS_BLANK(*remainder))
				remainder++;
			// record thread id
			if (*exp)
			{
				int tid = atoi(exp);
				if (tid >= 0)
				{
					p = (int*) malloc(sizeof(int));
					*p = tid;
					ca_list_push_front(threads, p);
				}
			}
			// move on
			exp = remainder;
		}
	}

	old_chain = make_cleanup_restore_current_thread ();
	find_shared_objects_by_threads(threads);
	// remember to resume the current thread/frame
	do_cleanups (old_chain);
	// cleanup thread list
	if (!ca_list_empty(threads))
	{
		ca_list_traverse_start(threads);
		while ( (p = (int*) ca_list_traverse_next(threads)))
			free (p);
	}
	ca_list_delete(threads);
}

static void
decode_command (char *arg, int from_tty)
{
	struct cleanup *old_chain;
	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	old_chain = make_cleanup_restore_current_thread ();

	decode_func(arg);

	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

static void
big_command (char *arg, int from_tty)
{
	unsigned int n = 0;
	struct cleanup *old_chain;

	if (arg)
		n = parse_and_eval_address (arg);

	if (n == 0)
		error_no_arg (_("Input number of biggest heap memory blocks to display"));

	/* We depend on typed segments */
	if (!update_memory_segments_and_heaps())
		return;

	old_chain = make_cleanup_restore_current_thread ();

	biggest_blocks(n);

	// remember to resume the current thread/frame
	do_cleanups (old_chain);
}

void
_initialize_heapcmd (void)
{
	add_cmd("ref", class_info, ref_command, _("Search for references to a given object.\nref <addr> [size] [depth]"), &cmdlist);
	add_cmd("tref", class_info, tref_command, _("Search for references to a given object in thread contexts(stack and registers).\ntref <addr> [size] [depth]"), &cmdlist);
	add_cmd("obj", class_info, obj_command, _("Search for object and reference to object of the same type as the input expression\nobj <type|variable>"), &cmdlist);
	add_cmd("dt", class_info, dt_command, _("Display type (windbg style)\ndt <type|variable>"), &cmdlist);
	add_cmd("shrobj", class_info, shrobj_command, _("Find objects that currently referenced from multiple threads\nshrobj [tid0] [tid1] [...]"), &cmdlist);

	add_cmd("block", class_info, block_command, _("Heap block info\nblock <addr>"), &cmdlist);
	add_cmd("heap", class_info, heap_command, _("Heap walk (all heaps or specified)\nheap [/v] [/leak] [addr] [num_blocks]"), &cmdlist);
	add_cmd("big", class_info, big_command, _("Display biggest heap memory blocks and their owners\nbig <num_blocks>"), &cmdlist);

	add_cmd("pattern", class_info, pattern_command, _("Reveal memory pattern\npattern <start> <end>"), &cmdlist);
	add_cmd("segment", class_info, segment_command, _("Display memory segments"), &cmdlist);
	add_cmd("decode", class_info, decode_command, _("Disassemble current function with detail annotation of object context\ndecode %reg=<val> from=<addr> to=<addr>|end"), &cmdlist);

	add_cmd("shrobj_level", class_info, shrobj_level_command, _("Set/Show the indirection level of shared-object search"), &cmdlist);
	add_cmd("max_indirection_level", class_info, max_indirection_level_command, _("Set/Show the maximum indirection level of reference search"), &cmdlist);
	add_cmd("assign", class_info, assign_command, _("Pretend the memory data is the given value\nassign [addr] [value]"), &cmdlist);
	add_cmd("unassign", class_info, unassign_command, _("Remove the fake value at the given address\nunassign <addr>"), &cmdlist);
	add_cmd("include_free", class_info, include_free_command, _("Reference search includes free heap memory blocks"), &cmdlist);
	add_cmd("ignore_free", class_info, ignore_free_command, _("Reference search excludes free heap memory blocks (default)"), &cmdlist);
	add_cmd("include_unknown", class_info, include_unknown_command, _("Reference search includes all memory"), &cmdlist);
	add_cmd("ignore_unknown", class_info, ignore_unknown_command, _("Reference search excludes memory with unknown storage type (default)"), &cmdlist);

	// !test!
	add_cmd("info_local", class_info, info_local_command, _("Display local variables"), &cmdlist);
}
