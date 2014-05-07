/*
 * pta.cpp
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include "segment.h"
#include "search.h"
#include "heap.h"
#include "stl_container.h"
#include "ca_i386.h"

extern size_t g_align;

/////////////////////////////////////////////////////
// Forwarded functions
/////////////////////////////////////////////////////
static void print_segment(struct ca_segment*);
static bool enter_command(PDEBUG_CLIENT4);
static void leave_command();
static void print_sym_group(PDEBUG_SYMBOL_GROUP2);

/////////////////////////////////////////////////////
// Globals
/////////////////////////////////////////////////////

WINDBG_EXTENSION_APIS   ExtensionApis;
IDebugSymbols3* gDebugSymbols3 = NULL;
IDebugControl*  gDebugControl = NULL;
IDebugSystemObjects* gDebugSystemObjects = NULL;
IDebugAdvanced2* gDebugAdvanced2 = NULL;
IDebugRegisters2* gDebugRegisters2 = NULL;
IDebugClient4* gDebugClient4 = NULL;
IDebugDataSpaces4* gDebugDataSpaces4 = NULL;

/////////////////////////////////////////////////////
// Init/Fini stuff, standard package
/////////////////////////////////////////////////////
extern "C"
HRESULT
CALLBACK
DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    IDebugClient *DebugClient = NULL;
    HRESULT Hr= S_OK;

    *Version = DEBUG_EXTENSION_VERSION(1, 0);
    *Flags = 0;

	// Connect to client
    if ((Hr = DebugCreate(__uuidof(IDebugClient),
                          (void **)&DebugClient)) != S_OK)
    {
        return Hr;
    }

	// Get the windbg-style extension APIS
	PDEBUG_CONTROL DebugControl;
    if ((Hr = DebugClient->QueryInterface(__uuidof(IDebugControl),
                                  (void **)&DebugControl)) == S_OK)
    {
        ExtensionApis.nSize = sizeof (ExtensionApis);
        Hr = DebugControl->GetWindbgExtensionApis64(&ExtensionApis);

        DebugControl->Release();
    }

	// done
    DebugClient->Release();
    return Hr;
}

extern "C"
void
CALLBACK
DebugExtensionNotify(ULONG Notify, ULONG64 Argument)
{
	static BOOL    Connected;

    UNREFERENCED_PARAMETER(Argument);

    // The first time we actually connect to a target
    if ((Notify == DEBUG_NOTIFY_SESSION_ACCESSIBLE) && (!Connected))
    {
        IDebugClient *DebugClient = NULL;
        HRESULT Hr;
        PDEBUG_CONTROL DebugControl = NULL;

        if ((Hr = DebugCreate(__uuidof(IDebugClient),
                              (void **)&DebugClient)) == S_OK)
        {
            //
            // Get the architecture type.
            //
            if ((Hr = DebugClient->QueryInterface(__uuidof(IDebugControl),
                                       (void **)&DebugControl)) == S_OK)
            {
            	ULONG   TargetMachine;
                if ((Hr = DebugControl->GetActualProcessorType(
                                             &TargetMachine)) == S_OK)
                {
                    Connected = TRUE;
                }

                //NotifyOnTargetAccessible(DebugControl);
                DebugControl->Release();
            }

            DebugClient->Release();
        }
    }

    // The target is gone
    if (Notify == DEBUG_NOTIFY_SESSION_INACTIVE)
        Connected = FALSE;

    return;
}

extern "C"
void
CALLBACK
DebugExtensionUninitialize(void)
{
    return;
}

/////////////////////////////////////////////////////
//  A built-in help for the extension dll
/////////////////////////////////////////////////////
DECLARE_API ( help )
{
    dprintf("Help for extension ref.dll\n"
			"   ref <addr> [size] [level] - Search references to object at <addr>; optional object size and levels of indirect reference\n"
			"   tref <addr> [size] [level] - Similar to <ref> command except references are searched in thread contexts only\n"
			"   obj <expr> - Extended function of Windbg \"s -v <Range> <Object>\" command - Search for object and reference to object of the same type as the input expression\n"
    		"   shrobj [tid0] [tid1] [...] - Find objects that currently referenced from multiple threads\n"
    		"\n"
    		"   block <addr>       - Heap block informatoin for given address\n"
            "   heap  [addr] [/v] [/leak]  - Walk heap for possible memory corruption, and/or memory layout information\n"
    		"   big   <num>        - Biggest heap memory blocks and their owners\n"
    		"\n"
			"   segment [addr]     - Print process' virtual address space\n"
			"   pattern <start> <end> - Reveal the data pattern within the given range\n"
    		"   decode [reg=<val>] [from=<addr>] [to=<addr>|end] - Disassemble current function with detail annotation of object context\n"
    		"\n"
    		"   shrobj_level [n]   - Set/Show the indirection level of shared-object search\n"
    		"   max_ref_level [n]  - Set/Show the maximum levels of indirection"
    		"   set <addr> <val>   - Set a pseudo value at address"
    		"   unset <addr>       - Undo the pseudo value at address"
            "   help               - Shows this help\n"
            );
}

//////////////////////////////////////////////////////////////
// Interfaces to Windbg
//////////////////////////////////////////////////////////////
HRESULT CALLBACK
block(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!args || strlen(args)==0)
	{
		dprintf("Please see help for this command's usage\n");
		return E_FAIL;
	}

	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	address_t addr = GetExpression(args);

	struct heap_block heap_block;
	if (addr && get_heap_block_info(addr, &heap_block))
	{
		if (heap_block.inuse)
			dprintf("\t[In-use]\n");
		else
			dprintf("\t[Free]\n");

		dprintf("\t[Address] "PRINT_FORMAT_POINTER"\n", heap_block.addr);
		dprintf("\t[Size]    "PRINT_FORMAT_SIZE"\n", heap_block.size);
		dprintf("\t[Offset] +"PRINT_FORMAT_SIZE"\n", addr - heap_block.addr);
	}
	else
		dprintf("[Error] Failed to query the memory block "PRINT_FORMAT_POINTER"\n", addr);

	leave_command();
    return S_OK;
}

HRESULT CALLBACK
heap(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

    address_t addr = 0;
    CA_BOOL verbose = CA_FALSE;
    CA_BOOL leak_check = CA_FALSE;
    if (args)
    {
    	// make a local copy
    	char* buf = strdup(args);
    	char* buf_orig = buf;
        while (*buf)
        {
    		while (*buf && isspace(*buf))
    			buf++;

        	if (buf[0] == '/' && buf[1] == 'v')
        	{
        		verbose = CA_TRUE;
        		buf += 2;
        	}
        	else if (strcmp(buf, "/leak") == 0)
        	{
        		leak_check = CA_TRUE;
        		break;
        	}
        	else
        	{
        		// replace rear space with '\0'
        		char* cursor = buf;
        		while (*cursor && !isspace(*cursor))
        			cursor++;
        		if (*cursor)
        			*cursor = '\0';
        		addr = GetExpression(buf);
        		break;
        	}
        }
    	// clean up
    	free(buf_orig);
    }

    if (leak_check)
    	display_heap_leak_candidates();
    else if (addr)
    {
    	if (!heap_walk(addr, verbose))
    		dprintf("[Error] Failed to show the related arena "PRINT_FORMAT_POINTER"\n", addr);
    }
    else if (!heap_walk(0, verbose))
    	dprintf("[Error] Failed to walk heap\n");

    leave_command();
    return S_OK;
}

HRESULT CALLBACK
big(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!args || strlen(args)==0)
	{
		dprintf("Please see help for this command's usage\n");
		return E_FAIL;
	}

	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	unsigned int n = (unsigned int) GetExpression(args);
	if (n == 0)
	{
		dprintf ("Input number of biggest heap memory blocks to display");
		leave_command();
		return S_OK;
	}

	biggest_blocks(n);

	leave_command();
    return S_OK;
}

/////////////////////////////////////////////////////
//  Horizontal reference search
/////////////////////////////////////////////////////
HRESULT CALLBACK
ref (PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!args || strlen(args)==0)
	{
		dprintf("Please see help for this command's usage\n");
		return E_FAIL;
	}

	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	// Get input
	int argc = 0;
	address_t addr;
	size_t size = 1;
	int level = 1;
	ULONG64 val;

	PCSTR remainder = NULL;
	if (!GetExpressionEx(args, (ULONG64*) &addr, &remainder) || addr == 0)
	{
		dprintf("Error: Invalid address argument\n");
		leave_command();
		return E_INVALIDARG;
	}
	else
		argc++;

	PCSTR  remainder2 = NULL;
	if (remainder && GetExpressionEx(remainder, (ULONG64*) &size, &remainder2))
	{
		if (size > 0)
		{
			argc++;
			PCSTR  remainder3 = NULL;
			if (remainder2 && GetExpressionEx(remainder2, (ULONG64*)&val, &remainder3))
			{
				argc++;
				level = static_cast<int>(val);
				if (level<1 || level>1024)
				{
					dprintf("Error: invalid levels of indirection\n");
					leave_command();
					return E_INVALIDARG;
				}
			}
		}
		else
		{
			dprintf("Error: Invalid size argument\n");
			leave_command();
			return E_INVALIDARG;
		}
	}

	bool rc;
	if (argc == 1)
		rc = find_object_type(addr);
	else
		rc = find_object_refs(addr, size, level);

	if (!rc )
		dprintf("Couldn't find requested references\n");

	leave_command();
	return S_OK;
}

HRESULT CALLBACK
tref (PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!args || strlen(args)==0)
	{
		dprintf("Please see help for this command's usage\n");
		return E_FAIL;
	}

	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	// Get input
	int argc = 0;
	address_t addr;
	size_t size = 1;
	int level = 1;
	ULONG64 val;

	PCSTR remainder = NULL;
	if (!GetExpressionEx(args, (ULONG64*) &addr, &remainder) || addr == 0)
	{
		dprintf("Error: Invalid address argument\n");
		leave_command();
		return E_INVALIDARG;
	}
	else
		argc++;

	PCSTR  remainder2 = NULL;
	if (remainder && GetExpressionEx(remainder, (ULONG64*) &size, &remainder2))
	{
		if (size > 0)
		{
			argc++;
			PCSTR  remainder3 = NULL;
			if (remainder2 && GetExpressionEx(remainder2, (ULONG64*)&val, &remainder3))
			{
				argc++;
				level = static_cast<int>(val);
				if (level<1 || level>1024)
				{
					dprintf("Error: invalid levels of indirection\n");
					leave_command();
					return E_INVALIDARG;
				}
			}
		}
		else
		{
			dprintf("Error: Invalid size argument\n");
			leave_command();
			return E_INVALIDARG;
		}
	}

	bool rc = find_object_refs_on_threads (addr, size, level);
	if (!rc )
		dprintf("Couldn't find requested references\n");

	leave_command();
	return S_OK;
}

HRESULT CALLBACK
obj(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!args || strlen(args)==0)
	{
		dprintf("Please see help for this command's usage\n");
		return E_FAIL;
	}

	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	search_cplusplus_objects_with_vptr (args);

	leave_command();
    return S_OK;
}

#define IS_BLANK(c) ((c)==' ' || (c)=='\t')

HRESULT CALLBACK
shrobj(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	struct CA_LIST* threads = ca_list_new();
	int* p;

	if (args)
	{
		const char* exp = args;
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
	find_shared_objects_by_threads(threads);
	// cleanup thread list
	if (!ca_list_empty(threads))
	{
		ca_list_traverse_start(threads);
		while ( (p = (int*) ca_list_traverse_next(threads)))
		{
			free (p);
		}
	}
	ca_list_delete(threads);

	leave_command();
    return S_OK;
}

HRESULT CALLBACK
shrobj_level(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!enter_command(Client))
		return E_FAIL;

	unsigned int level = 0;
    if (args && strlen(args))
    	level = (unsigned int) GetExpression(args);

    set_shared_objects_indirection_level(level);

    leave_command();
    return S_OK;
}

/////////////////////////////////////////////////////
//  Process info (address map, threads, etc.)
/////////////////////////////////////////////////////
HRESULT CALLBACK
segment(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	address_t addr;
    if (!args || strlen(args)==0)
    	addr = 0;
    else
    	addr = GetExpression(args);

	if (addr)
	{
		struct ca_segment* seg = get_segment(addr, 1);
		if (seg)
		{
			dprintf("Address 0x%lx belongs to segment:\n", addr);
			print_segment(seg);
		}
		else
			dprintf("Address 0x%lx doesn't belong to any segment\n", addr);
	}
	else
	{
		unsigned int i;
		dprintf("vaddr                         size      perm     name\n");
		dprintf("=====================================================\n");
		for (i=0; i<g_segment_count; i++)
		{
			dprintf("[%4d] ", i);
			print_segment(&g_segments[i]);
		}
	}

	leave_command();
    return S_OK;
}

HRESULT CALLBACK
pattern (PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!args || strlen(args)==0)
	{
		dprintf("Please see help for this command's usage\n");
		return E_FAIL;
	}

	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	// Get input
	int argc = 0;
	address_t lo, hi;
	ULONG64 val;

	PCSTR remainder = NULL;
	if (GetExpressionEx(args, (ULONG64*) &val, &remainder))
	{
		argc++;
		lo = val;
	}
	PCSTR  remainder2 = NULL;
	if (remainder && GetExpressionEx(remainder, (ULONG64*) &val, &remainder2))
	{
		argc++;
		hi = val;
	}

	if (argc != 2 || lo >=  hi)
	{
		dprintf("Error: invalid arguments\n");
		leave_command();
		return E_INVALIDARG;
	}

	print_memory_pattern(lo, hi);

	leave_command();
	return S_OK;
}

HRESULT CALLBACK
decode (PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	char* dup_args = _strdup(args);
	if (!decode_func(dup_args))
		dprintf("Failed to decode current function\n");
	free(dup_args);

	leave_command();
	return S_OK;
}

HRESULT CALLBACK
set (PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!args || strlen(args)==0)
	{
		print_set_values ();
		return S_OK;
	}

	// Get input
	int argc = 0;
	address_t arg1, arg2;
	ULONG64 val;

	PCSTR remainder = NULL;
	if (GetExpressionEx(args, (ULONG64*) &val, &remainder))
	{
		argc++;
		arg1 = val;
	}
	PCSTR  remainder2 = NULL;
	if (remainder && GetExpressionEx(remainder, (ULONG64*) &val, &remainder2))
	{
		argc++;
		arg2 = val;
	}

	if (argc != 2)
	{
		dprintf("Error: two arguments expected\n");
		return E_INVALIDARG;
	}

	set_value (arg1, arg2);

	return S_OK;
}

HRESULT CALLBACK
unset(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!args || strlen(args)==0)
	{
		dprintf("Please see help for this command's usage\n");
		return E_FAIL;
	}

	address_t addr = GetExpression(args);
	unset_value (addr);

    return S_OK;
}

/////////////////////////////////////////////////////
// Unexposed cmd to re-initialize once targetee changed
/////////////////////////////////////////////////////
HRESULT CALLBACK
set_alignment(PDEBUG_CLIENT4 Client, PCSTR args)
{
	size_t value;
    if (!args || strlen(args)==0)
    	value = 0;
    else
    	value = GetExpression(args);

    if (value == 0)
    	dprintf("Current alignment is "PRINT_FORMAT_SIZE"\n", g_align);
    else if (value==4 || value==8 || value==16)
		g_align = value;
	else
		dprintf("Invalid setting for alignment "PRINT_FORMAT_SIZE"\n", value);

    return S_OK;
}

HRESULT CALLBACK
include_free(PDEBUG_CLIENT4 Client, PCSTR args)
{
	g_skip_free = false;

	dprintf("Reference search will now include free heap memory blocks\n");

    return S_OK;
}

HRESULT CALLBACK
ignore_free(PDEBUG_CLIENT4 Client, PCSTR args)
{
	g_skip_free = true;

	dprintf("Reference search will now exclude free heap memory blocks (default)\n");

    return S_OK;
}

HRESULT CALLBACK
include_unknown(PDEBUG_CLIENT4 Client, PCSTR args)
{
	g_skip_unknown = false;

	dprintf("Reference search will now include all memory\n");

    return S_OK;
}

HRESULT CALLBACK
ignore_unknown(PDEBUG_CLIENT4 Client, PCSTR args)
{
	g_skip_unknown = true;

	dprintf("Reference search will now exclude memory with unknown storage type (default)\n\n");

    return S_OK;
}

/////////////////////////////////////////////////////
// Unexposed cmd to set max recursive reference depth
/////////////////////////////////////////////////////
HRESULT CALLBACK
block_size(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!args || strlen(args)==0)
	{
		dprintf("0");
		return E_FAIL;
	}

	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	address_t addr = GetExpression(args);

	struct heap_block heap_block;
	if (addr && get_heap_block_info(addr, &heap_block))
		dprintf(PRINT_FORMAT_SIZE, heap_block.size);
	else
		dprintf("0");

	leave_command();
    return S_OK;
}

HRESULT CALLBACK
max_ref_level(PDEBUG_CLIENT4 Client, PCSTR args)
{
	int value;
    if (!args || strlen(args)==0)
    	value = 0;
    else
    	value = (int) GetExpression(args);

    set_max_indirection_level(value);

    return S_OK;
}

HRESULT CALLBACK
info_local(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!enter_command(Client))
		return E_FAIL;

	if (!update_memory_segments_and_heaps())
	{
		leave_command();
		return S_OK;
	}

	HRESULT hr;
	DEBUG_STACK_FRAME frames[MAX_FRAMES];
	ULONG frameFilled = 0;
	if (gDebugControl->GetStackTrace(0,		// frame offset
									0,		// stack offset
									0,		// instruction offset
									frames,
									MAX_FRAMES,
									&frameFilled) != S_OK )
		goto Fail;

	PDEBUG_SYMBOL_GROUP2 symbolGroup2 = NULL;
	for (ULONG frame_num = 0; frame_num < frameFilled; frame_num++)
	{
		// Set scope to frame n
		// Beware, this method returns S_FALSE
		hr = gDebugSymbols3->SetScopeFrameByIndex(frame_num);
		if (FAILED(hr))
			break;
		dprintf("-------- frame %d fp="PRINT_FORMAT_POINTER" sp="PRINT_FORMAT_POINTER" --------\n",
				frame_num, frames[frame_num].FrameOffset, frames[frame_num].StackOffset);
		// Get the function name
		dprintf("Function:\n");
		char func_name[NAME_BUF_SZ];
		ULONG64 displacement = 0;
		hr = gDebugSymbols3->GetNameByOffset(frames[frame_num].InstructionOffset, func_name, NAME_BUF_SZ, NULL, &displacement);
		if (SUCCEEDED(hr))
			dprintf("\t%s() +%d\n", func_name, displacement);
		// Retrieve COM interface to symbols of this scope (frame)
		if (gDebugSymbols3->GetScopeSymbolGroup2(DEBUG_SCOPE_GROUP_ARGUMENTS, symbolGroup2, &symbolGroup2) != S_OK)
			goto Fail;
		dprintf("Parameters:\n");
		print_sym_group(symbolGroup2);
		if (gDebugSymbols3->GetScopeSymbolGroup2(DEBUG_SCOPE_GROUP_LOCALS, symbolGroup2, &symbolGroup2) != S_OK)
			goto Fail;
		dprintf("Local Variables:\n");
		print_sym_group(symbolGroup2);
		// line separator
		dprintf("\n");
	}

	goto NormalExit;

Fail:
	dprintf("Failed to query debug engine COM interface\n");
NormalExit:
	if (symbolGroup2)
		symbolGroup2->Release();

	leave_command();
	return S_OK;
}

// special command to print out mstr big memory cache
typedef struct _CacheBlock
{
	struct _CacheBlock*  next;
	size_t            blockSz;
} CacheBlock;
#define MAX_NUM_BANDS 16

HRESULT CALLBACK
mcache(PDEBUG_CLIENT4 Client, PCSTR args)
{
	if (!enter_command(Client))
		return E_FAIL;

	// read/print global variabls
	ULONG64 addr;

	unsigned int g_cache_max_free_pages;
	if (gDebugSymbols3->GetOffsetByName("shsmp64!g_cache_max_free_pages", &addr) != S_OK
		|| !inferior_memory_read(addr, &g_cache_max_free_pages, sizeof(g_cache_max_free_pages)))
	{
		dprintf("Failed to read shsmp64!g_cache_max_free_pages\n");
		goto McacheExit;
	}
	dprintf("Max 64KB small/medium pages to cache: %d\n", g_cache_max_free_pages);

	unsigned int g_cache_free_pages_total;
	if (gDebugSymbols3->GetOffsetByName("shsmp64!g_cache_free_pages_total", &addr) != S_OK
		|| !inferior_memory_read(addr, &g_cache_free_pages_total, sizeof(g_cache_free_pages_total)))
	{
		dprintf("Failed to read shsmp64!g_cache_free_pages_total\n");
		goto McacheExit;
	}
	dprintf("Currently cached %d pages\n\n", g_cache_free_pages_total);

	size_t g_max_cache_block_size;
	if (gDebugSymbols3->GetOffsetByName("shsmp64!g_max_cache_block_size", &addr) != S_OK
		|| !inferior_memory_read(addr, &g_max_cache_block_size, sizeof(g_max_cache_block_size)))
	{
		dprintf("Failed to read shsmp64!g_max_cache_block_size\n");
		goto McacheExit;
	}
	dprintf("Max size to cache: %ldKB\n", g_max_cache_block_size/1024);

	unsigned int g_max_cache_blocks_per_band;
	if (gDebugSymbols3->GetOffsetByName("shsmp64!g_max_cache_blocks_per_band", &addr) != S_OK
		|| !inferior_memory_read(addr, &g_max_cache_blocks_per_band, sizeof(g_max_cache_blocks_per_band)))
	{
		dprintf("Failed to read shsmp64!g_max_cache_blocks_per_band\n");
		goto McacheExit;
	}
	dprintf("Max number of cached blocks per band: %d\n", g_max_cache_blocks_per_band);

	size_t g_max_cache_size;
	if (gDebugSymbols3->GetOffsetByName("shsmp64!g_max_cache_size", &addr) != S_OK
		|| !inferior_memory_read(addr, &g_max_cache_size, sizeof(g_max_cache_size)))
	{
		dprintf("Failed to read shsmp64!g_max_cache_size\n");
		goto McacheExit;
	}
	dprintf("Max total size to cache: %ldMB\n\n", g_max_cache_size/(1024*1024));

	CacheBlock* g_cache_lists_heads[MAX_NUM_BANDS];
	if (gDebugSymbols3->GetOffsetByName("shsmp64!g_cache_lists_heads", &addr) != S_OK
		|| !inferior_memory_read(addr, &g_cache_lists_heads, sizeof(g_cache_lists_heads)))
	{
		dprintf("Failed to read shsmp64!g_cache_lists_heads\n");
		goto McacheExit;
	}
	unsigned int g_cache_lists_sizes[MAX_NUM_BANDS];
	if (gDebugSymbols3->GetOffsetByName("shsmp64!g_cache_lists_sizes", &addr) != S_OK
		|| !inferior_memory_read(addr, &g_cache_lists_sizes, sizeof(g_cache_lists_sizes)))
	{
		dprintf("Failed to read shsmp64!g_cache_lists_sizes\n");
		goto McacheExit;
	}
	size_t g_total_cache_size;
	if (gDebugSymbols3->GetOffsetByName("shsmp64!g_total_cache_size", &addr) != S_OK
		|| !inferior_memory_read(addr, &g_total_cache_size, sizeof(g_total_cache_size)))
	{
		dprintf("Failed to read shsmp64!g_total_cache_size\n");
		goto McacheExit;
	}

	dprintf("Size(KB)\t#Blocks\tTotal_Size(KB)\n");
	int i;
	size_t sz, totalSz=0;
	for (i = 0, sz = 64*1024; i < MAX_NUM_BANDS; i++)
	{
		unsigned int listsz = 0;
		CacheBlock* pblock = g_cache_lists_heads[i];
		while (pblock)
		{
			listsz++;
			CacheBlock cblock;
			if (!inferior_memory_read((address_t)pblock, &cblock, sizeof(cblock)))
			{
				dprintf("Failed to read CacheBlock at %p\n", pblock);
				break;
			}
			pblock = cblock.next;
		}
		if (listsz != g_cache_lists_sizes[i])
		{
			dprintf("Band %d list size doesn't match! %d <=> %d\n",
					i, listsz, g_cache_lists_sizes[i]);
		}
		else
			dprintf("%ld\t\t%d\t\t%ld\n", sz/1024, listsz, sz*listsz/1024);
		totalSz += (sz - 0x80) * listsz;
		sz = sz << 1;
	}
	dprintf("------------------------------------------\n");
	dprintf("\t\t\t\t%ld MB\n", totalSz/(1024*1024));

McacheExit:
	leave_command();
    return S_OK;
}

static void print_sym_group(PDEBUG_SYMBOL_GROUP2 symbolGroup2)
{
	HRESULT hr;
	// Get number of symbols
	ULONG num_sym;
	if (symbolGroup2->GetNumberSymbols(&num_sym) != S_OK)
		return;
	for (ULONG i=0; i<num_sym; i++)
	{
		// symbol name
		char name_buf[NAME_BUF_SZ];
		hr = symbolGroup2->GetSymbolName(i, name_buf, NAME_BUF_SZ, NULL);
		if (FAILED(hr))
		{
			dprintf("\t[%d] ??\n", i);
			continue;
		}
		else
			dprintf("\t[%d] %s ", i, name_buf);
		// symbol location
		ULONG64 location;
		hr = symbolGroup2->GetSymbolOffset(i, &location);
		if (SUCCEEDED(hr))
			dprintf(" @"PRINT_FORMAT_POINTER"", location);
		ULONG reg_index;
		hr = symbolGroup2->GetSymbolRegister(i, &reg_index);
		if (SUCCEEDED(hr))
			dprintf(" register(%ld)", reg_index);
		// symbol size
		ULONG sym_size;
		hr = symbolGroup2->GetSymbolSize(i, &sym_size);
		if (SUCCEEDED(hr))
			dprintf(" size=%ld", sym_size);
		// type name is included in the vale text
		/*hr = symbolGroup2->GetSymbolTypeName(i, name_buf, NAME_BUF_SZ, NULL);
		if (SUCCEEDED(hr))
			dprintf(" type=\"%s\"", name_buf);*/
		// value
		hr = symbolGroup2->GetSymbolValueText(i, name_buf, NAME_BUF_SZ, NULL);
		if (SUCCEEDED(hr))
			dprintf(" value=\"%s\"", name_buf);
		// done
		dprintf("\n");
	}
}

static void
print_segment(struct ca_segment* segment)
{
	dprintf("["PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER"] %6ldK  %c%c%c ",
		segment->m_vaddr, segment->m_vaddr+segment->m_vsize,
		segment->m_vsize/1024,
		segment->m_read?'r':'-', segment->m_write?'w':'-', segment->m_exec?'x':'-');
	if (g_debug_core && segment->m_fsize != segment->m_vsize)
		dprintf(" (fsize=%ldK)", segment->m_fsize/1024);
	if (segment->m_type == ENUM_MODULE_TEXT)
		dprintf("[.text/.rodata] [%s]", segment->m_module_name);
	else if (segment->m_type == ENUM_MODULE_DATA)
		dprintf("[.data/.bss] [%s]", segment->m_module_name);
	else if (segment->m_type == ENUM_STACK)
		dprintf("[stack] [tid=%d]", segment->m_thread.tid);
	else if (segment->m_type == ENUM_HEAP)
		dprintf("[heap]");
	dprintf("\n");
}

static ULONG64 intr;
static DEBUG_STACK_FRAME stack_frame;
static CONTEXT context;
static ULONG engine_tid;

static bool enter_command(PDEBUG_CLIENT4 Client)
{
	gDebugClient4 = Client;
	if (!gDebugSymbols3
		&& Client->QueryInterface(__uuidof(IDebugSymbols3), (void **)&gDebugSymbols3) != S_OK)
		return false;

	if (!gDebugControl
		&& Client->QueryInterface(__uuidof(IDebugControl), (void **)&gDebugControl) != S_OK)
		return false;

	if (!gDebugSystemObjects
		&& Client->QueryInterface(__uuidof(IDebugSystemObjects), (void **)&gDebugSystemObjects) != S_OK)
		return false;

	if (!gDebugAdvanced2
		&& Client->QueryInterface(__uuidof(IDebugAdvanced2), (void **)&gDebugAdvanced2) != S_OK)
		return false;

	if (!gDebugDataSpaces4
		&& Client->QueryInterface(__uuidof(IDebugDataSpaces4), (void **)&gDebugDataSpaces4) != S_OK)
		return false;

	if (!gDebugRegisters2
		&& Client->QueryInterface(__uuidof(IDebugRegisters2), (void **)&gDebugRegisters2) != S_OK)
		return false;

	// Get the current thread
	if (gDebugSystemObjects->GetCurrentThreadId(&engine_tid) != S_OK)
		return false;

	// Get the current scope
	if (gDebugSymbols3->GetScope(&intr, &stack_frame, &context, sizeof(context)) != S_OK)
		return false;

	g_debug_context.tid = engine_tid;
	g_debug_context.frame_level = stack_frame.FrameNumber;
	g_debug_context.sp = stack_frame.StackOffset;

	return true;
}

void restore_context()
{
	ULONG cur_engine_tid;
	// reset the current thread if changed
	if (gDebugSystemObjects
		&& gDebugSystemObjects->GetCurrentThreadId(&cur_engine_tid) == S_OK
		&& cur_engine_tid != engine_tid)
	{
		gDebugSystemObjects->SetCurrentThreadId(engine_tid);
	}

	// resume scope
	if (gDebugSymbols3)
		gDebugSymbols3->SetScope(intr, &stack_frame, &context, sizeof(context));
}

static void leave_command()
{
	restore_context();

	if (gDebugSymbols3)
	{
		gDebugSymbols3->Release();
		gDebugSymbols3 = NULL;
	}
	if (gDebugControl)
	{
		gDebugControl->Release();
		gDebugControl = NULL;
	}
	if (gDebugSystemObjects)
	{
		gDebugSystemObjects->Release();
		gDebugSystemObjects = NULL;
	}
	if (gDebugAdvanced2)
	{
		gDebugAdvanced2->Release();
		gDebugAdvanced2 = NULL;
	}
	if (gDebugRegisters2)
	{
		gDebugRegisters2->Release();
		gDebugRegisters2 = NULL;
	}
	if (gDebugDataSpaces4)
	{
		gDebugDataSpaces4->Release();
		gDebugDataSpaces4 = NULL;
	}
	gDebugClient4 = NULL;
}
