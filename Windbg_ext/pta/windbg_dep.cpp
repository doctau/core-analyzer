/*
 * windbg_dep.cpp
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <DbgHelp.h>
#include <stdio.h>
#include <vector>

#include "ref.h"
#include "segment.h"
#include "search.h"
#include "heap.h"
#include "stl_container.h"
#include "ca_i386.h"

struct addr_type_pair
{
	ULONG64 addr;
	ULONG   type_id;
	ULONG64 mod_base;
};

struct stack_symbol
{
	ULONG frame;
	ULONG size;
	ULONG64 offset;
	char* name;
	ULONG64 mod_base;
	ULONG type_id;
};

typedef std::vector<struct stack_symbol*> stack_symbols;

struct frame_info
{
	ULONG   frame_no;
	ULONG64 rbp;
	ULONG64 rsp;
};

typedef std::vector<struct frame_info> frames_t;

/////////////////////////////////////////////////////
// Global Variables
/////////////////////////////////////////////////////
#define MAX_MODULES 512
#define MAX_FRAMES 128
#define SYS_PAGE_SZ 0x1000

bool g_debug_core = false;

unsigned int g_ptr_bit = 64;
static const char* g_sp_name = "rsp";

static ULONG g_total_threads = 0;
static std::vector<stack_symbols*> g_all_stack_symbols;
static std::vector<frames_t*> g_all_stack_frames;

static struct addr_type_pair* addr_type_map = NULL;
static unsigned int addr_type_map_sz = 0;
static unsigned int addr_type_map_buf_sz = 0;

extern PDEBUG_CLIENT4 gClient;

struct ca_reg_value g_regs[TOTAL_REGS];
struct ca_debug_context g_debug_context;

/////////////////////////////////////////////////////
// Forward functions
/////////////////////////////////////////////////////
static bool mmap_core_file(const char* fname);
static void print_struct_field(const struct object_reference*, ULONG64, ULONG, ULONG);
static bool get_typeinfo(ULONG64, ULONG, ULONG64, EXT_TYPED_DATA&, bool);
static struct addr_type_pair* lookup_type_by_addr(const struct object_reference*);
static CA_BOOL resolve_or_print_stack_ref(const struct object_reference*, CA_BOOL, address_t*, size_t*);
static CA_BOOL resolve_or_print_global_ref(const struct object_reference*, CA_BOOL, address_t*, size_t*);
static bool is_process_segment_changed();
static void release_cached_stack_symbols();
static void release_frame_info_cache();
static bool build_frame_info_cache(int);
static struct stack_symbol* search_cached_stack_symbols(const struct object_reference*);
static void add_addr_type(ULONG64, ULONG, ULONG64);

/////////////////////////////////////////////////////
// Exposed functions
/////////////////////////////////////////////////////
bool inferior_memory_read (address_t addr, void* buffer, size_t sz)
{
	ULONG cb;
	if (!ReadMemory(addr, buffer, sz, &cb) || cb != sz)
		return false;
	return true;
}

void print_heap_ref(const struct object_reference* ref)
{
	HRESULT hr;
	if (ref->where.heap.inuse)
	{
		char type_name[NAME_BUF_SZ];
		struct addr_type_pair* addr_type;
		bool found_type = false;
		ULONG64 mod_base;
		ULONG type_id, type_sz;
		// Get _vptr name .. type_id .. type_sz
		if (is_heap_object_with_vptr(ref, type_name, NAME_BUF_SZ)
			&& gDebugSymbols3->GetSymbolTypeId(type_name, &type_id, &mod_base) == S_OK
			&& gDebugSymbols3->GetTypeSize(mod_base, type_id, &type_sz) == S_OK)
		{
			found_type = true;
		}
		else if (addr_type = lookup_type_by_addr(ref))
		{
			ULONG name_sz;
			hr = gDebugSymbols3->GetTypeName(addr_type->mod_base, addr_type->type_id, type_name, NAME_BUF_SZ, &name_sz);
			if (SUCCEEDED(hr) && name_sz < NAME_BUF_SZ)
			{
				found_type = true;
				mod_base = addr_type->mod_base;
				type_id  = addr_type->type_id;
				if (gDebugSymbols3->GetTypeSize(mod_base, type_id, &type_sz) != S_OK)
					type_sz = 0;
			}
		}
		// Process known type
		if (found_type && type_name[0])
		{
			if (type_sz > sizeof(address_t))
				dprintf(" (type=\"%s\" size=%d)", type_name, type_sz);
			if ((ref->value || ref->vaddr != ref->where.heap.addr) && ref->vaddr < ref->where.heap.addr + type_sz)
				print_struct_field(ref, mod_base, type_id, (ULONG)(ref->vaddr - ref->where.heap.addr));
		}
	}
	else
		dprintf(" FREE");
}

/*
 * Return true if the input addr starts with a _vptr
 */
bool is_heap_object_with_vptr(const struct object_reference* ref, char* type_name, size_t name_buf_sz)
{
	bool rs = false;
	address_t addr = ref->where.heap.addr;
	address_t val;
	if (read_memory_wrapper(NULL, addr, (void*)&val, sizeof(address_t)) && val)
	{
		struct ca_segment* segment = get_segment(val, 1);
		if (segment && (segment->m_type == ENUM_MODULE_DATA || segment->m_type == ENUM_MODULE_TEXT))
		{
			/*
			 * the first data belongs to a module's data section, it is likely a vptr
			 * to be sure, check its symbol
			 */
			char type_name_buf[NAME_BUF_SZ];
			ULONG name_sz;
			ULONG64 displacement = 0;
			char* cursor;
			char* syn_name;
			if (!type_name)
			{
				type_name = type_name_buf;
				name_buf_sz = NAME_BUF_SZ;
			}
			HRESULT hr = gDebugSymbols3->GetNameByOffset(val, type_name, name_buf_sz, &name_sz, &displacement);
			if (SUCCEEDED(hr) && displacement == 0 &&
				((cursor = strstr(type_name, "::`vftable'")) || (cursor = strstr(type_name, "::`vbtable'"))) )
			{
				*cursor = '\0';	// type name is w/o suffix `vftable' or `vbtable'
				ULONG type_id, type_sz;
				ULONG64 mod_base;
				// Compare type size vs heap block size
				if (gDebugSymbols3->GetSymbolTypeId(type_name, &type_id, &mod_base) == S_OK
					&& gDebugSymbols3->GetTypeSize(mod_base, type_id, &type_sz) == S_OK
					&& ref->vaddr < addr + type_sz)
					rs = true;
			}
		}
	}
	return rs;
}

void print_register_ref(const struct object_reference* ref)
{
	char reg_name[NAME_BUF_SZ];
	HRESULT hr = gDebugRegisters2->GetDescription(ref->where.reg.reg_num, reg_name, NAME_BUF_SZ, NULL, NULL);
	if (SUCCEEDED(hr))
		CA_PRINT(" thread %d %s="PRINT_FORMAT_POINTER, ref->where.reg.tid, reg_name, ref->value);
	else
		CA_PRINT(" thread %d reg[%d]="PRINT_FORMAT_POINTER, ref->where.reg.tid, ref->where.reg.reg_num, ref->value);
}

void print_stack_ref(const struct object_reference* ref)
{
	resolve_or_print_stack_ref (ref, CA_TRUE, NULL, NULL);
}

void print_global_ref (const struct object_reference* ref)
{
	resolve_or_print_global_ref (ref, CA_TRUE, NULL, NULL);
}

CA_BOOL known_global_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz)
{
	return resolve_or_print_global_ref(ref, CA_FALSE, sym_addr, sym_sz);
}

CA_BOOL known_stack_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz)
{
	return resolve_or_print_stack_ref(ref, CA_FALSE, sym_addr, sym_sz);
}

/*
 *  search C++ vtables of the type of the input expression
 */
CA_BOOL get_vtable_from_exp(const char*exp, struct CA_LIST*vtables, char* type_name, size_t bufsz, size_t* type_sz)
{
	CA_BOOL rc = CA_FALSE;
	ULONG type_id;
	ULONG64 module;
	if (gDebugSymbols3->GetSymbolTypeId(exp, &type_id, &module) == S_OK
		&& gDebugSymbols3->GetTypeName(module, type_id, type_name, bufsz, NULL) == S_OK
		&& gDebugSymbols3->GetTypeSize(module, type_id, (PULONG)type_sz) == S_OK)
	{
		unsigned int len = strlen(type_name);
		const char* vtbl_postfix = "::`vftable'";
		char* vtbl_name = new char[len + strlen(vtbl_postfix) + 1];
		sprintf(vtbl_name, "%s", type_name);
		// if symbol is of pointer type, we will get type name as "T**", remove the "*"
		while (len >= 1 && (vtbl_name[len-1] == '*' || vtbl_name[len-1] == '&'))
		{
			vtbl_name[len-1] = '\0';
			len--;
		}
		sprintf(&vtbl_name[len], "%s", vtbl_postfix);
		//dprintf("vtable symbol name \"%s\"\n", vtbl_name);

		HRESULT hr;
		ULONG64 vtbl_addr;
		ULONG64 handle;
		hr = gDebugSymbols3->StartSymbolMatch (vtbl_name, &handle);
		if (hr == S_OK)
		{
			while (1)
			{
				char sym_name[NAME_BUF_SZ];
				hr = gDebugSymbols3->GetNextSymbolMatch (handle, sym_name, NAME_BUF_SZ, 0, &vtbl_addr);
				if (hr == S_OK || hr == S_FALSE)
				{
					struct object_range* vtbl = new struct object_range;
					vtbl->low = vtbl_addr;
					vtbl->high = vtbl->low + 1;
					ca_list_push_front(vtables, vtbl);
					//dprintf("vtable address %p\n", vtbl_addr);
					rc = CA_TRUE;
				}
				else
					break;
			}
			hr = gDebugSymbols3->EndSymbolMatch (handle);
			// clean up
			delete[] vtbl_name;
		}
	}

	return rc;
}

/*
 * Prepare pta for user request:
 *  construct process map if it changed since last time
 */
bool update_memory_segments_and_heaps()
{
	bool rc = false;
	HRESULT Hr;
	struct ca_segment* seg;

	/*
	 *  It has been built previously.
	 */
	if (g_segments && g_segment_count)
	{
		// Don't need to update if target is core file, or live process didn't change
		if (g_debug_core || !is_process_segment_changed())
		{
			rc = true;
			goto NormalExit;
		}
		dprintf("Target process has changed. Rebuild heap information\n");
		// release old ca_segments
		release_all_segments();
		// drop cache
		release_cached_stack_symbols();
		release_frame_info_cache();
		g_total_threads = 0;
	}

	dprintf("Query Target Process Information\n");
	//////////////////////////////////////////////////////////
	// Get target type
	//////////////////////////////////////////////////////////
	char namebuf[NAME_BUF_SZ];
	ULONG target_class, target_qualifier;
	if ((Hr = gDebugControl->GetDebuggeeType(&target_class, &target_qualifier) ) == S_OK
			&& target_class == DEBUG_CLASS_USER_WINDOWS )
	{
		if (target_qualifier == DEBUG_USER_WINDOWS_PROCESS)
			dprintf("\tDebuggee is a user-mode process on the same computer\n");
		else if (target_qualifier == DEBUG_USER_WINDOWS_SMALL_DUMP)
		{
			dprintf("\tDebuggee is a user-mode minidump file");
			{
				ULONG namesz, type;
				if ((Hr = gDebugClient4->GetDumpFile(0, namebuf, NAME_BUF_SZ, &namesz, NULL, &type)) == S_OK)
				{
					dprintf(" \"%s\"", namebuf);
					g_debug_core = true;
				}
			}
			dprintf("\n");
		}
		else
			dprintf("\tError: debuggee (%d) is not supported\n", target_qualifier);
	}
	if (gDebugControl->IsPointer64Bit() == S_OK)
	{
		g_ptr_bit = 64;
		g_sp_name = "rsp";
	}
	else
	{
		g_ptr_bit = 32;
		g_sp_name = "esp";
	}
	//////////////////////////////////////////////////////////
	// Get all segments by querying the whole space space
	//////////////////////////////////////////////////////////
	address_t start = 0;
	address_t end   = ~start;
	while (start < end)
	{
		MEMORY_BASIC_INFORMATION64 info;
		if ((Hr = gDebugDataSpaces4->QueryVirtual(start, &info)) == S_OK)
		{
			// Free region is inaccessible virtual address
			// Valid address is either MEM_COMMIT or MEM_RESERVE
			if (!(info.State & MEM_FREE))
			{
				enum storage_type st = ENUM_UNKNOWN;
				int read  = info.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE);
				int write = info.Protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE);
				int exec  = info.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
				seg = add_one_segment(info.BaseAddress, info.RegionSize, read!=0, write!=0, exec!=0);
			}
			start = info.BaseAddress + info.RegionSize;
		}
		else
			break;
	}
	dprintf("\tThere are %ld segments\n", g_segment_count);
	if (g_debug_core)
	{
		if (!mmap_core_file(namebuf))
		{
			// Can't map the dump file.
			g_debug_core = false;
		}
	}

	//////////////////////////////////////////////////////////
	// Get module list
	//////////////////////////////////////////////////////////
	ULONG unloaded = 0;
	ULONG num_modules;
    if (gDebugSymbols3->GetNumberModules(&num_modules, &unloaded) != S_OK)
		goto Fail;
	dprintf("\tThere are %ld loaded modules\n", num_modules);
	for (ULONG mi = 0; mi < num_modules; mi++)
	{
		address_t mod_base;
		char module_name_buf[NAME_BUF_SZ];
		DEBUG_MODULE_PARAMETERS module_params;
		if (gDebugSymbols3->GetModuleByIndex((ULONG)mi, (PULONG64) &mod_base) == S_OK
			&& gDebugSymbols3->GetModuleParameters(1, NULL, (ULONG)mi, &module_params) == S_OK
			&& gDebugSymbols3->GetModuleNames((ULONG)mi, 0, module_name_buf, NAME_BUF_SZ, NULL, NULL, 0, NULL, NULL, 0, NULL) == S_OK)
		{
			// PE module's headers is allocated a distinct segment
			seg = get_segment(mod_base, 1);
			if (seg && seg->m_type == ENUM_UNKNOWN)
			{
				seg->m_type = ENUM_MODULE_TEXT;
				seg->m_module_name = _strdup(module_name_buf);
			}
			else
				continue;
			// The module base tarts with a DOS header
			IMAGE_DOS_HEADER dos_hdr;
			if (!read_memory_wrapper(seg, mod_base, &dos_hdr, sizeof(dos_hdr)))
				continue;
			// NT header is specified by dos header
			ULONG64 nt_hdr_addr = mod_base + dos_hdr.e_lfanew;
			ULONG num_sections;
			ULONG64 sec_addr;
			if (g_ptr_bit == 64)
			{
				IMAGE_NT_HEADERS nt_hdr;
				if (!read_memory_wrapper(seg, nt_hdr_addr, &nt_hdr, sizeof(nt_hdr)))
					continue;
				num_sections = nt_hdr.FileHeader.NumberOfSections;
				sec_addr = nt_hdr_addr + sizeof(IMAGE_NT_HEADERS);
			}
			else
			{
				IMAGE_NT_HEADERS32 nt_hdr_32;
				if (!read_memory_wrapper(seg, nt_hdr_addr, &nt_hdr_32, sizeof(nt_hdr_32)))
					continue;
				num_sections = nt_hdr_32.FileHeader.NumberOfSections;
				sec_addr = nt_hdr_addr + sizeof(IMAGE_NT_HEADERS32);
			}

			IMAGE_SECTION_HEADER* sec_hdrs = new IMAGE_SECTION_HEADER[num_sections];
			// Now iterate each section and its corresponding segment in memory
			if (read_memory_wrapper(seg, sec_addr, sec_hdrs, sizeof(IMAGE_SECTION_HEADER)*num_sections))
			{
				for (ULONG sec_index=0; sec_index<num_sections; sec_index++)
				{
					ULONG64 sec_addr = mod_base + sec_hdrs[sec_index].VirtualAddress;
					seg = get_segment(sec_addr, sec_hdrs[sec_index].Misc.VirtualSize);
					if (seg && seg->m_type == ENUM_UNKNOWN)
					{
						seg->m_module_name = _strdup(module_name_buf);
						if (sec_hdrs[sec_index].Characteristics & IMAGE_SCN_CNT_CODE)
							seg->m_type = ENUM_MODULE_TEXT;
						else if ( (sec_hdrs[sec_index].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
								|| (sec_hdrs[sec_index].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) )
							seg->m_type = ENUM_MODULE_DATA;
						else if (sec_hdrs[sec_index].Characteristics & IMAGE_SCN_MEM_WRITE)
							seg->m_type = ENUM_MODULE_DATA;
						else
							seg->m_type = ENUM_MODULE_TEXT;
					}
				}
				delete[] sec_hdrs;
			}
		}
		else
			goto Fail;
	}
	//////////////////////////////////////////////////////////
	// Get thread list
	//////////////////////////////////////////////////////////
	// total number of threads
	ULONG num_threads;
	if (gDebugSystemObjects->GetNumberThreads(&num_threads) != S_OK)
		goto Fail;
	g_total_threads = num_threads;
	// Register index of rsp
	ULONG rsp_index = ULONG_MAX;
	if (gDebugRegisters2->GetIndexByName(g_sp_name, &rsp_index) != S_OK)
		goto Fail;

	for (ULONG i = 0; i < num_threads; i++)
	{
		DEBUG_VALUE reg_val;
		ULONG engine_tid;
		// there are pseudo tid, engine tid and system tid
		// Here we get engine tid (not interested in sys tid) by pseudo tid
		if ((Hr = gDebugSystemObjects->GetThreadIdsByIndex(i, 1, &engine_tid, NULL)) != S_OK
			|| (Hr = gDebugSystemObjects->SetCurrentThreadId(engine_tid)) != S_OK)
			goto Fail;
		// get rsp
		if ((Hr = gDebugRegisters2->GetValue(rsp_index, &reg_val)) != S_OK)
			goto Fail;
		//rsp_values[i] = reg_val.I64;
		seg = get_segment(reg_val.I64, 1);
		if (seg && seg->m_type == ENUM_UNKNOWN)
		{
			seg->m_type = ENUM_STACK;
			seg->m_thread.tid = i;
		}
	}
	// thread is restored at top level
	dprintf("\tThere are %ld threads\n", num_threads);

	// dry run to mark heap segments
	if (!init_heap() || !test_segments(CA_TRUE) || !alloc_bit_vec())
		goto Fail;

	//////////////////////////////////////////////////////////
	// Done
	//////////////////////////////////////////////////////////
	dprintf("----Initialization Succeeded----\n", g_segment_count);
	rc = true;
	restore_context();
	goto NormalExit;

Fail:
	dprintf("----Initialization Failed----\n", g_segment_count);
NormalExit:
	// clear up old types
	clear_addr_type_map();

	return rc;
}

/*
 * Get the value of the registers of the thread context
 * If buffer is NULL, return number of registers could be returned
 */
int read_registers(const struct ca_segment* segment, struct reg_value* regs, int bufsz)
{
	ULONG numRegs = 0;
	HRESULT Hr;
	if ((Hr = gDebugRegisters2->GetNumberRegisters(&numRegs)) != S_OK)
		return 0;
	if (regs)
	{
		if ((ULONG)bufsz >= numRegs)
		{
			static DEBUG_VALUE* reg_vaules = NULL;
			if (reg_vaules == NULL)
				reg_vaules = new DEBUG_VALUE[numRegs];
			::memset(reg_vaules, 0, sizeof(DEBUG_VALUE)*numRegs);
			Hr = gDebugRegisters2->GetValues(numRegs, NULL, 0, reg_vaules);
			for (ULONG k=0; k<numRegs; k++)
			{
				regs[k].reg_num = k;
				if (reg_vaules[k].Type == DEBUG_VALUE_INT64)
				{
					regs[k].reg_width = 8;
					regs[k].value = (address_t) reg_vaules[k].I64;
				}
				else
					regs[k].reg_width = 0;
			}
			return numRegs;
		}
	}
	else
		return numRegs;
	return 0;
}

address_t get_rsp(const struct ca_segment* segment)
{
	// Register index of rsp
	ULONG rsp_index = ULONG_MAX;
	if (gDebugRegisters2->GetIndexByName(g_sp_name, &rsp_index) != S_OK)
		return 0;

	DEBUG_VALUE reg_val;
	ULONG engine_tid;
	if (gDebugSystemObjects->GetThreadIdsByIndex(segment->m_thread.tid, 1, &engine_tid, NULL) != S_OK
		|| gDebugSystemObjects->SetCurrentThreadId(engine_tid) != S_OK)
		return 0;
	// get rsp
	if (gDebugRegisters2->GetValue(rsp_index, &reg_val) != S_OK)
		return 0;
	return reg_val.I64;
}

int get_thread_id (const struct ca_segment* segment)
{
	return segment->m_thread.tid;
}

bool search_registers(const struct ca_segment* segment,
					struct CA_LIST* targets,
					struct CA_LIST* refs)
{
	bool lbFound = false;
	DEBUG_VALUE* reg_vaules = NULL;

	// total number of registers (should cache this)
	ULONG numRegs = 0;
	HRESULT Hr;
	if ((Hr = gDebugRegisters2->GetNumberRegisters(&numRegs)) != S_OK)
		goto Fail;

	// switch thread
	ULONG engine_tid;
	if (gDebugSystemObjects->GetThreadIdsByIndex(segment->m_thread.tid, 1, &engine_tid, NULL) != S_OK
		|| gDebugSystemObjects->SetCurrentThreadId(engine_tid) != S_OK)
		goto Fail;

	// check all registers for a match
	reg_vaules = new DEBUG_VALUE[numRegs];
	::memset(reg_vaules, 0, sizeof(DEBUG_VALUE)*numRegs);
	Hr = gDebugRegisters2->GetValues(numRegs, NULL, 0, reg_vaules);
	for (ULONG k=0; k<numRegs; k++)
	{
		if (reg_vaules[k].Type == DEBUG_VALUE_INT64)
		{
			struct object_range* target;
			ca_list_traverse_start(targets);
			while ( (target = (struct object_range*) ca_list_traverse_next(targets)) )
			{
				if (reg_vaules[k].I64 >= target->low && reg_vaules[k].I64 < target->high)
				{
					// stack unwinding is not working yet,
					// check registers of frame 0 only
					struct object_reference* ref = (struct object_reference*) malloc(sizeof(struct object_reference));
					ref->storage_type  = ENUM_REGISTER;
					ref->where.reg.tid = segment->m_thread.tid;
					ref->where.reg.reg_num = k;
					ref->where.reg.name    = NULL;
					ref->vaddr        = 0;
					ref->value        = reg_vaules[k].I64;
					ca_list_push_back(refs, ref);
					lbFound = true;
					break;
				}
			}
			ca_list_traverse_start(targets);
		}
	}
	// thread is restored at top level

	goto NormalExit;

Fail:
	dprintf("Fatal error in SearchValueInternal\n");
NormalExit:
	// clean up
	delete [] reg_vaules;

	return lbFound;
}

/*
 * Return the frame number with given address
 */
int get_frame_number(const struct ca_segment* segment, address_t addr, int* offset)
{
	int frame = -1;
	int tid = segment->m_thread.tid;

	// sanity check
	if ((ULONG)tid > g_total_threads - 1)
	{
		CA_PRINT("Internal error: tid=%d is out of range\n", tid);
		return -1;
	}

	// build frame cache if not yet
	if (g_all_stack_frames.empty() || g_all_stack_frames[tid] == NULL)
		build_frame_info_cache(tid);

	// search the cache
	std::vector<struct frame_info>* frame_infos = g_all_stack_frames[tid];
	ULONG total_frames = frame_infos->size();
	if (total_frames > 0 && addr >= frame_infos->at(0).rsp && addr <= frame_infos->at(total_frames-1).rbp)
	{
		for (ULONG i=0; i<total_frames; i++)
		{
			if (addr >= frame_infos->at(i).rsp && addr <= frame_infos->at(i).rbp)
			{
				frame = i;
				*offset = (int) (addr - frame_infos->at(i).rsp);
				break;
			}
		}
	}

	return frame;
}

address_t get_var_addr_by_name(const char* var_name)
{
	char* name = new char[strlen(var_name)+3];
	sprintf(name, "@$%s", var_name);
	DEBUG_VALUE val;
	// get the address
	if (gDebugControl->Evaluate(name, DEBUG_VALUE_INT64, &val, NULL) == E_FAIL)
		return 0;
	return val.I64;
}

void clear_addr_type_map()
{
	addr_type_map_sz = 0;
}

CA_BOOL user_request_break()
{
	if (CheckControlC() )
		return CA_TRUE;
	return CA_FALSE;
}

/////////////////////////////////////////////////////
// Type helper functions
/////////////////////////////////////////////////////
static bool
get_typeinfo(ULONG64 mod_base, ULONG type_id, ULONG64 addr, EXT_TYPED_DATA& typed_data, bool detail)
{
	HRESULT hr;
	EXT_TYPED_DATA typed_data_in;
	memset(&typed_data_in, 0, sizeof(EXT_TYPED_DATA));
	memset(&typed_data, 0, sizeof(EXT_TYPED_DATA));
	typed_data_in.Operation = EXT_TDOP_SET_FROM_TYPE_ID_AND_U64;
	typed_data_in.Flags     = 0;
	typed_data_in.InData.ModBase = mod_base;
	typed_data_in.InData.Offset  = addr;
	typed_data_in.InData.TypeId  = type_id;

	hr = gDebugAdvanced2->Request(DEBUG_REQUEST_EXT_TYPED_DATA_ANSI,
								&typed_data_in, sizeof(EXT_TYPED_DATA),
								&typed_data, sizeof(EXT_TYPED_DATA),
								NULL);
	if (FAILED(hr))
		return false;

	enum SymTagEnum tag = (enum SymTagEnum) typed_data.OutData.Tag;
	if (detail && typed_data.OutData.TypeId == typed_data.OutData.BaseTypeId
		&& (tag == SymTagPointerType || tag == SymTagArrayType))
	{
		char type_name[NAME_BUF_SZ];
		ULONG type_name_sz;
		hr = gDebugSymbols3->GetTypeName(mod_base, type_id, type_name, NAME_BUF_SZ, &type_name_sz);
		if (SUCCEEDED(hr) && type_name_sz < NAME_BUF_SZ-1)
		{
			if (tag == SymTagPointerType)
			{
				int cursor = type_name_sz - 1;
				while (cursor >= 0)
				{
					if (type_name[cursor] == '*')
					{
						type_name[cursor] = '\0';
						break;
					}
					cursor--;
				}
			}
			else // SymTagArrayType
			{
				char* pos = strstr(type_name, "[]");
				if (pos)
					*pos = '\0';
			}
			ULONG base_type_id;
			hr = gDebugSymbols3->GetTypeId(mod_base, type_name, &base_type_id);
			if (hr == S_OK)
				typed_data.OutData.BaseTypeId = base_type_id;
		}
	}
	return true;
}

static CA_BOOL
get_struct_field_type(ULONG64 mod_base,
					ULONG type_id,
					ULONG displacement,
					address_t* sym_addr,
					size_t*    sym_sz)
{
	HRESULT hr;
	EXT_TYPED_DATA typed_data;
	// Get the type category, pointer/array/function/...
	if (!get_typeinfo(mod_base, type_id, *sym_addr, typed_data, CA_FALSE))
		return CA_FALSE;
	enum SymTagEnum tag = (enum SymTagEnum) typed_data.OutData.Tag;
	if (tag == SymTagUDT)
	{
		for (int field_index = 0; ; field_index++)
		{
			//  Get field name
			char field_name[NAME_BUF_SZ];
			ULONG name_sz;
			hr = gDebugSymbols3->GetFieldName(mod_base, type_id, field_index, field_name, NAME_BUF_SZ, &name_sz);
			if (FAILED(hr) || name_sz >= NAME_BUF_SZ-1)
				break;
			// Get field type and its offset
			ULONG field_type_id;
			ULONG field_offset;
			if (gDebugSymbols3->GetFieldTypeAndOffset(mod_base, type_id, field_name, &field_type_id, &field_offset) != S_OK)
				break;
			// Get field size
			ULONG field_sz;
			if (gDebugSymbols3->GetTypeSize(mod_base, field_type_id, &field_sz) != S_OK)
				break;
			// Now we may check if ref to this field
			if (displacement >= field_offset && displacement < field_offset + field_sz)
			{
				ULONG base_type_sz;
				*sym_addr += field_offset;
				*sym_sz = field_sz;
				if (get_typeinfo(mod_base, field_type_id, *sym_addr - field_offset, typed_data, CA_FALSE)
					&& (enum SymTagEnum) typed_data.OutData.Tag == SymTagArrayType
					&& gDebugSymbols3->GetTypeSize(mod_base, typed_data.OutData.BaseTypeId, &base_type_sz) == S_OK)
				{
					ULONG array_index = (displacement - field_offset)/base_type_sz;
					*sym_addr += array_index * base_type_sz;
					return get_struct_field_type(mod_base, typed_data.OutData.BaseTypeId, displacement - field_offset - array_index * base_type_sz, sym_addr, sym_sz);
				}
				else
					return get_struct_field_type(mod_base, field_type_id, displacement - field_offset, sym_addr, sym_sz);
			}
		}
	}
	else
		return CA_TRUE;

	return CA_FALSE;
}

static CA_BOOL resolve_or_print_stack_ref(const struct object_reference* ref, CA_BOOL printit, address_t* sym_addr, size_t* sym_sz)
{
	bool found_sym = false;
	HRESULT hr;
	bool same_thread = true;

	if (printit)
	{
		if (g_debug_context.tid != ref->where.stack.tid)
		{
			dprintf(" thread %d frame %d", ref->where.stack.tid, ref->where.stack.frame);
			same_thread = false;
		}
	}

	if (ref->where.stack.frame >= 0)
	{
		struct stack_symbol* sym = search_cached_stack_symbols(ref);
		if (sym)
		{
			found_sym = true;
			if (printit)
			{
				if (same_thread && sym->frame != g_debug_context.frame_level)
					dprintf(" frame %d", sym->frame);
				dprintf(" %s", sym->name);
				// print sub field if any
				print_struct_field(ref, sym->mod_base, sym->type_id, (ULONG)(ref->vaddr - sym->offset));
			}
			if (sym_addr && sym_sz)
			{
				*sym_addr = sym->offset;
				*sym_sz   = sym->size;
				get_struct_field_type(sym->mod_base, sym->type_id, (ULONG)(ref->vaddr - sym->offset), sym_addr, sym_sz);
			}
		}
	}
	if (printit)
	{
		if (!found_sym)
		{
			if (same_thread && g_debug_context.frame_level != ref->where.stack.frame)
				dprintf(" frame %d", ref->where.stack.frame);
			dprintf(" SP+0x%lx", ref->where.stack.offset);
		}
		if (ref->value)
			dprintf(" @"PRINT_FORMAT_POINTER": "PRINT_FORMAT_POINTER"", ref->vaddr, ref->value);
	}

	return found_sym;
}

static CA_BOOL resolve_or_print_global_ref(const struct object_reference* ref, CA_BOOL printit, address_t* sym_addr, size_t* sym_sz)
{
	CA_BOOL rc = CA_FALSE;
	HRESULT hr;
	// Get symbol at the address
	char sym_name[NAME_BUF_SZ];
	ULONG name_sz;
	ULONG64 displacement = 0;
	hr = gDebugSymbols3->GetNameByOffset(ref->vaddr, sym_name, NAME_BUF_SZ, &name_sz, &displacement);
	if (FAILED(hr))
	{
		if (printit)
			dprintf(" unknown");
		goto NormalExit;
	}

	if (printit)
		dprintf(" %s", sym_name);

	// Get the type at the address
	ULONG type_id, type_sz;
	ULONG64 mod_base;
	if (gDebugSymbols3->GetOffsetTypeId(ref->vaddr - displacement, &type_id, &mod_base) == S_OK
		&& gDebugSymbols3->GetTypeSize(mod_base, type_id, &type_sz) == S_OK)
	{
		if (displacement < type_sz)
		{
			rc = CA_TRUE;
			if (sym_addr && sym_sz)
			{
				*sym_addr = ref->vaddr - displacement;
				*sym_sz   = type_sz;
			}
			if (printit)
				print_struct_field(ref, mod_base, type_id, (ULONG)displacement);
		}
		else if (ref->storage_type == ENUM_MODULE_TEXT)
		{
			// function's size need be dealt with differently
			DEBUG_MODULE_AND_ID id;
			ULONG64 displacement2;
			ULONG num_entry;
			DEBUG_SYMBOL_ENTRY sym_entry;
			if (gDebugSymbols3->GetSymbolEntriesByOffset(ref->vaddr - displacement, 0, &id, &displacement2, 1, &num_entry) == S_OK
				&& gDebugSymbols3->GetSymbolEntryInformation(&id, &sym_entry) == S_OK)
			{
				rc = CA_TRUE;
				if (sym_addr && sym_sz)
				{
					*sym_addr = ref->vaddr - displacement;
					*sym_sz   = sym_entry.Size;
				}
				if (printit)
					dprintf("+0x%I64x", displacement);
			}
		}
	}

NormalExit:
	if (printit)
	{
		if (!rc || ref->value)
			dprintf(" @"PRINT_FORMAT_POINTER, ref->vaddr);
		if (ref->value)
			dprintf(": "PRINT_FORMAT_POINTER, ref->value);
	}

	return rc;
}

static void
print_struct_field(const struct object_reference* ref,
					ULONG64 mod_base,
					ULONG type_id,
					ULONG displacement)
{
	HRESULT hr;
	EXT_TYPED_DATA typed_data;
	// Get the type category, pointer/array/function/...
	if (!get_typeinfo(mod_base, type_id, ref->vaddr - displacement, typed_data, ref->value > 0))
		return;
	enum SymTagEnum tag = (enum SymTagEnum) typed_data.OutData.Tag;
	if (tag == SymTagUDT)
	{
		for (int field_index = 0; ; field_index++)
		{
			//  Get field name
			char field_name[NAME_BUF_SZ];
			ULONG name_sz;
			hr = gDebugSymbols3->GetFieldName(mod_base, type_id, field_index, field_name, NAME_BUF_SZ, &name_sz);
			if (FAILED(hr) || name_sz >= NAME_BUF_SZ-1)
				break;
			// Get field type and its offset
			ULONG field_type_id;
			ULONG field_offset;
			if (gDebugSymbols3->GetFieldTypeAndOffset(mod_base, type_id, field_name, &field_type_id, &field_offset) != S_OK)
				break;
			// Get field size
			ULONG field_sz;
			if (gDebugSymbols3->GetTypeSize(mod_base, field_type_id, &field_sz) != S_OK)
				break;
			// Now we may check if ref to this field
			if (displacement >= field_offset && displacement < field_offset + field_sz)
			{
				ULONG base_type_sz;
				dprintf(".%s", field_name);
				if (get_typeinfo(mod_base, field_type_id, ref->vaddr - field_offset, typed_data, ref->value > 0)
					&& (enum SymTagEnum) typed_data.OutData.Tag == SymTagArrayType
					&& gDebugSymbols3->GetTypeSize(mod_base, typed_data.OutData.BaseTypeId, &base_type_sz) == S_OK)
				{
					ULONG array_index = (displacement - field_offset)/base_type_sz;
					dprintf("[%d]", array_index);
					print_struct_field(ref, mod_base, typed_data.OutData.BaseTypeId, displacement - field_offset - array_index * base_type_sz);
				}
				else
					print_struct_field(ref, mod_base, field_type_id, displacement - field_offset);
				break;
			}
		}
	}
	else
	{
		char type_name[NAME_BUF_SZ];
		ULONG type_name_sz;
		hr = gDebugSymbols3->GetTypeName(mod_base, type_id, type_name, NAME_BUF_SZ, &type_name_sz);
		if (SUCCEEDED(hr) && type_name_sz < NAME_BUF_SZ-1 && strcmp(type_name, "<function>")!=0)
			dprintf("(type=\"%s\")", type_name);
		if ( (tag == SymTagPointerType || tag == SymTagArrayType) && ref->value)
			add_addr_type(ref->value, typed_data.OutData.BaseTypeId, mod_base);
	}
}

/////////////////////////////////////////////////////
// Cached stack symbol helper functions
/////////////////////////////////////////////////////
static void release_cached_stack_symbols()
{
	for (int tid=0; tid<g_all_stack_symbols.size(); tid++)
	{
		stack_symbols* syms = g_all_stack_symbols[tid];
		if (syms)
		{
			for (int i=0; i<syms->size(); i++)
			{
				struct stack_symbol* sym = syms->at(i);
				if (sym->name)
					free(sym->name);
				delete sym;
			}
			syms->clear();
		}
		delete syms;
	}
	g_all_stack_symbols.clear();
}

/*
 * Collect all symbols(local variables) on this thread's stack
 */
static CA_BOOL build_stack_sym_cache( int tid)
{
	// Cache symbols only once
	if (g_all_stack_symbols.empty())
		g_all_stack_symbols.resize(g_total_threads);

	if (g_all_stack_symbols[tid] == NULL)
		g_all_stack_symbols[tid] = new stack_symbols;
	else
		return true;

	// switch thread
	// convert pseudo tid to engine tid and change scope to that thread
	ULONG engine_tid;
	if (gDebugSystemObjects->GetThreadIdsByIndex(tid, 1, &engine_tid, NULL) != S_OK
		|| gDebugSystemObjects->SetCurrentThreadId(engine_tid) != S_OK)
		return false;

	// Get the total number of frames
	DEBUG_STACK_FRAME frames[MAX_FRAMES];
	ULONG frameFilled = 0;
	if (gDebugControl->GetStackTrace(0,		// frame offset
									0,		// stack offset
									0,		// instruction offset
									frames,
									MAX_FRAMES,
									&frameFilled) != S_OK )
		return false;

	bool rc = false;
	PDEBUG_SYMBOL_GROUP2 symbolGroup2 = NULL;
	HRESULT hr;
	// Local variables don't seem to be bounded between sp and fp, check all frames
	for (ULONG frame_num = 0; frame_num < frameFilled; frame_num++)
	{
		// Set scope to frame_num
		// Beware, this method returns S_FALSE
		hr = gDebugSymbols3->SetScopeFrameByIndex(frame_num);
		if (FAILED(hr))
			break;
		// Retrieve COM interface to symbols of this scope (frame)
		if (gDebugSymbols3->GetScopeSymbolGroup2(DEBUG_SCOPE_GROUP_ALL, symbolGroup2, &symbolGroup2) != S_OK)
			goto NormalExit;
		// Get number of symbols
		ULONG total_syms;
		if (symbolGroup2->GetNumberSymbols(&total_syms) != S_OK)
			goto NormalExit;
		for (ULONG sym_index=0; sym_index<total_syms; sym_index++)
		{
			// symbol entry includes location/size/type_id, etc.
			DEBUG_SYMBOL_ENTRY entry;
			if (symbolGroup2->GetSymbolEntryInformation(sym_index, &entry) == S_OK)
			{
				// symbol name
				char name_buf[NAME_BUF_SZ];
				hr = symbolGroup2->GetSymbolName(sym_index, name_buf, NAME_BUF_SZ, NULL);
				if (FAILED(hr))
					break;
				struct stack_symbol* sym = new struct stack_symbol;
				sym->frame = frame_num;
				sym->size  = entry.Size;
				sym->offset = entry.Offset;
				sym->name = new char[strlen(name_buf)+1];
				strcpy(sym->name, name_buf);
				sym->mod_base = entry.ModuleBase;
				sym->type_id = entry.TypeId;
				g_all_stack_symbols[tid]->push_back(sym);
			}
		}
	}
	rc = true;

NormalExit:
	if (symbolGroup2)
		symbolGroup2->Release();

	return rc;
}

static struct stack_symbol* search_cached_stack_symbols(const struct object_reference* ref)
{
	// sanity check
	if ((ULONG)ref->where.stack.tid > g_total_threads - 1)
	{
		CA_PRINT("Internal error: tid=%d is out of range\n", ref->where.stack.tid);
		return NULL;
	}

	// build cache if not yet
	if (g_all_stack_symbols.empty() || g_all_stack_symbols[ref->where.stack.tid]==NULL)
		build_stack_sym_cache(ref->where.stack.tid);

	// search the cache
	stack_symbols* syms = g_all_stack_symbols[ref->where.stack.tid];
	for (int i=0; i<syms->size(); i++)
	{
		struct stack_symbol* sym = syms->at(i);
		if (ref->vaddr >= sym->offset && ref->vaddr < sym->offset + sym->size)
			return sym;
	}
	return NULL;
}

static void release_frame_info_cache()
{
	for (int i=0; i<g_all_stack_frames.size(); i++)
	{
		std::vector<struct frame_info>* frame_infos = g_all_stack_frames[i];
		if (frame_infos)
			delete frame_infos;
	}
	g_all_stack_frames.clear();
}

static bool build_frame_info_cache(int tid)
{
	if (g_all_stack_frames.empty())
		g_all_stack_frames.resize(g_total_threads);

	if (g_all_stack_frames[tid] == NULL)
	{
		g_all_stack_frames[tid] = new std::vector<struct frame_info>;

		std::vector<struct frame_info>* frame_infos = g_all_stack_frames[tid];
		DEBUG_STACK_FRAME frames[MAX_FRAMES];
		ULONG frameFilled = 0;
		// switch thread (remember to convert pseudo tid to engine tid)
		// then retrieve stack trace
		ULONG engine_tid;
		if (gDebugSystemObjects->GetThreadIdsByIndex(tid, 1, &engine_tid, NULL) == S_OK
			&& gDebugSystemObjects->SetCurrentThreadId(engine_tid) == S_OK
			&& gDebugControl->GetStackTrace(0,		// frame offset
											0,		// stack offset
											0,		// instruction offset
											frames,
											MAX_FRAMES,
											&frameFilled) == S_OK )
		{
			if (frameFilled > 0)
			{
				frame_infos->resize(frameFilled);
				for (ULONG fi = 0; fi < frameFilled; fi++)
				{
					struct frame_info* f_info = &frame_infos->at(fi);
					f_info->frame_no = fi;
					f_info->rbp = frames[fi].FrameOffset;
					f_info->rsp = frames[fi].StackOffset;
				}
			}
		}
	}
	return true;
}

/////////////////////////////////////////////////////
// Process segment helper functions
/////////////////////////////////////////////////////
static bool is_process_segment_changed()
{
	address_t start = 0;
	address_t end   = ~start;
	unsigned int seg_index = 0;
	while (start < end)
	{
		MEMORY_BASIC_INFORMATION64 info;
		if (gDebugDataSpaces4->QueryVirtual(start, &info) == S_OK)
		{
			// Free region is inaccessible virtual address
			// Valid address is either MEM_COMMIT or MEM_RESERVE
			if (!(info.State & MEM_FREE))
			{
				if (seg_index >= g_segment_count
					|| g_segments[seg_index].m_vaddr != info.BaseAddress
					|| g_segments[seg_index].m_vsize != info.RegionSize)
					return true;
				seg_index++;
			}
			start = info.BaseAddress + info.RegionSize;
		}
		else
			break;
	}
	if (seg_index != g_segment_count)
		return true;
	return false;
}

static bool fix_segments_with_mapped_file(char* start)
{
	MINIDUMP_HEADER* pdump = (MINIDUMP_HEADER*) start;
	if (MINIDUMP_SIGNATURE != pdump->Signature
		&& MINIDUMP_VERSION != (pdump->Version & 0xffff))
	{
		dprintf("Unrecognizable minidump file format\n");
		return false;
	}
	MINIDUMP_DIRECTORY* pMiniDumpDir = (MINIDUMP_DIRECTORY*) (start + pdump->StreamDirectoryRva);
	for (unsigned int k = 0; k < pdump->NumberOfStreams; k++, pMiniDumpDir++)
	{
		struct ca_segment* seg;
		MINIDUMP_LOCATION_DESCRIPTOR location = pMiniDumpDir->Location;
		// memory regions
		if (pMiniDumpDir->StreamType == Memory64ListStream)
		{
			MINIDUMP_MEMORY64_LIST* mem64_list = (MINIDUMP_MEMORY64_LIST*)(start + location.Rva);
			MINIDUMP_MEMORY_DESCRIPTOR64* region = &mem64_list->MemoryRanges[0];
			char* base = start + mem64_list->BaseRva;
			for (unsigned int i=0; i<mem64_list->NumberOfMemoryRanges; i++, region++)
			{
				seg = get_segment(region->StartOfMemoryRange, 1);
				if (seg && seg->m_vaddr == region->StartOfMemoryRange)
				{
					seg->m_faddr = base;
					if (region->DataSize >= seg->m_vsize)
						seg->m_fsize = seg->m_vsize;
					else
						seg->m_fsize = region->DataSize;
				}
				base += region->DataSize;
			}
		}
	}
	return true;
}

static bool mmap_core_file(const char* fname)
{
	DWORD rc;
	// silently ignores NULL file
	if (!fname)
		return false;

	// file stat
	struct __stat64 lStatBuf;
	if(_stat64(fname, &lStatBuf))
	{
		rc = ::GetLastError();
		dprintf("Failed to stat file %s, errno=%d\n", fname, rc);
		return false;
	}

	if(lStatBuf.st_size == 0)
	{
		dprintf("File %s is empty, ignored\n", fname);
		return false;
	}
	size_t mFileSize = lStatBuf.st_size;

	// Open file for mapping
	HANDLE lFileHandle = ::CreateFile(fname,
									GENERIC_READ,
									FILE_SHARE_READ,
									NULL,
									OPEN_EXISTING,
									FILE_ATTRIBUTE_NORMAL,
									NULL);
	if(INVALID_HANDLE_VALUE == lFileHandle)
	{
		rc = ::GetLastError();
		dprintf("Function CreateFile() Failed for %s LastError=%d\n", fname, rc);
		return false;
	}
	// Create mapping
	HANDLE mhFile = ::CreateFileMapping(lFileHandle,
										NULL,
										PAGE_READONLY,
										0,
										0,
										NULL);
	if(mhFile == NULL)
	{
		rc = ::GetLastError();
		dprintf("Function CreateFileMapping() failed for %s LastError=%d\n", fname, rc);
		return false;
	}
	// Get the memory address of mapping
	char* mpStartAddr = (char*) ::MapViewOfFile(mhFile,
												FILE_MAP_READ,
												0,
												0,
												0);
	if(mpStartAddr == NULL)
	{
		rc = ::GetLastError();
		dprintf("Function MapViewOfFile() failed for %s LastError=%d\n", fname, rc);
		return false;
	}
	// Now that we have mapped the dump file, fix all segments' m_faddr pointers
	if (!fix_segments_with_mapped_file(mpStartAddr))
		return false;

	return true;
}

/////////////////////////////////////////////////////
// Type map helper functions
/////////////////////////////////////////////////////
static void
add_addr_type(ULONG64 addr, ULONG type_id, ULONG64 mod_base)
{
	if (addr_type_map_sz >= addr_type_map_buf_sz)
	{
		if (addr_type_map_buf_sz == 0)
			addr_type_map_buf_sz = 64;
		else
			addr_type_map_buf_sz = addr_type_map_buf_sz * 2;
		addr_type_map = (struct addr_type_pair *) realloc(addr_type_map, addr_type_map_buf_sz * sizeof(struct addr_type_pair));
	}
	addr_type_map[addr_type_map_sz].addr = addr;
	addr_type_map[addr_type_map_sz].type_id = type_id;
	addr_type_map[addr_type_map_sz].mod_base = mod_base;
	addr_type_map_sz++;
}

// The input ref is assumed to be a heap block
static struct addr_type_pair*
lookup_type_by_addr(const struct object_reference* ref)
{
	// pick up the latest first
	for (int i = addr_type_map_sz - 1; i >=0 ; i--)
	{
		if (addr_type_map[i].addr == ref->vaddr
			|| addr_type_map[i].addr == ref->where.heap.addr)
			return &addr_type_map[i];
	}
	return NULL;
}

/*
 * Display known symbol/type of an instruction's operand value
 * !FIX!
 */
void print_op_value_context(size_t op_value, int op_size, address_t loc, int offset, int lea)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	struct type* type = NULL;
	struct addr_type_pair* addr_type;
	struct object_reference aref;

	// if op_value is known stack or global symbol
	if (op_size == ptr_sz && op_value)
	{
		memset(&aref, 0, sizeof(aref));
		aref.vaddr = op_value;
		aref.value = 0;
		aref.target_index = -1;
		fill_ref_location(&aref);
		if ( (aref.storage_type == ENUM_MODULE_TEXT || aref.storage_type == ENUM_MODULE_DATA)
			&& known_global_sym(&aref, NULL, NULL) )
		{
			// global symbol
			dprintf (" ");
			print_ref(&aref, 0, CA_FALSE, CA_TRUE);
			return;
		}
		else if (aref.storage_type == ENUM_STACK && known_stack_sym(&aref, NULL, NULL))
		{
			// stack symbol
			dprintf (" ");
			print_ref(&aref, 0, CA_FALSE, CA_TRUE);
			return;
		}
		else if (aref.storage_type == ENUM_HEAP /*&& known_heap_block(&aref) !FIX! */)
		{
			// heap block with known type
			dprintf (" ");
			print_ref(&aref, 0, CA_FALSE, CA_TRUE);
			return;
		}
	}

	// we are here because we don't know anything about the op_value
	// try if we know anything of its source if any
	if (loc)
	{
		struct object_reference loc_ref;
		memset(&loc_ref, 0, sizeof(loc_ref));
		loc_ref.vaddr = loc + offset;
		loc_ref.value = 0;
		loc_ref.target_index = -1;
		fill_ref_location(&loc_ref);
		if ( (loc_ref.storage_type == ENUM_MODULE_TEXT || loc_ref.storage_type == ENUM_MODULE_DATA)
			&& known_global_sym(&loc_ref, NULL, NULL) )
		{
			// global symbol
			dprintf (" SRC=");
			print_ref(&loc_ref, 0, CA_FALSE, CA_TRUE);
			return;
		}
		else if (loc_ref.storage_type == ENUM_STACK && known_stack_sym(&loc_ref, NULL, NULL))
		{
			// stack symbol
			dprintf (" SRC=");
			print_ref(&loc_ref, 0, CA_FALSE, CA_TRUE);
			return;
		}
		else if (loc_ref.storage_type == ENUM_HEAP && (addr_type = lookup_type_by_addr(&loc_ref)) )
		{
			ULONG name_sz;
			char type_name[NAME_BUF_SZ];
			HRESULT hr = gDebugSymbols3->GetTypeName(addr_type->mod_base, addr_type->type_id, type_name, NAME_BUF_SZ, &name_sz);
			if (SUCCEEDED(hr) && name_sz < NAME_BUF_SZ)
			{
				dprintf (" SRC=[%s]", type_name);
			}
			return;
		}
	}

	// lastly, we can still provide something useful, like heap/stack info
	if (op_size == ptr_sz && op_value)
	{
		if (aref.storage_type != ENUM_UNKNOWN)
		{
			dprintf (" ");
			print_ref(&aref, 0, CA_FALSE, CA_TRUE);
			return;
		}
	}

	dprintf ("\n");
}
