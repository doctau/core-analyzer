/*
 * x_dep.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_TYPE_H_
#define X_TYPE_H_

#include <ctype.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "defs.h"
#include "gdb_string.h"
#include "frame.h"
#include "symtab.h"
#include "gdbtypes.h"
#include "value.h"
#include "language.h"
#include "expression.h"
#include "gdbcore.h"
#include "gdbcmd.h"
#include "target.h"
#include "breakpoint.h"
#include "demangle.h"
#include "valprint.h"
#include "annotate.h"
#include "symfile.h"		/* for overlay functions */
#include "objfiles.h"		/* ditto */
#include "completer.h"		/* for completion functions */
#include "ui-out.h"
#include "gdb_assert.h"
#include "block.h"
#include "stack.h"
#include "dictionary.h"
#include "exceptions.h"
#include "disasm.h"
#include "solist.h"
#include "gdbthread.h"
#include "inferior.h"
#include "regcache.h"
#include "elf-bfd.h"
#include "arch-utils.h"
#include "solist.h"
#include "amd64-tdep.h"
#include "cp-abi.h"
#include "user-regs.h"

#ifdef linux
#include <elf.h>
#elif defined(__MACH__)
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <mach-o/loader.h>

extern struct cleanup *
make_cleanup_restore_current_thread (ptid_t inferior_ptid, int print);

#endif

typedef CORE_ADDR address_t;

#define CA_PRINT(format,args...) \
	printf_filtered(_(format), ##args)

#define PRINT_FORMAT_POINTER "0x%lx"
#define PRINT_FORMAT_SIZE    "%ld"

typedef int CA_BOOL;
#define CA_TRUE  1
#define CA_FALSE 0

// types for decode function
#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8  8
#define R9  9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15
#define RIP 16
#define RXMM0 17
#define RXMM1 18
#define RXMM2 19
#define RXMM3 20
#define RXMM4 21
#define RXMM5 22
#define RXMM6 23
#define RXMM7 24
#define RXMM8 25
#define RXMM9 26
#define RXMM10 27
#define RXMM11 28
#define RXMM12 29
#define RXMM13 30
#define RXMM14 31
#define RXMM15 32
#define TOTAL_REGS 33

struct ca_reg_value
{
	size_t value;
	size_t saved_value;
	unsigned int known:1;
	unsigned int saved:1;
	unsigned int reserved:30;
};

extern struct ca_reg_value g_regs[TOTAL_REGS];
extern CA_BOOL g_dis_silent;

extern int ca_print_insn_i386(bfd_vma pc, struct disassemble_info *info);
extern void decode_func(char *arg);

extern void print_op_value_context(size_t op_value, int op_size, address_t loc, int offset, int lea);

struct object_reference;

extern struct symbol* get_stack_sym(const struct object_reference*, address_t*, size_t*);
extern struct symbol* get_global_sym(const struct object_reference*, address_t*, size_t*);
extern struct type*   get_heap_object_type(const struct object_reference*);

extern struct cleanup *make_cleanup_restore_current_debug_context();
#endif // X_TYPE_H_
