/*
 * ca_i386.h
 *
 *  Created on: May 17, 2013
 *      Author: myan
 */
#ifndef CA_I386_H_
#define CA_I386_H_

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
extern struct ca_debug_context g_debug_context;

#endif // CA_I386_H_
