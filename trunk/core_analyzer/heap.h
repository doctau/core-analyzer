/*
 * heap.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef _HEAP_H
#define _HEAP_H

#include "ref.h"

/*
 * Exposed functions
 */
extern CA_BOOL init_heap(void);

extern CA_BOOL heap_walk(address_t addr);

extern CA_BOOL is_heap_block(address_t addr);

extern CA_BOOL get_heap_block_info(address_t addr, struct heap_block* blk);

extern CA_BOOL get_next_heap_block(address_t addr, struct heap_block* blk);

extern CA_BOOL get_biggest_blocks(struct heap_block* blks, unsigned int num);

#endif
