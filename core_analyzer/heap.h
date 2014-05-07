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

extern CA_BOOL heap_walk(address_t addr, CA_BOOL verbose);

extern CA_BOOL is_heap_block(address_t addr);

extern CA_BOOL get_heap_block_info(address_t addr, struct heap_block* blk);

extern CA_BOOL get_next_heap_block(address_t addr, struct heap_block* blk);

extern CA_BOOL get_biggest_blocks(struct heap_block* blks, unsigned int num);

extern void print_size(size_t sz);

/*
 * Memory leak check
 */
struct block_info
{
	address_t addr;
	size_t    size;
	unsigned int ref_count;
};

/*
 * Get all in-use memory blocks
 * 	If param opBlocks is NULL, return number of in-use only,
 * 	otherwise, populate the array with all in-use block info
 */
extern CA_BOOL walk_inuse_blocks(struct block_info* opBlocks, unsigned long* opCount);

extern CA_BOOL display_heap_leak_candidates(void);

/*
 * Histogram of heap blocks
 */
struct MemHistogram
{
	unsigned int   num_buckets;
	size_t*        bucket_sizes;
	unsigned long* inuse_cnt;
	size_t*        inuse_bytes;
	unsigned long* free_cnt;
	size_t*        free_bytes;
};
extern void display_mem_histogram(const char*);
extern void init_mem_histogram(unsigned int nbuckets);
extern void release_mem_histogram(void);
extern void add_block_mem_histogram(size_t, CA_BOOL, unsigned int);

#endif
