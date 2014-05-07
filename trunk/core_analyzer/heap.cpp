/*
 * heap.cpp
 * 		Functions for heap memory
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include "heap.h"
#include "segment.h"

#define COPY_BLOCK_INFO(dst,src) \
		(dst)->addr = (src)->addr; \
		(dst)->size = (src)->size; \
		(dst)->ref_count = (src)->ref_count

// Forward declaration
static CA_BOOL
mark_blocks_referenced_by_globals_locals(struct block_info*, unsigned long);
static CA_BOOL
mark_blocks_referenced_by_known_blocks(struct block_info*, unsigned long,
									struct block_info*, unsigned long);
static void display_histogram(const char*, unsigned int,
					const size_t*, const unsigned long*, const size_t*);
static struct block_info* build_inuse_heap_blocks(unsigned long*);

// Global Vars
static struct MemHistogram g_mem_hist;

// A utility function
void print_size(size_t sz)
{
	const size_t GB = 1024*1024*1024;
	const size_t MB = 1024*1024;
	const size_t KB = 1024;

	if (sz > GB)
		CA_PRINT("%.1fGB", (double)sz/(double)GB);
	else if (sz > MB)
		CA_PRINT(PRINT_FORMAT_SIZE"MB", sz/MB);
	else if (sz > KB)
		CA_PRINT(PRINT_FORMAT_SIZE"KB", sz/KB);
	else
		CA_PRINT(PRINT_FORMAT_SIZE, sz);
}

// A not-so-fast leak checking based on the concept what a heap block without any
// reference directly/indirectly from a global/local variable is a lost one
CA_BOOL display_heap_leak_candidates(void)
{
	unsigned long total_blocks, count, num_leak_blocks;
	struct block_info* blocks;
	struct block_info* cursor;
	struct block_info* leak_blocks;
	struct block_info* refed_buf = NULL;
	unsigned long      refed_buf_sz = 0;	// in terms of number of block_info
	unsigned int loops;
	time_t start_time = time(NULL);

	// First, create and populate an array of all in-use blocks
	blocks = build_inuse_heap_blocks(&total_blocks);
	if (!blocks || total_blocks == 0)
	{
		CA_PRINT("Failed: no in-use heap block is found\n");
		return CA_FALSE;
	}
	else if (total_blocks >= 2)
	{
		// sanity check whether the array is sorted by address, as required.
		for (count = 0, cursor = blocks; count < total_blocks - 1; count++, cursor++)
		{
			if (cursor->addr + cursor->size > (cursor+1)->addr)
			{
				CA_PRINT("Internal error: in-use array is not properly sorted at %ld\n", count);
				CA_PRINT("\t[%ld] "PRINT_FORMAT_POINTER" size=%ld\n", count, cursor->addr, cursor->size);
				CA_PRINT("\t[%ld] "PRINT_FORMAT_POINTER"\n", count+1, (cursor+1)->addr);
				free (blocks);
				return CA_FALSE;
			}
		}
	}

	start_time = time(NULL);
	// Second, search global/local(module's .text/.data/.bss and thread stack)
	//         memory for any reference to these blocks
	if (!mark_blocks_referenced_by_globals_locals(blocks, total_blocks))
	{
		free (blocks);
		return CA_FALSE;
	}

	// Third, search and update un-referenced blocks with newly found referenced heap
	//        blocks until none is found any more
	leak_blocks = blocks;
	num_leak_blocks = total_blocks;
	loops = 1;
	do
	{
		unsigned long num_refed_blocks = 0;
		// separate referenced and un-referenced blocks in the big array into two halves
		//         the bottom half (unreferenced blocks) need to keep original order
		// count number of referenced blocks
		for (count = 0, cursor = leak_blocks; count < num_leak_blocks; count++, cursor++)
		{
			if (cursor->ref_count)
				num_refed_blocks++;
		}
		// if more referenced blocks are found in this round
		// separate them from those un-referenced
		if (num_refed_blocks)
		{
			struct block_info* next_block;
			// use a buffer
			if (refed_buf_sz < num_refed_blocks)
			{
				if (refed_buf)
					free(refed_buf);
				refed_buf = (struct block_info*) malloc(sizeof(struct block_info) * num_refed_blocks);
				refed_buf_sz = num_refed_blocks;
				if (!refed_buf)
				{
					CA_PRINT("Failed to allocate %ld bytes\n", sizeof(struct block_info) * num_refed_blocks);
					free (blocks);
					return CA_FALSE;
				}
			}
			// copy referenced blocks to the buffer
			for (count = 0, cursor = leak_blocks, next_block = refed_buf;
				count < num_leak_blocks;
				count++, cursor++)
			{
				if (cursor->ref_count)
				{
					COPY_BLOCK_INFO(next_block, cursor);
					next_block++;
				}
			}
			// move un-referenced to the bottom half of the array
			// next_block should points to a referenced block, which is ready to be overwritten by an unref-ed one
			next_block = leak_blocks + num_leak_blocks - 1;
			cursor = next_block - 1;
			while(1)
			{
				// find a referenced slot backwards
				while (next_block >= leak_blocks && next_block->ref_count == 0)
					next_block--;
				if (next_block < leak_blocks)
					break;
				// find a unreferenced slot backwards from current slot
				if (cursor > next_block)	// this only happens the first time
					cursor = next_block;
				while (cursor >= leak_blocks && cursor->ref_count)
					cursor--;
				if (cursor < leak_blocks)
					break;
				// copy the unreferenced block at cursor to the referenced on at next_block
				COPY_BLOCK_INFO(next_block, cursor);
				cursor->ref_count = 1;
				next_block--;
				cursor--;
			}
			{
				/*
				if (next_block - leak_blocks != num_refed_blocks - 1)
					CA_PRINT("==> [ca_debug] Error to separate ref and un-ref blocks\n");
				for (count = 0, cursor = leak_blocks; count < num_refed_blocks; count++, cursor++)
				{
					if (cursor->ref_count == 0)
						CA_PRINT("\t[ca_debug] [block %ld] is expected to be referenced\n", count);
				}
				for (count = num_refed_blocks, cursor = leak_blocks + num_refed_blocks;
					count < num_leak_blocks; count++, cursor++)
				{
					if (cursor->ref_count)
						CA_PRINT("\t[ca_debug] [block %ld] is expected to be un-referenced\n", count);
				}
				*/
			}
			// copy referenced blocks back from buffer to the big array
			memcpy(leak_blocks, refed_buf, sizeof(struct block_info) * num_refed_blocks);

			// debug timing information
			/*
			CA_PRINT("[ca_debug] [loop %d] [time=%ld] %ld refed-block found, with %ld un-referenced left\n",
				loops, time(NULL) - start_time, num_refed_blocks, num_leak_blocks - num_refed_blocks);
			*/
			// if there is still some un-referenced left
			if (num_leak_blocks > num_refed_blocks)
			{
				mark_blocks_referenced_by_known_blocks(leak_blocks,
									num_refed_blocks,
									leak_blocks + num_refed_blocks,
									num_leak_blocks - num_refed_blocks);
			}
			leak_blocks += num_refed_blocks;
			num_leak_blocks -= num_refed_blocks;
		}
		else
			break;
		loops++;
	} while (num_leak_blocks);
	// done with the buffer
	if (refed_buf)
		free (refed_buf);

	// Display blocks that found no references to them directly or indirectly from global/local areas
	if (num_leak_blocks)
	{
		size_t total_leak_bytes = 0;
		size_t total_bytes = 0;

		CA_PRINT("Potentially leaked heap memory blocks:\n");
		for (count = 0, cursor = leak_blocks;
			count < num_leak_blocks;
			count++, cursor++)
		{
			CA_PRINT("[%ld] addr="PRINT_FORMAT_POINTER" size="PRINT_FORMAT_SIZE"\n",
				count+1, cursor->addr, cursor->size);
			total_leak_bytes += cursor->size;
		}

		for (count = 0, cursor = blocks; count < total_blocks; count++, cursor++)
			total_bytes += cursor->size;

		CA_PRINT("Total %ld (", num_leak_blocks);
		print_size(total_leak_bytes);
		CA_PRINT(") leak candidates out of %ld (", total_blocks);
		print_size(total_bytes);
		CA_PRINT(") in-use memory blocks\n");
	}
	else
		CA_PRINT("All %ld heap blocks are referenced\n", total_blocks);

	// clean
	free (blocks);
	return CA_TRUE;
}

/*
 * Histogram functions
 */

void display_mem_histogram(const char* prefix)
{

	if (!g_mem_hist.num_buckets || !g_mem_hist.bucket_sizes
		|| !g_mem_hist.inuse_cnt || !g_mem_hist.inuse_bytes
		|| !g_mem_hist.free_cnt || !g_mem_hist.free_bytes)
		return;

	CA_PRINT("%s========== In-use Memory Histogram ==========\n", prefix);
	display_histogram(prefix, g_mem_hist.num_buckets, g_mem_hist.bucket_sizes, g_mem_hist.inuse_cnt, g_mem_hist.inuse_bytes);

	CA_PRINT("%s========== Free Memory Histogram ==========\n", prefix);
	display_histogram(prefix, g_mem_hist.num_buckets, g_mem_hist.bucket_sizes, g_mem_hist.free_cnt, g_mem_hist.free_bytes);
}

void release_mem_histogram(void)
{
	if (g_mem_hist.bucket_sizes)
		free(g_mem_hist.bucket_sizes);
	if (g_mem_hist.inuse_cnt)
		free(g_mem_hist.inuse_cnt);
	if (g_mem_hist.inuse_bytes)
		free(g_mem_hist.inuse_bytes);
	if (g_mem_hist.free_cnt)
		free(g_mem_hist.free_cnt);
	if (g_mem_hist.free_bytes)
		free(g_mem_hist.free_bytes);
	memset(&g_mem_hist, 0, sizeof(g_mem_hist));
}

void init_mem_histogram(unsigned int nbuckets)
{
	unsigned int i;

	release_mem_histogram();

	g_mem_hist.num_buckets = nbuckets;
	g_mem_hist.bucket_sizes = (size_t*)malloc(nbuckets * sizeof(size_t));
	for (i = 0; i < nbuckets; i++)
		g_mem_hist.bucket_sizes[i] = 16 << i;
	g_mem_hist.inuse_cnt = (unsigned long*)malloc((nbuckets+1) * sizeof(unsigned long));
	g_mem_hist.inuse_bytes = (size_t*)malloc((nbuckets+1) * sizeof(size_t));
	g_mem_hist.free_cnt = (unsigned long*)malloc((nbuckets+1) * sizeof(unsigned long));
	g_mem_hist.free_bytes = (size_t*)malloc((nbuckets+1) * sizeof(size_t));
	for (i = 0; i < nbuckets + 1; i++)
	{
		g_mem_hist.inuse_cnt[i] = 0;
		g_mem_hist.inuse_bytes[i] = 0;
		g_mem_hist.free_cnt[i] = 0;
		g_mem_hist.free_bytes[i] = 0;
	}
}

void add_block_mem_histogram(size_t size, CA_BOOL inuse, unsigned int num_block)
{
	unsigned int n;

	if (!g_mem_hist.num_buckets || !g_mem_hist.bucket_sizes
		|| !g_mem_hist.inuse_cnt || !g_mem_hist.inuse_bytes
		|| !g_mem_hist.free_cnt || !g_mem_hist.free_bytes)
		return;

	for (n = 0; n < g_mem_hist.num_buckets; n++)
	{
		if (size <= g_mem_hist.bucket_sizes[n])
			break;
	}
	if (inuse)
	{
		g_mem_hist.inuse_cnt[n] += num_block;
		g_mem_hist.inuse_bytes[n] += size * num_block;
	}
	else
	{
		g_mem_hist.free_cnt[n] += num_block;
		g_mem_hist.free_bytes[n] += size * num_block;
	}
}

/*
 * Helper functions
 */
static void display_histogram(const char* prefix,
			unsigned int   nbuckets,
			const size_t*        bucket_sizes,
			const unsigned long* block_cnt,
			const size_t*        block_bytes)
{
	unsigned int n;
	unsigned long total_cnt, total_cnt2;
	size_t total_bytes;

	CA_PRINT("%sSize-Range    Count    Total-Bytes\n", prefix);
	total_cnt = 0;
	total_bytes = 0;
	for (n = 0; n <= nbuckets; n++)
	{
		total_cnt += block_cnt[n];
		total_bytes += block_bytes[n];
	}

	total_cnt2 = 0;
	for (n = 0; n <= nbuckets && total_cnt2 < total_cnt; n++)
	{
		if (block_cnt[n] > 0)
		{
			CA_PRINT("%s", prefix);
			// bucket size range
			if (n == 0)
			{
				CA_PRINT("0 - ");
				print_size(bucket_sizes[n]);
			}
			else if (n == nbuckets)
			{
				print_size(bucket_sizes[n-1]);
				CA_PRINT(" -    ");
			}
			else
			{
				print_size(bucket_sizes[n-1]);
				CA_PRINT(" - ");
				print_size(bucket_sizes[n]);
			}

			// count and total bytes and percentage
			CA_PRINT("    %ld(%ld%%)    ",
					block_cnt[n], block_cnt[n] * 100 / total_cnt);
			print_size(block_bytes[n]);
			CA_PRINT("(%ld%%)\n", block_bytes[n] * 100 / total_bytes);

			total_cnt2 += block_cnt[n];
		}
	}
}

static void add_ref_count(address_t addr, struct block_info* blocks, unsigned long total_blocks)
{
	// Binary search if addr belongs to one of the blocks
	unsigned long l_index = 0;
	unsigned long u_index = total_blocks;

	// bail out for out of bound addr
	// move this to the caller for optimization
	//if (addr < blocks[0].addr || addr >= blocks[total_blocks-1].addr + blocks[total_blocks-1].size)
	//	return;

	while (l_index < u_index)
	{
		unsigned long m_index = (l_index + u_index) / 2;
		struct block_info* blk = &blocks[m_index];
		if (addr < blk->addr)
			u_index = m_index;
		else if (addr >= blk->addr + blk->size)
			l_index = m_index + 1;
		else
		{
			blk->ref_count++;
			return;
		}
	}
	return;
}

static CA_BOOL
mark_blocks_referenced_by_globals_locals(struct block_info* blocks, unsigned long total_blocks)
{
	unsigned int seg_index;
	size_t ptr_sz = g_ptr_bit >> 3;
	address_t low_addr = blocks[0].addr;
	address_t high_addr = blocks[total_blocks-1].addr + blocks[total_blocks-1].size;

	for (seg_index = 0; seg_index < g_segment_count; seg_index++)
	{
		struct ca_segment* segment = &g_segments[seg_index];

		if (segment->m_fsize == 0)
			continue;
		else
		{
			// if we are debugging core file, read memory from mmap-ed file
			// for live process, use a buffer to read in the whole segment
			if (!g_debug_core)
			{
				segment->m_faddr = (char*)malloc(segment->m_fsize);
				if (segment->m_faddr)
				{
					if (!read_memory_wrapper(segment, segment->m_vaddr, segment->m_faddr, segment->m_fsize))
					{
						// can't read the segment's data, something is broken
						free (segment->m_faddr);
						continue;
					}
				}
				else
				{
					// Out of memory
					return CA_FALSE;
				}
			}
		}

		if (segment->m_type == ENUM_STACK
			|| segment->m_type == ENUM_MODULE_DATA
			|| segment->m_type == ENUM_MODULE_TEXT)
		{
			const char* start;
			const char* next;
			const char* end;
			// ignore stack memory below stack pointer
			if (segment->m_type == ENUM_STACK)
			{
				address_t rsp = get_rsp(segment);
				if (rsp >= segment->m_vaddr && rsp < segment->m_vaddr + segment->m_vsize)
					start = rsp - segment->m_vaddr + segment->m_faddr;
				else
					start = segment->m_faddr;
				end = segment->m_faddr + segment->m_fsize;
			}
			else
			{
				start = segment->m_faddr;
				end   = start + segment->m_fsize;
			}

			next  = start;
			while (next + ptr_sz <= end)
			{
				address_t ptr = 0;
				if (ptr_sz == 8)
					ptr = *(address_t*)next;
				else
					ptr = *(unsigned int*)next;
				if (ptr >= low_addr && ptr < high_addr)
					add_ref_count(ptr, blocks, total_blocks);
				next += ptr_sz;
			}
		}

		// release the temporary buffer
		if (!g_debug_core)
			free (segment->m_faddr);

		// This search may take long, bail out if user is impatient
		if (user_request_break())
		{
			CA_PRINT("Abort searching\n");
			break;
		}
	}

	return CA_TRUE;
}

static CA_BOOL
mark_blocks_referenced_by_known_blocks(
						struct block_info* known_blocks,
						unsigned long num_known_blocks,
						struct block_info* blocks,
						unsigned long num_blocks)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	unsigned long index;
	struct block_info* cursor;
	address_t low_addr = blocks[0].addr;
	address_t high_addr = blocks[num_blocks-1].addr + blocks[num_blocks-1].size;

	for (index = 0, cursor = known_blocks;
		index < num_known_blocks;
		index++, cursor++)
	{
		address_t start = cursor->addr;
		address_t end   = start + cursor->size;
		address_t next  = start;
		while (next + ptr_sz <= end)
		{
			address_t ptr = 0;
			if (!read_memory_wrapper(NULL, next, &ptr, ptr_sz))
				break;
			else if (ptr >= low_addr && ptr < high_addr)
				add_ref_count(ptr, blocks, num_blocks);
			next += ptr_sz;
		}
	}
	return CA_TRUE;
}

/*
 * Return an array of struct block_info, of all in-use blocks
 */
static struct block_info* build_inuse_heap_blocks(unsigned long* opCount)
{
	struct block_info* blocks = NULL;
	unsigned long total_inuse = 0;

	*opCount = 0;
	// 1st walk counts the number of in-use blocks
	if (walk_inuse_blocks(NULL, &total_inuse) && total_inuse)
	{
		// allocate memory for block_info array
		blocks = (struct block_info*) calloc(total_inuse, sizeof(struct block_info));
		if (!blocks)
		{
			CA_PRINT("Failed: Out of Memory\n");
			return NULL;
		}
		// 2nd walk populate the array for in-use block info
		if (!walk_inuse_blocks(blocks, opCount) || *opCount != total_inuse)
		{
			CA_PRINT("Unexpected error while walking in-use blocks\n");
			*opCount = 0;
			free (blocks);
			blocks = NULL;
		}
	}
	return blocks;
}
