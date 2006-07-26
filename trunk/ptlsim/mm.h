// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Memory Management
//
// Copyright 2000-2006 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _MM_H_
#define _MM_H_

#include <globals.h>

void* ptl_alloc_private_pages(Waddr bytecount, int prot = PROT_READ|PROT_WRITE|PROT_EXEC, Waddr base = 0);
void* ptl_alloc_private_32bit_pages(Waddr bytecount, int prot = PROT_READ|PROT_WRITE|PROT_EXEC, Waddr base = 0);
void ptl_free_private_pages(void* addr, Waddr bytecount);
void ptl_zero_private_pages(void* base, Waddr bytecount);

void* ptl_alloc_private_page();
void* ptl_alloc_private_32bit_page();
void ptl_free_private_page(void* addr);
void ptl_zero_private_page(void* addr);

void* ptl_mm_alloc(size_t bytes);
void ptl_mm_free(void* p);
void ptl_mm_reclaim();

class DataStoreNode;
DataStoreNode& ptl_mm_capture_stats(DataStoreNode& root);
void ptl_mm_init(byte* heap_start = null, byte* heap_end = null);

//
// Memory management
//
#define PTL_PAGE_POOL_BYTES (4ULL*1024*1024*1024) // lower 4 GB
#define PTL_PAGE_POOL_SIZE (PTL_PAGE_POOL_BYTES / 4096)
#define PTL_PAGE_POOL_BASE 0 // starts at base of address space

#define PTL_IMAGE_BASE 0x70000000ULL
#define PTL_IMAGE_SIZE (256*1024*1024) // 256 MB (up to 0x80000000)

#ifdef __x86_64__

// On x86-64 K8's, there are 48 bits of virtual address space and 40 bits of physical address space: 
#define TOP_OF_MEM 0x1000000000000ULL

#define mmap_invalid(addr) (((W64)(addr) & 0xfffffffffffff000) == 0xfffffffffffff000)
#define mmap_valid(addr) (!mmap_invalid(addr))

#else // ! __x86_64__

// On x86, there are 32 bits of virtual address space and 32 bits of physical address space: 
#define TOP_OF_MEM 0x100000000LL

#define mmap_invalid(addr) (((W32)(addr) & 0xfffff000) == 0xfffff000)
#define mmap_valid(addr) (!mmap_invalid(addr))

#endif

#endif // _MM_H_
