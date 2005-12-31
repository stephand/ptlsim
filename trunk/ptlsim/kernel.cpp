//
// PTLsim: Cycle Accurate x86-64 Simulator
// Memory Manager and threading support
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <linux/unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <signal.h>
#include <asm/ldt.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>

#ifdef __x86_64__
#include <asm/prctl.h>
#include <sys/prctl.h>
#endif

//
// Performance Counter Support:
//
// If you have a kernel compiled with the perfctr library (see below)
// and have installed the appropriate userspace headers, edit the
// Makefile to uncomment "ENABLE_KERNEL_PERFCTRS = 1".
//
// This will let PTLsim profile the native CPU for cycle counts,
// cache hit rate, uop and x86 instruction counts, etc. This mode
// is enabled by the "-profonly" configuration option, and can be
// useful for comparing PTLsim against a real processor.
//
// Note that you will need a modified kernel that allows hooking
// the native exit() syscall so PTLsim can regain control and
// print the performance counters. If you don't have this, you'll
// need to use ptlcall_switch_to_native() at the end of the
// benchmark being profiled to make the perfctr support work.
//
// The perfctr library can be obtained here:
// http://www.csd.uu.se/~mikpe/linux/perfctr
// 

#ifdef ENABLE_KERNEL_PERFCTRS
extern "C" {
#include <libperfctr.h>
#include <perfctr_event_codes.h>
}
#endif

#include <ptlsim.h>
#include <config.h>
#include <kernel.h>
#include <ptlcalls.h>
#include <loader.h>

#ifdef __x86_64__
declare_syscall2(__NR_arch_prctl, W64, arch_prctl, int, code, void*, addr);
#endif

declare_syscall0(__NR_gettid, pid_t, sys_gettid);
declare_syscall0(__NR_fork, pid_t, sys_fork);
declare_syscall1(__NR_exit, void, sys_exit, int, code);
declare_syscall1(__NR_brk, void*, sys_brk, void*, p);
declare_syscall3(__NR_write, ssize_t, sys_write, int, fd, const void*, buf, size_t, count);
declare_syscall3(__NR_execve, int, sys_execve, char*, filename, char**, argv, char**, envp);
declare_syscall4(__NR_ptrace, W64, sys_ptrace, int, request, pid_t, pid, W64, addr, W64, data);

static inline W64 do_syscall_64bit(W64 syscallid, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5, W64 arg6) {
  W64 rc;
  asm volatile ("movq %5,%%r10\n"
                "movq %6,%%r8\n"
                "movq %7,%%r9\n"
                "syscall\n"
                : "=a" (rc)
                : "0" (syscallid),"D" ((W64)(arg1)),"S" ((W64)(arg2)),
                "d" ((W64)(arg3)), "g" ((W64)(arg4)), "g" ((W64)(arg5)),
                "g" ((W64)(arg6)) 
                : "r11","rcx","memory" ,"r8", "r10", "r9" );
	return rc;
}

struct user_desc_32bit {
	W32 entry_number;
	W32 base_addr;
	W32 limit;
	W32 seg_32bit:1;
	W32 contents:2;
	W32 read_exec_only:1;
	W32 limit_in_pages:1;
	W32 seg_not_present:1;
	W32 useable:1;
};

#ifdef __x86_64__
// Parameters in: ebx ecx edx esi edi ebp
static inline W32 do_syscall_32bit(W32 sysid, W32 arg1, W32 arg2, W32 arg3, W32 arg4, W32 arg5, W32 arg6) {
  W32 rc;
  asm volatile ("push %%rbp ; movl %[arg6],%%ebp ; int $0x80 ; pop %%rbp" : "=a" (rc) :
                "a" (sysid), "b" (arg1), "c" (arg2), "d" (arg3),
                "S" (arg4), "D" (arg5), [arg6] "r" (arg6));
  return rc;
}

Waddr get_fs_base() {
  Waddr fsbase;
  assert(arch_prctl(ARCH_GET_FS, &fsbase) == 0);
  return fsbase;
}

Waddr get_gs_base() {
  W64 gsbase;
  assert(arch_prctl(ARCH_GET_GS, &gsbase) == 0);
  return gsbase;
}

#else
// We need this here because legacy x86 readily runs out of registers:
static W32 tempsysid;

// 32-bit only
static inline W32 do_syscall_32bit(W32 sysid, W32 arg1, W32 arg2, W32 arg3, W32 arg4, W32 arg5, W32 arg6) {
  W32 rc;
  tempsysid = sysid;

  asm volatile ("push %%ebp ; movl %%eax,%%ebp ; movl tempsysid,%%eax ; int $0x80 ; pop %%ebp" : "=a" (rc) :
                "b" (arg1), "c" (arg2), "d" (arg3), 
                "S" (arg4), "D" (arg5), "0" (arg6));
  return rc;
}

declare_syscall1(__NR_get_thread_area, int, sys_get_thread_area, void*, udesc);
declare_syscall1(__NR_set_thread_area, int, sys_set_thread_area, void*, udesc);

Waddr get_fs_base() {
  user_desc_32bit ud;
  ud.entry_number = get_fs() >> 3;
  int rc = sys_get_thread_area(&ud);
  return (rc) ? 0 : ud.base_addr;
}

Waddr get_gs_base() {
  user_desc_32bit ud;
  ud.entry_number = get_gs() >> 3;
  int rc = sys_get_thread_area(&ud);
  return (rc) ? 0 : ud.base_addr;
}

#endif // !__x86_64__

// Based on /usr/include/asm-i386/unistd.h:
#define __NR_32bit_mmap 90
#define __NR_32bit_mmap2 192
#define __NR_32bit_munmap 91
#define __NR_32bit_mprotect 125
#define __NR_32bit_mremap 163
#define __NR_32bit_brk 45
#define __NR_32bit_exit 1
#define __NR_32bit_exit_group 252
#define __NR_32bit_mremap 163
#define __NR_32bit_set_thread_area 243
#define __NR_32bit_rt_sigaction 174

void early_printk(const char* text) {
  sys_write(2, text, strlen(text));
}

// Avoid c++ scoping problems:

void* sys_mmap(void* start, W64 length, int prot, int flags, int fd, off_t offset) {
  return mmap(start, length, prot, flags, fd, offset);
}

int sys_munmap(void* start, W64 length) {
  return munmap((void*)start, length);
}

int sys_mprotect(void* start, W64 length, int prot) {
  return mprotect(start, length, prot);
}

int sys_madvise(void* start, W64 length, int action) {
  return madvise(start, length, action);
}

// Makes it easy to identify which segments PTLsim owns versus the user address space:
bool inside_ptlsim = false;

void* ptl_alloc_private_pages(Waddr bytecount, int prot, Waddr base) {
  int flags = MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : 0);
  flags |= (inside_ptlsim) ? MAP_SHARED : MAP_PRIVATE;
  if (base == 0) base = PTL_PAGE_POOL_BASE;
  void* addr = sys_mmap((void*)base, ceil(bytecount, PAGE_SIZE), prot, flags, 0, 0);

  return addr;
}

void* ptl_alloc_private_32bit_pages(Waddr bytecount, int prot, Waddr base) {
#ifdef __x86_64__
  int flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : MAP_32BIT);
#else
  int flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : 0);
#endif
  return sys_mmap((void*)base, ceil(bytecount, PAGE_SIZE), prot, flags, 0, 0);  
}

void ptl_free_private_pages(void* addr, Waddr bytecount) {
  sys_munmap(addr, bytecount);
}

void ptl_zero_private_pages(void* addr, Waddr bytecount) {
  sys_madvise((void*)floor((Waddr)addr, PAGE_SIZE), bytecount, MADV_DONTNEED);
}

//
// Very simple linked-list based malloc()/free().
// Derived from klibc-0.153 malloc.c: 
//

/*
 * This is the minimum chunk size we will ask the kernel for; this should
 * be a multiple of the page size on all architectures.
 */
#define MALLOC_CHUNK_SIZE	65536
#define MALLOC_CHUNK_MASK (MALLOC_CHUNK_SIZE-1)

/*
 * This structure should be a power of two.  This becomes the
 * alignment unit.
 */
struct free_arena_header;

struct arena_header {
  size_t type;
  size_t size;			/* Also gives the location of the next entry */
  struct free_arena_header *next, *prev;
};

#ifdef DEBUG_MALLOC
#define ARENA_TYPE_USED 0x64e69c70
#define ARENA_TYPE_FREE 0x012d610a
#define ARENA_TYPE_HEAD 0x971676b5
#define ARENA_TYPE_DEAD 0xeeeeeeee
#else
#define ARENA_TYPE_USED 0
#define ARENA_TYPE_FREE 1
#define ARENA_TYPE_HEAD 2
#endif

#define ARENA_SIZE_MASK (~(sizeof(struct arena_header)-1))

/*
 * This structure should be no more than twice the size of the
 * previous structure.
 */
struct free_arena_header {
  struct arena_header a;
  struct free_arena_header *next_free, *prev_free;
};

extern struct free_arena_header __malloc_head;

struct free_arena_header __malloc_head = {
  {
    ARENA_TYPE_HEAD,
    0,
    &__malloc_head,
    &__malloc_head,
  },
  &__malloc_head,
  &__malloc_head
};

static void *__malloc_from_block(struct free_arena_header *fp, size_t size) {
  size_t fsize;
  struct free_arena_header *nfp, *na;

  fsize = fp->a.size;
  
  /* We need the 2* to account for the larger requirements of a free block */
  if ( fsize >= size+2*sizeof(struct arena_header) ) {
    /* Bigger block than required -- split block */
    nfp = (struct free_arena_header *)((char *)fp + size);
    na = fp->a.next;

    nfp->a.type = ARENA_TYPE_FREE;
    nfp->a.size = fsize-size;
    fp->a.type  = ARENA_TYPE_USED;
    fp->a.size  = size;

    /* Insert into all-block chain */
    nfp->a.prev = fp;
    nfp->a.next = na;
    na->a.prev = nfp;
    fp->a.next = nfp;
    
    /* Replace current block on free chain */
    nfp->next_free = fp->next_free;
    nfp->prev_free = fp->prev_free;
    fp->next_free->prev_free = nfp;
    fp->prev_free->next_free = nfp;
  } else {
    /* Allocate the whole block */
    fp->a.type = ARENA_TYPE_USED;

    /* Remove from free chain */
    fp->next_free->prev_free = fp->prev_free;
    fp->prev_free->next_free = fp->next_free;
  }

  //fprintf(stdout, "__malloc_from_block(%p, %d): returning %p: a->size = %d\n", fp, size, (void*)(&fp->a + 1), fp->a.size);
  return (void *)(&fp->a + 1);
}

static struct free_arena_header *
__free_block(struct free_arena_header *ah) {
  struct free_arena_header *pah, *nah;

  pah = ah->a.prev;
  nah = ah->a.next;
  if ( pah->a.type == ARENA_TYPE_FREE &&
       (char *)pah+pah->a.size == (char *)ah ) {
    /* Coalesce into the previous block */
    pah->a.size += ah->a.size;
    pah->a.next = nah;
    nah->a.prev = pah;

#ifdef DEBUG_MALLOC
    ah->a.type = ARENA_TYPE_DEAD;
#endif

    ah = pah;
    pah = ah->a.prev;
  } else {
    /* Need to add this block to the free chain */
    ah->a.type = ARENA_TYPE_FREE;

    ah->next_free = __malloc_head.next_free;
    ah->prev_free = &__malloc_head;
    __malloc_head.next_free = ah;
    ah->next_free->prev_free = ah;
  }

  /* In either of the previous cases, we might be able to merge
     with the subsequent block... */
  if ( nah->a.type == ARENA_TYPE_FREE &&
       (char *)ah+ah->a.size == (char *)nah ) {
    ah->a.size += nah->a.size;

    /* Remove the old block from the chains */
    nah->next_free->prev_free = nah->prev_free;
    nah->prev_free->next_free = nah->next_free;
    ah->a.next = nah->a.next;
    nah->a.next->a.prev = ah;

#ifdef DEBUG_MALLOC
    nah->a.type = ARENA_TYPE_DEAD;
#endif
  }

  /* Return the block that contains the called block */
  return ah;
}

extern "C" void *malloc(size_t size) {
  struct free_arena_header *fp;
  struct free_arena_header *pah;
  size_t fsize;

  if ( size == 0 )
    return NULL;

  /* Add the obligatory arena header, and round up */
  size = (size+2*sizeof(struct arena_header)-1) & ARENA_SIZE_MASK;

  for ( fp = __malloc_head.next_free ; fp->a.type != ARENA_TYPE_HEAD ;
	fp = fp->next_free ) {
    if ( fp->a.size >= size ) {
      /* Found fit -- allocate out of this block */
      return __malloc_from_block(fp, size);
    }
  }

  /* Nothing found... need to request a block from the kernel */
  fsize = (size+MALLOC_CHUNK_MASK) & ~MALLOC_CHUNK_MASK;

  fp = (struct free_arena_header*)ptl_alloc_private_pages(fsize);

  if ( fp == (struct free_arena_header *)MAP_FAILED ) {
    return NULL;		/* Failed to get a block */
  }

  /* Insert the block into the management chains.  We need to set
     up the size and the main block list pointer, the rest of
     the work is logically identical to free(). */
  fp->a.type = ARENA_TYPE_FREE;
  fp->a.size = fsize;

  /* We need to insert this into the main block list in the proper
     place -- this list is required to be sorted.  Since we most likely
     get memory assignments in ascending order, search backwards for
     the proper place. */
  for ( pah = __malloc_head.a.prev ; pah->a.type != ARENA_TYPE_HEAD ;
	pah = pah->a.prev ) {
    if ( pah < fp )
      break;
  }

  /* Now pah points to the node that should be the predecessor of
     the new node */
  fp->a.next = pah->a.next;
  fp->a.prev = pah;
  pah->a.next  = fp;
  fp->a.next->a.prev = fp;


  /* Insert into the free chain and coalesce with adjacent blocks */
  fp = __free_block(fp);

  /* Now we can allocate from this block */
  return __malloc_from_block(fp, size);
}

extern "C" void free(void *ptr)
{
  struct free_arena_header *ah;

  if ( !ptr )
    return;

  ah = (struct free_arena_header *)
    ((struct arena_header *)ptr - 1);

#ifdef DEBUG_MALLOC
  assert( ah->a.type == ARENA_TYPE_USED );
#endif

  __free_block(ah);

  // (memory can be unmapped here if whole page is free)
}

extern "C" void* realloc(void* ptr, size_t size) {
  assert(false); //++MTY FIXME This does not work correctly!
}

void dump_ooo_state();

extern "C" void __assert_fail (__const char *__assertion, __const char *__file, unsigned int __line, __const char *__function) {
  fprintf(stderr, "\nAssert %s failed in %s:%d (%s) at simcycle %lld iters %lld commits %lld\n\n", __assertion, __file, __line, __function, sim_cycle, iterations, total_user_insns_committed);
  fflush(stderr);
  if (logfile) {
    fprintf(logfile, "\nAssert %s failed in %s:%d (%s) at simcycle %lld iters %lld commits %lld\n\n", __assertion, __file, __line, __function, sim_cycle, iterations, total_user_insns_committed);
    if (use_out_of_order_core) {
#ifdef __x86_64__
      dump_ooo_state();
#endif
    }

    logfile.flush();
    logfile.close();
  }
  abort();
}

//
// Shadow page accessibility table format (x86-64 only): 
// Top level:  1048576 bytes: 131072 64-bit pointers to chunks
//
// Leaf level: 65536 bytes per chunk: 524288 bits, one per 4 KB page
// Total: 131072 chunks x 524288 pages per chunk x 4 KB per page = 48 bits virtual address space
// Total: 17 bits       + 19 bits                + 12 bits       = 48 bits virtual address space
//
// In 32-bit version, SPAT is a flat 131072-byte bit vector.
//

byte& AddressSpace::pageid_to_map_byte(spat_t top, Waddr pageid) {
#ifdef __x86_64__
  W64 chunkid = pageid >> log2(SPAT_PAGES_PER_CHUNK);

  if (!top[chunkid]) {
    top[chunkid] = (SPATChunk*)ptl_alloc_private_pages(SPAT_BYTES_PER_CHUNK);
  }
  SPATChunk& chunk = *top[chunkid];
  W64 byteid = bits(pageid, 3, log2(SPAT_BYTES_PER_CHUNK));
  assert(byteid <= SPAT_BYTES_PER_CHUNK);
  return chunk[byteid];
#else
  return top[pageid >> 3];
#endif
}

void AddressSpace::make_accessible(void* p, Waddr size, spat_t top) {
  Waddr address = lowbits((Waddr)p, ADDRESS_SPACE_BITS);
  Waddr firstpage = (Waddr)address >> log2(PAGE_SIZE);
  Waddr lastpage = ((Waddr)address + size - 1) >> log2(PAGE_SIZE);
  assert(ceil((W64)address + size, PAGE_SIZE) <= ADDRESS_SPACE_SIZE);
#if 0
  logfile << "SPT: Making byte range ", (void*)(firstpage << log2(PAGE_SIZE)), " to ", (void*)(lastpage << log2(PAGE_SIZE)), " accessible for ", 
    ((top == readmap) ? "read" : (top == writemap) ? "write" : (top == execmap) ? "exec" : "UNKNOWN"), endl, flush;
#endif
  for (W64 i = firstpage; i <= lastpage; i++) { setbit(pageid_to_map_byte(top, i), lowbits(i, 3)); }
}

void AddressSpace::make_inaccessible(void* p, Waddr size, spat_t top) {
  Waddr address = lowbits((Waddr)p, ADDRESS_SPACE_BITS);
  Waddr firstpage = (Waddr)address >> log2(PAGE_SIZE);
  Waddr lastpage = ((Waddr)address + size - 1) >> log2(PAGE_SIZE);
  assert(ceil((W64)address + size, PAGE_SIZE) <= ADDRESS_SPACE_SIZE);
#if 0
  logfile << "SPT: Making byte range ", (void*)(firstpage << log2(PAGE_SIZE)), " to ", (void*)(lastpage << log2(PAGE_SIZE)), " inaccessible for ", 
    ((top == readmap) ? "read" : (top == writemap) ? "write" : (top == execmap) ? "exec" : "UNKNOWN"), endl, flush;
#endif
  for (Waddr i = firstpage; i <= lastpage; i++) { clearbit(pageid_to_map_byte(top, i), lowbits(i, 3)); }
}

AddressSpace::AddressSpace() { }

AddressSpace::~AddressSpace() { }

void AddressSpace::reset() {
  brkbase = sys_brk(0);
  brk = brkbase;

#ifdef __x86_64__
  if (readmap) ptl_free_private_pages(readmap, SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
  if (writemap) ptl_free_private_pages(writemap, SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
  if (execmap) ptl_free_private_pages(execmap, SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
  if (dtlbmap) ptl_free_private_pages(dtlbmap, SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
  if (itlbmap) ptl_free_private_pages(itlbmap, SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));

  readmap  = (spat_t)ptl_alloc_private_pages(SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
  writemap = (spat_t)ptl_alloc_private_pages(SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
  execmap  = (spat_t)ptl_alloc_private_pages(SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
  dtlbmap  = (spat_t)ptl_alloc_private_pages(SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
  itlbmap  = (spat_t)ptl_alloc_private_pages(SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
#else
  if (readmap) ptl_free_private_pages(readmap, SPAT_BYTES);
  if (writemap) ptl_free_private_pages(writemap, SPAT_BYTES);
  if (execmap) ptl_free_private_pages(execmap, SPAT_BYTES);
  if (dtlbmap) ptl_free_private_pages(dtlbmap, SPAT_BYTES);
  if (itlbmap) ptl_free_private_pages(itlbmap, SPAT_BYTES);

  readmap  = (spat_t)ptl_alloc_private_pages(SPAT_BYTES);
  writemap = (spat_t)ptl_alloc_private_pages(SPAT_BYTES);
  execmap  = (spat_t)ptl_alloc_private_pages(SPAT_BYTES);
  dtlbmap  = (spat_t)ptl_alloc_private_pages(SPAT_BYTES);
  itlbmap  = (spat_t)ptl_alloc_private_pages(SPAT_BYTES);
#endif
}

void AddressSpace::setattr(void* start, Waddr length, int prot) {
  logfile << "setattr: region ", start, " to ", (void*)((char*)start + length), " (", length >> 10, " KB) has user-visible attributes ",
    ((prot & PROT_READ) ? 'r' : '-'), ((prot & PROT_WRITE) ? 'w' : '-'), ((prot & PROT_EXEC) ? 'x' : '-'), endl;

  if (prot & PROT_READ)
    allow_read(start, length);
  else disallow_read(start, length);

  if (prot & PROT_WRITE)
    allow_write(start, length);
  else disallow_write(start, length);

  if (prot & PROT_EXEC)
    allow_exec(start, length);
  else disallow_exec(start, length);
}

int AddressSpace::getattr(void* addr) {
  Waddr address = lowbits((Waddr)addr, ADDRESS_SPACE_BITS);

  Waddr page = pageid(address);

  int prot = 
    (bit(pageid_to_map_byte(readmap, page), lowbits(page, 3)) ? PROT_READ : 0) |
    (bit(pageid_to_map_byte(writemap, page), lowbits(page, 3)) ? PROT_WRITE : 0) |
    (bit(pageid_to_map_byte(execmap, page), lowbits(page, 3)) ? PROT_EXEC : 0);

  return prot;
}
 
int AddressSpace::mprotect(void* start, Waddr length, int prot) {
  length = ceil(length, PAGE_SIZE);
  int rc = ::mprotect(start, length, prot);
  if (rc) return rc;
  setattr(start, length, prot);
  return 0;
}

int AddressSpace::munmap(void* start, Waddr length) {
  length = ceil(length, PAGE_SIZE);
  int rc = ::munmap(start, length);
  sys_errno = errno;
  if (rc) return rc;
  setattr(start, length, PROT_NONE);
  return 0;
}

void* AddressSpace::mmap(void* start, Waddr length, int prot, int flags, int fd, off_t offset) {
  // Guarantee enough room will be available post-alignment:
  length = ceil(length, PAGE_SIZE);
  start = ::mmap(start, length, prot, flags, fd, offset);
  if (mmap_invalid(start)) return start;
  setattr(start, length, prot);
  return start;
}

void* AddressSpace::mremap(void* start, Waddr oldlength, Waddr newlength, int flags) {
  int oldattr = getattr(start);

  void* p = ::mremap(start, oldlength, newlength, flags);
  if (mmap_invalid(p)) return p;

  setattr(start, oldlength, 0);
  setattr(p, newlength, oldattr);
  return p;
}

void* AddressSpace::setbrk(void* reqbrk) {
  Waddr oldsize = ceil(((Waddr)brk - (Waddr)brkbase), PAGE_SIZE);

  if (!reqbrk) {
    assert(brk == sys_brk(0));
    logfile << "setbrk(0): returning current brk ", brk, endl;
    return brk;
  }

  logfile << "setbrk(", reqbrk, "): old range ", brkbase, "-", brk, " (", oldsize, " bytes); new range ", brkbase, "-", reqbrk, " (delta ", ((Waddr)reqbrk - (Waddr)brk), ", size ", ((Waddr)reqbrk - (Waddr)brkbase), ")", endl;

  setattr(brkbase, oldsize, PROT_NONE);
  void* newbrk = sys_brk(reqbrk);
  Waddr newsize = (Waddr)newbrk - (Waddr)brkbase;
  brk = newbrk;
  logfile << "setbrk(", reqbrk, "): new range ", brkbase, "-", newbrk, " (size ", newsize, ")", endl, flush;

  setattr(brkbase, newsize, PROT_READ|PROT_WRITE|PROT_EXEC);
  return newbrk;
}

Waddr stack_min_addr;
Waddr stack_max_addr;

//
// These are in PTL space accessed directly by uops:
//
W64 csbase;
W64 dsbase;
W64 esbase;
W64 ssbase;
W64 fsbase;
W64 gsbase;

W16 csreg;
W16 dsreg;
W16 esreg;
W16 ssreg;
W16 fsreg;
W16 gsreg;

/*
 * Memory map query support
 *
 * The prot field supports the same PROT_READ, PROT_WRITE, PROT_EXEC bits
 * used in the mmap() system call.
 *
 * The flags field may have the following standard mmap()-style bits set:
 *
 * MAP_SHARED       Shared (writes to map update the file)
 * MAP_PRIVATE      Private copy on write
 * MAP_ANONYMOUS    Anonymous (no file) mapping
 * MAP_GROWSDOWN    Stack
 *
 * Additionally, these additional bits may be present:
 *
 * MAP_ZERO         Inheritable shared memory on /dev/zero
 * MAP_HEAP         Heap terminated by brk
 * MAP_VDOS         VDSO (vsyscall) gateway page
 * MAP_KERNEL       special mapping reserved by kernel
 *
 */

#define MAP_STACK   MAP_GROWSDOWN
#define MAP_ZERO    0x01000000
#define MAP_HEAP    0x02000000
#define MAP_VDSO    0x04000000

struct MemoryMapExtent {
  void* start;
  unsigned long length;
  unsigned int prot;
  unsigned int flags;
  unsigned long long offset;
  unsigned long long inode;
  unsigned short devmajor;
  unsigned short devminor;
};

int mqueryall(MemoryMapExtent* startmap, size_t count);

ostream& operator <<(ostream& os, const MemoryMapExtent& map);

int mqueryall(MemoryMapExtent* startmap, size_t count) {
  MemoryMapExtent* map = startmap;

  // Atomically capture process memory: otherwise we may allocate our own memory while reading /proc/self/maps 
#define MAX_PROC_MAPS_SIZE 16*1024*1024

  char* mapdata = (char*)ptl_alloc_private_pages(MAX_PROC_MAPS_SIZE);
  int mapsize = 0;

  int fd = open("/proc/self/maps", O_RDONLY);
  assert(fd >= 0);

  for (;;) {
    int rc = read(fd, mapdata + mapsize, MAX_PROC_MAPS_SIZE-PAGE_SIZE);
    if (rc <= 0) break;
    mapsize += rc;
    assert(inrange(mapsize, 0, (int)(MAX_PROC_MAPS_SIZE-PAGE_SIZE)));
  }
  mapdata[mapsize] = 0;

  // Now process the saved maps
  char* p = mapdata;

  byte* stackbase = null;

  // Count lines
  int linecount = 0;

  while (p && (*p)) {
    p = strchr(p, '\n');
    if (p) { linecount++; p++; }
  }

  p = mapdata;

  int line = 0;

  while (p && (*p)) {
    if (map == &startmap[count]) break;

    char* s = p;
    p = strchr(p, '\n');
    if (p) *p++ = 0; // skip over newline

    byte* start = null;
    byte* stop = null;
    char rperm, wperm, xperm, private_or_shared;
    byte* offset = null;
    int devmajor;
    int devminor;
    unsigned long inode;

    int n = sscanf(s, "%p-%p %c%c%c%c %p %x:%x %ld", &start, &stop, &rperm, &wperm, &xperm, &private_or_shared, &offset, &devmajor, &devminor, &inode);
    if (n != 10) {
      cout << "Warning: /proc/self/maps not in proper format", endl, flush;
      assert(false);
      break;
    }

    char* pattr = strrchr(s, '[');
    char* pfilename = strrchr(s, '/');
    //
    // vdso is the kernel syscall gateway page and contains things
    // like the gettimeofday and getpid vsyscalls, various TLS fields
    // and so on. It is not really a user page, it just happens to
    // be accessible to accelerate common syscalls. Unfortunately
    // some kernels incorrectly report the size of this region,
    // but it is always 4 KB long.
    //

    map->start = start;
    map->length = stop - start;

    bool vdso = ((pattr && strequal(pattr, "[vdso]")) || 
        ((map->start == (byte*)0xffffe000) &&
         (map->length == PAGE_SIZE)));

    // 2.6 kernels always have the stack second-to-last and vdso last in the list:
    bool stack = (((pattr && strequal(pattr, "[stack]")) || 
                   (line == (linecount-2))) ? MAP_STACK : 0);

    map->prot = 
      ((rperm == 'r') ? PROT_READ : 0) |
      ((wperm == 'w') ? PROT_WRITE : 0) |
      ((xperm == 'x') ? PROT_EXEC : 0);
    map->flags =
      ((private_or_shared == 'p') ? MAP_PRIVATE : 0) |
      ((private_or_shared == 's') ? MAP_SHARED : 0) |
      ((!devmajor && !devminor && !inode) ? MAP_ANONYMOUS : 0) |
      (stack ? MAP_STACK : 0) |
      ((pattr && strequal(pattr, "[heap]")) ? MAP_HEAP : 0) |
      ((pfilename && strequal(pfilename, "/zero (deleted)")) ? MAP_ZERO : 0) |
      (vdso ? MAP_VDSO : 0);

    if (vdso) map->length = PAGE_SIZE;

    map->devmajor = devmajor;
    map->devminor = devminor;
    map->offset = (Waddr)offset;
    map->inode = inode;

    // In some kernel versions (at least 2.6.11 and below), the VDSO page is given
    // in /proc/xxx/maps with no permissions (bug?), so we correct that here:
    if (map->flags & MAP_VDSO) map->prot |= PROT_READ|PROT_EXEC;

    map++;
    line++;
  }

  ptl_free_private_pages(mapdata, MAX_PROC_MAPS_SIZE);
  close(fd);
  return map - startmap;
}

ostream& operator <<(ostream& os, const MemoryMapExtent& map) {
  os << ((map.flags & MAP_ANONYMOUS) ? 'a' : '-');
  os << ((map.prot & PROT_READ) ? 'r' : '-');
  os << ((map.prot & PROT_WRITE) ? 'w' : '-');
  os << ((map.prot & PROT_EXEC) ? 'x' : '-');
  os << ((map.flags & MAP_PRIVATE) ? 'p' : 
         (map.flags & MAP_SHARED) ? 's' : '-');
  os << ((map.flags & MAP_STACK) ? 'S' : 
         (map.flags & MAP_HEAP) ? 'h' :
         (map.flags & MAP_VDSO) ? 'v' : 
         (map.flags & MAP_ZERO) ? 'z' : '-');
  os << " ";
  stringbuf sb;
  sb << (void*)map.start;
  os << "  ", padstring(sb, 18), " ", intstring(map.length >> 10, 16), " KB ";
  if (!(map.flags & MAP_ANONYMOUS)) {
    sb.reset();
    sb << "0x", hexstring(map.offset, 64);
    os << padstring((map.offset) ? (char*)sb : "0", 10), " in ", map.devmajor, ".", map.devminor, ".", map.inode;
  }
  return os;
}

#define MAX_MAPS_PER_PROCESS 65536

void AddressSpace::resync_with_process_maps() {
  bool DEBUG = 1;

  asp.reset();

  MemoryMapExtent* mapstart = (MemoryMapExtent*)ptl_alloc_private_pages(MAX_MAPS_PER_PROCESS * sizeof(MemoryMapExtent));
  int n = mqueryall(mapstart, MAX_MAPS_PER_PROCESS);
  Waddr stackbase = 0;

  ThreadState* tls = getcurrent();

  MemoryMapExtent* map = mapstart;

  logfile << "resync_with_process_maps: found ", n, " memory map extents:", endl;
  foreach (i, n) {
    logfile << "  ", mapstart[i], endl;
  }
  logfile << flush;

  foreach (i, n) {
    if (map->flags & MAP_STACK) stackbase = (Waddr)map->start;
    setattr(map->start, map->length, (map->flags & MAP_ZERO) ? 0 : map->prot);
    map++;
  }

  ptl_free_private_pages(mapstart, MAX_MAPS_PER_PROCESS * sizeof(MemoryMapExtent));

  // Find current brk value kernel thinks we are using:
  brk = sys_brk(null);
  if (DEBUG) logfile << "resync_with_process_maps: brk from ", (void*)brkbase, " to ", (void*)brk, endl;

  fsbase = get_fs_base();
  gsbase = get_gs_base();

  if (DEBUG) logfile << "resync_with_process_maps: fsbase ", (void*)(Waddr)fsbase, ", gsbase ", (void*)(Waddr)gsbase, endl;

  Waddr stackleft = stackbase - stack_min_addr;

  if (DEBUG) logfile << "  Original user stack range: ", (void*)stack_min_addr, " to ", (void*)stack_max_addr, " (", (stack_max_addr - stack_min_addr), " bytes)", endl, flush;

  if (DEBUG) logfile << "  Stack from ", (void*)stack_min_addr, " to ", (void*)stackbase, " (", stackleft, " bytes) is allocate-on-access", endl, flush;

  //
  // Make sure the user code does not see and cannot access PTL native code.
  // When running x86-64 apps, all PTL native code resides (for now) at 
  // 0x70000000 - 0x78000000. This region is marked as do-not-touch.
  //
  // In arch/x86_64/kernel/sys_x86_64.c: find_start_end() and arch_get_unmapped_area():
  // If MAP_32BIT is specified, pages are only allocated
  // in the 1GB range 0x70000000 to 0x78000000.
  //
  // All 64-bit mmap allocations start at 0x2AAAAAAAA000; i.e., floor(0x800000000000 / 3, PAGE_SIZE)
  //
  // Hence, using this simplistic approach works fine on 2.6.x kernels.
  //
  setattr((void*)PTL_PAGE_POOL_BASE, PTL_PAGE_POOL_SIZE, PROT_NONE);
}

AddressSpace asp;

W64 ldt_seg_base_cache[LDT_SIZE];

void flush_cpu_caches() {
  char flushdata[] = "1\n";
  // wbinvd is privileged so we need to go through the PTLsim kernel module:
  int fd = open("/proc/ptlsim/flushcache", O_WRONLY);
  if (fd < 0) return;
  assert(write(fd, flushdata, sizeof(flushdata)) == sizeof(flushdata));
  close(fd);
}

//
// NOTE: Linux puts a cap on the amount of non-reserved private memory we can allocate per process. 
// See Documentation/vm/overcommit-accounting for details on how to control the commit charges.
//

// Saved and restored by asm code:
X87State x87state;

W64 x87_fp_80bit_to_64bit(const X87Reg& x87reg) {
  W64 reg64;
  asm("fldt %[mem80]\n"
      "fstpl %[mem64]\n"
      : [mem64] "=m" (reg64) 
      : [mem80] "m" (x87reg));
  return reg64;
}

void x87_fp_64bit_to_80bit(X87Reg& x87reg, W64 reg64) {
  asm("fldl %[mem64]\n"
      "fstpt %[mem80]\n"
      : [mem80] "=m" (x87reg) 
      : [mem64] "m" (reg64));
}

void cpu_fsave(X87State& state) {
  asm volatile("fsave %[state]" : [state] "=m" (*&state));
}

void cpu_frstor(X87State& state) {
  asm volatile("frstor %[state]" : : [state] "m" (*&state));
}

void fpu_state_to_ptlsim_state() {
  ctx.commitarf[REG_fptos] = x87state.sw.fields.tos * 8;
  ctx.commitarf[REG_fpsw] = x87state.sw.data;
  ctx.commitarf[REG_fpcw] = x87state.cw.data;

  ctx.commitarf[REG_fptags] = 0;
  foreach (i, 8) {
    int type = bits(x87state.tw, i*2, 2);
    ctx.commitarf[REG_fptags] |= ((W64)(type != 3)) << i*8;
  }

  // x86 FSAVE state is in order of stack rather than physical registers:
  foreach (i, 8) {
    fpregs[lowbits(x87state.sw.fields.tos + i, 3)] = x87_fp_80bit_to_64bit(x87state.stack[i]);
  }
}

void ptlsim_state_to_fpu_state() {
  // x87state.cw already filled and assumed not to be modified
  // clear everything but 4 FP status flag bits (c3/c2/c1/c0):
  x87state.sw.data = ctx.commitarf[REG_fpsw] & ((0x7 << 8) | (1 << 14));
  int tos = ctx.commitarf[REG_fptos] >> 3;
  assert(inrange(tos, 0, 7));
  x87state.sw.fields.tos = tos;
  x87state.tw = 0;

  // Prepare tag word
  foreach (i, 8) {
    x87state.tw |= (bit(ctx.commitarf[REG_fptags], i*8) ? 0 : 3) << (i*2);
  }

  // Prepare actual registers
  foreach (i, 8) {
    x87_fp_64bit_to_80bit(x87state.stack[i], fpregs[lowbits(tos + i, 3)]);
  }

  ctx.commitarf[REG_fpsw] = x87state.sw.data;
  ctx.commitarf[REG_fptags] = x87state.tw;
}

#define ARCH_ENABLE_EXIT_HOOK 0x2001
#define ARCH_SET_EXIT_HOOK_ADDR 0x2002

extern "C" void switch_to_sim_save_context();

// This can be brought down considerably in the future: 
#define SIM_THREAD_STACK_SIZE (1024*1024*4)

extern "C" void switch_to_sim_save_context();

#ifdef __x86_64__
struct FarJumpDescriptor {
  W32 offset;
  W16 seg;

  FarJumpDescriptor() { }

  FarJumpDescriptor(void* target) {
    offset = LO32((W64)target);
    seg = 0x33;
  }
};

FarJumpDescriptor switch_to_native_desc;

void switch_stack_and_jump_32_or_64(void* code, void* stack, bool use64) {
  if (use64) {
    // Currently in 64-bit mode anyway, so no need to go through a far jump; in fact
    // this is impossible because far jumps only encode 32 bits of target address.
    asm volatile("mov %[stack],%%rsp\n"
                 "jmp *%[code]\n" : : [code] "r" (code), [stack] "m" (stack));
  } else {
    // 64-bit PTLsim to 32-bit x86 jump:
    
    switch_to_native_desc.offset = (W64)code;
    switch_to_native_desc.seg = 0x23;

    asm volatile("mov %[stack],%%rsp\n"
                 "ljmp *(%[desc])\n" : : [desc] "r" (&switch_to_native_desc), [stack] "m" (stack));
  }
}

extern "C" void save_context_switch_to_sim_lowlevel();
FarJumpDescriptor switch_to_sim_save_context_indirect((void*)&save_context_switch_to_sim_lowlevel);

struct SwitchToSimThunkCode {
  byte opcode[3];
  W32 indirtarget;

  SwitchToSimThunkCode() { }

  void farjump(FarJumpDescriptor& target) {
    if (ctx.use64) {
      // ff 2c 25 xx xx xx xx = ljmp ds:[imm32]
      opcode[0] = 0xff;
      opcode[1] = 0x2c;
      opcode[2] = 0x25;
    } else {
      // 90 ff 2d xx xx xx xx = nop | ljmp ds:[imm32]
      opcode[0] = 0x90;
      opcode[1] = 0xff;
      opcode[2] = 0x2d;
    }
    indirtarget = LO32((W64)&target);
  }

  void indircall(W64& ptr) {
    if (ctx.use64) {
      // ff 14 25 xx xx xx xx = call ds:[imm32]
      opcode[0] = 0xff; opcode[1] = 0x14; opcode[2] = 0x25;
    } else {
      // 90 ff 15 xx xx xx xx = nop | call ds:[imm32]
      opcode[0] = 0x90; opcode[1] = 0xff; opcode[2] = 0x15;
    }
    indirtarget = LO32((W64)&ptr);
  }

  void indirjump(W64& ptr) {
    if (ctx.use64) {
      // ff 24 25 xx xx xx xx = jmp ds:[imm32]
      opcode[0] = 0xff; opcode[1] = 0x24; opcode[2] = 0x25;
    } else {
      // 90 ff 25 xx xx xx xx = nop | jmp ds:[imm32]
      opcode[0] = 0x90; opcode[1] = 0xff; opcode[2] = 0x25;
    }
    indirtarget = LO32((W64)&ptr);
  }
} __attribute__((packed));

extern "C" void inside_sim_escape_code_template_32bit();
extern "C" void inside_sim_escape_code_template_32bit_end();
extern "C" void inside_sim_escape_code_template_64bit();
extern "C" void inside_sim_escape_code_template_64bit_end();

struct InsideSimEscapeCode { 
  byte bytes[64];

  void prep() {
    byte* src;
    int length;
    if (ctx.use64) {
      src = (byte*)&inside_sim_escape_code_template_64bit;
      length = ((byte*)&inside_sim_escape_code_template_64bit_end) - src;
    } else {
      src = (byte*)&inside_sim_escape_code_template_32bit;
      length = ((byte*)&inside_sim_escape_code_template_32bit_end) - src;
    }
    assert(length <= lengthof(bytes));
    memcpy(&bytes, src, length);
  }
};
#else // ! __x86_64__

extern "C" void save_context_switch_to_sim_lowlevel();
W64 switch_to_sim_save_context_indirect;

struct SwitchToSimThunkCode {
  byte opcode[3];
  W32 indirtarget;

  SwitchToSimThunkCode() { }

  void indirjump(W64& ptr) {
    // 90 ff 25 xx xx xx xx = nop | jmp ds:[imm32]
    opcode[0] = 0x90; opcode[1] = 0xff; opcode[2] = 0x25;
    indirtarget = LO32((W32)&ptr);
  }
} __attribute__((packed));

extern "C" void inside_sim_escape_code_template_32bit();
extern "C" void inside_sim_escape_code_template_32bit_end();

struct InsideSimEscapeCode { 
  byte bytes[64];

  void prep() {
    byte* src;
    int length;
    src = (byte*)&inside_sim_escape_code_template_32bit;
    length = ((byte*)&inside_sim_escape_code_template_32bit_end) - src;
    assert(length <= lengthof(bytes));
    memcpy(&bytes, src, length);
  }
};

#endif // ! __x86_64__

struct PTLsimThunkPagePrivate: public PTLsimThunkPage {
  SwitchToSimThunkCode switch_to_sim_thunk;
  InsideSimEscapeCode call_within_sim_thunk;
};

void enable_ptlsim_call_gate() {
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;
  thunkpage->magic = PTLSIM_THUNK_MAGIC;
}

void disable_ptlsim_call_gate() {
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;
  thunkpage->magic = 0;
}

void setup_sim_thunk_page() {
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;

  // Map in the PTL call gate page. This is NOT a PTL private page, so make sure the user can access it too:
  Waddr v = (Waddr)asp.mmap(thunkpage, 4*PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  assert(v == PTLSIM_THUNK_PAGE);

  thunkpage->simulated = 0;
  thunkpage->call_code_addr = 0; // (initialized later)
#ifdef __x86_64__
  thunkpage->switch_to_sim_thunk.farjump(switch_to_sim_save_context_indirect);
#else // ! __x86_64__
  switch_to_sim_save_context_indirect = (Waddr)&save_context_switch_to_sim_lowlevel;
  thunkpage->switch_to_sim_thunk.indirjump(switch_to_sim_save_context_indirect);
#endif
  thunkpage->call_within_sim_thunk.prep();
  enable_ptlsim_call_gate();
}

SwitchToSimThunkCode saved_bytes_behind_switch_to_sim_thunk;
SwitchToSimThunkCode* pending_patched_switch_to_sim_addr = null;

void set_switch_to_sim_breakpoint(void* addr) {
  SwitchToSimThunkCode* thunk = (SwitchToSimThunkCode*)addr;
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;

  mprotect(floorptr(addr, PAGE_SIZE), 2*PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
  saved_bytes_behind_switch_to_sim_thunk = *thunk;
  thunk->indirjump(thunkpage->call_code_addr);
  pending_patched_switch_to_sim_addr = thunk;

  logfile << endl, "Breakpoint inserted at rip ", addr, endl, flush;
}

extern void switch_to_sim();

extern "C" void switch_to_native_restore_context_lowlevel(const UserContext& ctx, int switch_64_to_32);

void switch_to_native_restore_context() {
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;

  thunkpage->call_code_addr = (Waddr)&thunkpage->switch_to_sim_thunk;
  thunkpage->simulated = 0;
  ptlsim_state_to_fpu_state();

  logfile << endl, "=== Preparing to switch to native mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " ===", endl, endl, flush;

  logfile << "Final state:", endl;
  logfile << ctx.commitarf;

  logfile << endl, "=== Switching to native mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " ===", endl, endl, flush;

  switch_to_native_restore_context_lowlevel(ctx.commitarf, !ctx.use64);
}

// Called by save_context_switch_to_sim_lowlevel
extern "C" void save_context_switch_to_sim() {
  if (pending_patched_switch_to_sim_addr) {
    ctx.commitarf[REG_rip] = (Waddr)pending_patched_switch_to_sim_addr;
    logfile << endl, "=== Removed thunk patch at rip ", pending_patched_switch_to_sim_addr, " ===", endl, flush;
    *pending_patched_switch_to_sim_addr = saved_bytes_behind_switch_to_sim_thunk;
    pending_patched_switch_to_sim_addr = 0;
  } else {
    logfile << endl, "=== Trigger request ===", endl, flush;
    // REG_rip set from first word on stack, but REG_rsp needs to be incremented
    ctx.commitarf[REG_rsp] += (ctx.use64) ? 8 : 4;
  }

#ifdef __x86_64__
  if (!ctx.use64) ctx.commitarf[REG_rip] &= 0xffffffff;
#endif

  logfile << endl, "=== Switching to simulation mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " ===", endl, endl, flush;

  ctx.commitarf[REG_flags] &= ~(FLAG_INV|FLAG_WAIT);
  fpu_state_to_ptlsim_state();
  asp.resync_with_process_maps();

  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;
  thunkpage->call_code_addr = (Waddr)&thunkpage->call_within_sim_thunk;
  thunkpage->simulated = 1;

  if (user_profile_only) {
    logfile << endl, "=== Trigger reached during profile mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], ": starting counters ===", endl, endl, flush;
    flush_cpu_caches();
    start_perfctrs();
    switch_to_native_restore_context();
  }

  //
  // Revoke user signal handlers: we don't want them messing with PTLsim
  // since it makes debugging significantly more difficult
  // 
  assert(signal(SIGTRAP, SIG_DFL) != SIG_ERR);

  switch_to_sim();
}

#ifdef __x86_64__

const char* syscall_names_64bit[] = {
  "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid"};

//
// SYSCALL instruction from x86-64 mode
//

void handle_syscall_64bit() {
  bool DEBUG = 1; //analyze_in_detail();
  //
  // Handle an x86-64 syscall:
  // (This is called from the assist_syscall ucode assist)
  //

  int syscallid = ctx.commitarf[REG_rax];
  W64 arg1 = ctx.commitarf[REG_rdi];
  W64 arg2 = ctx.commitarf[REG_rsi];
  W64 arg3 = ctx.commitarf[REG_rdx];
  W64 arg4 = ctx.commitarf[REG_r10];
  W64 arg5 = ctx.commitarf[REG_r8];
  W64 arg6 = ctx.commitarf[REG_r9];

  if (DEBUG) 
    logfile << "handle_syscall (#", syscallid, " ", ((syscallid < lengthof(syscall_names_64bit)) ? syscall_names_64bit[syscallid] : "???"), 
      ") from ", (void*)ctx.commitarf[REG_rcx], " args ", " (", (void*)arg1, ", ", (void*)arg2, ", ", (void*)arg3, ", ", (void*)arg4, ", ",
      (void*)arg5, ", ", (void*)arg6, ") at iteration ", iterations, endl, flush;

  switch (syscallid) {
  case __NR_mmap:
    ctx.commitarf[REG_rax] = (W64)asp.mmap((void*)arg1, arg2, arg3, arg4, arg5, arg6);
    break;
  case __NR_munmap:
    ctx.commitarf[REG_rax] = asp.munmap((void*)arg1, arg2);
    break;
  case __NR_mprotect:
    ctx.commitarf[REG_rax] = asp.mprotect((void*)arg1, arg2, arg3);
    break;
  case __NR_brk:
    ctx.commitarf[REG_rax] = (W64)asp.setbrk((void*)arg1);
    break;
  case __NR_mremap: {
    ctx.commitarf[REG_rax] = (W64)asp.mremap((void*)arg1, arg2, arg3, arg4);
    break;
  }
  case __NR_arch_prctl: {
    // We need to trap this so we can virtualize ARCH_SET_FS and ARCH_SET_GS:
    ctx.commitarf[REG_rax] = arch_prctl(arg1, (void*)arg2);
    switch (arg1) {
    case ARCH_SET_FS:
      logfile << "arch_prctl: set FS base to ", (void*)arg2, endl;
      fsbase = arg2; break;
    case ARCH_SET_GS:
      logfile << "arch_prctl: set GS base to ", (void*)arg2, endl;
      gsbase = arg2; break;
    }
    break;
  }
  case __NR_exit: {
    logfile << "handle_syscall at iteration ", iterations, ": exit(): exiting with arg ", (W64s)arg1, "...", endl, flush;
    user_process_terminated((int)arg1);
  }
  case __NR_exit_group: {
    logfile << "handle_syscall at iteration ", iterations, ": exit_group(): exiting with arg ", (W64s)arg1, "...", endl, flush;
    user_process_terminated((int)arg1);
  }
  case __NR_rt_sigaction: {
    // This is only so we receive SIGSEGV on our own:
#if 1
    logfile << "handle_syscall: signal(", arg1, ", ", (void*)arg2, ")", endl, flush;
    ctx.commitarf[REG_rax] = 0;
#else
    ctx.commitarf[REG_rax] = do_syscall_64bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
#endif
    break;
  }
  default:
    ctx.commitarf[REG_rax] = do_syscall_64bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
    break;
  }
  //ctx.commitarf[REG_rax] = -EINVAL;
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_rcx];

  if (DEBUG) logfile << "handle_syscall: result ", ctx.commitarf[REG_rax], " (", (void*)ctx.commitarf[REG_rax], "); returning to ", (void*)ctx.commitarf[REG_rip], endl, flush;
}

#endif // __x86_64__

struct old_mmap32_arg_struct {
	W32 addr;
	W32 len;
	W32 prot;
	W32 flags;
	W32 fd;
	W32 offset;
};

const char* syscall_names_32bit[] = {"restart_syscall", "exit", "fork", "read", "write", "open", "close", "waitpid", "creat", "link", "unlink", "execve", "chdir", "time", "mknod", "chmod", "lchown", "break", "oldstat", "lseek", "getpid", "mount", "umount", "setuid", "getuid", "stime", "ptrace", "alarm", "oldfstat", "pause", "utime", "stty", "gtty", "access", "nice", "ftime", "sync", "kill", "rename", "mkdir", "rmdir", "dup", "pipe", "times", "prof", "brk", "setgid", "getgid", "signal", "geteuid", "getegid", "acct", "umount2", "lock", "ioctl", "fcntl", "mpx", "setpgid", "ulimit", "oldolduname", "umask", "chroot", "ustat", "dup2", "getppid", "getpgrp", "setsid", "sigaction", "sgetmask", "ssetmask", "setreuid", "setregid", "sigsuspend", "sigpending", "sethostname", "setrlimit", "getrlimit", "getrusage", "gettimeofday", "settimeofday", "getgroups", "setgroups", "select", "symlink", "oldlstat", "readlink", "uselib", "swapon", "reboot", "readdir", "mmap", "munmap", "truncate", "ftruncate", "fchmod", "fchown", "getpriority", "setpriority", "profil", "statfs", "fstatfs", "ioperm", "socketcall", "syslog", "setitimer", "getitimer", "stat", "lstat", "fstat", "olduname", "iopl", "vhangup", "idle", "vm86old", "wait4", "swapoff", "sysinfo", "ipc", "fsync", "sigreturn", "clone", "setdomainname", "uname", "modify_ldt", "adjtimex", "mprotect", "sigprocmask", "create_module", "init_module", "delete_module", "get_kernel_syms", "quotactl", "getpgid", "fchdir", "bdflush", "sysfs", "personality", "afs_syscall", "setfsuid", "setfsgid", "_llseek", "getdents", "_newselect", "flock", "msync", "readv", "writev", "getsid", "fdatasync", "_sysctl", "mlock", "munlock", "mlockall", "munlockall", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_yield", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "nanosleep", "mremap", "setresuid", "getresuid", "vm86", "query_module", "poll", "nfsservctl", "setresgid", "getresgid", "prctl", "rt_sigreturn", "rt_sigaction", "rt_sigprocmask", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "pread64", "pwrite64", "chown", "getcwd", "capget", "capset", "sigaltstack", "sendfile", "getpmsg", "putpmsg", "vfork", "ugetrlimit", "mmap2", "truncate64", "ftruncate64", "stat64", "lstat64", "fstat64", "lchown32", "getuid32", "getgid32", "geteuid32", "getegid32", "setreuid32", "setregid32", "getgroups32", "setgroups32", "fchown32", "setresuid32", "getresuid32", "setresgid32", "getresgid32", "chown32", "setuid32", "setgid32", "setfsuid32", "setfsgid32", "pivot_root", "mincore", "madvise", "madvise1", "getdents64", "fcntl64", "<unused>", "<unused>", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "sendfile64", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "get_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "fadvise64", "<unused>", "exit_group", "lookup_dcookie", "epoll_create", "epoll_ctl", "epoll_wait", "remap_file_pages", "set_tid_address", "timer_create", "statfs64", "fstatfs64", "tgkill", "utimes", "fadvise64_64", "vserver", "mbind", "get_mempolicy", "set_mempolicy", "mq_open", "sys_kexec_load", "waitid"};

W32 sysenter_retaddr = 0;

W32 get_sysenter_retaddr(W32 end_of_sysenter_insn) {
  if (!sysenter_retaddr) {
    byte* p = (byte*)(Waddr)end_of_sysenter_insn;
    logfile << "First sysenter call: finding return point starting from ", p, endl, flush;
    while (*p == 0x90) p++;
    assert(*p == 0xeb); // short jump
    p += 2;
    assert(*p == 0x5d); // "pop %ebp" instruction
    logfile << "Found sysenter return address at ", p, endl, flush;
    sysenter_retaddr = (W32)(Waddr)p;
  }
  return sysenter_retaddr;
}

void handle_syscall_32bit(int semantics) {
  bool DEBUG = 1; //analyze_in_detail();
  //
  // Handle a 32-bit syscall:
  // (This is called from the assist_syscall ucode assist)
  //

  static const char* semantics_name[] = {"int80", "syscall", "sysenter"};

  int syscallid;
  W32 arg1, arg2, arg3, arg4, arg5, arg6;
  W32 retaddr;

  if (semantics == SYSCALL_SEMANTICS_INT80) {
    //
    // int 0x80 can be called from either 32-bit or 64-bit mode,
    // but in 64-bit mode, its semantics exactly match the 32-bit
    // semantics, i.e. x86 syscall IDs, truncates addresses to 32
    // bits, etc.
    //
    syscallid = ctx.commitarf[REG_rax];
    arg1 = ctx.commitarf[REG_rbx];
    arg2 = ctx.commitarf[REG_rcx];
    arg3 = ctx.commitarf[REG_rdx];
    arg4 = ctx.commitarf[REG_rsi];
    arg5 = ctx.commitarf[REG_rdi];
    arg6 = ctx.commitarf[REG_rbp];
    retaddr = ctx.commitarf[REG_sr1];
  } else if (semantics == SYSCALL_SEMANTICS_SYSENTER) {
    //
    // SYSENTER is just like int 0x80, but it only works in 32-bit
    // mode. Its semantics are identical to int 0x80, except that
    // %ebp contains the stack pointer to restore, and *(%ebp)
    // is the sixth argument. It always returns to a fixed address
    // in the VDSO page, so there's no need to store the address.
    // We do need to dynamically find that address though.
    //
    retaddr = get_sysenter_retaddr(ctx.commitarf[REG_sr1]);

    assert(!ctx.use64);
    syscallid = ctx.commitarf[REG_rax];
    arg1 = ctx.commitarf[REG_rbx];
    arg2 = ctx.commitarf[REG_rcx];
    arg3 = ctx.commitarf[REG_rdx];
    arg4 = ctx.commitarf[REG_rsi];
    arg5 = ctx.commitarf[REG_rdi];

    W32* arg6ptr = (W32*)(Waddr)LO32(ctx.commitarf[REG_rbp]);

    if (!asp.check(arg6ptr, PROT_READ)) {
      ctx.commitarf[REG_rax] = (W64)(-EFAULT);
      ctx.commitarf[REG_rip] = retaddr;
      if (DEBUG) logfile << "handle_syscall (#", syscallid, " ", ((syscallid < lengthof(syscall_names_32bit)) ? syscall_names_32bit[syscallid] : "???"), 
                   " via ", semantics_name[semantics], ") from ", (void*)(Waddr)retaddr, " args ", " (", (void*)(Waddr)arg1, ", ", (void*)(Waddr)arg2, ", ", 
                   (void*)(Waddr)arg3, ", ", (void*)(Waddr)arg4, ", ", (void*)(Waddr)arg5, ", ???", ") at iteration ", iterations, ": arg6 @ ", arg6ptr,
                   " inaccessible via SYSENTER; returning -EFAULT", endl, flush;
    }

    arg6 = *arg6ptr;

  } else if (semantics == SYSCALL_SEMANTICS_SYSCALL) {
    assert(!ctx.use64);
    //
    // SYSCALL can also be used from 32-bit mode when the vsyscall
    // kernel page is used. The semantics are then as follows:
    //
    // Arguments:
    // %eax	System call number.
    // %ebx Arg1
    // %ecx return EIP 
    // %edx Arg3
    // %esi Arg4
    // %edi Arg5
    // %ebp Arg2    [note: not saved in the stack frame, should not be touched]
    // %esp user stack 
    // 0(%esp) Arg6
    //
    syscallid = LO32(ctx.commitarf[REG_rax]);
    arg1 = LO32(ctx.commitarf[REG_rbx]);
    arg2 = LO32(ctx.commitarf[REG_rbp]);
    arg3 = LO32(ctx.commitarf[REG_rdx]);
    arg4 = LO32(ctx.commitarf[REG_rsi]);
    arg5 = LO32(ctx.commitarf[REG_rdi]);
    retaddr = ctx.commitarf[REG_rcx];

    W32* arg6ptr = (W32*)(Waddr)LO32(ctx.commitarf[REG_rsp]);

    if (!asp.check(arg6ptr, PROT_READ)) {
      ctx.commitarf[REG_rax] = (W64)(-EFAULT);
      ctx.commitarf[REG_rip] = retaddr;
      if (DEBUG) logfile << "handle_syscall (#", syscallid, " ", ((syscallid < lengthof(syscall_names_32bit)) ? syscall_names_32bit[syscallid] : "???"), 
                   " via ", semantics_name[semantics], ") from ", (void*)(Waddr)retaddr, " args ", " (", (void*)(Waddr)arg1, ", ", (void*)(Waddr)arg2, ", ", 
                   (void*)(Waddr)arg3, ", ", (void*)(Waddr)arg4, ", ", (void*)(Waddr)arg5, ", ???", ") at iteration ", iterations, ": arg6 @ ", arg6ptr,
                   " inaccessible; returning -EFAULT", endl, flush;
    }

    arg6 = *arg6ptr;
  } else {
    assert(false);
  }

  if (DEBUG) 
    logfile << "handle_syscall (#", syscallid, " ", ((syscallid < lengthof(syscall_names_32bit)) ? syscall_names_32bit[syscallid] : "???"), 
      " via ", semantics_name[semantics], ") from ", (void*)(Waddr)retaddr, " args ", " (", (void*)(Waddr)arg1, ", ", 
      (void*)(Waddr)arg2, ", ", (void*)(Waddr)arg3, ", ", (void*)(Waddr)arg4, ", ", (void*)(Waddr)arg5, ", ", (void*)(Waddr)arg6,
      ") at iteration ", iterations, endl, flush;

  switch (syscallid) {
  case __NR_32bit_mmap2:
    // mmap2 specifies the 4KB page number to allow mapping 2^(32+12) = 2^44 bit
    // files; x86-64 mmap doesn't have this silliness:
    ctx.commitarf[REG_rax] = (Waddr)asp.mmap((void*)(Waddr)arg1, arg2, arg3, arg4, arg5, arg6 << log2(PAGE_SIZE));
    break;
  case __NR_32bit_munmap:
    ctx.commitarf[REG_rax] = asp.munmap((void*)(Waddr)arg1, arg2);
    break;
  case __NR_32bit_mprotect:
    ctx.commitarf[REG_rax] = asp.mprotect((void*)(Waddr)arg1, arg2, arg3);
    break;
  case __NR_32bit_brk:
    ctx.commitarf[REG_rax] = (Waddr)asp.setbrk((void*)(Waddr)arg1);
    break;
  case __NR_32bit_mremap:
    ctx.commitarf[REG_rax] = (Waddr)asp.mremap((void*)(Waddr)arg1, arg2, arg3, arg4);
    break;
  case __NR_32bit_exit: {
    logfile << "handle_syscall at iteration ", iterations, ": exit(): exiting with arg ", (W64s)arg1, "...", endl, flush;
    user_process_terminated((int)arg1);
  }
  case __NR_32bit_exit_group: {
    logfile << "handle_syscall at iteration ", iterations, ": exit_group(): exiting with arg ", (W64s)arg1, "...", endl, flush;
    user_process_terminated((int)arg1);
  }
  case __NR_32bit_set_thread_area: {
    user_desc_32bit* desc = (user_desc_32bit*)(Waddr)arg1;
    ctx.commitarf[REG_rax] = do_syscall_32bit(syscallid, arg1, 0, 0, 0, 0, 0);
    if (!ctx.commitarf[REG_rax]) {
      logfile << "handle_syscall at iteration ", iterations, ": set_thread_area: LDT desc 0x", 
        hexstring(((desc->entry_number << 3) + 3), 16), " now has base ", (void*)(Waddr)desc->base_addr, endl, flush;
      ldt_seg_base_cache[desc->entry_number] = desc->base_addr;
    }
    break;
  }
  case __NR_32bit_rt_sigaction: {
    //++MTY This is only so we receive SIGSEGV on our own:
#if 1
    logfile << "handle_syscall: signal(", arg1, ", ", (void*)(Waddr)arg2, ")", endl, flush;
    ctx.commitarf[REG_rax] = 0;
#else
    ctx.commitarf[REG_rax] = do_syscall_32bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
#endif
    break;
  }
  case __NR_32bit_mmap: {
    old_mmap32_arg_struct* mm = (old_mmap32_arg_struct*)(Waddr)arg1;
    ctx.commitarf[REG_rax] = (Waddr)asp.mmap((void*)(Waddr)mm->addr, mm->len, mm->prot, mm->flags, mm->fd, mm->offset);
    break;
  }
  default:
    ctx.commitarf[REG_rax] = do_syscall_32bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
    break;
  }
  ctx.commitarf[REG_rip] = retaddr;

  if (DEBUG) logfile << "handle_syscall: result ", ctx.commitarf[REG_rax], " (", (void*)(Waddr)ctx.commitarf[REG_rax], "); returning to ", (void*)(Waddr)ctx.commitarf[REG_rip], endl, flush;
}

const char* ptlcall_names[PTLCALL_COUNT] = {"nop", "marker", "switch_to_sim", "switch_to_native", "capture_stats"};

bool requested_switch_to_native = 0;

W64 handle_ptlcall(W64 rip, W64 callid, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5) {
  logfile << "PTL call from userspace (", (void*)(Waddr)rip, "): callid ", callid, " (", ((callid < PTLCALL_COUNT) ? ptlcall_names[callid] : "UNKNOWN"), 
    ") args (", (void*)(Waddr)arg1, ", ", (void*)(Waddr)arg2, ", ", (void*)(Waddr)arg3, ", ", (void*)(Waddr)arg4, ", ", (void*)(Waddr)arg5, ")", endl, flush;
  if (callid >= PTLCALL_COUNT) return (W64)(-EINVAL);

  switch (callid) {
  case PTLCALL_NOP: {
    logfile << "  (no operation)", endl;
    break;
  }
  case PTLCALL_MARKER: {
    logfile << "  MARKER: iteration ", iterations, ", cycle ", sim_cycle, ", user commits ", total_user_insns_committed, endl;
    break;
  };
  case PTLCALL_SWITCH_TO_SIM: {
    logfile << "  WARNING: already running in simulation mode", endl;
    return (W64)(-EINVAL);
  }
  case PTLCALL_SWITCH_TO_NATIVE: {
    logfile << "  Switching to native mode at rip ", (void*)(Waddr)rip, endl;
    requested_switch_to_native = 1;
    break;
  }
  }
  return 0;
}

// This is where we end up after issuing opcode 0x0f37 (undocumented x86 PTL call opcode)
void assist_ptlcall() {
  ctx.commitarf[REG_rax] = handle_ptlcall(ctx.commitarf[REG_sr1], ctx.commitarf[REG_rdi], ctx.commitarf[REG_rsi], ctx.commitarf[REG_rdx], ctx.commitarf[REG_rcx], ctx.commitarf[REG_r8], ctx.commitarf[REG_r9]);
}

CycleTimer ctperfctrs;

//
// Performance counters
//
#ifdef ENABLE_KERNEL_PERFCTRS
static struct vperfctr* perfctrset = null;

static void setup_perfctr_control(struct perfctr_cpu_control *cpu_control, int eventcount, const W64* events) {
  memset(cpu_control, 0, sizeof(*cpu_control));
	/* count at CPL > 0, Enable */
  static const W64 FLAGS_USERMODE_AND_ENABLED = ((1 << 16) | (1 << 22));
  cpu_control->tsc_on = 1;
  cpu_control->nractrs = eventcount;
  cpu_control->nrictrs = 0;
  foreach (i, eventcount) {
    cpu_control->evntsel[i] = events[i] | FLAGS_USERMODE_AND_ENABLED;
    cpu_control->pmc_map[i] = i;
  }
}

static struct perfctr_sum_ctrs baseline_perfctrs;

void init_perfctrs() {
  int rc;

  perfctrset = vperfctr_open();
#if 0
  // Don't abort, just don't use the counters
  if (!perfctrset) {
    cerr << endl;
    cerr << "ptlsim: Error: cannot access CPU performance counters!", endl;
    cerr << "ptlsim: Cannot initialize virtual machine; aborting", endl;
    cerr << endl, flush;
    exit(1);
  }
#endif
}

void start_perfctrs() {
  if (!perfctrset) return;
  static struct vperfctr_control perfctrcontrol;
  const int eventcount = 4;
  W64 events[4] = { K7_RETIRED_INSTRUCTIONS, K7_RETIRED_OPS, K7_DATA_CACHE_ACCESSES, K7_DATA_CACHE_MISSES };
  setup_perfctr_control(&perfctrcontrol.cpu_control, eventcount, events);
  assert(vperfctr_control(perfctrset, &perfctrcontrol) >= 0);
  vperfctr_read_ctrs(perfctrset, &baseline_perfctrs);
  ctperfctrs.start();
}

void stop_perfctrs() {
  if (!perfctrset) return;
  static struct vperfctr_control perfctrcontrol;
  memset(&perfctrcontrol.cpu_control, 0, sizeof(perfctrcontrol.cpu_control));
  assert(vperfctr_control(perfctrset, &perfctrcontrol) >= 0);
  vperfctr_read_ctrs(perfctrset, &baseline_perfctrs);
}

void print_perfctrs(ostream& os) {
#define deltaof(member) (perfctrs.member - baseline_perfctrs.member)
  if (!perfctrset) return;

  struct perfctr_sum_ctrs perfctrs;
  vperfctr_read_ctrs(perfctrset, &perfctrs);
  ctperfctrs.stop();
  W64 cycles = deltaof(tsc);
  double seconds = (double)cycles / CycleTimer::gethz();
  W64 x86insns = deltaof(pmc[0]);
  W64 uops = deltaof(pmc[1]);
  W64 dcache_accesses = deltaof(pmc[2]);
  W64 dcache_misses = deltaof(pmc[3]);
  W64 dcache_hits = dcache_accesses - dcache_misses;

  os << "Performance Counters (K8 core):", endl;
  os << "  Total cycles:                   ", intstring(cycles, 15), " = ", floatstring(seconds, 0, 6), " seconds", endl;
  os << "  Total cycles (by rdtsc):        ", intstring(ctperfctrs.cycles(), 15), " = ", floatstring(ctperfctrs.seconds(), 0, 6), " seconds", endl;
  os << "  Total x86 instructions retired: ", intstring(x86insns, 15), " = IPC ", floatstring((double)uops / (double)cycles, 5, 3), endl;
  os << "  Total uops retired:             ", intstring(uops, 15),     " = IPC ", floatstring((double)x86insns / (double)cycles, 5, 3), endl;
  os << "  uops-to-x86 ratio:              ", floatstring((double)uops / (double)x86insns, 15, 3), endl;
  os << "  L1 accesses:                    ", intstring(dcache_accesses, 15), endl;
  os << "  L1 hits:                        ", intstring(dcache_hits, 15), " = ", floatstring(percent(dcache_hits, dcache_accesses), 6, 3), "% hit rate", endl;
#undef deltaof
}
#else // ! ENABLE_KERNEL_PERFCTRS

void init_perfctrs() {
  // (No operation unless we have a perfctr-enabled kernel)
}

void start_perfctrs() {
  // Use the TSC based userspace counter only
  ctperfctrs.start();
}

void stop_perfctrs() {
  // Use the TSC based userspace counter only
  ctperfctrs.stop();
}

void print_perfctrs(ostream& os) {
  W64 cycles = ctperfctrs.cycles();
  double seconds = (double)cycles / CycleTimer::gethz();

  os << "Performance Counters (K8 core):", endl;
  os << "  Total cycles (by rdtsc):        ", intstring(ctperfctrs.cycles(), 15), " = ", floatstring(ctperfctrs.seconds(), 0, 6), " seconds", endl;
}

#endif // ! ENABLE_KERNEL_PERFCTRS

//
// Injection into target process
//

#ifdef __x86_64__

void copy_from_process_memory(int pid, void* target, const void* source, int size) {
  W64* destp = (W64*)target;
  W64* srcp = (W64*)source;

  foreach (i, ceil(size, 8) / sizeof(W64)) {
    W64 rc = sys_ptrace(PTRACE_PEEKDATA, pid, (W64)srcp++, (W64)destp++);
    if (errno != 0) { cerr << "ERROR copying to target ", target, ": ", strerror(errno), endl, flush; assert(false); }
  }
}

void copy_to_process_memory(int pid, void* target, const void* source, int size) {
  W64* destp = (W64*)target;
  W64* srcp = (W64*)source;

  foreach (i, ceil(size, 8) / sizeof(W64)) {
    W64 rc = sys_ptrace(PTRACE_POKEDATA, pid, (W64)(destp++), (W64)(*srcp++));
    assert(rc == 0);
  }
}

void write_process_memory_W64(int pid, W64 target, W64 data) {
  int rc = sys_ptrace(PTRACE_POKEDATA, pid, target, data);
  assert(rc == 0);
}

W64 read_process_memory_W64(int pid, W64 source) {
  W64 data;
  int rc = sys_ptrace(PTRACE_PEEKDATA, pid, source, (W64)&data);
  assert(rc == 0);
  return data;
}

void write_process_memory_W32(int pid, W64 target, W32 data) {
  // This is tricky because writes are always 64 bits on x86-64, so we must read, merge and write:
  W64 v;
  int rc = sys_ptrace(PTRACE_PEEKDATA, pid, target, (W64)&v);
  assert(rc == 0);
  v = (v & 0xffffffff00000000ULL) | data;
  rc = sys_ptrace(PTRACE_POKEDATA, pid, target, v);
  assert(rc == 0);
}

W32 read_process_memory_W32(int pid, W64 source) {
  W64 data;
  int rc = sys_ptrace(PTRACE_PEEKDATA, pid, source, (W64)&data);
  assert(rc == 0);
  return LO32(data);
}

extern "C" void ptlsim_loader_thunk_64bit(LoaderInfo* info);
extern "C" void ptlsim_loader_thunk_32bit(LoaderInfo* info);

int is_elf_64bit(const char* filename) {
  idstream is;
  is.open(filename);
  if (!is) return -1;

  struct ELFPartialHeader {
    W32 magic;
    byte class3264;
  };

  ELFPartialHeader h;
  static const W32 ELFMAGIC = 0x464c457f; // ^ELF

  is.read(&h, sizeof(h));
  assert(h.magic == ELFMAGIC);

  return (h.class3264 == ELFCLASS64);
}

int ptlsim_inject(int argc, char** argv) {
  static const bool DEBUG = 0;

  char* filename = argv[1];

  int x86_64_mode = is_elf_64bit(filename);

  if (x86_64_mode < 0) {
    cerr << "ptlsim: cannot open ", filename, endl;
    sys_exit(1);
  }

  if (DEBUG) cerr << "ptlsim[", sys_gettid(), "]: ", filename, " is a ", (x86_64_mode ? "64-bit" : "32-bit"), " ELF executable", endl;

  int pid = sys_fork();

  if (!pid) {
    if (DEBUG) cerr << "ptlsim[", sys_gettid(), "]: Executing ", filename, endl, flush;
    sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
    // Child process stops after execve() below:
    int rc = sys_execve(filename, argv+1, environ);

    if (rc < 0) {
      cerr << "ptlsim: rc ", rc, ": unable to exec ", filename, " (error: ", strerror(errno), ")", endl, flush;
      sys_exit(2);
    }
    assert(false);
  }

  if (pid < 0) {
    cerr << "ptlsim[", sys_gettid(), "]: fork() failed with rc ", pid, " errno ", strerror(errno), endl, flush;
    sys_exit(0);
  }

  if (DEBUG) cerr << "ptlsim: waiting for child pid ", pid, "...", endl, flush;

  int status;
  int rc = waitpid(pid, &status, 0);
  if (rc != pid) {
    cerr << "ptlsim: waitpid returned ", rc, " (vs expected pid ", pid, "); failed with error ", strerror(errno), endl;
    sys_exit(3);
  }

  assert(rc == pid);
  assert(WIFSTOPPED(status));

  struct user_regs_struct regs;
  assert(sys_ptrace(PTRACE_GETREGS, pid, 0, (W64)&regs) == 0);

  LoaderInfo info;
  info.initialize = 1;
  info.origrip = regs.rip;
  info.origrsp = regs.rsp;
  const char* ptlsim_filename = get_full_exec_filename();
  if (DEBUG) cerr << "ptlsim: PTLsim full filename is ", ptlsim_filename, endl;
  strncpy(info.ptlsim_filename, ptlsim_filename, sizeof(info.ptlsim_filename)-1);
  info.ptlsim_filename[sizeof(info.ptlsim_filename)-1] = 0;

  if (DEBUG) cerr << "ptlsim: Original process rip ", (void*)info.origrip, ", rsp ", (void*)info.origrsp, " for pid ", pid, endl;

  regs.rsp -= sizeof(LoaderInfo);

  void* thunk_source = (void*)(x86_64_mode ? &ptlsim_loader_thunk_64bit : &ptlsim_loader_thunk_32bit);
  int thunk_size = LOADER_THUNK_SIZE;

  if (DEBUG) cerr << "Saving old code (", thunk_size, " bytes) at thunk rip ", (void*)regs.rip, " in pid ", pid, endl;
  copy_from_process_memory(pid, &info.saved_thunk, (void*)info.origrip, LOADER_THUNK_SIZE);

  if (DEBUG) cerr << "Writing new code (", LOADER_THUNK_SIZE, " bytes) at thunk rip ", (void*)regs.rip, " in pid ", pid, endl;
  copy_to_process_memory(pid, (void*)info.origrip, thunk_source, LOADER_THUNK_SIZE);

  //
  // Write stack frame
  //
  if (DEBUG)  cerr << "Copy loader info (", sizeof(LoaderInfo), " bytes) to rsp ", (void*)regs.rsp, " in pid ", pid, endl;
  copy_to_process_memory(pid, (void*)regs.rsp, &info, sizeof(LoaderInfo));

  W64 loader_info_base = regs.rsp;

  regs.rsp -= (x86_64_mode) ? 2*8 : 2*4;

  if (DEBUG) cerr << "Make stack frame at rsp ", (void*)regs.rsp, " in pid ", pid, endl;

  if (x86_64_mode) {
    write_process_memory_W64(pid, regs.rsp + 0*8, info.origrip); // return address
    write_process_memory_W64(pid, regs.rsp + 1*8, loader_info_base); // pointer to info block
  } else {
    write_process_memory_W32(pid, regs.rsp + 0*4, info.origrip); // return address
    write_process_memory_W32(pid, regs.rsp + 1*4, loader_info_base); // pointer to info block
    if (DEBUG) cerr << "value = ", hexstring(read_process_memory_W64(pid, regs.rsp), 64), endl;
  }

  if (DEBUG) cerr << "  retaddr = 0x", hexstring(info.origrip, 64), endl;
  if (DEBUG) cerr << "  arg[0]  = 0x", hexstring(loader_info_base, 64), endl;

  // Set up register calling convention on x86-64:
  regs.rdi = loader_info_base;

  assert(sys_ptrace(PTRACE_SETREGS, pid, 0, (W64)&regs) == 0);

  if (DEBUG) cerr << "ptlsim: restarting child pid ", pid, " at ", (void*)regs.rip, "...", endl, flush;

  rc = ptrace(PTRACE_DETACH, pid, 0, 0);
  if (rc) {
    cerr << "ptlsim: detach returned ", rc, ", error code ", strerror(errno), endl, flush;
    sys_exit(4);
  }
  rc = waitpid(pid, &status, 0);

  // (child done)
  status = WEXITSTATUS(status);
  if (DEBUG) cerr << "ptlsim: exiting with exit code ", status, endl, flush;
  return WEXITSTATUS(status);
}

#else // ! __x86_64__

void copy_from_process_memory(int pid, void* target, const void* source, int size) {
  W32* destp = (W32*)target;
  W32* srcp = (W32*)source;

  foreach (i, ceil(size, 4) / sizeof(W32)) {
    W64 rc = sys_ptrace(PTRACE_PEEKDATA, pid, (W32)srcp++, (W32)destp++);
    if (errno != 0) { cerr << "ERROR copying to target ", target, ": ", strerror(errno), endl, flush; assert(false); }
  }
}

void copy_to_process_memory(int pid, void* target, const void* source, int size) {
  W32* destp = (W32*)target;
  W32* srcp = (W32*)source;

  foreach (i, ceil(size, 4) / sizeof(W32)) {
    W64 rc = sys_ptrace(PTRACE_POKEDATA, pid, (W32)(destp++), (W32)(*srcp++));
    assert(rc == 0);
  }
}

void write_process_memory_W64(int pid, W64 target, W64 data) {
  int rc;
  rc = sys_ptrace(PTRACE_POKEDATA, pid, target+0, LO32(data));
  assert(rc == 0);
  rc = sys_ptrace(PTRACE_POKEDATA, pid, target+4, HI32(data));
  assert(rc == 0);
}

W64 read_process_memory_W64(int pid, Waddr source) {
  W64 datalo;
  W64 datahi;
  int rc;
  rc = sys_ptrace(PTRACE_PEEKDATA, pid, source, (W32)&datalo);
  assert(rc == 0);
  rc = sys_ptrace(PTRACE_PEEKDATA, pid, source+4, (W32)&datahi);
  assert(rc == 0);

  return ((W64)datahi << 32) | datalo;
}

void write_process_memory_W32(int pid, Waddr target, W32 data) {
  int rc = sys_ptrace(PTRACE_POKEDATA, pid, target, data);
  assert(rc == 0);
}

W32 read_process_memory_W32(int pid, Waddr source) {
  W64 data;
  int rc = sys_ptrace(PTRACE_PEEKDATA, pid, source, (Waddr)&data);
  assert(rc == 0);
  return LO32(data);
}

extern "C" void ptlsim_loader_thunk_32bit(LoaderInfo* info);

int is_elf_valid(const char* filename) {
  idstream is;
  is.open(filename);
  if (!is) return 0;

  struct ELFPartialHeader {
    W32 magic;
    byte class3264;
  };

  ELFPartialHeader h;
  static const W32 ELFMAGIC = 0x464c457f; // ^ELF

  is.read(&h, sizeof(h));
  if (h.magic != ELFMAGIC) return 0;
  if (h.class3264 != ELFCLASS32) return 0;

  return 1;
}

int ptlsim_inject(int argc, char** argv) {
  static const bool DEBUG = 0;

  char* filename = argv[1];

  if (!is_elf_valid(filename)) {
    cerr << "ptlsim: cannot open ", filename, endl;
    sys_exit(1);
  }

  if (DEBUG) cerr << "ptlsim[", sys_gettid(), "]: ", filename, " is a 32-bit ELF executable", endl;

  int pid = sys_fork();

  if (!pid) {
    if (DEBUG) cerr << "ptlsim[", sys_gettid(), "]: Executing ", filename, endl, flush;
    sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
    // Child process stops after execve() below:
    int rc = sys_execve(filename, argv+1, environ);

    if (rc < 0) {
      cerr << "ptlsim: rc ", rc, ": unable to exec ", filename, " (error: ", strerror(errno), ")", endl, flush;
      sys_exit(2);
    }
    assert(false);
  }

  if (pid < 0) {
    cerr << "ptlsim[", sys_gettid(), "]: fork() failed with rc ", pid, " errno ", strerror(errno), endl, flush;
    sys_exit(0);
  }

  if (DEBUG) cerr << "ptlsim: waiting for child pid ", pid, "...", endl, flush;

  int status;
  int rc = waitpid(pid, &status, 0);
  if (rc != pid) {
    cerr << "ptlsim: waitpid returned ", rc, " (vs expected pid ", pid, "); failed with error ", strerror(errno), endl;
    sys_exit(3);
  }

  assert(rc == pid);
  assert(WIFSTOPPED(status));

  struct user_regs_struct regs;
  assert(sys_ptrace(PTRACE_GETREGS, pid, 0, (Waddr)&regs) == 0);

  LoaderInfo info;
  info.initialize = 1;
  info.origrip = regs.eip;
  info.origrsp = regs.esp;
  const char* ptlsim_filename = get_full_exec_filename();
  if (DEBUG) cerr << "ptlsim: PTLsim full filename is ", ptlsim_filename, endl;
  strncpy(info.ptlsim_filename, ptlsim_filename, sizeof(info.ptlsim_filename)-1);
  info.ptlsim_filename[sizeof(info.ptlsim_filename)-1] = 0;

  if (DEBUG) cerr << "ptlsim: Original process rip ", (void*)(Waddr)info.origrip, ", rsp ", (void*)(Waddr)info.origrsp, " for pid ", pid, endl;

  regs.esp -= sizeof(LoaderInfo);

  void* thunk_source = (void*)&ptlsim_loader_thunk_32bit;
  int thunk_size = LOADER_THUNK_SIZE;

  if (DEBUG) cerr << "Saving old code (", thunk_size, " bytes) at thunk rip ", (void*)regs.eip, " in pid ", pid, endl;
  copy_from_process_memory(pid, &info.saved_thunk, (void*)(Waddr)info.origrip, LOADER_THUNK_SIZE);

  if (DEBUG) cerr << "Writing new code (", LOADER_THUNK_SIZE, " bytes) at thunk rip ", (void*)regs.eip, " in pid ", pid, endl;
  copy_to_process_memory(pid, (void*)(Waddr)info.origrip, thunk_source, LOADER_THUNK_SIZE);

  //
  // Write stack frame
  //
  if (DEBUG) cerr << "Copy loader info (", sizeof(LoaderInfo), " bytes) to rsp ", (void*)regs.esp, " in pid ", pid, endl;
  copy_to_process_memory(pid, (void*)regs.esp, &info, sizeof(LoaderInfo));

  W64 loader_info_base = regs.esp;

  regs.esp -= 2*4;

  if (DEBUG) cerr << "Make stack frame at rsp ", (void*)regs.esp, " in pid ", pid, endl;

  write_process_memory_W32(pid, regs.esp + 0*4, info.origrip); // return address
  write_process_memory_W32(pid, regs.esp + 1*4, loader_info_base); // pointer to info block
  if (DEBUG) cerr << "value = ", hexstring(read_process_memory_W64(pid, regs.esp), 64), endl;

  if (DEBUG) cerr << "  retaddr = 0x", hexstring(info.origrip, 64), endl;
  if (DEBUG) cerr << "  arg[0]  = 0x", hexstring(loader_info_base, 64), endl;

  regs.edi = loader_info_base;

  assert(sys_ptrace(PTRACE_SETREGS, pid, 0, (Waddr)&regs) == 0);

  if (DEBUG) cerr << "ptlsim: restarting child pid ", pid, " at ", (void*)regs.eip, "...", endl, flush;

  rc = ptrace(PTRACE_DETACH, pid, 0, 0);
  if (rc) {
    cerr << "ptlsim: detach returned ", rc, ", error code ", strerror(errno), endl, flush;
    sys_exit(4);
  }
  rc = waitpid(pid, &status, 0);

  // (child done)
  status = WEXITSTATUS(status);
  if (DEBUG) cerr << "ptlsim: exiting with exit code ", status, endl, flush;
  return WEXITSTATUS(status);
}

#endif

//
// Profiling thread exit callbacks
//

/*
 * This is called as a signal handler when a native thread exits;
 * it prints profiling information for the user process. The
 * exit callback is automatically turned off before the kernel
 * calls this so we don't get infinite recursion.
 */
extern "C" void thread_exit_callback(int sig, siginfo_t *si, void *puc) {
  int exitcode = si->si_code;

  if (logfile) {
    logfile << endl, "=== Thread ", sys_gettid(), " exited with status ", exitcode, " ===", endl, endl;
    print_perfctrs(logfile);
    logfile.close();
  }

  sys_exit(exitcode);
}

void init_exit_callback() {
  // Presently the exit callback only works in x86-64 mode because it uses signals:
  if (!ctx.use64) return;
#ifdef __x86_64__
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = thread_exit_callback;
  sa.sa_flags = SA_SIGINFO;
  assert(sigaction(SIGXCPU, &sa, NULL) == 0);
  arch_prctl(ARCH_ENABLE_EXIT_HOOK, (void*)1);
#endif
}

void remove_exit_callback() {
#ifdef __x86_64__
  arch_prctl(ARCH_ENABLE_EXIT_HOOK, (void*)0);
#endif
}

//
// State management
//
ThreadState basetls;

native_auxv_t* auxv_start;

native_auxv_t* find_auxv_entry(int type) {
  native_auxv_t* auxp = auxv_start;

  while (auxp->a_type != AT_NULL) {
    //logfile << "  auxv type ", intstring(auxp->a_type, 3), ": 0x", hexstring((W64)auxp->a_un.a_ptr, 64), " = ", intstring(auxp->a_un.a_val, 24), endl, flush;
    if (auxp->a_type == type) return auxp;
    auxp++;
  }

  return null;
}

//
// Conversion of args, environment and auxv between 64-bit and 32-bit formats:
//

template <typename ptrsize_t, typename auxv_t>
int get_stack_reqs_for_args_env_auxv(const byte* origargv) {
  // go back to argc before argv
  origargv -= sizeof(ptrsize_t);
  ptrsize_t* p = (ptrsize_t*)origargv;

  int argc = *p++;
  p += argc;

  // skip over null after args
  p++;

  // skip over environment
  int envc = 0;
  while (*p) { p++; envc++; }
  p++;

  auxv_t* auxv = (auxv_t*)p;
  int auxvc = 0;
  while (auxv->a_type != AT_NULL) { auxv++; auxvc++; }

  stringbuf sb;
  // sb << "Stack reqs: ", argc, " args, ", envc, " envs, ", auxvc, " auxvs", endl;
  write(2, (char*)sb, strlen(sb));

  return ((1 + argc + 1 + envc + 1) * sizeof(char**)) + ((auxvc + 1) * sizeof(native_auxv_t));
}

struct Elf32_auxv_32bit {
  W32 a_type;
  union {
    W32 a_val;
    W32 a_ptr;
  } a_un;
};

char** initenv;

template <typename ptrsize_t, typename auxv_t>
byte* copy_args_env_auxv(byte* destptr, const byte* origargv) {
  char** dest = (char**)destptr;

  origargv -= sizeof(ptrsize_t);
  ptrsize_t* p = (ptrsize_t*)origargv;

  Waddr argc = *p++;
  *dest++ = (char*)argc;

  foreach (i, argc+1) *dest++ = (char*)(Waddr)(*p++);

  // skip over null at end of args
  *dest++ = 0; p++;

  initenv = (char**)dest;

  while (*p) *dest++ = (char*)(Waddr)(*p++);

  // skip over null at end of environment
  *dest++ = 0; p++;

  native_auxv_t* destauxv = (native_auxv_t*)dest;

  auxv_t* auxv = (auxv_t*)p;

  auxv_start = destauxv;

  while (auxv->a_type != AT_NULL) {
    if ((auxv->a_type == AT_SYSINFO) || (auxv->a_type == AT_SYSINFO_EHDR)) {
      // We do not support SYSENTER-style VDSOs, so disable this:
      logfile << "copy_args_env_auxv: Disabled 32-bit AT_SYSINFO auxv", endl;
      destauxv->a_type = AT_IGNORE;
      auxv->a_type = AT_IGNORE;
    } else {
      destauxv->a_type = auxv->a_type;
      destauxv->a_un.a_val = auxv->a_un.a_val;
    }
    auxv++; destauxv++;
  }
  
  destauxv->a_type = AT_NULL;
  destauxv->a_un.a_val = 0;
  auxv++; destauxv++;

  return (byte*)destauxv;
}

//
// Give user thread a really big stack by accessing memory
// below the grows-down stack object. We have to do this
// now since PTLsim has no concept of grow down auto allocate
// stacks and will just throw page faults.
//
// In this clever function, we just keep on recursively
// descending into the stack until the desired rsp is hit.
//
#ifdef __x86_64__
inline void* get_rsp() { W64 rsp; asm volatile("mov %%rsp,%[dest]" : [dest] "=r" (rsp)); return (void*)rsp; }
#else // ! __x86_64__
inline void* get_rsp() { W32 esp; asm volatile("mov %%esp,%[dest]" : [dest] "=r" (esp)); return (void*)esp; }
#endif

void expand_user_stack_to_addr(W64 desired_rsp) {
  byte dummy[PAGE_SIZE];

  Waddr current_rsp = (Waddr)get_rsp();

  if (current_rsp > desired_rsp)
    expand_user_stack_to_addr(desired_rsp);
}

extern time_t ptlsim_build_timestamp;

//
// The real PTLsim entry point called by the kernel immediately after injecting
// the ptlsim image into the target process is ptlsim_preinit_entry. This in
// turn calls ptlsim_preinit() below before returning to the libc _start to
// finish initializing PTLsim as if it were a regular program thread.
//
// ptlsim_preinit() sets up our custom memory management and threading model,
// then captures any user process arguments, environment and auxv, possibly
// converting between 64-bit and 32-bit formats.
//

extern "C" void* ptlsim_preinit(void* origrsp, void* nextinit) {
  //
  // We don't yet have any I/O streams or console output at this point
  // so we are limited to things we can do without using libc:
  //

  // The loader thunk patched our ELF header with the real RIP to enter at:
#ifdef __x86_64__
  Elf64_Ehdr* ptlsim_ehdr = (Elf64_Ehdr*)PTL_PAGE_POOL_BASE;
#else
  Elf32_Ehdr* ptlsim_ehdr = (Elf32_Ehdr*)PTL_PAGE_POOL_BASE;
#endif

  inside_ptlsim = (ptlsim_ehdr->e_type == ET_PTLSIM);
  ptlsim_build_timestamp = (time_t)ptlsim_ehdr->e_version;

  if (!inside_ptlsim) {
    // We're still a normal process - don't do anything special
    return origrsp;
  }

  // Set up initial context:
  ctx.reset();
  ctx.commitarf[REG_rsp] = (Waddr)origrsp;
  ctx.commitarf[REG_rip] = (Waddr)ptlsim_ehdr->e_entry;

  ctx.commitarf[REG_flags] = 0;
  ctx.use64 = (ptlsim_ehdr->e_machine == EM_X86_64);
  cpu_fsave(x87state);
  fpu_state_to_ptlsim_state();
  ctx.commitarf[REG_mxcsr] = x86_stmxcsr();

  fsbase = get_fs_base();
  gsbase = get_gs_base();

  //
  // Generally the true stack top can be found by rounding up to some big fraction
  // of the address space on most kernels, since it is always at 0x7fffffffffff
  // on x86-64, 0xbfffffff on ia32 or 0xffffffff on ia32-on-x86-64.
  //
  stack_max_addr = ceil(ctx.commitarf[REG_rsp], 256*1024*1024);

  Waddr user_stack_size;

  struct rlimit rlimit;
  assert(getrlimit(RLIMIT_STACK, &rlimit) == 0);
  user_stack_size = rlimit.rlim_cur;

  // Round up a little so we don't over-run it when we fault in the stack:
  stack_min_addr = floor(stack_max_addr - user_stack_size, PAGE_SIZE) + 65536;

  assert(stack_min_addr >= (PTL_PAGE_POOL_BASE + 128*1024*1024));

  expand_user_stack_to_addr(stack_min_addr);

  asp.reset();

  ThreadState* tls = &basetls;
  tls->self = tls;
  // Give PTLsim itself 64 MB for the .text, .data and .bss sections:
  void* stack = ptl_alloc_private_pages(SIM_THREAD_STACK_SIZE, PROT_READ|PROT_WRITE, PTL_PAGE_POOL_BASE + 64*1024*1024);
  assert(mmap_valid(stack));
  tls->stack = (byte*)stack + SIM_THREAD_STACK_SIZE;
  setup_sim_thunk_page();

#ifdef __x86_64__
  const byte* argv = (ctx.use64)
    ? (const byte*)(((W64*)origrsp)+1)
    : (const byte*)(((W32*)origrsp)+1);

  int bytes = (ctx.use64)
    ? get_stack_reqs_for_args_env_auxv<W64, Elf64_auxv_t>(argv)
    : get_stack_reqs_for_args_env_auxv<W32, Elf32_auxv_32bit>(argv);

  byte* sp = (byte*)(tls->stack);
  sp -= bytes;

  byte* endp = (ctx.use64)
    ? copy_args_env_auxv<W64, Elf64_auxv_t>(sp, argv)
    : copy_args_env_auxv<W32, Elf32_auxv_32bit>(sp, argv);
#else

  const byte* argv = (const byte*)(((W32*)origrsp)+1);

  int bytes = get_stack_reqs_for_args_env_auxv<W32, Elf32_auxv_32bit>(argv);

  byte* sp = (byte*)(tls->stack);
  sp -= bytes;

  byte* endp = copy_args_env_auxv<W32, Elf32_auxv_32bit>(sp, argv);
#endif
  assert(endp == tls->stack);

  return sp;
}
