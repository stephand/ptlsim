// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Kernel interface for memory and thread management
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _KERNEL_H_
#define _KERNEL_H_

#include <globals.h>
#include <ptlhwdef.h>
#include <elf.h>

#undef __syscall_return
#define __syscall_return(type, res) return (type)(res);
#define __syscall_clobber "r11","rcx","memory" 
#define __syscall "syscall"

#define declare_syscall0(sysid,type,name) type name(void) { long __res; asm volatile \
  (__syscall : "=a" (__res) : "0" (sysid) : __syscall_clobber ); __syscall_return(type,__res); }

#define declare_syscall1(sysid,type,name,type1,arg1) type name(type1 arg1) { long __res; asm volatile \
  (__syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)) : __syscall_clobber ); __syscall_return(type,__res); }

#define declare_syscall2(sysid,type,name,type1,arg1,type2,arg2) type name(type1 arg1,type2 arg2) { long __res; asm volatile \
  (__syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)) : __syscall_clobber ); __syscall_return(type,__res); }

#define declare_syscall3(sysid,type,name,type1,arg1,type2,arg2,type3,arg3) type name(type1 arg1,type2 arg2,type3 arg3) { \
  long __res; asm volatile (__syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), "d" ((long)(arg3)) : \
  __syscall_clobber); __syscall_return(type,__res); }

#define declare_syscall4(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
  type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
  long __res; asm volatile ("movq %5,%%r10 ;" __syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), \
  "d" ((long)(arg3)),"g" ((long)(arg4)) : __syscall_clobber,"r10" ); __syscall_return(type,__res); }

#define declare_syscall5(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5) \
  type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) { long __res; asm volatile ("movq %5,%%r10 ; movq %6,%%r8 ; " __syscall \
  : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), "d" ((long)(arg3)),"g" ((long)(arg4)),"g" ((long)(arg5)) : \
  __syscall_clobber,"r8","r10"); __syscall_return(type,__res); }

#define declare_syscall6(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5,type6,arg6) \
  type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) { long __res; asm volatile \
  ("movq %5,%%r10 ; movq %6,%%r8 ; movq %7,%%r9 ; " __syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), \
   "d" ((long)(arg3)), "g" ((long)(arg4)), "g" ((long)(arg5)), "g" ((long)(arg6)) : __syscall_clobber,"r8","r10","r9" ); __syscall_return(type,__res); }

//
// Thread local storage
//
typedef W64 (*simcall_func_t)(W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5, W64 arg6);

struct ThreadState {
  ThreadState* self;
  void* stack;
  simcall_func_t simcall;
};

extern ThreadState basetls;

static inline ThreadState* getcurrent() {
  return &basetls;
}

pid_t gettid();
W64 arch_prctl(int code, void* addr);
void sys_exit(int code);
void* sys_brk(void* newbrk);
ssize_t sys_write(int fd, const void* buf, size_t count);
W64 sys_ptrace(int request, pid_t pid, W64 addr, W64 data);

void early_printk(const char* text);

// Initialize all PTLsim kernel structures
void init_kernel();

//
// Memory management
//
// On x86-64 K8's, there are 48 bits of virtual address space and 40 bits of physical address space: 
#define TOP_OF_MEM 0x1000000000000LL
//#define PTL_PAGE_POOL_BASE 0x7ff000000000LL
#define PTL_PAGE_POOL_BASE 0x70000000LL
#define PTL_PAGE_POOL_SIZE (1*1024*1024*1024LL)  // (1 GB)
#define PTL_PAGE_POOL_END (PTL_PAGE_POOL_BASE + PTL_PAGE_POOL_SIZE)

#define mmap_invalid(addr) (((W64)addr & 0xfffffffffffff000) == 0xfffffffffffff000)
#define mmap_valid(addr) (!mmap_invalid(addr))

//
// These take pages from the private page pool so we can keep all PTLsim 
// data out of the way of the user virtual machine to ensure deterministic
// allocations.
//  
void* ptl_alloc_private_pages(W64 bytecount, int prot = PROT_READ|PROT_WRITE|PROT_EXEC, W64 base = 0);
void* ptl_alloc_private_32bit_pages(W64 bytecount, int prot = PROT_READ|PROT_WRITE|PROT_EXEC, W64 base = 0);
void ptl_free_private_pages(void* base, W64 bytecount);
void ptl_zero_private_pages(void* base, W64 bytecount);
bool try_to_extend_stack(W64 addr);

//
// Thunk and breakpoint management
//
Elf64_auxv_t* find_auxv_entry(int type);

void switch_stack_and_jump_32_or_64(void* code, void* stack, bool use64);
void switch_to_native_restore_context();
void set_switch_to_sim_breakpoint(void* addr);

int ptlsim_inject(int argc, char* argv[]);

//
// Performance counters
//
extern void init_perfctrs();
extern void start_perfctrs();
extern void stop_perfctrs();
extern void print_perfctrs(ostream& os);
extern void flush_cpu_caches();
extern void init_exit_callback();
extern void remove_exit_callback();

//
// Address space management
//

// Each chunk covers 2 GB of virtual address space:
#define SPAT_TOPLEVEL_CHUNK_BITS 17
#define SPAT_PAGES_PER_CHUNK_BITS 19
#define SPAT_TOPLEVEL_CHUNKS (1 << SPAT_TOPLEVEL_CHUNK_BITS) // 262144
#define SPAT_PAGES_PER_CHUNK (1 << SPAT_PAGES_PER_CHUNK_BITS) // 524288
#define SPAT_BYTES_PER_CHUNK (SPAT_PAGES_PER_CHUNK / 8)    // 65536
#define ADDRESS_SPACE_BITS (48)
#define ADDRESS_SPACE_SIZE (1LL << ADDRESS_SPACE_BITS)

class AddressSpace {
public:
  AddressSpace();
  ~AddressSpace();
  void reset();
public:

  W64 imagebase;
  W64 entrypoint;
  W64 end_code;

  void* brkbase;
  void* brk;

  W64 top_of_stack;
  W64 stack_base;

public:
  W64 prep(int argc, char** argv, int envc, char** envp);

public:
  //
  // Shadow page attribute table
  //
  typedef byte SPATChunk[SPAT_BYTES_PER_CHUNK];
  SPATChunk** readmap;
  SPATChunk** writemap;
  SPATChunk** execmap;
  SPATChunk** dtlbmap;
  SPATChunk** itlbmap;

  byte& pageid_to_map_byte(SPATChunk** top, W64 pageid);
  void make_accessible(void* address, W64 size, SPATChunk** top);
  void make_inaccessible(void* address, W64 size, SPATChunk** top);

  void make_page_accessible(void* address, SPATChunk** top) {
    W64 pageid = ((W64)lowbits((W64)address, ADDRESS_SPACE_BITS)) >> PAGE_SHIFT;
    setbit(pageid_to_map_byte(top, pageid), lowbits(pageid, 3));
  }

  void make_page_inaccessible(void* address, SPATChunk** top) {
    W64 pageid = ((W64)lowbits((W64)address, ADDRESS_SPACE_BITS)) >> PAGE_SHIFT;
    clearbit(pageid_to_map_byte(top, pageid), lowbits(pageid, 3));
  }

  void allow_read(void* address, W64 size) { make_accessible(address, size, readmap); }
  void disallow_read(void* address, W64 size) { make_inaccessible(address, size, readmap); }
  void allow_write(void* address, W64 size) { make_accessible(address, size, writemap); }
  void disallow_write(void* address, W64 size) { make_inaccessible(address, size, writemap); }
  void allow_exec(void* address, W64 size) { make_accessible(address, size, execmap); }
  void disallow_exec(void* address, W64 size) { make_inaccessible(address, size, execmap); }

public:
  //
  // Memory management passthroughs
  //
  long sys_errno;

  void setattr(void* start, W64 length, int prot);
  int getattr(void* start);
  int mprotect(void* start, W64 length, int prot);
  int munmap(void* start, W64 length);
  void* mmap(void* start, W64 length, int prot, int flags, int fd, off_t offset);
  void* mremap(void* start, W64 oldsize, W64 newsize, int flags);
  void* setbrk(void* targetbrk);

  bool fastcheck(W64 addr, SPATChunk** top) const {
    W64 pageid = lowbits(addr, ADDRESS_SPACE_BITS) >> PAGE_SHIFT;
    W64 chunkid = pageid >> log2(SPAT_PAGES_PER_CHUNK);

    if (!top[chunkid])
      return false;

    AddressSpace::SPATChunk& chunk = *top[chunkid];
    W64 byteid = bits(pageid, 3, log2(SPAT_BYTES_PER_CHUNK));
    return bit(chunk[byteid], lowbits(pageid, 3));
  }

  bool fastcheck(void* addr, SPATChunk** top) const {
    return fastcheck((W64)addr, top);
  }

  bool check(void* p, int prot) const {
    if ((prot & PROT_READ) && (!fastcheck(p, readmap)))
      return false;
    
    if ((prot & PROT_WRITE) && (!fastcheck(p, writemap)))
      return false;
    
    if ((prot & PROT_EXEC) && (!fastcheck(p, execmap)))
      return false;
    
    return true;
  }

  bool dtlbcheck(void* page) const { return fastcheck(page, dtlbmap); }
  void dtlbset(void* page) { make_page_accessible(page, dtlbmap); }
  void dtlbclear(void* page) { make_page_inaccessible(page, dtlbmap); }

  bool itlbcheck(void* page) const { return fastcheck(page, itlbmap); }
  void itlbset(void* page) { make_page_accessible(page, itlbmap); }
  void itlbclear(void* page) { make_page_inaccessible(page, itlbmap); }

  void resync_with_process_maps();
};

extern AddressSpace asp;

//
// System calls
//
void handle_syscall_32bit();
void handle_syscall_64bit();

//
// Local descriptor table
//
#define LDT_SIZE 8192
extern W64 ldt_seg_base_cache[LDT_SIZE];

static inline W16 get_fs() {
  W64 value;
  asm("mov %%fs,%%ax\n" : "=a" (value));
  return value;
}

static inline W16 get_gs() {
  W64 value;
  asm("mov %%gs,%%ax\n" : "=a" (value));
  return value;
}

static inline W64 get_limit(W16 desc) {
  W64 value;
  asm("lsl %[desc],%[value]\n" : [value] "=r" (value) : [desc] "m" (desc));
  return value;
}

static inline W64 access_tls_segment(W64 offset) {
  W64 value;
  asm("movq %%fs:(%[offset]),%[value]\n" : [value] "=r" (value) : [offset] "r" (offset));
  return value;
}

//
// This is set if we are running within the target process address space;
// it controls the way PTLsim behaves on startup. If not set, PTLsim is
// acting as a regular program, typically to inject itself into another
// process (which will then have inside_ptlsim set) or to print help info.
//
extern bool inside_ptlsim;

extern bool requested_switch_to_native;

#endif // _KERNEL_H_
