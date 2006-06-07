// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Linux Kernel Interface
//
// Copyright 2000-2006 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _KERNEL_H_
#define _KERNEL_H_

#include <globals.h>
#include <ptlhwdef.h>
#include <elf.h>

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

void early_printk(const char* text);

// Initialize all PTLsim kernel structures
void init_kernel();

//
// Thunk and breakpoint management
//
#ifdef __x86_64__
typedef Elf64_auxv_t native_auxv_t;
#else
typedef Elf32_auxv_t native_auxv_t;
#endif

native_auxv_t* find_auxv_entry(int type);

void switch_stack_and_jump_32_or_64(void* code, void* stack, bool use64);
void switch_to_native_restore_context();
void set_switch_to_sim_breakpoint(void* addr);
void enable_ptlsim_call_gate();
void disable_ptlsim_call_gate();

int ptlsim_inject(int argc, const char** argv);

//
// Performance counters
//
void init_perfctrs();
void start_perfctrs();
void stop_perfctrs();
void print_perfctrs(ostream& os);
void flush_cpu_caches();

//
// Signal callbacks
//
void init_signal_callback();
void remove_signal_callback();
// Set whenever PTLsim is running inside some simulator loop
extern bool running_in_sim_mode;

//
// x87 structures
//

typedef byte X87Reg[10];

union X87StatusWord {
  struct { W16 ie:1, de:1, ze:1, oe:1, ue:1, pe:1, sf:1, es:1, c0:1, c1:1, c2:1, tos:3, c3:1, b:1; } fields;
  W16 data;
};

union X87ControlWord {
  struct { W16 im:1, dm:1, zm:1, om:1, um:1, pm:1, res1:2, pc:2, rc:2, y:1, res2:3; } fields;
  W16 data;
};

struct X87State {
  X87ControlWord cw;
  W16 reserved1;
  X87StatusWord sw;
  W16 reserved2;
  W16 tw;
  W16 reserved3;
  W32 eip;
  W16 cs;
  W16 opcode;
  W32 dataoffs;
  W16 ds;
  W16 reserved4;
  X87Reg stack[8];
} __attribute__((packed));

inline W64 x87_fp_80bit_to_64bit(const X87Reg* x87reg) {
  W64 reg64;
  asm("fldt (%[mem80])\n"
      "fstpl %[mem64]\n"
      : : [mem64] "m" (reg64), [mem80] "r" (x87reg));
  return reg64;
}

inline void x87_fp_64bit_to_80bit(X87Reg* x87reg, W64 reg64) {
  asm("fldl %[mem64]\n"
      "fstpt (%[mem80])\n"
      : : [mem80] "r" (*x87reg), [mem64] "m" (reg64) : "memory");
}

inline void cpu_fsave(X87State& state) {
  asm volatile("fsave %[state]" : [state] "=m" (*&state));
}

inline void cpu_frstor(X87State& state) {
  asm volatile("frstor %[state]" : : [state] "m" (*&state));
}

inline W16 cpu_get_fpcw() {
  W16 fpcw;
  asm volatile("fstcw %[fpcw]" : [fpcw] "=m" (fpcw));
  return fpcw;
}

inline void cpu_set_fpcw(W16 fpcw) {
  asm volatile("fldcw %[fpcw]" : : [fpcw] "m" (fpcw));
}


//
// Address space management
//

#ifdef __x86_64__

// Each chunk covers 2 GB of virtual address space:
#define SPAT_TOPLEVEL_CHUNK_BITS 17
#define SPAT_PAGES_PER_CHUNK_BITS 19
#define SPAT_TOPLEVEL_CHUNKS (1 << SPAT_TOPLEVEL_CHUNK_BITS) // 262144
#define SPAT_PAGES_PER_CHUNK (1 << SPAT_PAGES_PER_CHUNK_BITS) // 524288
#define SPAT_BYTES_PER_CHUNK (SPAT_PAGES_PER_CHUNK / 8)    // 65536
#define ADDRESS_SPACE_BITS (48)
#define ADDRESS_SPACE_SIZE (1LL << ADDRESS_SPACE_BITS)

#else

// Each chunk covers 2 GB of virtual address space:
#define ADDRESS_SPACE_BITS (32)
#define ADDRESS_SPACE_SIZE (1LL << ADDRESS_SPACE_BITS)
#define SPAT_BYTES ((ADDRESS_SPACE_SIZE / PAGE_SIZE) / 8)

#endif

class AddressSpace {
public:
  AddressSpace();
  ~AddressSpace();
  void reset();
public:

  Waddr imagebase;
  Waddr entrypoint;
  Waddr end_code;

  void* brkbase;
  void* brk;

  Waddr top_of_stack;
  Waddr stack_base;

public:
  Waddr prep(int argc, char** argv, int envc, char** envp);

public:
  //
  // Shadow page attribute table
  //
#ifdef __x86_64__
  typedef byte SPATChunk[SPAT_BYTES_PER_CHUNK];
  typedef SPATChunk** spat_t;
#else
  typedef byte* spat_t;
#endif
  spat_t readmap;
  spat_t writemap;
  spat_t execmap;
  spat_t dtlbmap;
  spat_t itlbmap;

  byte& pageid_to_map_byte(spat_t top, Waddr pageid);
  void make_accessible(void* address, Waddr size, spat_t top);
  void make_inaccessible(void* address, Waddr size, spat_t top);

  Waddr pageid(void* address) const {
#ifdef __x86_64__
    return ((W64)lowbits((W64)address, ADDRESS_SPACE_BITS)) >> log2(PAGE_SIZE);
#else
    return ((Waddr)address) >> log2(PAGE_SIZE);
#endif
  }

  Waddr pageid(Waddr address) const { return pageid((void*)address); }

  void make_page_accessible(void* address, spat_t top) {
    setbit(pageid_to_map_byte(top, pageid(address)), lowbits(pageid(address), 3));
  }

  void make_page_inaccessible(void* address, spat_t top) {
    clearbit(pageid_to_map_byte(top, pageid(address)), lowbits(pageid(address), 3));
  }

  void allow_read(void* address, Waddr size) { make_accessible(address, size, readmap); }
  void disallow_read(void* address, Waddr size) { make_inaccessible(address, size, readmap); }
  void allow_write(void* address, Waddr size) { make_accessible(address, size, writemap); }
  void disallow_write(void* address, Waddr size) { make_inaccessible(address, size, writemap); }
  void allow_exec(void* address, Waddr size) { make_accessible(address, size, execmap); }
  void disallow_exec(void* address, Waddr size) { make_inaccessible(address, size, execmap); }

public:
  //
  // Memory management passthroughs
  //
  long sys_errno;

  void setattr(void* start, Waddr length, int prot);
  int getattr(void* start);
  int mprotect(void* start, Waddr length, int prot);
  int munmap(void* start, Waddr length);
  void* mmap(void* start, Waddr length, int prot, int flags, int fd, W64 offset);
  void* mremap(void* start, Waddr oldsize, Waddr newsize, int flags);
  void* setbrk(void* targetbrk);

  bool fastcheck(Waddr addr, spat_t top) const {
#ifdef __x86_64__
    W64 chunkid = pageid(addr) >> log2(SPAT_PAGES_PER_CHUNK);

    if (!top[chunkid])
      return false;

    AddressSpace::SPATChunk& chunk = *top[chunkid];
    Waddr byteid = bits(pageid(addr), 3, log2(SPAT_BYTES_PER_CHUNK));
    return bit(chunk[byteid], lowbits(pageid(addr), 3));
#else // 32-bit
    return bit(top[pageid(addr) >> 3], lowbits(pageid(addr), 3));
#endif
  }

  bool fastcheck(void* addr, spat_t top) const {
    return fastcheck((Waddr)addr, top);
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
enum { SYSCALL_SEMANTICS_INT80, SYSCALL_SEMANTICS_SYSCALL, SYSCALL_SEMANTICS_SYSENTER };

void handle_syscall_32bit(int semantics);

// x86-64 mode has only one type of system call (the syscall instruction)
void handle_syscall_64bit();

//
// Local descriptor table
//
#define LDT_SIZE 8192
extern W64 ldt_seg_base_cache[LDT_SIZE];

extern "C" {
  int get_gs();
  int get_fs();
};

//
// This is set if we are running within the target process address space;
// it controls the way PTLsim behaves on startup. If not set, PTLsim is
// acting as a regular program, typically to inject itself into another
// process (which will then have inside_ptlsim set) or to print help info.
//
extern bool inside_ptlsim;

extern bool requested_switch_to_native;

#endif // _KERNEL_H_
