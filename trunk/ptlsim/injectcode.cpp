//
// PTLsim: Cycle Accurate x86-64 Simulator
// Injected loader stub code
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <loader.h>
#include <asm/unistd.h>
#include <elf.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>

#undef __syscall_return
#define __syscall_return(type, res) return (type)(res);

#ifdef __x86_64__

#define __syscall "syscall"

#define declare_syscall0(sysid,type,name) static inline type name(void) { long __res; asm volatile \
  (__syscall : "=a" (__res) : "0" (sysid) : __syscall_clobber ); __syscall_return(type,__res); }

#define declare_syscall1(sysid,type,name,type1,arg1) static inline type name(type1 arg1) { long __res; asm volatile \
  (__syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)) : __syscall_clobber ); __syscall_return(type,__res); }

#define declare_syscall2(sysid,type,name,type1,arg1,type2,arg2) static inline type name(type1 arg1,type2 arg2) { long __res; asm volatile \
  (__syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)) : __syscall_clobber ); __syscall_return(type,__res); }

#define declare_syscall3(sysid,type,name,type1,arg1,type2,arg2,type3,arg3) static inline type name(type1 arg1,type2 arg2,type3 arg3) { \
  long __res; asm volatile (__syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), "d" ((long)(arg3)) : \
  __syscall_clobber); __syscall_return(type,__res); }

#define declare_syscall4(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
  static inline type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) { \
  long __res; asm volatile ("movq %5,%%r10 ;" __syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), \
  "d" ((long)(arg3)),"g" ((long)(arg4)) : __syscall_clobber,"r10" ); __syscall_return(type,__res); }

#define declare_syscall5(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5) \
  static inline type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) { long __res; asm volatile ("movq %5,%%r10 ; movq %6,%%r8 ; " __syscall \
  : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), "d" ((long)(arg3)),"g" ((long)(arg4)),"g" ((long)(arg5)) : \
  __syscall_clobber,"r8","r10"); __syscall_return(type,__res); }

#define declare_syscall6(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5,type6,arg6) \
  static inline type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) { long __res; asm volatile \
  ("movq %5,%%r10 ; movq %6,%%r8 ; movq %7,%%r9 ; " __syscall : "=a" (__res) : "0" (sysid),"D" ((long)(arg1)),"S" ((long)(arg2)), \
   "d" ((long)(arg3)), "g" ((long)(arg4)), "g" ((long)(arg5)), "g" ((long)(arg6)) : __syscall_clobber,"r8","r10","r9" ); __syscall_return(type,__res); }

#else // 32-bit

#define declare_syscall0(sysid,type,name) static inline type name(void) { long __res; asm volatile ("int $0x80" \
  : "=a" (__res) : "0" (sysid)); __syscall_return(type,__res); }

#define declare_syscall1(sysid,type,name,type1,arg1) static inline type name(type1 arg1) { long __res; \
  asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1))); __syscall_return(type,__res); }

#define declare_syscall2(sysid,type,name,type1,arg1,type2,arg2) static inline type name(type1 arg1,type2 arg2) { \
  long __res; asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2))); __syscall_return(type,__res); }

#define declare_syscall3(sysid,type,name,type1,arg1,type2,arg2,type3,arg3) static inline type name(type1 arg1,type2 arg2,type3 arg3) { \
  long __res; asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2)), "d" ((long)(arg3))); __syscall_return(type,__res); }

#define declare_syscall4(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) static inline type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
  { long __res; asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2)), "d" ((long)(arg3)),"S" ((long)(arg4))); \
  __syscall_return(type,__res); }

#define declare_syscall5(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, type5,arg5) static inline type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
  { long __res; asm volatile ("int $0x80" : "=a" (__res) : "0" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2)), "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5))); \
  __syscall_return(type,__res); }

#define declare_syscall6(sysid,type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, type5,arg5,type6,arg6) \
  static inline type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) { \
  long __res; asm volatile ("push %%ebp ; movl %%eax,%%ebp ; movl %1,%%eax ; int $0x80 ; pop %%ebp" : "=a" (__res) \
	: "i" (sysid),"b" ((long)(arg1)),"c" ((long)(arg2)), "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5)), \
  "0" ((long)(arg6))); __syscall_return(type,__res); }

#endif // 32-bit

#ifdef PTLSIM_FORCE_32BIT_ONLY
// Building PTLsim32 only:

static inline void switch_stack_and_jump(void* code, void* stack, bool use64) {
  asm volatile("mov %[code],%%eax\n"
               "mov %[stack],%%esp\n"
               "jmp *%%eax\n" : : [code] "r" (code), [stack] "m" (stack));
}

#else

struct FarJumpDescriptor {
  W32 offset;
  W16 seg;
};

static inline void switch_stack_and_jump(void* code, void* stack, bool use64) {
  FarJumpDescriptor desc;
  desc.offset = LO32((W64)code);
  desc.seg = (use64) ? 0x33 : 0x23;

  asm volatile(
#ifdef __x86_64__
               "lea %[desc],%%rax\n"
               "mov %[stack],%%rsp\n"
               "ljmp *(%%rax)\n" : : [desc] "m" (desc), [stack] "m" (stack));
#else
               "lea %[desc],%%eax\n"
               "mov %[stack],%%esp\n"
               "ljmp *(%%eax)\n" : : [desc] "m" (desc), [stack] "m" (stack));
#endif
}

#endif // ! PTLSIM_FORCE_32BIT_ONLY

declare_syscall0(__NR_pause, void, sys_pause);

declare_syscall2(__NR_munmap, int, sys_munmap, void*, start, size_t, length);
declare_syscall2(__NR_fstat, int, sys_fstat, int, fd, struct stat*, buf);

declare_syscall3(__NR_write, ssize_t, sys_write, int, fd, const void*, buf, size_t, count);
declare_syscall3(__NR_lseek, off_t, sys_lseek, int, fd, off_t, offset, int, whence);
declare_syscall3(__NR_open, int, sys_open, const char*, filename, int, flags, mode_t, mode);
declare_syscall3(__NR_mprotect, int, sys_mprotect, const void*, addr, size_t, len, int, prot);

#ifdef __x86_64__
declare_syscall6(__NR_mmap, void*, sys_mmap, void*, start, size_t, length, int, prot, int, flags, int, fd, off_t, offset);
#else // 32-bit
// We use mmap2() instead of the historical mmap() because mmap2() has a nice calling convention:
declare_syscall6(__NR_mmap2, void*, sys_mmap2, void*, start, size_t, length, int, prot, int, flags, int, fd, off_t, pgoff);
static inline void* sys_mmap(void* start, size_t length, int prot, int flags, int fd, off_t offset) {
  return sys_mmap2(start, length, prot, flags, fd, offset >> log2(PAGE_SIZE));
}
#endif

declare_syscall1(__NR_exit, void, sys_exit, int, status);
declare_syscall1(__NR_close, void, sys_close, int, status);

#ifdef __x86_64__
#define ptlsim_loader_thunk_name ptlsim_loader_thunk_64bit
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#else // 32-bit
#define ptlsim_loader_thunk_name ptlsim_loader_thunk_32bit
// NOTE: PTLsim is ALWAYS 64-bit image
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
//#define Elf_Ehdr Elf32_Ehdr
//#define Elf_Phdr Elf32_Phdr
#endif // 32-bit

extern "C" void ptlsim_loader_thunk_name(LoaderInfo* info);

#define PTLSIM_THUNK_PAGE 0x1000

#ifdef PTLSIM_FORCE_32BIT_ONLY
typedef Elf32_Ehdr PTLsim_Elf_Ehdr;
typedef Elf32_Phdr PTLsim_Elf_Phdr;
#else
typedef Elf64_Ehdr PTLsim_Elf_Ehdr;
typedef Elf64_Phdr PTLsim_Elf_Phdr;
#endif

void ptlsim_loader_thunk_name(LoaderInfo* info) {
  if (info->initialize) {
    byte* loader_temp_code = (byte*)PTLSIM_THUNK_PAGE;

    info->initialize = 0;

    byte* p = (byte*)sys_mmap(loader_temp_code, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
    if (p != loader_temp_code) sys_exit(240);

    byte* loader_at_entry = (byte*)info->origrip;

    foreach (i, LOADER_THUNK_SIZE) loader_temp_code[i] = loader_at_entry[i];

    typedef void (*loader_func_t)(LoaderInfo* info);
    loader_func_t func = (loader_func_t)loader_temp_code;

    func(info);
  }

  byte* loader_at_entry = (byte*)info->origrip;

  int rc = sys_mprotect(floorptr(loader_at_entry, PAGE_SIZE), 2*PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
  if (rc) sys_exit(249);

  foreach (i, LOADER_THUNK_SIZE) loader_at_entry[i] = info->saved_thunk[i];

  int fd = sys_open(info->ptlsim_filename, O_RDONLY, 0);
  if (fd < 0) sys_exit(250);

  struct stat sd;
  rc = sys_fstat(fd, &sd);
  if (rc < 0) sys_exit(251);

  void* temp = (void*)sys_mmap(0, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);

  PTLsim_Elf_Ehdr* ehdr = (PTLsim_Elf_Ehdr*)temp;
  PTLsim_Elf_Phdr* phdr = (PTLsim_Elf_Phdr*)(((byte*)ehdr) + ehdr->e_phoff);

  W64 phdr_vaddr, phdr_filesz, phdr_memsz, phdr_offset;
  W64 image_base = floor(phdr->p_vaddr, PAGE_SIZE);

  while (phdr->p_type == PT_LOAD) {
    phdr_vaddr = floor(phdr->p_vaddr, PAGE_SIZE);
    phdr_filesz = phdr->p_filesz + (phdr->p_vaddr % PAGE_SIZE);
    phdr_offset = floor(phdr->p_offset, PAGE_SIZE);
    phdr_memsz = phdr->p_memsz + (phdr->p_vaddr % PAGE_SIZE);

    byte* baseaddr = (byte*)sys_mmap((void*)phdr_vaddr, ceil(phdr_filesz, PAGE_SIZE), PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED, fd, phdr_offset);
    if ((W64)baseaddr != phdr_vaddr) { sys_exit(253); }

    phdr++;
  }

  phdr--;

  // Zero-fill remainder of page
  byte* p = (byte*)(phdr_vaddr + phdr_filesz);
  byte* bssp = (byte*)ceil(phdr_vaddr + phdr_filesz, PAGE_SIZE);
  while (p < bssp) *p++ = 0;

  byte* endp = (byte*)ceil(phdr_vaddr + phdr_memsz, PAGE_SIZE);

  // Map zero pages for remainder of segment
  byte* bssaddr = (byte*)sys_mmap(bssp, endp - bssp, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);

  if (bssaddr != bssp) sys_exit(254);

  // ELF header can now be accessed at base of PTLsim image:
  ehdr = (PTLsim_Elf_Ehdr*)image_base;

  void* func = (void*)ehdr->e_entry;

  // Patch PTLsim ELF header's e_entry field with original rip so we can get at it later
  ehdr->e_entry = info->origrip;
  // Patch PTLsim ELF header's e_machine field so we know what ISA (IA32 or x86-64) the
  // target address space originally used before we switched to PTLsim mode.
#ifdef __x86_64__
  ehdr->e_machine = EM_X86_64;
#else
  ehdr->e_machine = EM_386;
#endif
  // Tell PTLsim it's running inside of target process address space now:
  ehdr->e_type = ET_PTLSIM;
  // Update the PTLsim version
  ehdr->e_version = sd.st_mtime;
  sys_munmap(temp, PAGE_SIZE);
  sys_close(fd);

  switch_stack_and_jump(func, (void*)info->origrsp, true);
}
