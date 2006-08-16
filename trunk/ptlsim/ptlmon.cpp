//
// PTLsim: Cycle Accurate x86-64 Simulator
// PTLxen monitor and control program running in dom0
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <config.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

typedef W16 domid_t;

#include <xen-types.h>
#include <xen/linux/privcmd.h>
#include <xen/linux/evtchn.h>

#define EXCLUDE_BOOTINFO_SHINFO
#include <ptlxen.h>

asmlinkage {
#include <xenctrl.h>
};

#include <xen/io/console.h>

#undef DEBUG

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

static inline W32 do_syscall_32bit(W32 sysid, W32 arg1, W32 arg2, W32 arg3, W32 arg4, W32 arg5, W32 arg6) {
  W32 rc;
  asm volatile ("push %%rbp ; movl %[arg6],%%ebp ; int $0x80 ; pop %%rbp" : "=a" (rc) :
                "a" (sysid), "b" (arg1), "c" (arg2), "d" (arg3),
                "S" (arg4), "D" (arg5), [arg6] "r" (arg6));
  return rc;
}

static int do_privcmd(int xc_handle, unsigned int cmd, unsigned long data) {
  return ioctl(xc_handle, cmd, data);
}

int do_xen_hypercall(int xc_handle, privcmd_hypercall_t *hypercall) {
  return do_privcmd(xc_handle, IOCTL_PRIVCMD_HYPERCALL, (unsigned long)hypercall);
}

static int do_evtchn_op(int xc_handle, int cmd, void *arg, size_t arg_size) {
  int ret = -1;
  privcmd_hypercall_t hypercall;
  
  hypercall.op     = __HYPERVISOR_event_channel_op;
  hypercall.arg[0] = cmd;
  hypercall.arg[1] = (unsigned long)arg;
  
  if ( mlock(arg, arg_size) != 0 ) {
    goto out;
  }

  if ((ret = do_xen_hypercall(xc_handle, &hypercall)) < 0) {
    // cerr << "do_evtchn_op: HYPERVISOR_event_channel_op failed: ", ret, ", errno ", errno, " (", strerror(errno), ")", endl;
  }

  munlock(arg, arg_size);
  out:
  return ret;
}

static int xc_alloc_unbound(int xc, int domfrom, int domto) {
  evtchn_alloc_unbound_t req;
  req.dom = domto;
  req.remote_dom = domfrom;
  int rc = do_evtchn_op(xc, EVTCHNOP_alloc_unbound, &req, sizeof(req));
  cout << "Result: ", rc, " vs port ", req.port, endl;
  return (rc < 0) ? rc : req.port;
}

static int xc_bind_interdomain(int xc, int remotedom, int remoteport) {
  evtchn_bind_interdomain_t req;
  req.remote_dom = remotedom;
  req.remote_port = remoteport;
  int rc = do_evtchn_op(xc, EVTCHNOP_bind_interdomain, &req, sizeof(req));
  return (rc < 0) ? rc : req.local_port;
}

static int xc_send(int xc, int localport) {
  evtchn_send_t req;
  req.port = localport;
  int rc = do_evtchn_op(xc, EVTCHNOP_send, &req, sizeof(req));
  return rc;
}

static int xc_evtchn_unmask(int xc, int localport) {
  evtchn_unmask_t req;
  req.port = localport;
  int rc = do_evtchn_op(xc, EVTCHNOP_unmask, &req, sizeof(req));
  return rc;
}

#define barrier() asm volatile("": : :"memory")

#if defined(__i386__)

#define L1_PAGETABLE_SHIFT_PAE	12
#define L2_PAGETABLE_SHIFT_PAE	21
#define L3_PAGETABLE_SHIFT_PAE	30

#define L1_PAGETABLE_SHIFT		12
#define L2_PAGETABLE_SHIFT		22

#define L0_PAGETABLE_MASK_PAE	0x0000000ffffff000ULL
#define L1_PAGETABLE_MASK_PAE	0x1ffULL
#define L2_PAGETABLE_MASK_PAE	0x1ffULL
#define L3_PAGETABLE_MASK_PAE	0x3ULL

#define L0_PAGETABLE_MASK		0xfffff000ULL
#define L1_PAGETABLE_MASK		0x3ffULL
#define L2_PAGETABLE_MASK		0x3ffULL

#elif defined(__x86_64__)

#define L1_PAGETABLE_SHIFT_PAE	12
#define L2_PAGETABLE_SHIFT_PAE	21
#define L3_PAGETABLE_SHIFT_PAE	30
#define L4_PAGETABLE_SHIFT_PAE	39

#define L1_PAGETABLE_SHIFT		L1_PAGETABLE_SHIFT_PAE
#define L2_PAGETABLE_SHIFT		L2_PAGETABLE_SHIFT_PAE

#define L0_PAGETABLE_MASK_PAE	0x000000fffffff000ULL
#define L1_PAGETABLE_MASK_PAE	0x1ffULL
#define L2_PAGETABLE_MASK_PAE	0x1ffULL
#define L3_PAGETABLE_MASK_PAE	0x1ffULL
#define L4_PAGETABLE_MASK_PAE	0x1ffULL

#define L0_PAGETABLE_MASK		L0_PAGETABLE_MASK_PAE
#define L1_PAGETABLE_MASK		L1_PAGETABLE_MASK_PAE
#define L2_PAGETABLE_MASK		L2_PAGETABLE_MASK_PAE

#endif

#define mmap_invalid(addr) (((W64)(addr) & 0xfffffffffffff000) == 0xfffffffffffff000)
#define mmap_valid(addr) (!mmap_invalid(addr))

#define PTL_PAGE_POOL_BASE 0x70000000LL

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

void* ptl_alloc_private_pages(Waddr bytecount, int prot, Waddr base = 0, int extraflags = 0) {
  int flags = MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : 0);
  //flags |= (inside_ptlsim) ? MAP_SHARED : MAP_PRIVATE;
  flags |= MAP_PRIVATE;
  flags |= extraflags;
  if (base == 0) base = PTL_PAGE_POOL_BASE;
  void* addr = sys_mmap((void*)base, ceil(bytecount, PAGE_SIZE), prot, flags, 0, 0);

  return addr;
}

void* ptl_alloc_private_page() {
  return ptl_alloc_private_pages(4096, PROT_READ|PROT_WRITE|PROT_EXEC);
}

void* ptl_alloc_private_32bit_pages(Waddr bytecount, int prot, Waddr base) {
#ifdef __x86_64__
  int flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : MAP_32BIT);
#else
  int flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : 0);
#endif
  return sys_mmap((void*)base, ceil(bytecount, PAGE_SIZE), prot, flags, 0, 0);  
}

bool ptl_lock_private_pages(void* addr, Waddr bytecount) {
  return (mlock(addr, bytecount) == 0);
}

bool ptl_unlock_private_pages(void* addr, Waddr bytecount) {
  return (munlock(addr, bytecount) == 0);
}

void ptl_free_private_pages(void* addr, Waddr bytecount) {
  sys_munmap(addr, bytecount);
}

void ptl_free_private_page(void* addr) {
  ptl_free_private_pages(addr, 4096);
}

void ptl_zero_private_pages(void* addr, Waddr bytecount) {
  sys_madvise((void*)floor((Waddr)addr, PAGE_SIZE), bytecount, MADV_DONTNEED);
}

#define PSL_T 0x00000100 // single step bit in eflags

// This is from ptlxen.bin.o:
extern byte _binary_ptlxen_bin_start;
extern byte _binary_ptlxen_bin_end;

struct PendingRequest {
  W64 uuid;
  int fd;
  char* data;

  void init(int i) { data = null; }
  void validate() { }
};

Queue<PendingRequest, 16> requestq;

Hashtable<W64, PendingRequest, 16> pendingreqs;

struct XenController;

void complete_upcall(XenController& xc, W64 uuid);

ostream& operator <<(ostream& os, const xencons_interface& console) {
  os << "Console page:", endl;
  os << "  Input  ring (console -> guest): head ", intstring(console.in_cons, 4),  " to tail ", intstring(console.in_prod, 4), endl;
  os << "  Output ring (guest -> console): head ", intstring(console.out_cons, 4), " to tail ", intstring(console.out_prod, 4), endl;

  os << "  Input data:", endl, flush;
  os << "  ";
  for (int i = (console.in_cons % sizeof(console.in)); i != (console.in_prod % sizeof(console.in)); i = ((i + 1) % sizeof(console.in))) os << console.in[i];
  os << endl;

  os << "  Output data:", endl, flush;
  os << "  ";
  for (int i = console.out_cons % sizeof(console.out); i != (console.out_prod % sizeof(console.out)); i = ((i + 1) % sizeof(console.out))) os << console.out[i];
  os << endl;

  os << flush;
  return os;
}

static inline bool thunk_ptr_valid(Waddr w) {
  //Waddr w = (Waddr)p;
  return (inrange(w, (Waddr)PTLSIM_XFER_PAGE_VIRT_BASE, PTLSIM_XFER_PAGE_VIRT_BASE+4095));
}

struct XenController {
  int xc;
  int domain;
  mfn_t* pagelist;
  W64 pagecount;
  W64 maxpages;
  cpumap_t cpus;
  xc_domaininfo_t info;

  shared_info_t* shinfo;

  Level4PTE* toplevel_page_table;

  //Level1PTE* ptes;
  //int ptes_page_count;

  //Level1PTE* phys_ptes;
  //int phys_ptes_page_count;

  byte* image;
  int ptl_page_count;
  int ptl_pagedir_mfn_count;
  int ptl_remaining_pages;
  int shared_map_page_count;

  mfn_t* pagedir_mfns;
  mfn_t* pagedir_map_mfns;

  shared_info_t* shadow_shinfo;

  PTLsimMonitorInfo* bootinfo;

  int vcpu_count;
  int vcpu_online_count;

  int evtchnfd;
  int ptlsim_hostcall_port;
  int ptlsim_upcall_port;

  W64 total_machine_pages;
  W64 xen_hypervisor_start_va;
  int page_table_levels;

  //Context* frozen_ptlctx;
  //Context* frozen_guestctx;

  Context* ctx;
  //Context* frozen_ptlctx;
  //Context* frozen_guestctx;

  xencons_interface* console;

  XenController() { reset(); }

  void reset() {
    xc = -1; domain = -1; pagelist = 0; pagecount = 0; ptlsim_hostcall_port = -1;
    shinfo = null;
    bootinfo = null;
    //frozen_ptlctx = null;
    //frozen_guestctx = null;
    ctx = null;
    console = null;
  }

  void* map_pages(mfn_t* mfns, size_t count, int prot = PROT_READ, void* base = null, int flags = 0) {
    if (base) flags |= MAP_FIXED;
    void* addr = mmap(base, count * PAGE_SIZE, prot, flags | MAP_SHARED, xc, 0);

    if (mmap_invalid(addr)) return null;

    privcmd_mmapbatch_t ioctlx; 
    ioctlx.num = count;
    ioctlx.dom = domain;
    ioctlx.addr = (unsigned long)addr;
    ioctlx.arr = mfns;
    int rc = ioctl(xc, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);

    if (rc < 0) {
      cout << "ERROR: XenController::map_pages() failed: errno = ", strerror(errno), endl, flush;
      munmap(addr, count * PAGE_SIZE);
      return null;
    }
    return addr;
  }

  byte* map_page(mfn_t mfn, int prot = PROT_READ, void* addr = null) {
    mfn_t mfns[1];
    mfns[0] = mfn;

    return (byte*)map_pages(mfns, 1, prot, addr);
  }

  void unmap_pages(void* virt, int count) {
    int rc = munmap(virt, count * PAGE_SIZE);
    if (rc < 0) {
      cout << "unmap_pages(", virt, ", ", count, "): rc = ", rc, ", errno ", strerror(errno), endl, flush;
      assert(false);
    }
  }

  void unmap_page(void* virt) {
    unmap_pages(virt, 1);
  }

  pfn_t ptl_virt_to_pfn(void* virt) {
    Waddr offset = (Waddr)virt - (Waddr)image;
    assert(inrange(offset, (Waddr)0, (Waddr)((ptl_page_count*PAGE_SIZE)-1)));
    return offset >> 12;
  }

  mfn_t ptl_virt_to_mfn(void* virt) {
    return pagedir_mfns[ptl_virt_to_pfn(virt)];

    /*
    W64 pfn = ((Waddr)virt) >> log2(PAGE_SIZE);
    W64 pfn_lo = ((Waddr)image) >> log2(PAGE_SIZE);
    W64 pfn_hi = pfn_lo + ptl_page_count - 1;
    // cout << "ptl_virt_to_mfn(", virt, "): pfn ", pfn, " vs [", pfn_lo, " to ", pfn_hi, "], rel ", (pfn - pfn_lo), endl, flush;
    if (!inrange(pfn, pfn_lo, pfn_hi)) {
      assert(false);
      return INVALID_MFN;
    }
    return pagedir_mfns[pfn - pfn_lo];
    */
  }

  bool map_ptlsim_pages(shared_info_t* shinfo) {    
    static const bool DEBUG = 0;

    PTLsimStub* stub = (PTLsimStub*)(((byte*)shinfo) + PAGE_SIZE - sizeof(PTLsimStub));
    if (stub->magic != PTLSIM_STUB_MAGIC) {
      cerr << endl;
      cerr << "PTLsim error: domain ", domain, " does not have any physical memory reserved for PTLsim.", endl,
        endl,
        "Please use the reservedmem=xxx option in the domain config file, or use", endl,
        "the 'xm restore <filename> --reserve xxx' option to reserve the specified", endl,
        "number of megabytes and hide it from the guest OS. At least 32 MB is required.", endl,
        endl;

      return false;
    }

    bootinfo = (PTLsimMonitorInfo*)map_page(stub->boot_page_mfn);
    assert(bootinfo);

    assert(bootinfo->magic == PTLSIM_BOOT_PAGE_MAGIC);

    ptl_page_count = bootinfo->mfn_count;
    ptl_remaining_pages = bootinfo->avail_mfn_count;

    if (DEBUG) cerr << "Map pagedir map mfn ", bootinfo->ptl_pagedir_map_mfn, endl, flush;
    Level2PTE* pagedir_map_ptes = (Level2PTE*)map_page(bootinfo->ptl_pagedir_map_mfn);
    assert(pagedir_map_ptes);

    if (DEBUG) cerr << "pagedir_map_ptes = ", pagedir_map_ptes, endl, flush;

    if (DEBUG) cerr << "ptl_pagedir_mfn_count = ", bootinfo->ptl_pagedir_mfn_count, endl, flush;

    pagedir_map_mfns = new mfn_t[bootinfo->ptl_pagedir_mfn_count];
    foreach (i, bootinfo->ptl_pagedir_mfn_count) { pagedir_map_mfns[i] = pagedir_map_ptes[i].mfn; }

    if (DEBUG) cerr << "OK copied", endl, flush;

    unmap_page(pagedir_map_ptes);

    if (DEBUG) cerr << "OK unmapped", endl, flush;

    if (DEBUG) {
      foreach (i, bootinfo->ptl_pagedir_mfn_count) {
        cerr << "  pagedir page ", intstring(i, 8), " -> mfn ", intstring(pagedir_map_mfns[i], 8), endl;
      }
    }

    Level1PTE* ptes = (Level1PTE*)map_pages(pagedir_map_mfns, bootinfo->ptl_pagedir_mfn_count, PROT_READ);

    if (DEBUG) cerr << "ptes = ", ptes, endl, flush;
    assert(ptes);

    //delete[] pagedir_map_mfns;

    pagedir_mfns = new mfn_t[ptl_page_count];
    if (DEBUG) cerr << "pagedir_mfns = ", pagedir_mfns, endl, flush;

    foreach (i, ptl_page_count) pagedir_mfns[i] = ptes[i].mfn;

    PTLsimBootPageInfo* newbootinfo = ptlcore_ptr_to_ptlmon_ptr(bootinfo->boot_page);

    unmap_pages(ptes, bootinfo->ptl_pagedir_mfn_count);

    //
    //++MTY TODO: Start r/o map at PTLSIM_FIRST_READ_ONLY_PAGE!!!!
    // BUT, we need to load the PTLsim image and zero bss, so we may need to redo this boundary later.
    // Map in three parts: first 16 KB, rest of image up to ptl_remaining_pages, and last PT part. 
    //
    /*
    Waddr first_region_base_page = 0;
    byte* first_region_base_addr = (byte*)PTLSIM_PSEUDO_VIRT_BASE + (first_region_base_page * PAGE_SIZE);
    Waddr first_region_pages = PTLSIM_FIRST_READ_ONLY_PAGE;
    Waddr first_region_bytes = first_region_pages * 4096;

    image = (byte*)PTLSIM_PSEUDO_VIRT_BASE;

    if (DEBUG) cerr << "Remap first ", first_region_pages, " pages as read/write at ", first_region_base_addr, " (page ", first_region_base_page, ")", endl, flush;
    assert((byte*)map_pages(pagedir_mfns + first_region_base_page, first_region_pages, PROT_READ|PROT_WRITE, first_region_base_addr, MAP_FIXED) == first_region_base_addr);
    bootinfo = (PTLsimMonitorInfo*)newbootinfo;

    Waddr middle_region_base_page = PTLSIM_FIRST_READ_ONLY_PAGE;
    byte* middle_region_base_addr = (byte*)PTLSIM_PSEUDO_VIRT_BASE + (middle_region_base_page * PAGE_SIZE);
    Waddr middle_region_pages = (bootinfo->avail_mfn_count - PTLSIM_FIRST_READ_ONLY_PAGE);

    if (DEBUG) cerr << "Remap middle ", middle_region_pages, " pages as read/write at ", middle_region_base_addr, " (page ", middle_region_base_page, ")", endl, flush;
    assert((byte*)map_pages(pagedir_mfns + middle_region_base_page, middle_region_pages, PROT_READ|PROT_WRITE, middle_region_base_addr, MAP_FIXED) == middle_region_base_addr);

    ptl_page_count = bootinfo->mfn_count;
    ptl_remaining_pages = bootinfo->avail_mfn_count;

    Waddr last_region_base_page = bootinfo->avail_mfn_count;
    byte* last_region_base_addr = (byte*)PTLSIM_PSEUDO_VIRT_BASE + (last_region_base_page * PAGE_SIZE);
    Waddr last_region_pages = (bootinfo->mfn_count - bootinfo->avail_mfn_count);

    if (DEBUG) cerr << "Remap last ", last_region_pages, " pages as read only at ", last_region_base_addr, " (page ", last_region_base_page, ")", endl, flush;
    assert((byte*)map_pages(pagedir_mfns + last_region_base_page, last_region_pages, PROT_READ, last_region_base_addr, MAP_FIXED) == last_region_base_addr);

    toplevel_page_table = ptlcore_ptr_to_ptlmon_ptr(bootinfo->toplevel_page_table);
    if (DEBUG) cerr << "toplevel_page_table = ", toplevel_page_table, " (mfn ", ptl_virt_to_mfn(toplevel_page_table), ")", endl;
    if (DEBUG) cerr << "toplevel_page_table_mfn = ", bootinfo->toplevel_page_table_mfn, endl, flush;
    if (DEBUG) cerr << "ptl_pagedir_map_mfn = ", bootinfo->ptl_pagedir_map_mfn, endl, flush;
    assert(bootinfo->toplevel_page_table_mfn == ptl_virt_to_mfn(toplevel_page_table));
    assert(bootinfo->magic == PTLSIM_BOOT_PAGE_MAGIC);
    */

    image = (byte*)PTLSIM_PSEUDO_VIRT_BASE;
    if (DEBUG) cerr << "Map ", bootinfo->mfn_count, " pages as read/write at ", image, " (page ", 0, ")", endl, flush;
    assert((Waddr)map_pages(pagedir_mfns, bootinfo->mfn_count, PROT_READ|PROT_WRITE, (void*)PTLSIM_PSEUDO_VIRT_BASE, MAP_FIXED) == PTLSIM_PSEUDO_VIRT_BASE);
    unmap_page(bootinfo);
    bootinfo = (PTLsimMonitorInfo*)newbootinfo;

    ptl_page_count = bootinfo->mfn_count;
    ptl_pagedir_mfn_count = bootinfo->ptl_pagedir_mfn_count;
    ptl_remaining_pages = bootinfo->avail_mfn_count;

    toplevel_page_table = ptlcore_ptr_to_ptlmon_ptr(bootinfo->toplevel_page_table);
    if (DEBUG) cerr << "toplevel_page_table = ", toplevel_page_table, " (mfn ", ptl_virt_to_mfn(toplevel_page_table), ")", endl;
    if (DEBUG) cerr << "toplevel_page_table_mfn = ", bootinfo->toplevel_page_table_mfn, endl, flush;
    if (DEBUG) cerr << "ptl_pagedir_map_mfn = ", bootinfo->ptl_pagedir_map_mfn, endl, flush;
    assert(bootinfo->toplevel_page_table_mfn == ptl_virt_to_mfn(toplevel_page_table));
    assert(bootinfo->magic == PTLSIM_BOOT_PAGE_MAGIC);

    if (config.console_mfn) {
      console = (xencons_interface*)map_page(config.console_mfn);
      cerr << "  Mapped console page mfn ", config.console_mfn, " to ", console, endl, flush;
    }

    if (DEBUG) {
      cerr << "PTLsim mapped at ", image, ":", endl;
      cerr << "Page counts:", endl;
      cerr << "  Total pages:      ", intstring(bootinfo->mfn_count, 8), endl;
      cerr << "  Remaining pages:  ", intstring(bootinfo->avail_mfn_count, 8), endl;
      cerr << "Addresses:", endl;
      cerr << "  Base:             ", (void*)image, endl;
      cerr << flush;
    }

    return true;
  }

  int pin_page_table_page(void* virt, int level) {
    assert(inrange(level, 0, 4));
    
    // Was it in PTLsim space?
    mfn_t mfn = ptl_virt_to_mfn(virt);
    cerr << "pinning mfn ", mfn, " (virt ", virt, "): level ", level, endl, flush;

    if (mfn == INVALID_MFN) return -1;
    
    int level_to_function[5] = {MMUEXT_UNPIN_TABLE, MMUEXT_PIN_L1_TABLE, MMUEXT_PIN_L2_TABLE, MMUEXT_PIN_L3_TABLE, MMUEXT_PIN_L4_TABLE};
    int func = level_to_function[level];
    
    int rc = 0;
    mmuext_op op;
    op.cmd = func;
    op.arg1.mfn = mfn;

    // Pages can only be pinned once!
    rc = xc_mmuext_op(xc, &op, 1, domain);
    return rc;
  }

  int pin_page_table_mfns(const mfn_t* mfns, int count, int level) {
    assert(inrange(level, 0, 4));
    
    int level_to_function[5] = {MMUEXT_UNPIN_TABLE, MMUEXT_PIN_L1_TABLE, MMUEXT_PIN_L2_TABLE, MMUEXT_PIN_L3_TABLE, MMUEXT_PIN_L4_TABLE};
    int func = level_to_function[level];
    
    mmuext_op* ops = new mmuext_op[count];
    foreach (i, count) {
      // cerr << "Pin mfn ", mfns[i], " as level ", level, endl, flush;
      ops[i].cmd = func;
      ops[i].arg1.mfn = mfns[i];
    }

    // Pages can only be pinned once!
    int rc = xc_mmuext_op(xc, ops, count, domain);
    //cerr << "Pin rc = ", rc, endl, flush;

    delete[] ops;
    return rc;
  }

  int pin_page_table_mfn(mfn_t mfn, int level) {
    return pin_page_table_mfns(&mfn, 1, level);
  }

  /*
  void pin_page_table_page(void* virt, int level) {
    assert(false);
    return;

    Level1PTE* ptes = (Level1PTE*)virt;
    assert(inrange(level, 1, 4));
    mfn_t mfn = ptl_virt_to_mfn(ptes);
    assert(mfn != INVALID_MFN);

    cout << "pin_page_table_page(", ptes, ", level ", level, ") => mfn ", mfn, endl, flush;

    int level_to_function[4] = {MMUEXT_PIN_L1_TABLE, MMUEXT_PIN_L2_TABLE, MMUEXT_PIN_L3_TABLE, MMUEXT_PIN_L4_TABLE};
    int func = level_to_function[level - 1];

    int rc = 0;
    mmuext_op op;

    // First unpin the table (this is absolutely required):
    op.cmd = MMUEXT_UNPIN_TABLE;
    op.arg1.mfn = mfn;
    rc = xc_mmuext_op(xc, &op, 1, domain);
    if (rc < 0) {
      cout << "Warning: while unpinning mfn ", mfn, ": MMUEXT_UNPIN_TABLE failed (probably not pinned)", endl;
    }

    op.cmd = func;
    op.arg1.mfn = mfn;

    // Pages can only be pinned once!
    rc = xc_mmuext_op(xc, &op, 1, domain);

    if (rc < 0) {
      cout << "ERROR: pin_page_table_page(", ptes, ", level ", level, ") (mfn ", mfn, "): rc = ", rc, endl, flush;
      if (level == 1) {
        print_page_table(cout, (Level1PTE*)ptes, prefix);
      }
      cout.flush();

      assert(false);
    }
  }
  */
  /*
  byte* alloc_page_from_end(mfn_t& mfn) {
    assert(ptl_remaining_pages > 0);
    ptl_remaining_pages--;
    byte* addr = image + (ptl_remaining_pages * PAGE_SIZE);
    cout << "alloc_page_from_end(): alloc page ", ptl_remaining_pages, ", virt ", addr, endl, flush;
    mfn = ptl_virt_to_mfn(addr);
    cout << "alloc_page_from_end(): alloc page ", ptl_remaining_pages, ", virt ", addr, ", mfn ", mfn, endl, flush; 
    memset(addr, 0, PAGE_SIZE);
    return addr;
  }
  */
  /*
  void pin_page_table_page(void* virt, W64 prefix, int level) {
    assert(false);
    return;

    Level1PTE* ptes = (Level1PTE*)virt;
    assert(inrange(level, 1, 4));
    mfn_t mfn = ptl_virt_to_mfn(ptes);
    assert(mfn != INVALID_MFN);

    cout << "pin_page_table_page(", ptes, ", level ", level, ") => mfn ", mfn, endl, flush;

    int level_to_function[4] = {MMUEXT_PIN_L1_TABLE, MMUEXT_PIN_L2_TABLE, MMUEXT_PIN_L3_TABLE, MMUEXT_PIN_L4_TABLE};
    int func = level_to_function[level - 1];

    int rc = 0;
    mmuext_op op;

    // First unpin the table (this is absolutely required):
    op.cmd = MMUEXT_UNPIN_TABLE;
    op.arg1.mfn = mfn;
    rc = xc_mmuext_op(xc, &op, 1, domain);
    if (rc < 0) {
      cout << "Warning: while unpinning mfn ", mfn, ": MMUEXT_UNPIN_TABLE failed (probably not pinned)", endl;
    }

    op.cmd = func;
    op.arg1.mfn = mfn;

    // Pages can only be pinned once!
    rc = xc_mmuext_op(xc, &op, 1, domain);

    if (rc < 0) {
      cout << "ERROR: pin_page_table_page(", ptes, ", level ", level, ") (mfn ", mfn, "): rc = ", rc, endl, flush;
      if (level == 1) {
        print_page_table(cout, (Level1PTE*)ptes, prefix);
      }
      cout.flush();

      assert(false);
    }
  }
  */

  bool attach(int domain) {
    static const bool DEBUG = config.log_ptlsim_boot;

    int rc;

    reset();

    this->domain = domain;
    xc = xc_interface_open();
    if (xc < 0) {
      cerr << endl;
      cerr << "PTLsim error: cannot connect to Xen hypervisor (xc_interface_open failed: rc ", xc, ")", endl,
        endl,
        "Please make sure you are running as root, the machine is running under Xen,", endl,
        "and the appropriate Xen libraries are installed.", endl, endl;

      return false;
    }

    xen_capabilities_info_t xen_caps = "";
    xen_platform_parameters_t xen_params;

    assert(xc_version(xc, XENVER_platform_parameters, &xen_params) == 0);
    assert(xc_version(xc, XENVER_capabilities, &xen_caps) == 0);

    total_machine_pages = xc_memory_op(xc, XENMEM_maximum_ram_page, NULL);
    assert(total_machine_pages > 0);

    xen_hypervisor_start_va = xen_params.virt_start;

    if (strstr(xen_caps, "xen-3.0-x86_64"))
      page_table_levels = 4;
    else if (strstr(xen_caps, "xen-3.0-x86_32p"))
      page_table_levels = 3; 
    else if (strstr(xen_caps, "xen-3.0-x86_32"))
      page_table_levels = 2; 
    else {
      cerr << "XenController: hypervisor version or capabilities '", xen_caps, "' not supported", endl; 
      return false;
    }

    if (!strstr(xen_caps, "ptl")) {
      cerr << endl;
      cerr << "PTLsim error: the Xen hypervisor on this machine does not support", endl,
        "the required PTLsim extensions. Please apply the PTLsim patch to", endl,
        "enable these features. The installed Xen version is ", xen_caps, endl, endl;
      return false;
    }

    if (DEBUG) {
      cerr << "Xen Information:", endl;
      cerr << "  Running on Xen version ", xen_caps, endl;
      cerr << "  Total machine physical pages: ", total_machine_pages, " (", ((total_machine_pages * PAGE_SIZE) / 1024), " KB host physical memory)", endl;
      cerr << "  Xen is mapped at virtual address ", (void*)(Waddr)xen_hypervisor_start_va, endl;
      cerr << "  Page table has ", page_table_levels, " levels", endl;
    }

    //
    // Attach to target domain
    //
    dom0_op_t op;

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = domain;
    rc = xc_dom0_op(xc, &op);

    memcpy(&info, &op.u.getdomaininfo, sizeof(info));
    vcpu_count = info.max_vcpu_id + 1;
    vcpu_online_count = info.nr_online_vcpus;

    if (rc | (info.domain != domain)) {
      cerr << endl;
      cerr << "PTLsim error: cannot access domain ", domain, " (error ", rc, ")", endl,
        "Please make sure the specified domain is running.", endl, endl;
      return false;
    }

    if (DEBUG) cerr << "PTLsim has connected to domain ", domain, ":", endl;

    if (info.flags & DOMFLAGS_PAUSED) {
      //cerr << "  Domain was already paused", endl;
    } else if ((rc = xc_domain_pause(xc, domain))) {
      cerr << "XenController: PAUSE failed (", rc, ")", endl;
      return false;
    }

    maxpages = info.tot_pages;

    shinfo = (shared_info_t*)map_page(info.shared_info_frame, PROT_READ|PROT_WRITE);

    if(!shinfo) {
      cerr << "XenController: xc_map_foreign_range(info.shared_info_frame ", info.shared_info_frame, ") failed", endl;
      return false;
    }

    int max_pfn = shinfo->arch.max_pfn;

    if (DEBUG) {
      cerr << "  ", vcpu_online_count, " out of ", vcpu_count, " VCPUs online", endl;
      cerr << "  ", info.tot_pages, " total pages (", ((info.tot_pages * 4096) / (1024 * 1024)), " MB), limit ", ((info.tot_pages * 4096) / (1024 * 1024)), " MB", endl;
      cerr << "  ", "Shared info mfn ", info.shared_info_frame, endl;
    }

    return map_ptlsim_pages(shinfo);
  }

  /*
  W64 virt_to_mfn(W64 toplevel_mfn, W64 rawvirt) {
    VirtAddr virt(rawvirt);
    Level4PTE* level4_base = null;
    Level3PTE* level3_base = null;
    Level2PTE* level2_base = null;
    Level1PTE* level1_base = null;

    Level4PTE level4;
    Level3PTE level3;
    Level2PTE level2;
    Level1PTE level1;

    // cout << "Translating virt ", (void*)rawvirt, " (vpn ", (rawvirt >> 12), ") using toplevel mfn ", toplevel_mfn, ":", endl;

    level4_base = (Level4PTE*)map_page(toplevel_mfn);
    level4 = level4_base[virt.lm.level4];
    // cout << "  Level 4: mfn ", intstring(toplevel_mfn, 12), ", pte ", intstring(virt.lm.level4, 4), " -> ", level4, endl;
    if (!level4.p) goto out_level4;

    level3_base = (Level3PTE*)map_page(level4.mfn);
    level3 = level3_base[virt.lm.level3];
    // cout << "  Level 3: mfn ", intstring(level4.mfn, 12), ", pte ", intstring(virt.lm.level3, 4), " -> ", level3, endl;

    if (!level3.p) goto out_level3;

    level2_base = (Level2PTE*)map_page(level3.mfn);
    level2 = level2_base[virt.lm.level2];
    // cout << "  Level 2: mfn ", intstring(level3.mfn, 12), ", pte ", intstring(virt.lm.level2, 4), " -> ", level2, endl;

    if (!level2.p) goto out_level2;
    if (level2.psz) {
      W64 mfn = level2.mfn;
      unmap_page(level4_base);
      unmap_page(level3_base);
      unmap_page(level2_base);
      return mfn; // 2MB/4MB huge pages
    }

    level1_base = (Level1PTE*)map_page(level2.mfn);
    level1 = level1_base[virt.lm.level1];
    // cout << "  Level 1: mfn ", intstring(level2.mfn, 12), ", pte ", intstring(virt.lm.level1, 4), " -> ", level1, endl;

    if (!level1.p) goto out_level1;

    // cout << "  Final: mfn ", intstring(level1.mfn, 12), endl;

    return level1.mfn;

  out_level1:
    unmap_page(level1_base);
  out_level2:
    unmap_page(level2_base);
  out_level3:
    unmap_page(level3_base);
  out_level4:
    unmap_page(level4_base);
    return INVALID_MFN;
  }
  */

  void inject_ptlsim_into_ptbase(mfn_t mfn) {
    int rc;
    int slot = VirtAddr(PTLSIM_VIRT_BASE).lm.level4;
    Level4PTE newpte;
    newpte = 0;
    newpte.p = 1;
    newpte.rw = 1;
    newpte.us = 1;
    newpte.nx = 0;
    newpte.a = 1;
    newpte.mfn = bootinfo->ptl_level3_mfn;

    cerr << "Inject PTLsim page table (L3 top mfn ", bootinfo->ptl_level3_mfn, ") into mfn ", mfn, " slot ", slot, ": ", newpte, endl, flush;

    //rc = pin_page_table_mfn(mfn, 0);
    //cerr << "unpin rc = ", rc, endl, flush;

    mmu_update_t update;
    update.ptr = (mfn << 12) + (slot * 8);
    cerr << "pte phys addr ", (void*)update.ptr, endl, flush;
    update.val = 0; //newpte;

    int updatecount = 0;
    privcmd_hypercall_t hypercall;
    hypercall.op     = __HYPERVISOR_mmu_update;
    hypercall.arg[0] = (u64)&update;
    hypercall.arg[1] = 1;
    hypercall.arg[2] = (u64)&updatecount;
    hypercall.arg[3] = domain;

    assert(mlock(&update, sizeof(update)) == 0);

    rc = do_xen_hypercall(xc, &hypercall);

    if (rc) cerr << "ERROR: mmu_update rc = ", rc, endl, flush;

    munlock(&update, sizeof(update));

    /*
    xc_mmu_t* mmu = xc_init_mmu_updates(xc, domain);
    assert(mmu);

    int rc = xc_add_mmu_update(xc, mmu, update.ptr, update.val);
    cerr << "add rc = ", rc, endl, flush;
    
    rc = xc_finish_mmu_updates(xc, mmu);

    cerr << "finish rc = ", rc, endl, flush;
    */
  }

  //
  // Prepare the initial PTLsim entry context
  //
  void prep_initial_context(Context* ctx, int vcpu_count) {
    //
    //++MTY TODO: Put all other VCPUs into spin state (i.e. blocked)
    //

    foreach (i, vcpu_count) {
      Context& ptlctx = ctx[i];
      // These are filled in later on a per-VCPU basis.
      // ptlctx.user_regs.rip = ehdr.e_entry;
      // ptlctx.user_regs.rsp = (Waddr)sp;
      // ptlctx.user_regs.rdi = (Waddr)si; // start info in %rdi (arg[0])
      //memset(ptlctx, 0, sizeof(ptlctx));

      // Use as a template:
      getcontext(i, ptlctx);
      //cerr << "VCPU ", i, " has current page table base mfn ", (ptlctx.cr3 >> 12), endl, flush;
      //cerr << ptlctx;

      //inject_ptlsim_into_ptbase(ptlctx.cr3 >> 12);

      ptlctx.cr3 = (ptl_virt_to_mfn(toplevel_page_table) << log2(PAGE_SIZE));
      ptlctx.kernel_ptbase_mfn = ptlctx.cr3 >> 12;
      ptlctx.user_ptbase_mfn = ptlctx.cr3 >> 12;

      ptlctx.kernel_mode = 1;
      ptlctx.seg[SEGID_CS].selector = FLAT_KERNEL_CS;
      ptlctx.seg[SEGID_DS].selector = FLAT_KERNEL_DS;
      ptlctx.seg[SEGID_SS].selector = FLAT_KERNEL_SS;
      ptlctx.seg[SEGID_ES].selector = FLAT_KERNEL_DS;
      ptlctx.seg[SEGID_FS].selector = 0;
      ptlctx.seg[SEGID_GS].selector = 0;
      ptlctx.commitarf[REG_flags] = 0; // 1<<9 (set interrupt flag)
      ptlctx.saved_upcall_mask = 1;

      memset(ptlctx.idt, 0, sizeof(ptlctx.idt));

#if defined(__i386__)
      ptlctx.event_callback_cs     = FLAT_KERNEL_CS;
      ptlctx.event_callback_rip    = 0;
      ptlctx.failsafe_callback_cs  = FLAT_KERNEL_CS;
      ptlctx.failsafe_callback_rip = 0;
#elif defined(__x86_64__)
      ptlctx.event_callback_rip    = 0;
      ptlctx.failsafe_callback_rip = 0;
      ptlctx.syscall_rip = 0;
#endif
    }
  }

  bool inject_ptlsim_image(int argc, char** argv, int stacksize) {
    static const bool DEBUG = config.log_ptlsim_boot;

    int rc;

    size_t bytes = &_binary_ptlxen_bin_end - &_binary_ptlxen_bin_start;
    const byte* data = &_binary_ptlxen_bin_start;
    const Elf64_Ehdr& ehdr = *(const Elf64_Ehdr*)data;
    const Elf64_Phdr* phdr = (const Elf64_Phdr*)(((const byte*)&ehdr) + ehdr.e_phoff);

    if (DEBUG) cerr << "Injecting PTLsim into domain ", domain, ":", endl;
    if (DEBUG) cerr << "  PTLcore is ", bytes, " bytes @ virt addr ", image, endl, flush;

    // Copy ELF header
    //memcpy(image, data, PTLSIM_BOOT_PAGE_PADDING);
    // Skip boot info page, hypercall page and shinfo
    Waddr real_code_start_offset = (ehdr.e_entry - PTLSIM_VIRT_BASE);
    shared_map_page_count = real_code_start_offset / PAGE_SIZE;

    int bytes_remaining = bytes - real_code_start_offset; //PTLSIM_ELF_SKIP_END;
    if (DEBUG) cerr << "  Real code starts at offset ", real_code_start_offset, endl;
    if (DEBUG) cerr << "  Bytes to copy: ", bytes_remaining, endl, flush;
    memcpy(image + real_code_start_offset, data + real_code_start_offset, bytes_remaining);

    //
    // Prepare the heap
    //
    byte* end_of_image = image + ceil(phdr[0].p_memsz, PAGE_SIZE);
    Waddr bss_size = phdr[0].p_memsz - phdr[0].p_filesz;
    if (DEBUG) cerr << "  PTLsim has ", ptl_remaining_pages, " pages left out of ", ptl_page_count, " pages allocated", endl;
    if (DEBUG) cerr << "  PTLxen file size ", phdr[0].p_filesz, ", virtual size ", phdr[0].p_memsz, ", end_of_image ", end_of_image, endl;
    if (DEBUG) cerr << "  Zero ", bss_size, " bss bytes starting at ", (image + phdr[0].p_filesz), endl, flush;
    memset(image + phdr[0].p_filesz, 0, bss_size);

    //
    // Set up stack
    //
    byte* sp = image + (ptl_remaining_pages * PAGE_SIZE);
    bootinfo->stack_top = ptlmon_ptr_to_ptlcore_ptr(sp);
    bootinfo->stack_size = stacksize;
    if (DEBUG) cerr << "  Setting up ", stacksize, "-byte stack starting at ", ptlmon_ptr_to_ptlcore_ptr(sp), endl, flush;

    //
    // Alocate virtual shinfo redirect page (for event recording and replay)
    //
    //sp = floorptr(sp, 4096);
    //sp -= PAGE_SIZE;
    //bootinfo->shadow_shinfo = PTLSIM_SHADOW_SHINFO_PAGE_VIRT_BASE;
    shadow_shinfo = ptlcore_ptr_to_ptlmon_ptr((shared_info_t*)PTLSIM_SHADOW_SHINFO_PAGE_VIRT_BASE);
    memcpy(shadow_shinfo, shinfo, PAGE_SIZE);
    if (DEBUG) cerr << "  Shadow shared info page at ", shadow_shinfo, endl, flush;

    //
    // Allocate VCPU contexts
    //
    //sp -= (vcpu_count * sizeof(Context));
    //sp = floorptr(sp, 4096);

    ctx = ptlcore_ptr_to_ptlmon_ptr((Context*)PTLSIM_CTX_PAGE_VIRT_BASE);
    if (DEBUG) cerr << "  Context array starts at ", ptlmon_ptr_to_ptlcore_ptr(ctx), " (", sizeof(Context), " bytes each)", endl, flush;

    /*
    //
    // Build command line arguments
    //

    sp -= (argc+1) * sizeof(char*);
    char** newargv = (char**)sp;

    bootinfo->argv = newargv;
    bootinfo->argc = argc;

    foreach (i, argc+1) {
      int n = strlen(argv[i])+1;
      sp -= n;
      memcpy(sp, argv[i], n);
      newargv[i] = (char*)sp;
    }
    */

    // Align sp to 16-byte boundary according to what gcc expects:
    sp = floorptr(sp, 16);

    bootinfo->heap_start = ptlmon_ptr_to_ptlcore_ptr(end_of_image);
    bootinfo->heap_end = bootinfo->stack_top - stacksize;
    if (DEBUG) cerr << "  Heap start ", bootinfo->heap_start, " to heap end ", bootinfo->heap_end, " (", ((bootinfo->heap_end - bootinfo->heap_start) / 1024), " kbytes)", endl;

    bootinfo->vcpu_count = vcpu_count;
    bootinfo->max_pages = info.max_pages;
    bootinfo->total_machine_pages = total_machine_pages;
    bootinfo->monitor_hostcall_port = ptlsim_hostcall_port;
    bootinfo->hostcall_port = -1; // will be filled in by PTLsim on connect
    bootinfo->monitor_upcall_port = ptlsim_upcall_port;
    bootinfo->upcall_port = -1; // will be filled in by PTLsim on connect
    bootinfo->hostreq.ready = 0;
    bootinfo->hostreq.op = PTLSIM_HOST_NOP;
    bootinfo->ptlsim_state = PTLSIM_STATE_INITIALIZING;
    bootinfo->queued_upcall_count = 0;
    bootinfo->hostreq.op = PTLSIM_HOST_NOP;
    // These will be filled in by PTLsim once it starts up:
    bootinfo->startup_log_buffer = null;
    bootinfo->startup_log_buffer_tail = 0;
    bootinfo->startup_log_buffer_size = 0;

    //
    // Set up hypercall page
    //
    {
      dom0_op_t dom0op;
      dom0op.u.hypercall_init.domain = domain;
      dom0op.u.hypercall_init.gmfn = pagedir_mfns[PTLSIM_HYPERCALL_PAGE_PFN];
      dom0op.cmd = DOM0_HYPERCALL_INIT;
      assert(xc_dom0_op(xc, &dom0op) == 0);
    }

    //
    // Set page protections correctly (can't have writable mappings to page table pages)
    //
    Level1PTE* l1ptes = ptlcore_ptr_to_ptlmon_ptr(bootinfo->ptl_pagedir);
    if (DEBUG) cerr << "  ", bootinfo->ptl_pagedir_mfn_count, " L1 ptes start at ", l1ptes, endl, flush;
    int first_l1_page = ptl_virt_to_pfn(l1ptes);

    foreach (i, bootinfo->ptl_pagedir_mfn_count) {
      // if (DEBUG) cerr << "  Make L1 pfn ", (first_l1_page + i), " read only", endl, flush;
      l1ptes[first_l1_page + i].rw = 0;
    }

    int l2_page = ptl_virt_to_pfn(ptlcore_ptr_to_ptlmon_ptr(bootinfo->ptl_pagedir_map));
    if (DEBUG) cerr << "  Make L2 pfn ", l2_page, " read only", endl, flush;
    l1ptes[l2_page].rw = 0;

    int l3_page = ptl_virt_to_pfn(ptlcore_ptr_to_ptlmon_ptr(bootinfo->ptl_level3_map));
    if (DEBUG) cerr << "  Make L3 pfn ", l3_page, " read only", endl, flush;
    l1ptes[l3_page].rw = 0;

    int l4_page = ptl_virt_to_pfn(ptlcore_ptr_to_ptlmon_ptr(bootinfo->toplevel_page_table));
    if (DEBUG) cerr << "  Make L4 pfn ", l4_page, " read only", endl, flush;
    l1ptes[l4_page].rw = 0;
    
    //
    // Unmap the read/write middle region and remap as read only (except for stack, which gets mapped read/write)
    //
    mfn_t ptl_level2_mfn = bootinfo->ptl_pagedir_map_mfn;
    mfn_t ptl_level3_mfn = bootinfo->ptl_level3_mfn;
    mfn_t toplevel_page_table_mfn = bootinfo->toplevel_page_table_mfn;

    if (DEBUG) cerr << "Unmap ", bootinfo->mfn_count, " pages at ", image, endl, flush;
    unmap_pages(image, bootinfo->mfn_count);

    //
    // NOTE! bootpage is no longer accessible at this point!
    //

    rc = pin_page_table_mfns(pagedir_map_mfns, ptl_pagedir_mfn_count, 1);
    //cerr << "L1 pin rc = ", rc, endl, flush;
    assert(rc == 0);

    rc = pin_page_table_mfn(ptl_level2_mfn, 2);
    //cerr << "L2 pin rc = ", rc, endl, flush;
    assert(rc == 0);

    rc = pin_page_table_mfn(ptl_level3_mfn, 3);
    //cerr << "L3 pin rc = ", rc, endl, flush;
    assert(rc == 0);

    rc = pin_page_table_mfn(toplevel_page_table_mfn, 4);
    //cerr << "L4 pin rc = ", rc, endl, flush;
    assert(rc == 0);

    //
    // Make everything re-accessible:
    //
    if (DEBUG) cerr << "  Remap ", shared_map_page_count, " pages as read/write at ", image, " (page ", 0, ")", endl, flush;
    assert((Waddr)map_pages(pagedir_mfns, shared_map_page_count, PROT_READ|PROT_WRITE, (void*)PTLSIM_PSEUDO_VIRT_BASE, MAP_FIXED) == PTLSIM_PSEUDO_VIRT_BASE);

    //if (DEBUG) cerr << "Signature = ", hexstring(bootinfo->magic, 64), endl, flush;

    //
    // Set up the PTLsim context
    //
    /*
    Level4PTE* overlayptes = (Level4PTE*)ptl_alloc_private_page();
    memset(overlayptes, 0, PAGE_SIZE);
    mlock(overlayptes, 4096);

    int l4slot = VirtAddr(PTLSIM_VIRT_BASE).lm.level4;
    Level4PTE& l4pte = overlayptes[l4slot];
    l4pte = 0;
    l4pte.p = 1;
    l4pte.rw = 1;
    l4pte.us = 1;
    l4pte.nx = 0;
    l4pte.a = 1;
    l4pte.mfn = bootinfo->ptl_level3_mfn;
    cerr << "Inject PTLsim page table (L3 top mfn ", bootinfo->ptl_level3_mfn, ") into overlay page slot ", l4slot, ": ", l4pte, endl, flush;

    {
      mmuext_op_t op;
      op.cmd = MMUEXT_SET_PT_OVERLAY;
      op.arg1.linear_addr = (unsigned long)overlayptes;
      rc = xc_mmuext_op(xc, &op, 1, domain);
      cerr << "Overlay set rc = ", rc, endl, flush;
    }    

    munlock(overlayptes, 4096);
    ptl_free_private_page(overlayptes);
    */

    //Context* ptlctx = new Context[vcpu_count];
    prep_initial_context(ctx, vcpu_count);
    ctx[0].commitarf[REG_rip] = ehdr.e_entry;
    ctx[0].commitarf[REG_rsp] = (Waddr)ptlmon_ptr_to_ptlcore_ptr(sp);
    ctx[0].commitarf[REG_rdi] = (Waddr)ptlmon_ptr_to_ptlcore_ptr(bootinfo); // start info in %rdi (arg[0])

    //frozen_guestctx = ctx;
    //frozen_ptlctx = ptlctx;

    //W64 target_cr3 = (ptl_virt_to_mfn(toplevel_page_table) << log2(PAGE_SIZE));
    if (DEBUG) cerr << "  PTLsim initial toplevel cr3 = ", (void*)ctx[0].cr3, " (mfn ", (ctx[0].cr3 >> log2(PAGE_SIZE)), ")", endl;
    //if (DEBUG) cerr << "  Guest Xen GDT template page mfn ", bootinfo->gdt_mfn, endl;
    if (DEBUG) cerr << "  PTLsim entrypoint at ", (void*)ehdr.e_entry, endl;

    if (DEBUG) cerr << "  Ready, set, go!", endl, flush;

    /*
      if (DEBUG & 0) {
      Level4PTE* ptes = (Level4PTE*)map_page(ptlctx[0].cr3 >> 12);
      assert(ptes);

      cerr << "Guest toplevel page table @ ", ptes, " (mfn ", (ptlctx[0].cr3 >> 12), "):", endl, flush;
      print_page_table(cerr, (Level1PTE*)ptes, 0);
      cerr << flush;

      int slot = 256;
      Level3PTE* l3ptes = (Level3PTE*)map_page(ptes[slot].mfn);
      cerr << "l3ptes = ", l3ptes, " (for pte ", slot, ": ", ptes[slot], ")", endl, flush;

      print_page_table(cerr, (Level1PTE*)l3ptes, 0);
      cerr << flush;

      unmap_page(l3ptes);
      unmap_page(ptes);
      //mfn_t l3mfn = toplevel_page_table[510].mfn;
      //cerr << "l3mfn ", l3mfn, endl, flush;
      //Level1PTE* l3 = (Level1PTE*)map_page(l3mfn);
      //cerr << "l3 = ", l3, endl, flush;
      //print_page_table(cerr, l3, 0xffffff0000000000);
      cerr.flush();
    }
    */

    //usleep(100000);

    switch_to_ptlsim(true);

    /*
    if (DEBUG & 0) {
      cerr << "New PTLsim context for vcpu 0:", endl, flush;
      Context newctx;
      getcontext(0, newctx);
      cerr << newctx, flush;
    }
    */
    if (DEBUG) cerr << "  PTLsim is now in control inside domain ", domain, endl, flush;

    return true;
  }

  ostream& print_evtchn_mask(ostream& os, const char* title, const unsigned long* data) {
    os << title, ":", endl;
    foreach (i, 8) { // foreach (i, 64) {  // really 4096 possible events
      if (data[i]) {
        os << "  word ", intstring(i, -2), " = ", hexstring(data[i], 64), endl;
      }
    }
    return os;
  }

  void alloc_control_port() {
    evtchnfd = open("/dev/xen/evtchn", O_RDWR);
    assert(evtchnfd >= 0);

    ioctl_evtchn_bind_unbound_port alloc;
    alloc.remote_domain = domain;
    ptlsim_hostcall_port = ioctl(evtchnfd, IOCTL_EVTCHN_BIND_UNBOUND_PORT, &alloc);

    alloc.remote_domain = domain;
    ptlsim_upcall_port = ioctl(evtchnfd, IOCTL_EVTCHN_BIND_UNBOUND_PORT, &alloc);
  }

  /*
  void swap_context(Context* saved, Context* restored, int vcpu_count) {
    int rc;
    pause();

    foreach (i, vcpu_count) {
      rc = getcontext(i, saved[i]);
      rc = setcontext(i, restored[i]);
    }
  }
  */

  //
  // Copy the saved context in ctx (in PTLsim space) into the real
  // context, and save the old context back into ctx.
  //
  void swap_context() {
    int rc;
    pause();

    Context temp;

    foreach (i, vcpu_count) {
      getcontext(i, temp);
      setcontext(i, ctx[i]);
      ctx[i] = temp;
    }
  }

  //
  // Switch back to a frozen instance of PTLsim
  //
  void switch_to_ptlsim(bool first_time = false) {
    //cerr << "frozen_guestctx = ", frozen_guestctx, ", frozen_ptlctx = ", frozen_ptlctx, endl, flush;

    shinfo->vcpu_info[0].evtchn_upcall_mask = 1;
    /*
    if (first_time) {
      // Block upcalls until PTLsim installs its handlers for the first time
      shinfo->vcpu_info[0].evtchn_upcall_mask = 1;
    } else {
      // Unblock everything
      shinfo->evtchn_mask[0] = 0;
      shinfo->evtchn_pending[0] = 0;
      shinfo->vcpu_info[0].evtchn_pending_sel = 0;
      shinfo->vcpu_info[0].evtchn_upcall_pending = 0;
      shinfo->vcpu_info[0].evtchn_upcall_mask = 0;
    }
    */

    swap_context();

    // cerr << "swapping!", endl, flush;
    // swap_context(frozen_guestctx, frozen_ptlctx, vcpu_count);

    // cout << "Guest context:", endl, frozen_guestctx[0], endl, flush;
    // cout << "Guest shadow shinfo:", endl, *bootinfo->shadow_shinfo, endl, flush;

    //
    // Send event to kick-start it
    //

    if (!first_time) {
      bootinfo->hostreq.ready = 1;
      bootinfo->hostreq.rc = 0;
      ioctl_evtchn_notify notify;
      notify.port = ptlsim_hostcall_port;
      ioctl(evtchnfd, IOCTL_EVTCHN_NOTIFY, &notify);
    }

    bootinfo->ptlsim_state = PTLSIM_STATE_RUNNING;

    unpause();

    // cerr << "Unpaused", endl, flush;
    //sleep(100000); // <<< Without this, the machine crashes here.
    // With sleep(100000), it starts up and goes into blocked
    // state, but never prints the PTLsim banner or anything...
  }

  int process_event() {
    int rc;

    W32 readyport = 0;
    rc = read(evtchnfd, &readyport, sizeof(readyport));
    // Re-enable it:
    rc = write(evtchnfd, &readyport, sizeof(readyport));

    //if (bootinfo->hostreq.op != PTLSIM_HOST_SYSCALL) {
    // cerr << "Got event from PTLsim: ", bootinfo->hostreq.op, endl, flush;
    //}

    int op = bootinfo->hostreq.op;

    bootinfo->hostreq.ready = 0;

    switch (bootinfo->hostreq.op) {
    case PTLSIM_HOST_SYSCALL: {
      W64 syscall = bootinfo->hostreq.syscall.syscallid;
      W64 arg1 = bootinfo->hostreq.syscall.arg1;
      W64 arg2 = bootinfo->hostreq.syscall.arg2;
      W64 arg3 = bootinfo->hostreq.syscall.arg3;
      W64 arg4 = bootinfo->hostreq.syscall.arg4;
      W64 arg5 = bootinfo->hostreq.syscall.arg5;
      W64 arg6 = bootinfo->hostreq.syscall.arg6;

#if 0
      cerr << "  syscall request ", syscall, " (",
        arg1, ", ",
        arg2, ", ",
        arg3, ", ",
        arg4, ", ",
        arg5, ", ",
        arg6, ")", endl, flush;
#endif
      switch (syscall) {
      case __NR_open:
      case __NR_unlink:
      case __NR_uname:
      case __NR_gettimeofday:
        assert(thunk_ptr_valid(arg1));
        arg1 = ptlcore_ptr_to_ptlmon_ptr(arg1);
        break;
      case __NR_read:
      case __NR_write:
        assert(thunk_ptr_valid(arg2));
	arg2 = ptlcore_ptr_to_ptlmon_ptr(arg2);
        break;
      case __NR_rename:
      case __NR_readlink:
      case __NR_nanosleep:
        assert(thunk_ptr_valid(arg1));
        assert(thunk_ptr_valid(arg2));
        arg1 = ptlcore_ptr_to_ptlmon_ptr(arg1);
        arg2 = (arg2) ? ptlcore_ptr_to_ptlmon_ptr(arg2) : 0;
        break;
      case __NR_close:
      case __NR_fdatasync:
      case __NR_lseek:
        // no thunking required
        break;
      default:
        cerr << "PTLmon does not support thunked syscall ", syscall, "!", endl, flush;
        abort();
      }
      bootinfo->hostreq.rc = do_syscall_64bit(syscall,
                                              arg1,
                                              arg2,
                                              arg3,
                                              arg4,
                                              arg5,
                                              arg6);
#if 0
      cerr << "  syscall result = ", bootinfo->hostreq.rc, endl, flush;
#endif
      break;
    };
    case PTLSIM_HOST_SWITCH_TO_NATIVE:
    case PTLSIM_HOST_TERMINATE: {
      cerr << "Got hostreq ", bootinfo->hostreq.op, endl, flush;

      pause();
      //
      // We have to be careful when copying the shadow shinfo page
      // back over the real shinfo page since Xen updates the timers
      // asynchronously. We do not want them to appear to run backwards
      // since this royally screws up the guest kernel's scheduler.
      // Hence we avoid copying these.
      //
      // Unmask and clear all events, so the guest kernel gets them when it wakes up.
      // It may have missed some periodic events (timer, console) but those can be
      // discarded without ill effects (other than unavoidable jumpyness).
      //
      memcpy(shinfo->evtchn_mask, shadow_shinfo->evtchn_mask, sizeof(shinfo->evtchn_mask));
      memcpy(shinfo->evtchn_pending, shadow_shinfo->evtchn_pending, sizeof(shinfo->evtchn_pending));
      foreach (i, vcpu_count) {
        const vcpu_info& src = shadow_shinfo->vcpu_info[i];
        vcpu_info& dest = shinfo->vcpu_info[i];
        dest.arch = src.arch;
        dest.evtchn_upcall_mask = src.evtchn_upcall_mask;
        dest.evtchn_upcall_pending = src.evtchn_upcall_pending;
        dest.evtchn_pending_sel = src.evtchn_pending_sel;
      }

      assert(bootinfo->ptlsim_state == PTLSIM_STATE_RUNNING);

      swap_context();

      {
        Context newctx;
        getcontext(0, newctx);
        cout << "ptlmon: Updated context:", endl, newctx, endl, flush;
      }

      bootinfo->ptlsim_state = ((bootinfo->hostreq.op == PTLSIM_HOST_SWITCH_TO_NATIVE) ? PTLSIM_STATE_NATIVE : PTLSIM_STATE_NONE);
      cout << "ptlmon: Domain ", domain, " is now running in native mode", endl, flush;
      bootinfo->hostreq.rc = 0;
      if (!bootinfo->hostreq.switch_to_native.pause) unpause();

      return (bootinfo->hostreq.op == PTLSIM_HOST_TERMINATE);
    };
    case PTLSIM_HOST_ACCEPT_UPCALL: {
      if ((!requestq.empty()) | (!bootinfo->hostreq.accept_upcall.blocking)) complete_hostcall();
      //cout << "get_request: queue empty!", endl, flush;
      // Otherwise wait for user to add a request
      return 0;
    }
    case PTLSIM_HOST_COMPLETE_UPCALL: {
      complete_upcall(*this, bootinfo->hostreq.complete_upcall.uuid);
      break;
    }
    default:
      bootinfo->hostreq.rc = (W64)-ENOSYS;
    };

    complete_hostcall();
    return 0;
  }

  //
  // Complete a pending request, and unblock the domain
  //
  int complete_hostcall() {
    int op = xchg(bootinfo->hostreq.op, (W32)PTLSIM_HOST_NOP);

    switch (op) {
    case PTLSIM_HOST_NOP: {
      // nothing pending
      return 0;
    }
    case PTLSIM_HOST_ACCEPT_UPCALL: {
      PendingRequest* req = requestq.dequeue();

      if (req) {
        xadd(bootinfo->queued_upcall_count, -1);
        int n = min(strlen(req->data), bootinfo->hostreq.accept_upcall.count-1);

        // cout << "Returning accept_upcall for uuid ", req->uuid, ": data [", req->data, "]", endl, flush; 
        strncpy(ptlcore_ptr_to_ptlmon_ptr(bootinfo->hostreq.accept_upcall.buf), req->data, n);
        *(ptlcore_ptr_to_ptlmon_ptr(bootinfo->hostreq.accept_upcall.buf + n)) = 0;
        bootinfo->hostreq.rc = req->uuid;

        pendingreqs.add(req->uuid, *req);
      } else {
        if (bootinfo->hostreq.accept_upcall.blocking) {
          //cout << "Cannot complete get_request: queue empty!", endl, flush;
          return 0;
        }

        // Non-blocking: let caller try again
        bootinfo->hostreq.rc = 0;
      }

      break;
    }
    default: {
      //cout << "ptlmon: host request type ", op, " was not a continuation", endl;
      break;
    }
    }

#if 1
    int rc;
    bootinfo->hostreq.ready = 1;
    ioctl_evtchn_notify notify;
    notify.port = ptlsim_hostcall_port;
    rc = ioctl(evtchnfd, IOCTL_EVTCHN_NOTIFY, &notify);
#endif
    return 0;
  }

  //
  // Send an asynchronous upcall to PTLsim inside the domain
  //
  /*
  int send_upcall(const PTLsimUpcall& upcall) {
    memcpy(&bootinfo->upcall, &upcall, sizeof(upcall));
    ioctl_evtchn_notify notify;
    notify.port = ptlsim_upcall_port;
    int rc = ioctl(evtchnfd, IOCTL_EVTCHN_NOTIFY, &notify);
    return rc;
  }
  */

  XenController(int domain) {
    attach(domain);
  }

  int detach() {
    static const bool DEBUG = 0;

    int rc;

    if ((xc < 0) | (domain < 0)) return 0;

    xc_domain_unpause(xc, domain);

    if (ptlsim_hostcall_port >= 0) {
      evtchn_close arg;
      arg.port = ptlsim_hostcall_port;
      int rc = do_evtchn_op(xc, EVTCHNOP_close, &arg, sizeof(arg));
    }

    if (ptlsim_upcall_port >= 0) {
      evtchn_close arg;
      arg.port = ptlsim_upcall_port;
      int rc = do_evtchn_op(xc, EVTCHNOP_close, &arg, sizeof(arg));
    }

    domain = -1;

    if (xc >= 0) assert(xc_interface_close(xc) == 0);

    xc = -1;

    return 0;
  }

  int getcontext(int vcpu, Context& ctx) {
    vcpu_guest_context_t xenctx;
    assert(domain != 0);
    int rc = xc_vcpu_getcontext(xc, domain, vcpu, &xenctx);
    assert(rc == 0);

    ctx.restorefrom(xenctx);

    mmuext_op_t op;

    ctx.kernel_ptbase_mfn = 0;
    op.cmd = MMUEXT_GET_KERNEL_BASEPTR;
    op.arg1.linear_addr = (Waddr)&ctx.kernel_ptbase_mfn;
    op.arg2.vcpuid = vcpu;
    rc = xc_mmuext_op(xc, &op, 1, domain);
    // cerr << "xc_mmuext_op(MMUEXT_GET_KERNEL_BASEPTR) => rc ", rc, ", mfn ", ctx.kernel_ptbase_mfn, endl, flush;

    ctx.user_ptbase_mfn = 0;
    op.cmd = MMUEXT_GET_USER_BASEPTR;
    op.arg1.linear_addr = (Waddr)&ctx.user_ptbase_mfn;
    op.arg2.vcpuid = vcpu;
    rc = xc_mmuext_op(xc, &op, 1, domain);
    // cerr << "xc_mmuext_op(MMUEXT_GET_USER_BASEPTR) => rc ", rc, ", mfn ", ctx.user_ptbase_mfn, endl, flush;

    return rc;
  }

  int setcontext(int vcpu, Context& ctx) {
    vcpu_guest_context_t xenctx;
    ctx.saveto(xenctx);
    assert(domain != 0);

    pause();

    //
    // Force it to kernel_ptbase: on reschedule path,
    // hypervisor needs to set up iret frame on kernel
    // stack; it will switch to user stack before context
    // switching.
    //

    int rc = xc_vcpu_setcontext(xc, domain, vcpu, &xenctx);

    mmuext_op_t op;

    // cerr << "Setting base pointers (kernel ", ctx.kernel_ptbase_mfn, ", user ", ctx.user_ptbase_mfn, ")...", endl, flush;

    if (ctx.user_ptbase_mfn) {
      op.cmd = MMUEXT_SET_USER_BASEPTR;
      op.arg1.mfn = ctx.user_ptbase_mfn;
      op.arg2.vcpuid = vcpu;
      rc = xc_mmuext_op(xc, &op, 1, domain);
      //cerr << "xc_mmuext_op(MMUEXT_SET_USER_BASEPTR) => rc ", rc, ", errno ", errno, ", mfn ", ctx.user_ptbase_mfn, endl, flush;
    }

    if (ctx.kernel_ptbase_mfn) {
      op.cmd = MMUEXT_SET_KERNEL_BASEPTR;
      op.arg1.mfn = ctx.kernel_ptbase_mfn;
      op.arg2.vcpuid = vcpu;
      rc = xc_mmuext_op(xc, &op, 1, domain);
      //cerr << "xc_mmuext_op(MMUEXT_SET_KERNEL_BASEPTR) => rc ", rc, ", errno ", errno, ", mfn ", ctx.kernel_ptbase_mfn, endl, flush;
    }


    return rc;
  }

  int pause() {
    int rc;
    if ((rc = xc_domain_pause(xc, domain))) {
      cout << "XenController: PAUSE failed (", rc, ")", endl;
      return rc;
    }
    return rc;
  }

  int unpause() {
    int rc;
    if ((rc = xc_domain_unpause(xc, domain))) {
      cout << "XenController: UNPAUSE failed (", rc, ")", endl;
      return rc;
    }
    return rc;
  }

  int enable_dirty_logging() {
    int rc = xc_shadow_control(xc, domain, DOM0_SHADOW_CONTROL_OP_ENABLE_LOGDIRTY, NULL, 0, NULL);

    if (rc < 0) {
      cout << "XenController::enable_dirty_logging(): couldn't enable: rc ", rc, endl;
    }

    return rc;
  }

  int disable_dirty_logging() {
    int rc = xc_shadow_control(xc, domain, DOM0_SHADOW_CONTROL_OP_OFF, NULL, 0, NULL);

    if (rc < 0) {
      cout << "XenController::disble_dirty_logging(): couldn't enable: rc ", rc, endl;
    }

    return rc;
  }

  int query_dirty_pages() {
    pause();

    cout << "Updating page map for ", info.max_pages, " total pages", endl;

    //
    // Get frame MFNs
    //
    mfn_t* pagelist = (mfn_t*)ptl_alloc_private_pages(info.max_pages * sizeof(mfn_t), PROT_READ | PROT_WRITE);
    assert(mmap_valid(pagelist));

    //
    // NOTE: All this does inside Xen is goes through the linked list of pages
    // belonging to the domain, and puts them in an array in arbitrary order.
    // The order is always the same when the domain is paused, however.
    //
    int pagecount = xc_get_pfn_list(xc, domain, pagelist, info.max_pages);
    cout << "Got ", pagecount, " out of max ", info.max_pages, " pages", endl;
    assert(pagecount > 0);

    //
    // Get frame types
    //
    unsigned long* typelist = (unsigned long*)ptl_alloc_private_pages(info.max_pages * sizeof(unsigned long), PROT_READ | PROT_WRITE);
    assert(mmap_valid(typelist));

    int pagetypecount = xc_get_pfn_type_batch(xc, domain, info.max_pages, typelist);
    cout << "Got ", pagecount, " out of max ", info.max_pages, " page types", endl;
    assert(pagetypecount > 0);
    assert(pagetypecount == pagecount);

    //
    // Print the list (including pages belonging to PTLsim):
    //

    cout << "Page list of ", pagecount, " pages (", ((pagecount * PAGE_SIZE) / 1024), " kbytes):", endl;
    foreach (i, pagecount) {
      unsigned long type = typelist[i];
      cout << intstring(i, 8), ": mfn ", intstring(pagelist[i], 8), ", type ", hexstring(type, 32);
      if (type & L1TAB) cout << " L1";
      if (type & L2TAB) cout << " L2";
      if (type & L3TAB) cout << " L3";
      if (type & L4TAB) cout << " L4";
      if (type & LPINTAB) cout << " pintab";
      if (type & XTAB) cout << " invalid";
      cout << endl;
    }

    //
    // Assume the shared info frame and other system pages not in the list
    // are always dirty.
    //

    int mapbytes = ceil(((info.max_pages, 8) / 8), PAGE_SIZE);

    cout <<"XenController::query_dirty_pages(): ", mapbytes, " map bytes for ", info.max_pages, " pages", endl, flush;

    byte* dirty_page_bitmap = (byte*)ptl_alloc_private_pages(mapbytes, PROT_READ|PROT_WRITE);

    assert(mmap_valid(dirty_page_bitmap));
    assert(ptl_lock_private_pages(dirty_page_bitmap, mapbytes));

    dom0_shadow_control_stats_t stats;
    memset(&stats, 0, sizeof(stats));

    int dirtybitcount = xc_shadow_control(xc, domain, DOM0_SHADOW_CONTROL_OP_PEEK, (long unsigned int*)dirty_page_bitmap, maxpages, &stats);

    assert(ptl_unlock_private_pages(dirty_page_bitmap, mapbytes));

    cout << "Got ", dirtybitcount, " out of max ", info.max_pages, " dirty bits", endl;

    cout << "Shadow control stats:", endl;
    cout << "  ", intstring(stats.fault_count, 8), " page faults", endl;
    cout << "  ", intstring(stats.dirty_count, 8), " dirty pages", endl;
    cout << "  ", intstring(stats.dirty_net_count, 8), " dirty pages from network virtual DMA", endl;
    cout << "  ", intstring(stats.dirty_block_count, 8), " dirty pages from block virtual DMA", endl;

    int dirty_page_count = 0;

    cout << "Dirty pages:", endl;

    foreach (i, maxpages) {
      bool dirty = bit(dirty_page_bitmap[i >> 3], lowbits(i, 3));
      mfn_t mfn = pagelist[i];

      if (dirty) {
        unsigned long type = typelist[i];
        cout << intstring(i, 8), ": mfn ", intstring(pagelist[i], 8), ", type ", hexstring(type, 32);
        if (type & L1TAB) cout << " L1";
        if (type & L2TAB) cout << " L2";
        if (type & L3TAB) cout << " L3";
        if (type & L4TAB) cout << " L4";
        if (type & LPINTAB) cout << " pintab";
        if (type & XTAB) cout << " invalid";
        cout << endl;
      }
    }

    ptl_free_private_pages(dirty_page_bitmap, mapbytes);
    ptl_free_private_pages(typelist, info.max_pages * sizeof(unsigned long));
    ptl_free_private_pages(pagelist, info.max_pages * sizeof(mfn_t));

    return 0;
  }

  ostream& print_log_buffer(ostream& os) const {
    os << "========================================================", endl;
    os << "Log buffer @ ", bootinfo->startup_log_buffer, " (tail ", bootinfo->startup_log_buffer_tail, ", size ", bootinfo->startup_log_buffer_size, ")", endl;
    if (!bootinfo->startup_log_buffer) {
      os << "  (log buffer not initialized)", endl;
      return os;
    }

    // Must be a power of two:
    W32 log_buffer_mask = bootinfo->startup_log_buffer_size - 1;

    int t = bootinfo->startup_log_buffer_tail;

    foreach (i, bootinfo->startup_log_buffer_size) {
      void* p = (void*)&bootinfo->startup_log_buffer[t];
      char c = bootinfo->startup_log_buffer[t];
      if (c) os << (char)c;
      t = (t + 1) & (bootinfo->startup_log_buffer_size - 1);
    }

    os << "(end of log buffer)", endl;
    return os;
  }

  ~XenController() {
    detach();
  }
};

extern "C" void sigterm_handler(int sig, siginfo_t* si, void* contextp) {
  sys_exit(0);
}

int send_request_to_ptlmon(int domain, const char* request) {
  int rc;
  int sd = socket(PF_LOCAL, SOCK_STREAM, 0);
  assert(sd >= 0);

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));

  stringbuf sockname;
  sockname << "/tmp/ptlmon-domain-", domain;

  addr.sun_family = AF_LOCAL;
  strncpy(addr.sun_path, (char*)sockname, sizeof(addr.sun_path)-1);

  rc = connect(sd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));

  if (rc < 0) {
    // (This may be normal if it's the first time we've connected to this domain)
    return -1;
  }

  cerr << "Sending request to PTLmon: [", request, "]", endl, flush;

  rc = sys_write(sd, request, strlen(request));
  sys_write(sd, "\n", 1);

  cout << "Sent message (rc = ", rc, " vs size ", strlen(request), "); wait for reply...", endl, flush;

  char reply[64];
  rc = sys_read(sd, reply, sizeof(reply)); 
  cout << "Received upcall reply: bytes = ", rc, ", text: '", reply, "'", endl, flush;

  sys_close(sd);

  return 0;
}

extern ConfigurationOption optionlist[];
extern int lengthof_optionlist;

stringbuf& merge_string_list(stringbuf& sb, const char* sep, int n, char** list) {
  foreach (i, n) {
    sb << list[i];
    if (i != (n-1)) sb << sep;
  }
  return sb;
}

W64 next_upcall_uuid = 1;

void complete_upcall(XenController& xc, W64 uuid) {
  //cout << "Completing upcall for uuid ", uuid, " -> ", endl;

  PendingRequest req;

  if (!pendingreqs.remove(uuid, req)) {
    cout << endl;
    cout << "Warning: PTLxen notified us of an unknown completed request (uuid ", uuid, ")", endl, flush;
    return;
  }

  //cout << "uuid ", req.uuid, ", fd ", req.fd, ", data [", req.data, "]", endl, flush;

  stringbuf reply;
  reply << "OK", endl;
  sys_write(req.fd, (char*)reply, strlen(reply));
  sys_close(req.fd);

  delete req.data;
  req.data = null;
}

void handle_upcall(XenController& xc, int fd) {
  int rc = -EINVAL;
  int n;
  size_t request_bytes = 0;
  dynarray<char*> argv;
  stringbuf reply;

  stringbuf sb;
  istream is(fd);
  is.readline(sb);

  char* temp = argv.tokenize(strdup(sb), " ");
  PTLsimConfig config;
  config.reset();
  n = configparser.parse(config, argv.count(), argv.data);
  delete[] temp;

  if (config.run) {
    // If it's in the native state, switch to PTLsim first, then send the command
    if (xc.bootinfo->ptlsim_state == PTLSIM_STATE_NATIVE) {
      cout << "Switching domain from native mode back to PTLsim mode...", endl, flush;
      xc.switch_to_ptlsim();
      reply << "Domain ", config.domain, " switched back to PTLsim mode.", endl;
      cout << reply, flush;
    } else {
      // PTLsim may be in the idle state: send it anyway
      //reply << "ptlmon: Warning: cannot switch to simulation mode: domain ", domain, " was already in state ", xc.bootinfo->ptlsim_state, endl;
      //cout << reply, flush;
    }
  }

  if (PendingRequest* req = requestq.alloc()) {
    req->uuid = next_upcall_uuid++;
    req->fd = fd;
    req->data = strdup(sb);
    cerr << "Received request ", req->uuid, " [", req->data, "]", endl, flush;
    xadd(xc.bootinfo->queued_upcall_count, +1);
    xc.complete_hostcall();
  } else {
    reply << "ptlmon: Warning: Request queue FIFO is full. PTLsim may not be responding", endl;
  }

  return;
}

int main(int argc, char** argv) {
  int rc;

  // cerr << "sizeof(Context) = ", sizeof(Context), endl, flush;
  assert(sizeof(Context) == PAGE_SIZE);

  argc--; argv++;
  configparser.setup();
  config.reset();

  if (!argc) {
    print_banner(cerr);
    configparser.printusage(cout, config);
    return -1;
  }

  int n = configparser.parse(config, argc, argv);

  if ((W64s)config.domain < 0) {
    cout << "Please use the -domain XXX option to specify a Xen domain to access.", endl, endl;
    return -2;
  }

  stringbuf cmdsb;
  merge_string_list(cmdsb, " ", argc, argv);

  rc = send_request_to_ptlmon(config.domain, cmdsb);

  if (rc < 0) {
    cerr << "PTLsim does not appear to be running in this domain. Starting ptlmon...", endl, flush;

    // Inject into guest for first time, or reboot PTLsim within guest
    XenController xc;
    if (!xc.attach(config.domain)) return -1;
    xc.alloc_control_port();
    xc.inject_ptlsim_image(argc, argv, 1048576);

    int rc = 0;
    int sd = socket(PF_LOCAL, SOCK_STREAM, 0);
    assert(sd >= 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    stringbuf sockname;
    sockname << "/tmp/ptlmon-domain-", config.domain;
    unlink(sockname);

    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, (char*)sockname, sizeof(addr.sun_path)-1);

    if (bind(sd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
      cout << "ERROR: Cannot bind control socket '", sockname, "': error ", strerror(errno), endl;
      return 0;
    }

    // Start listening in pre-fork to avoid race:
    if ((rc = listen(sd, 0)) < 0) {
      cout << "ERROR: Cannot bind control socket '", sockname, "': error ", strerror(errno), endl;
      return 0;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigterm_handler;
    sa.sa_flags = SA_SIGINFO;
    assert(sys_rt_sigaction(SIGXCPU, &sa, NULL, sizeof(W64)) == 0);

    // !!! Fork to daemonize is not allowed with xenctrl: apparently the Xen handles are not inherited...
    // if (fork()) return 0;

    //
    // Child process: act as server
    //

    int waitfd = epoll_create(2);
    assert(waitfd >= 0);
    epoll_event eventctl;

    memset(&eventctl, 0, sizeof(eventctl));
    eventctl.events = EPOLLIN|EPOLLPRI|EPOLLERR|EPOLLHUP;
    eventctl.data.fd = sd;
    assert(epoll_ctl(waitfd, EPOLL_CTL_ADD, sd, &eventctl) == 0);

    memset(&eventctl, 0, sizeof(eventctl));
    eventctl.events = EPOLLIN|EPOLLPRI|EPOLLERR|EPOLLHUP;
    eventctl.data.fd = xc.evtchnfd;
    assert(epoll_ctl(waitfd, EPOLL_CTL_ADD, xc.evtchnfd, &eventctl) == 0);

    // Add the initial command line to the request queue.
    PendingRequest* initreq = requestq.alloc();
    assert(initreq);
    stringbuf cmdsb;
    initreq->uuid = next_upcall_uuid++;
    initreq->fd = -1;
    initreq->data = strdup(merge_string_list(cmdsb, " ", argc, argv));
    xadd(xc.bootinfo->queued_upcall_count, +1);
    xc.complete_hostcall();

    for (;;) {
      epoll_event event;
      memset(&event, 0, sizeof(event));
      int rc = epoll_wait(waitfd, &event, 1, 100);
      if (rc < 0) break;

      if (xc.console) cerr << *xc.console, flush;

      if (!rc) continue;

      if (event.data.fd == sd) {
        sockaddr_un acceptaddr;
        socklen_t acceptlen = sizeof(acceptaddr);
        int acceptsd = accept(sd, (sockaddr*)&acceptaddr, &acceptlen);
        // NOTE: potential denial of service here, if data hasn't arrived yet (can hold up servicing hostcalls from ptlcore): use a timeout
        handle_upcall(xc, acceptsd);
        epoll_ctl(waitfd, EPOLL_CTL_DEL, acceptsd, null);
      } else if (event.data.fd == xc.evtchnfd) {
        int done = xc.process_event();

        if (done) {
          cout << "PTLsim exited", endl, flush;
          xc.print_log_buffer(cout);
          cout << flush;
          break;
        }
      }
    }

    cout << "Process ", sys_gettid(), " exiting loop...", endl, flush;

    xc.unpause();
    xc.detach();

    cout << "All done!", endl, flush;
    cerr << flush;

    sys_exit(0);
  }

  return 0;
}
