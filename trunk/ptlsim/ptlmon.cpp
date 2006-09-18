//
// PTLsim: Cycle Accurate x86-64 Simulator
// PTLxen monitor and control program running in dom0
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
//#include <config.h>
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

template <typename T, typename LM = superstl::ObjectLinkManager<T> >
class queue: selflistlink {
public:
  void reset() { next = this; prev = this; }
  queue() { reset(); }

  void add_to_head(selflistlink* link) { addlink(this, link, next); }
  void add_to_head(T& obj) { add_to_head(LM::linkof(&obj)); }
  void add_to_head(T* obj) { add_to_head(LM::linkof(obj)); }

  void add_to_tail(selflistlink* link) { addlink(prev, link, this); }
  void add_to_tail(T& obj) { add_to_tail(LM::linkof(&obj)); }
  void add_to_tail(T* obj) { add_to_tail(LM::linkof(obj)); }

  T* remove_head() {
    if unlikely (empty()) return null;
    selflistlink* link = next;
    link->unlink();
    return LM::objof(link);
  }

  T* remove_tail() {
    if unlikely (empty()) return null;
    selflistlink* link = prev;
    link->unlink();
    return LM::objof(link);
  }

  void enqueue(T* obj) { add_to_tail(obj); }
  T* dequeue() { return remove_head(); }

  void push(T* obj) { add_to_tail(obj); }
  void pop(T* obj) { remove_tail(); }

  T* head() const {
    return (unlikely (empty())) ? null : next;
  }

  T* tail() const {
    return (unlikely (empty())) ? null : tail;
  }

  bool empty() const { return (next == this); }

  operator bool() const { return (!empty()); }

protected:
  void addlink(selflistlink* prev, selflistlink* link, selflistlink* next) {
    next->prev = link;
    link->next = next;
    link->prev = prev;
    prev->next = link;
  }
};

int domain = -1;
bool log_ptlsim_boot = 0;

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

struct PendingRequest: public selflistlink {
  W64 uuid;
  int fd;
  char* data;
};

struct PendingRequestLinkManager: public ObjectLinkManager<PendingRequest> {
  static inline W64& keyof(PendingRequest* obj) {
    return obj->uuid;
  }
};

queue<PendingRequest, PendingRequestLinkManager> requestq;

SelfHashtable<W64, PendingRequest, 16, PendingRequestLinkManager> pendingreqs;

struct XenController;

void complete_upcall(XenController& xc, W64 uuid);
void fill_requestq_from_scriptq(XenController& xc);

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
  Context* ctx;

  XenController() { reset(); }

  void reset() {
    xc = -1; domain = -1; pagelist = 0; pagecount = 0; ptlsim_hostcall_port = -1;
    shinfo = null;
    bootinfo = null;
    ctx = null;
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

  bool attach(int domain) {
    static const bool DEBUG = log_ptlsim_boot;

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
    static const bool DEBUG = log_ptlsim_boot;

    int rc;

    size_t bytes = &_binary_ptlxen_bin_end - &_binary_ptlxen_bin_start;
    const byte* data = &_binary_ptlxen_bin_start;
    const Elf64_Ehdr& ehdr = *(const Elf64_Ehdr*)data;
    const Elf64_Phdr* phdr = (const Elf64_Phdr*)(((const byte*)&ehdr) + ehdr.e_phoff);

    if (DEBUG) cerr << "Injecting PTLsim into domain ", domain, ":", endl;
    if (DEBUG) cerr << "  PTLcore is ", bytes, " bytes @ virt addr ", image, endl, flush;

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
    shadow_shinfo = ptlcore_ptr_to_ptlmon_ptr((shared_info_t*)PTLSIM_SHADOW_SHINFO_PAGE_VIRT_BASE);
    memcpy(shadow_shinfo, shinfo, PAGE_SIZE);
    if (DEBUG) cerr << "  Shadow shared info page at ", shadow_shinfo, endl, flush;

    //
    // Allocate VCPU contexts
    //
    ctx = ptlcore_ptr_to_ptlmon_ptr((Context*)PTLSIM_CTX_PAGE_VIRT_BASE);
    if (DEBUG) cerr << "  Context array starts at ", ptlmon_ptr_to_ptlcore_ptr(ctx), " (", sizeof(Context), " bytes each)", endl, flush;

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

    prep_initial_context(ctx, vcpu_count);
    ctx[0].commitarf[REG_rip] = ehdr.e_entry;
    ctx[0].commitarf[REG_rsp] = (Waddr)ptlmon_ptr_to_ptlcore_ptr(sp);
    ctx[0].commitarf[REG_rdi] = (Waddr)ptlmon_ptr_to_ptlcore_ptr(bootinfo); // start info in %rdi (arg[0])

    if (DEBUG) cerr << "  PTLsim initial toplevel cr3 = ", (void*)ctx[0].cr3, " (mfn ", (ctx[0].cr3 >> log2(PAGE_SIZE)), ")", endl;
    if (DEBUG) cerr << "  PTLsim entrypoint at ", (void*)ehdr.e_entry, endl;

    if (DEBUG) cerr << "  Ready, set, go!", endl, flush;

    switch_to_ptlsim(true);

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
    shinfo->vcpu_info[0].evtchn_upcall_mask = 1;
    swap_context();

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
  }

  int process_event() {
    int rc;

    W32 readyport = 0;
    rc = read(evtchnfd, &readyport, sizeof(readyport));
    // Re-enable it:
    rc = write(evtchnfd, &readyport, sizeof(readyport));

    int op = bootinfo->hostreq.op;

    bootinfo->hostreq.ready = 0;

    // cerr << "procss_event: hostreq op ", bootinfo->hostreq.op, ", syscall_id ", bootinfo->hostreq.syscall.syscallid, ", pending_upcall_count ", bootinfo->queued_upcall_count, endl, flush;

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
    case PTLSIM_HOST_SWITCH_TO_NATIVE: {
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

      swap_context();

      // Context newctx;
      // getcontext(0, newctx);
      // cout << "ptlmon: Updated context:", endl, newctx, endl, flush;

      bootinfo->ptlsim_state = ((bootinfo->hostreq.op == PTLSIM_HOST_SWITCH_TO_NATIVE) ? PTLSIM_STATE_NATIVE : PTLSIM_STATE_NONE);
      cout << "ptlmon: Domain ", domain, " is now running in native mode", endl, flush;
      bootinfo->hostreq.rc = 0;
      if (!bootinfo->hostreq.switch_to_native.pause) unpause();

      return 0;
    };
    case PTLSIM_HOST_SHUTDOWN: {
      pause();
      cout << "ptlmon: Domain ", domain, " has shut down", endl, flush;
      return 1;
    };
    case PTLSIM_HOST_ACCEPT_UPCALL: {
      if (requestq.empty()) {
        fill_requestq_from_scriptq(*this);
      }

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

        pendingreqs.add(req);
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

    int rc;
    bootinfo->hostreq.ready = 1;
    ioctl_evtchn_notify notify;
    notify.port = ptlsim_hostcall_port;
    rc = ioctl(evtchnfd, IOCTL_EVTCHN_NOTIFY, &notify);
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

    ctx.user_ptbase_mfn = 0;
    op.cmd = MMUEXT_GET_USER_BASEPTR;
    op.arg1.linear_addr = (Waddr)&ctx.user_ptbase_mfn;
    op.arg2.vcpuid = vcpu;
    rc = xc_mmuext_op(xc, &op, 1, domain);

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

    if (ctx.user_ptbase_mfn) {
      op.cmd = MMUEXT_SET_USER_BASEPTR;
      op.arg1.mfn = ctx.user_ptbase_mfn;
      op.arg2.vcpuid = vcpu;
      rc = xc_mmuext_op(xc, &op, 1, domain);
    }

    if (ctx.kernel_ptbase_mfn) {
      op.cmd = MMUEXT_SET_KERNEL_BASEPTR;
      op.arg1.mfn = ctx.kernel_ptbase_mfn;
      op.arg2.vcpuid = vcpu;
      rc = xc_mmuext_op(xc, &op, 1, domain);
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
  sockname << "/tmp/ptlsim-domain-", domain;

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

queue<PendingRequest> scriptq;
W64 script_list_uuid_currently_pending = 0;

void fill_requestq_from_scriptq(XenController& xc) {
  //if (req->uuid == script_list_uuid_currently_pending) {
  script_list_uuid_currently_pending = 0;
  PendingRequest* scriptreq;
  if ((scriptreq = scriptq.dequeue())) {
    assert(scriptreq); assert(scriptreq != (PendingRequest*)&scriptq);
    
    PendingRequest* newreq = new PendingRequest();
    newreq->uuid = next_upcall_uuid++;
    newreq->fd = -1;
    newreq->data = scriptreq->data; // don't strdup here: we already have a copy
    delete scriptreq;
    cerr << "Queued request [", newreq->data, "]", endl;
    script_list_uuid_currently_pending = newreq->uuid;
    requestq.enqueue(newreq);
    xadd(xc.bootinfo->queued_upcall_count, +1);
  }
}

void complete_upcall(XenController& xc, W64 uuid) {
  //cout << "Completing upcall for uuid ", uuid, " -> ", endl;

  PendingRequest* req = pendingreqs.get(uuid);

  if (!req) {
    cout << endl;
    cout << "Warning: PTLxen notified us of an unknown completed request (uuid ", uuid, ")", endl, flush;
    return;
  }

  pendingreqs.remove(req);

  //cout << "uuid ", req.uuid, ", fd ", req.fd, ", data [", req.data, "]", endl, flush;

  if (req->fd >= 0) {
    stringbuf reply;
    reply << "OK", endl;
    sys_write(req->fd, (char*)reply, strlen(reply));
    sys_close(req->fd);
  }

  delete req->data;
  req->data = null;
  delete req;

  fill_requestq_from_scriptq(xc);
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

  bool run = 0;

  foreach (i, argv.count()) {
    run |= (strequal(argv[i], "-run"));
  }

  delete[] temp;

  if (run) {
    // If it's in the native state, switch to PTLsim first, then send the command
    if (xc.bootinfo->ptlsim_state == PTLSIM_STATE_NATIVE) {
      cerr << "Switching domain from native mode back to PTLsim mode...", endl, flush;
      xc.switch_to_ptlsim();
      reply << "Domain ", domain, " switched back to PTLsim mode.", endl;
      cerr << reply, flush;
    } else {
      // PTLsim may be in the idle state: send it anyway
      //reply << "ptlmon: Warning: cannot switch to simulation mode: domain ", domain, " was already in state ", xc.bootinfo->ptlsim_state, endl;
      //cerr << reply, flush;
    }
  }

  PendingRequest* req = new PendingRequest();
  req->uuid = next_upcall_uuid++;
  req->fd = fd;
  req->data = strdup(sb);
  cerr << "Received request ", req->uuid, " [", req->data, "]", endl, flush;
  requestq.enqueue(req);
  xadd(xc.bootinfo->queued_upcall_count, +1);
  xc.complete_hostcall();

  return;
}

void print_banner(ostream& os) {
  os << "//  ", endl;
  os << "//  PTLsim: Cycle Accurate x86-64 Full System SMP/SMT Simulator", endl;
  os << "//  Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>", endl;
  os << "// ", endl;
  os << "//  Revision ", stringify(SVNREV), " (", stringify(SVNDATE), ")", endl;
  os << "//  Built ", __DATE__, " ", __TIME__, " on ", stringify(BUILDHOST), " using gcc-", 
    stringify(__GNUC__), ".", stringify(__GNUC_MINOR__), endl;
  os << "//  ", endl;
  os << endl;
  os << flush;
}

//
// During the build process, we capture the usage info screen into usage.h
// so we don't need to duplicate the full PTLsimConfig class here.
//
extern char _binary_usage_txt_start;
extern char _binary_usage_txt_end;

void print_saved_usage(ostream& os) {
  os.write(&_binary_usage_txt_start, &_binary_usage_txt_end - &_binary_usage_txt_start);
}

int main(int argc, char** argv) {
  int rc;

  // We need each VCPU context to be exactly one page; it was padded this way in ptlhwdef.h:
  assert(sizeof(Context) == PAGE_SIZE);

  argc--; argv++;

  char* listfile = null;

  foreach (i, argc) {
    if (strequal(argv[i], "-domain")) {
      if (argc > i) { domain = atoi(argv[i+1]); }
    } else if (strequal(argv[i], "-bootlog")) {
      log_ptlsim_boot = 1;
    } else if (argv[i][0] == '@') {
      listfile = argv[i] + 1;
    }
  }

  if (!argc) {
    print_banner(cerr);
    print_saved_usage(cerr);
    return -1;
  }

  if (domain < 0) {
    cerr << "Please use the -domain XXX option to specify a Xen domain to access.", endl, endl;
    return -2;
  }

  stringbuf cmdsb;
  merge_string_list(cmdsb, " ", argc, argv);

  rc = send_request_to_ptlmon(domain, cmdsb);

  if (rc < 0) {
    cerr << "PTLsim does not appear to be running in this domain. Starting ptlmon...", endl, flush;

    // Inject into guest for first time, or reboot PTLsim within guest
    XenController xc;
    if (!xc.attach(domain)) return -1;
    xc.alloc_control_port();
    xc.inject_ptlsim_image(argc, argv, 1048576);

    int rc = 0;
    int sd = socket(PF_LOCAL, SOCK_STREAM, 0);
    assert(sd >= 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));

    stringbuf sockname;
    sockname << "/tmp/ptlsim-domain-", domain;
    unlink(sockname);

    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, (char*)sockname, sizeof(addr.sun_path)-1);

    if (bind(sd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) < 0) {
      cerr << "ERROR: Cannot bind control socket '", sockname, "': error ", strerror(errno), endl;
      return 0;
    }

    // Start listening in pre-fork to avoid race:
    if ((rc = listen(sd, 0)) < 0) {
      cerr << "ERROR: Cannot bind control socket '", sockname, "': error ", strerror(errno), endl;
      return 0;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigterm_handler;
    sa.sa_flags = SA_SIGINFO;
    assert(sys_rt_sigaction(SIGXCPU, &sa, NULL, sizeof(W64)) == 0);

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
    PendingRequest* initreq = new PendingRequest();
    stringbuf cmdsb;
    initreq->uuid = next_upcall_uuid++;
    initreq->fd = -1;
    initreq->data = strdup(merge_string_list(cmdsb, " ", argc, argv));
    requestq.enqueue(initreq);
    xadd(xc.bootinfo->queued_upcall_count, +1);
    xc.complete_hostcall();

    if (listfile) {
      istream is(listfile);
      if (is) {
        stringbuf line;
        for (;;) {
          line.reset();
          is >> line;
          if (!is) break;

          char* p = strrchr(line, '#');
          if (p) *p = 0;
          if (!strlen(line)) continue;

          PendingRequest* req = new PendingRequest();
          req->data = strdup(line);
          scriptq.enqueue(req);
        }
      } else {
        cerr << "Warning: cannot open command list file '", listfile, "'", endl;
      }
    }

    for (;;) {
      epoll_event event;
      memset(&event, 0, sizeof(event));
      int rc = epoll_wait(waitfd, &event, 1, 100);
      if (rc < 0) break;

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
          cerr << "PTLsim exited", endl, flush;
          cerr << flush;
          break;
        }
      }
    }

    cerr << "PTLsim monitor process ", sys_gettid(), " exiting...", endl, flush;

    xc.unpause();
    xc.detach();

    cerr << "Done", endl, flush;
    cerr << flush;

    sys_exit(0);
  }

  return 0;
}
