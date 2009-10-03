//
// PTLsim: Cycle Accurate x86-64 Simulator
// PTLxen monitor and control program running in dom0
//
// Copyright 2005-2008 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

typedef W16 domid_t;

asmlinkage {
#include <xenctrl.h>
#include <xs.h>
};

#include <xen-types.h>
#include <xen/linux/privcmd.h>
#include <xen/linux/evtchn.h>
#include <xen/platform.h>

#define PTLSIM_IN_PTLMON
#include <ptlxen.h>

#include <xen/io/console.h>

#undef DEBUG

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

static int do_msr_op(int xc, int cmd, int cpu, W32 index, W64& value) {
  int rc = -1;
  privcmd_hypercall_t hypercall;
  xen_platform_op_t op;
  op.cmd = cmd;
  op.interface_version = XENPF_INTERFACE_VERSION;
  op.u.msr.cpu = cpu;
  op.u.msr.index = index;
  op.u.msr.value = value;

  hypercall.op     = __HYPERVISOR_platform_op;
  hypercall.arg[0] = W64(&op);
  
  if (mlock(&op, sizeof(op))) goto out;

  rc = do_xen_hypercall(xc, &hypercall);
#if 0
  cerr << "do_msr_op(", cmd, ", ", cpu, ", ", (void*)index, ", value ", (void*)value, "): "
    "hypercall rc ", rc, ", msr rc ", op.u.msr.rc, ", new value ", (void*)op.u.msr.value, endl, flush;
#endif

  value = op.u.msr.value;

  if (!rc) rc = op.u.msr.rc;

  munlock(&op, sizeof(op));
  out:
  return rc;
}

static W64 rdmsr(int xc, int cpu, W32 index) {
  W64 value = 0;
  int rc = do_msr_op(xc, XENPF_rdmsr, cpu, index, value);
  return value;
}

static int wrmsr(int xc, int cpu, W32 index, W64 value) {
  int rc = do_msr_op(xc, XENPF_wrmsr, cpu, index, value);
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
  return ptl_alloc_private_pages(4096, PROT_READ|PROT_WRITE);
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

// In dom0, PTLmon runs in userspace so it can't mmap at the real address.
#define PTLSIM_PSEUDO_VIRT_BASE 0x10000000

template <typename T>
static inline T ptlcore_ptr_to_ptlmon_ptr(T p) {
  if (!p) return p;
  return (T)((((Waddr)p) - PTLSIM_VIRT_BASE) + PTLSIM_PSEUDO_VIRT_BASE);
}

template <typename T>
static inline T ptlmon_ptr_to_ptlcore_ptr(T p) {
  if (!p) return p;
  return (T)((((Waddr)p) - PTLSIM_PSEUDO_VIRT_BASE) + PTLSIM_VIRT_BASE);
}

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

typedef SelfHashtable<W64, PendingRequest, 16, PendingRequestLinkManager> PendingRequestTable;
PendingRequestTable pendingreqs;

struct XenController;

static inline bool thunk_ptr_valid(Waddr w) {
  return (inrange(w, (Waddr)PTLSIM_XFER_PAGES_VIRT_BASE, PTLSIM_XFER_PAGES_VIRT_BASE+(PTLSIM_XFER_PAGES_SIZE-1)));
}

static ostream& operator <<(ostream& os, const page_type_t& pagetype) {
  static const char* page_type_names[] = {"none", "L1", "L2", "L3", "L4", "GDT", "LDT", "write"};
  const char* page_type_name = 
    (pagetype.out.type == PAGE_TYPE_INVALID_MFN) ? "inv" :
    (pagetype.out.type == PAGE_TYPE_INACCESSIBLE) ? "inacc" :
    (pagetype.out.type < lengthof(page_type_names)) ? page_type_names[pagetype.out.type] :
    "???";
  
  os << padstring(page_type_name, -5), " ", (pagetype.out.pinned ? "pin" : "   "), " ",
    intstring(pagetype.out.total_count, 5), " total, ", intstring(pagetype.out.type_count, 5), " by type";
  return os;
}

struct XenController {
  int xc;
  int domain;
  xc_domaininfo_t info;

  shared_info* shinfo;

  Level4PTE* toplevel_page_table;

  byte* image;
  int ptl_page_count;
  int ptl_pagedir_mfn_count;
  int shared_map_page_count;

  mfn_t* ptl_mfns;

  shared_info* shadow_shinfo;

  PTLsimMonitorInfo* bootinfo;

  int vcpu_count;
  int vcpu_online_count;

  int evtchnfd;
  int ptlsim_hostcall_port;
  int ptlsim_upcall_port;
  int ptlsim_breakout_port;

  W64 total_machine_pages;
  W64 xen_hypervisor_start_va;
  int page_table_levels;
  Context* ctx;
  W64 phys_cpu_affinity;

  int cpu_type;

  XenController() { reset(); }

  void reset() {
    xc = -1; domain = -1; ptlsim_hostcall_port = -1;
    shinfo = null;
    bootinfo = null;
    ctx = null;
    next_upcall_uuid = 1;
    cpu_type = CPU_TYPE_UNKNOWN;
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
    if (!inrange(offset, (Waddr)0, (Waddr)((ptl_page_count*PAGE_SIZE)-1))) {
      cerr << "ptl_virt_to_pfn(", virt, "): in page ", (offset / 4096), ": not in range 0 to ", ptl_page_count, " pages", endl, flush;
      assert(false);
    }
    return offset >> 12;
  }

  mfn_t ptl_virt_to_mfn(void* virt) {
    return ptl_mfns[ptl_virt_to_pfn(virt)];
  }

  pfn_t ptl_level4_pfn, ptl_level3_pfn, phys_level3_pfn, ptl_level2_pfn, ptl_level1_pfn;
  mfn_t ptl_level4_mfn, ptl_level3_mfn, phys_level3_mfn, ptl_level2_mfn;

  byte* per_vcpu_stack_base;

  shared_info* ptlsim_entry_shinfo;
  char* log_buffer_base;

  bool alloc_ptlsim_pages(mfn_t* mfns, int ptl_page_count) {
    static const int MAX_ATTEMPTS = 4;

    int pages_so_far = 0;
    W64 sleep_time_nsec = 50 * (1000000);

    if (log_ptlsim_boot) cerr << "Allocate ", ptl_page_count, " pages (", ((ptl_page_count * 4096) / 1024), " KB) for PTLsim", endl, flush;

    foreach (i, MAX_ATTEMPTS) {
      xen_memory_reservation_t res;
      res.extent_start.p = mfns + pages_so_far;
      res.nr_extents = ptl_page_count - pages_so_far;
      res.extent_order = 0;
      res.address_bits = 0;
      res.domid = domain;

      assert(pages_so_far <= ptl_page_count);

      int rc = xc_memory_op(xc, XENMEM_increase_reservation, &res);
      // foreach (i, rc) { cerr << "  page ", intstring(i, 8), " -> mfn ", intstring(mfns[i], 8), endl; }

      if (rc < 0) {
        cerr << "PTLsim error: cannot increase domain reservation on attempt ", i, ": rc ", rc, endl, flush;
        return false;
      }

      pages_so_far += rc;

      if (pages_so_far == ptl_page_count) {
        return true;
      }

      if (log_ptlsim_boot) cerr << "  alloc_ptlsim_pages (attempt ", i, "): allocated ", rc, " pages; total so far: ", pages_so_far, " out of ", ptl_page_count, " pages", endl, flush;

      W64 current_target = 0;

      {
        istream is("/proc/xen/balloon");
        if (!is) {
          cerr << "PTLsim error: alloc_ptlsim_pages: cannot open /proc/xen/balloon", endl, flush;
          return false;
        }

        stringbuf line;
        dynarray<char*> tok;
        for (;;) {
          line.reset();
          is >> line;
          if (!is) break;

          tok.tokenize(line, " :");
          if ((tok.length >= 4) && strequal(tok[0], "Current") && strequal(tok[1], "allocation") && strequal(tok[3], "kB")) {
            current_target = atoll(tok[2]) * 1024;
            break;
          }
        }
      }

      if (log_ptlsim_boot) cerr << "  Current requested target: ", current_target, " bytes", endl, flush;

      if (!current_target) {
        cerr << "PTLsim error: cannot read current target reservation from /proc/xen/balloon! Is this the wrong Xen version?", endl, flush;
        return false;
      }

      W64 pages_still_needed = ptl_page_count - pages_so_far;
      W64 bytes_still_needed = pages_still_needed * 4096;

      if (log_ptlsim_boot) cerr << "  Still need ", pages_still_needed, " pages (", bytes_still_needed, " bytes)", endl, flush;

      W64 new_target = current_target - (bytes_still_needed + 1048576);

      if (log_ptlsim_boot) cerr << "  New target: ", new_target, endl;

      stringbuf sb;
      sb << new_target, endl;

      {
        ostream os("/proc/xen/balloon");
        os << sb;
        os.flush();
        if (!os.ok()) {
          cerr << "PTLsim error: cannot write new target reservation (", new_target, ") to /proc/xen/balloon! Is there a permissions problem?", endl, flush;
          return false;
        }
      }

      if (log_ptlsim_boot) cerr << "Sleeping for ", (sleep_time_nsec / 1000000), " milliseconds while pages are freed...", endl, flush;
      sys_nanosleep(sleep_time_nsec);
      sleep_time_nsec *= 2; // exponential backoff
    }

    cerr << "PTLsim error: cannot allocate ", ptl_page_count, " pages (", ((ptl_page_count * 4096) / 1024), " KB) for PTLsim", endl;
    cerr << "  Tried ", MAX_ATTEMPTS, " attempts but only got ", pages_so_far, " pages (", ((pages_so_far * 4096) / 1024), " KB)", endl;
    cerr << "  Make sure no other domains are running, try to free up some memory in dom0 and try again.", endl;
    cerr << endl;
    cerr << flush;
    return false;
  }

  void prep_initial_ptlsim_context(int vcpuid, Context& ptlctx) {
    setzero(ptlctx);
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
    ptlctx.commitarf[REG_flags] = 0; // interrupts initially off
    ptlctx.saved_upcall_mask = 1;
    
    Waddr per_vcpu_sp = ((Waddr)bootinfo->per_vcpu_stack_base) + (vcpuid * 4096) + 4096;
    ptlctx.commitarf[REG_rsp] = (vcpuid > 0) ? per_vcpu_sp : (Waddr)bootinfo->stack_top;
    ptlctx.commitarf[REG_rip] = PTLSIM_ENTRYPOINT_RIP;
    // start info in %rdi (arg[0]):
    ptlctx.commitarf[REG_rdi] = (Waddr)ptlmon_ptr_to_ptlcore_ptr(bootinfo);
    // vcpuid is passed in rsi so we know whether or not we're the primary VCPU:
    ptlctx.commitarf[REG_rsi] = vcpuid;
  }

  bool inject_ptlsim(int reserved_mbytes) {
    bool DEBUG = log_ptlsim_boot;

    static const int stacksize = 2048*1024;
    ptl_page_count = (reserved_mbytes * 1024*1024) / 4096;

    xen_domctl_t op;

    op.cmd = XEN_DOMCTL_getdomaininfo;
    op.domain = domain;
    int rc = xc_domctl(xc, &op);

    xen_domctl_getdomaininfo_t info;
    memcpy(&info, &op.u.getdomaininfo, sizeof(info));

    if (rc) {
      cerr << endl;
      cerr << "PTLsim error: cannot access domain ", domain, " (error ", rc, ")", endl,
        "Please make sure the specified domain is running.", endl, endl;
      return false;
    }

    W64 new_max_pages = info.tot_pages + ptl_page_count;

    if (DEBUG) {
      cerr << "Inject PTLsim into domain ", domain, ":", endl;
      cerr << "  Current allocation: ", intstring(info.tot_pages, 8), " pages", endl;
      cerr << "  Max allocation:     ", intstring(info.max_pages, 8), " pages", endl;
      cerr << "  PTLsim reserved:    ", intstring(ptl_page_count, 8), " pages", endl;
      cerr << "  Increase to:        ", intstring(new_max_pages, 8), " pages", endl;
    }

    op.cmd = XEN_DOMCTL_max_mem;
    op.domain = domain;
    op.u.max_mem.max_memkb = (new_max_pages * 4096) / 1024;
    rc = xc_domctl(xc, &op);

    if (rc) {
      cerr << "PTLsim error: cannot increase domain limit to ", new_max_pages, " pages (rc ", rc, ")", endl, flush;
      return false;
    }

    ptl_mfns = new mfn_t[ptl_page_count];
    memset(ptl_mfns, 0, ptl_page_count * sizeof(mfn_t));

    rc = alloc_ptlsim_pages(ptl_mfns, ptl_page_count);

    if (!rc) {
      cerr << "PTLsim error: cannot increase domain reservation to ", new_max_pages, " pages (rc ", rc, ")", endl, flush;
      return false;
    }

    image = (byte*)map_pages(ptl_mfns, ptl_page_count, PROT_READ|PROT_WRITE, (void*)PTLSIM_PSEUDO_VIRT_BASE, MAP_FIXED);
    assert(image == (byte*)PTLSIM_PSEUDO_VIRT_BASE);

    if (!image) {
      cerr << "PTLsim error: cannot map ", ptl_page_count, " allocated pages!", endl, flush;
      return false;
    }

    memset(image, 0, ptl_page_count * PAGE_SIZE);

    int next_free_page_pfn = ptl_page_count;

#define alloc_page(T, virt, pfn, mfn) next_free_page_pfn--; mfn = ptl_mfns[next_free_page_pfn]; pfn = next_free_page_pfn; T* virt = (T*)(image + (next_free_page_pfn * PAGE_SIZE))
#define alloc_pages(T, virt, pfn, n) next_free_page_pfn -= (n); pfn = next_free_page_pfn; T* virt = (T*)(image + (next_free_page_pfn * PAGE_SIZE))
#define virt_to_pfn(virt) ((((byte*)(virt)) - image) / PAGE_SIZE)

    int ptl_pagedir_mfn_count = (ptl_page_count + PTES_PER_PAGE-1) / PTES_PER_PAGE;

    bootinfo = (PTLsimMonitorInfo*)(image + (PTLSIM_BOOT_PAGE_PFN * PAGE_SIZE));
    mfn_t bootpage_mfn = ptl_mfns[PTLSIM_BOOT_PAGE_PFN];

    bootinfo->mfn_count = ptl_page_count;
    bootinfo->ptl_pagedir_mfn_count = ptl_pagedir_mfn_count;
    bootinfo->shared_info_mfn = info.shared_info_frame;
    bootinfo->total_machine_pages = total_machine_pages;
    bootinfo->phys_cpu_affinity = phys_cpu_affinity;

    alloc_pages(Level1PTE, ptl_level1, ptl_level1_pfn, ptl_pagedir_mfn_count);

    memset(ptl_level1, 0, ptl_pagedir_mfn_count * PAGE_SIZE);

    ptl_level1_pfn = virt_to_pfn(ptl_level1);

    bootinfo->ptl_pagedir = (Level1PTE*)(PTLSIM_VIRT_BASE + ((byte*)ptl_level1 - image));

    foreach (i, ptl_page_count) {
      Level1PTE& pte = ptl_level1[i];
      pte.p = 1;
      pte.rw = 1; // writable (unless reset below for pinned page tables)
      pte.us = 1; // supervisor only
      pte.a = 1;
      pte.mfn = ptl_mfns[i];
    }

    //
    // Map shared info page in appropriate place
    //
    ptl_level1[PTLSIM_SHINFO_PAGE_PFN].mfn = bootinfo->shared_info_mfn;
    bootinfo->shared_info = (shared_info*)PTLSIM_SHINFO_PAGE_VIRT_BASE;

    //
    // Allocate L2 PTE page
    //
    alloc_page(Level2PTE, ptl_level2, ptl_level2_pfn, ptl_level2_mfn);
    memset(ptl_level2, 0, PAGE_SIZE);

    foreach (i, ptl_pagedir_mfn_count) {
      Level2PTE& pte = ptl_level2[i];
      pte.p = 1;
      pte.rw = 1; // sub-pages are writable unless overridden
      pte.us = 1; // both user and supervisor
      pte.a = 1;
      pte.mfn = ptl_mfns[ptl_level1_pfn + i];
    }

    bootinfo->ptl_pagedir_map = (Level2PTE*)(PTLSIM_VIRT_BASE + ((byte*)ptl_level2 - image));
    bootinfo->ptl_pagedir_map_mfn = ptl_level2_mfn;

    //
    // Allocate PTLsim L3 page
    //
    alloc_page(Level3PTE, ptl_level3, ptl_level3_pfn, ptl_level3_mfn);
    memset(ptl_level3, 0, PAGE_SIZE);

    ptl_level3->p = 1;
    ptl_level3->rw = 1; // sub-pages are writable unless overridden
    ptl_level3->us = 1;
    ptl_level3->a = 1;
    ptl_level3->mfn = ptl_level2_mfn;

    bootinfo->ptl_level3_map = (Level3PTE*)(PTLSIM_VIRT_BASE + ((byte*)ptl_level3 - image));
    bootinfo->ptl_level3_mfn = ptl_level3_mfn;

    //
    // Finish toplevel template
    //
    alloc_page(Level4PTE, ptl_level4, ptl_level4_pfn, ptl_level4_mfn);
    memset(ptl_level4, 0, PAGE_SIZE);

    {
      Level4PTE& pte = ptl_level4[bits(PTLSIM_VIRT_BASE, (12+9+9+9), 9)];
      pte.p = 1;
      pte.rw = 1; // sub-pages are writable unless overridden
      pte.us = 1; // both user and supervisor
      pte.a = 1;
      pte.mfn = ptl_level3_mfn;
    }

    //
    // Finish up bootpage
    //
    bootinfo->toplevel_page_table = (Level4PTE*)(PTLSIM_VIRT_BASE + ((byte*)ptl_level4 - image));
    bootinfo->toplevel_page_table_mfn = ptl_level4_mfn;

    toplevel_page_table = ptlcore_ptr_to_ptlmon_ptr(bootinfo->toplevel_page_table);
    if (DEBUG) cerr << "toplevel_page_table = ", toplevel_page_table, " (mfn ", ptl_virt_to_mfn(toplevel_page_table), ")", endl, flush;
    if (DEBUG) cerr << "toplevel_page_table_mfn = ", bootinfo->toplevel_page_table_mfn, endl, flush;
    if (DEBUG) cerr << "ptl_pagedir_map_mfn = ", bootinfo->ptl_pagedir_map_mfn, endl, flush;
    assert(bootinfo->toplevel_page_table_mfn == ptl_virt_to_mfn(toplevel_page_table));

    size_t bytes = &_binary_ptlxen_bin_end - &_binary_ptlxen_bin_start;
    const byte* data = &_binary_ptlxen_bin_start;
    const Elf64_Ehdr& ehdr = *(const Elf64_Ehdr*)data;
    const Elf64_Phdr* phdr = (const Elf64_Phdr*)(((const byte*)&ehdr) + ehdr.e_phoff);

    if (DEBUG) cerr << "Injecting PTLsim into domain ", domain, ":", endl;
    if (DEBUG) cerr << "  PTLcore is ", bytes, " bytes @ virt addr ", image, endl, flush;

    Waddr real_code_start_offset = (ehdr.e_entry - PTLSIM_VIRT_BASE);
    shared_map_page_count = real_code_start_offset / PAGE_SIZE;

    int bytes_remaining = bytes - real_code_start_offset;
    if (DEBUG) cerr << "  Real code starts at offset ", real_code_start_offset, endl;
    if (DEBUG) cerr << "  Bytes to copy: ", bytes_remaining, endl, flush;
    memcpy(image + real_code_start_offset, data + real_code_start_offset, bytes_remaining);

    //
    // Prepare the heap
    //
    byte* end_of_image = image + ceil(phdr[0].p_memsz, PAGE_SIZE);
    Waddr bss_size = phdr[0].p_memsz - phdr[0].p_filesz;
    if (DEBUG) cerr << "  PTLsim has ", next_free_page_pfn, " pages left out of ", ptl_page_count, " pages allocated", endl;
    if (DEBUG) cerr << "  PTLxen file size ", phdr[0].p_filesz, ", virtual size ", phdr[0].p_memsz, ", end_of_image ", end_of_image, endl;
    if (DEBUG) cerr << "  Zero ", bss_size, " bss bytes starting at ", (image + phdr[0].p_filesz), endl, flush;
    memset(image + phdr[0].p_filesz, 0, bss_size);

    //
    // Set up primary stack
    //
    byte* sp = image + (next_free_page_pfn * PAGE_SIZE);
    bootinfo->stack_top = ptlmon_ptr_to_ptlcore_ptr(sp);
    bootinfo->stack_size = stacksize;
    next_free_page_pfn -= (stacksize / PAGE_SIZE);
    if (DEBUG) cerr << "  Setting up ", stacksize, "-byte stack starting at ", ptlmon_ptr_to_ptlcore_ptr(sp), endl, flush;

    //
    // Allocate up per-VCPU stacks
    //
    pfn_t per_vcpu_stack_base_pfn;
    alloc_pages(byte, per_vcpu_stack_base, per_vcpu_stack_base_pfn, MAX_CONTEXTS);
    bootinfo->per_vcpu_stack_base = ptlmon_ptr_to_ptlcore_ptr(per_vcpu_stack_base);
    if (DEBUG) cerr << "  Setting up ", vcpu_count, " stacks of ", 4096, " bytes each starting at ", bootinfo->per_vcpu_stack_base, endl, flush;

    //
    // Allocate virtual shinfo redirect page (for event recording and replay)
    //
    shadow_shinfo = ptlcore_ptr_to_ptlmon_ptr((shared_info*)PTLSIM_SHADOW_SHINFO_PAGE_VIRT_BASE);
    // shadow_shinfo will be filled in by Xen during the context swap
    if (DEBUG) cerr << "  Shadow shared info page at ", shadow_shinfo, endl, flush;

    //
    // Allocate VCPU contexts
    //
    ctx = ptlcore_ptr_to_ptlmon_ptr((Context*)PTLSIM_CTX_PAGE_VIRT_BASE);
    if (DEBUG) cerr << "  Context array starts at ", ptlmon_ptr_to_ptlcore_ptr(ctx), " (", sizeof(Context), " bytes each)", endl, flush;

    bootinfo->heap_start = ptlmon_ptr_to_ptlcore_ptr(end_of_image);
    bootinfo->heap_end = ptlmon_ptr_to_ptlcore_ptr(image + ((next_free_page_pfn-1) * PAGE_SIZE));
    bootinfo->avail_mfn_count = (next_free_page_pfn-1);

    if (DEBUG) {
      cerr << "PTLsim mapped at ", image, ":", endl;
      cerr << "Page counts:", endl;
      cerr << "  Total pages:      ", intstring(bootinfo->mfn_count, 8), endl;
      cerr << "  Remaining pages:  ", intstring(bootinfo->avail_mfn_count, 8), endl;
      cerr << "Addresses:", endl;
      cerr << "  Base:             ", (void*)image, endl;
      cerr << flush;
    }

    if (DEBUG) cerr << "  Heap start ", bootinfo->heap_start, " to heap end ", bootinfo->heap_end, " (", ((bootinfo->heap_end - bootinfo->heap_start) / 1024), " kbytes)", endl;
    if (DEBUG) cerr << "  Per-VCPU stacks from ", bootinfo->heap_start, " to heap end ", bootinfo->heap_end, " (", ((bootinfo->heap_end - bootinfo->heap_start) / 1024), " kbytes)", endl;

    bootinfo->vcpu_count = vcpu_count;
    bootinfo->max_pages = info.max_pages;
    bootinfo->total_machine_pages = total_machine_pages;
    bootinfo->monitor_hostcall_port = ptlsim_hostcall_port;
    bootinfo->hostcall_port = -1; // will be filled in by PTLsim on connect
    bootinfo->monitor_upcall_port = ptlsim_upcall_port;
    bootinfo->upcall_port = -1; // will be filled in by PTLsim on connect
    bootinfo->monitor_breakout_port = ptlsim_breakout_port;
    bootinfo->breakout_port = -1; // will be filled in by PTLsim on connect
    bootinfo->hostreq.ready = 0;
    bootinfo->hostreq.op = PTLSIM_HOST_NOP;
    bootinfo->ptlsim_state = PTLSIM_STATE_INITIALIZING;
    bootinfo->queued_upcall_count = 0;
    bootinfo->hostreq.op = PTLSIM_HOST_NOP;
    bootinfo->logbuf_tail = 0;
    bootinfo->logbuf_spinlock.reset();

    if (DEBUG) cerr << "  Hostcall port: ", bootinfo->monitor_hostcall_port, endl;
    if (DEBUG) cerr << "  Upcall port:   ", bootinfo->monitor_upcall_port, endl;
    if (DEBUG) cerr << "  Breakout port: ", bootinfo->monitor_breakout_port, endl;

    //
    // Set up hypercall page
    //
    {
      xen_domctl_t dom0op;
      dom0op.domain = domain;
      dom0op.u.hypercall_init.gmfn = ptl_mfns[PTLSIM_HYPERCALL_PAGE_PFN];
      dom0op.cmd = XEN_DOMCTL_hypercall_init;
      assert(xc_domctl(xc, &dom0op) == 0);
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

    if (DEBUG) cerr << "  Make L4 mfn ", ptl_level4_mfn, " the L4 page table overlay page", endl, flush;

    //
    // Unmap the read/write middle region and remap as read only (except for stack, which gets mapped read/write)
    //
    if (DEBUG) cerr << "Unmap ", bootinfo->mfn_count, " pages at ", image, endl, flush;
    unmap_pages(image, bootinfo->mfn_count);

    //
    // NOTE! bootpage is no longer accessible at this point!
    //

    rc = pin_page_table_mfns(ptl_mfns + ptl_level1_pfn, ptl_pagedir_mfn_count, 1);
    assert(rc == 0);

    rc = pin_page_table_mfn(ptl_level2_mfn, 2);
    assert(rc == 0);

    rc = pin_page_table_mfn(ptl_level3_mfn, 3);
    assert(rc == 0);

    rc = pin_page_table_mfn(ptl_level4_mfn, 4);
    assert(rc == 0);

    //
    // Make DMA area re-accessible:
    //
    if (DEBUG) cerr << "  Remap ", shared_map_page_count, " pages as read/write at ", image, " (page ", 0, ")", endl, flush;
    assert((Waddr)map_pages(ptl_mfns, shared_map_page_count, PROT_READ|PROT_WRITE, (void*)PTLSIM_PSEUDO_VIRT_BASE, MAP_FIXED) == PTLSIM_PSEUDO_VIRT_BASE);

    log_buffer_base = (char*)(PTLSIM_PSEUDO_VIRT_BASE + (PTLSIM_LOGBUF_PAGE_PFN * PAGE_SIZE));
    memset(log_buffer_base, 0, PTLSIM_LOGBUF_SIZE);

    foreach (i, vcpu_count) {
      Context& ptlctx = ctx[i];
      prep_initial_ptlsim_context(i, ptlctx);
    }

    //
    // Prepare initial shinfo page.
    // Upcalls must be disabled on every vcpu;
    // PTLsim will re-enable them on startup.
    //
    ptlsim_entry_shinfo = (shared_info*)ptl_alloc_private_page();
    memset(ptlsim_entry_shinfo, 0, 4096);
    foreach (i, vcpu_count) {
      ptlsim_entry_shinfo->vcpu_info[i].evtchn_upcall_mask = 1;
      //
      // Put in the initial CPU frequency since this will not be filled in until
      // PTLsim has been scheduled for the first timeslice.
      //
      ptlsim_entry_shinfo->vcpu_info[i].time.tsc_to_system_mul = shinfo->vcpu_info[i].time.tsc_to_system_mul;
      ptlsim_entry_shinfo->vcpu_info[i].time.tsc_shift = shinfo->vcpu_info[i].time.tsc_shift;
      memset(ptlsim_entry_shinfo->evtchn_mask, 0xff, sizeof(ptlsim_entry_shinfo->evtchn_mask));
    }

    if (DEBUG) cerr << "  PTLsim initial toplevel overlay cr3 = ", (void*)ctx[0].cr3, " (mfn ", (ctx[0].cr3 >> log2(PAGE_SIZE)), ")", endl;
    if (DEBUG) cerr << "  PTLsim entrypoint at ", (void*)ehdr.e_entry, endl;

    return true;
  }

  //
  // Print the early boot log buffer
  //
  void print_log_buffer(ostream& os) {
    bootinfo->logbuf_spinlock.acquire();
    int tail = bootinfo->logbuf_tail;
    os << "=== Start of log buffer (tail ", tail, ") ===", endl; os.flush();
    foreach (i, PTLSIM_LOGBUF_SIZE) {
      int offset = (tail + i) % PTLSIM_LOGBUF_SIZE;
      char c = log_buffer_base[offset];
      if (c) os << c;
    }
    os << endl, "=== End of log buffer ==", endl; os.flush();
    bootinfo->logbuf_spinlock.release();
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

  page_type_t query_page_type(const mfn_t mfn) {
    page_type_t pt;
    pt.in.mfn = mfn;
    
    mmuext_op_t op;
    op.cmd = MMUEXT_QUERY_PAGES;
    op.arg1.linear_addr = (Waddr)&pt;
    op.arg2.nr_ents = 1;
    int rc = xc_mmuext_op(xc, &op, 1, domain);
    return pt;
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
    cpu_type = get_cpu_type();

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

    xen_sysctl_t sysinfo;
    sysinfo.cmd = XEN_SYSCTL_physinfo;
    sysinfo.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    assert(xc_sysctl(xc, &sysinfo) == 0);

    if (DEBUG) {
      cerr << "Xen Information:", endl;
      cerr << "  Running on Xen version ", xen_caps, endl;
      cerr << "  Total machine physical pages: ", total_machine_pages, " (", ((total_machine_pages * PAGE_SIZE) / 1024), " KB host physical memory)", endl;
      cerr << "  Xen is mapped at virtual address ", (void*)(Waddr)xen_hypervisor_start_va, endl;
      cerr << "  Page table has ", page_table_levels, " levels", endl;
      cerr << "  Machine has ", sysinfo.u.physinfo.nr_nodes, " nodes, ", sysinfo.u.physinfo.sockets_per_node, " sockets/node, ", 
        sysinfo.u.physinfo.cores_per_socket, " cores/socket, ", sysinfo.u.physinfo.threads_per_core, " threads/core", endl;
      cerr << "  Core frequency: ", (sysinfo.u.physinfo.cpu_khz / 1000), " MHz", endl;
      cerr << "  Core type: ", get_cpu_type_name(cpu_type), endl;
    }

    //
    // Attach to target domain
    //
    xen_domctl_t op;

    op.cmd = XEN_DOMCTL_getdomaininfo;
    op.domain = domain;
    rc = xc_domctl(xc, &op);

    memcpy(&info, &op.u.getdomaininfo, sizeof(info));
    vcpu_count = info.max_vcpu_id + 1;
    vcpu_online_count = info.nr_online_vcpus;

    if (rc | (info.domain != domain)) {
      cerr << endl;
      cerr << "PTLsim error: cannot access domain ", domain, " (error ", rc, ")", endl,
        "Please make sure the specified domain is running.", endl, endl;
      return false;
    }

    phys_cpu_affinity = 0;
    foreach (i, vcpu_count) {
      uint64_t map = 0;
      int rc = xc_vcpu_getaffinity(xc, domain, i, &map);
      if (DEBUG) cerr << "  VCPU ", i, " has affinity map ", bitstring(map, 64, true), endl;
      phys_cpu_affinity |= map;
    }

    if (DEBUG) cerr << "PTLsim has connected to domain ", domain, ":", endl;

    // Support multiple Xen hypervisor API revisions:
#ifndef XEN_DOMINF_paused
#define XEN_DOMINF_paused DOMFLAGS_PAUSED
#endif
    if (info.flags & XEN_DOMINF_paused) {
      //cerr << "  Domain was already paused", endl;
    } else if ((rc = xc_domain_pause(xc, domain))) {
      cerr << "XenController: PAUSE failed (", rc, ")", endl;
      return false;
    }

    W64 current_page_count = info.tot_pages;
    W64 max_page_count = info.max_pages;

    shinfo = (shared_info*)map_page(info.shared_info_frame, PROT_READ|PROT_WRITE);

    if(!shinfo) {
      cerr << "XenController: xc_map_foreign_range(info.shared_info_frame ", info.shared_info_frame, ") failed", endl;
      return false;
    }

    int max_pfn = shinfo->arch.max_pfn;

    if (DEBUG) {
      cerr << "  ", vcpu_online_count, " out of ", vcpu_count, " VCPUs online", endl;
      cerr << "  ", info.tot_pages, " current pages (", ((info.tot_pages * 4096) / (1024 * 1024)), " MB), limit ", ((info.tot_pages * 4096) / (1024 * 1024)), " MB", endl;
      cerr << "  ", info.max_pages, " max pages (", ((info.max_pages * 4096) / (1024 * 1024)), " MB), limit ", ((info.max_pages * 4096) / (1024 * 1024)), " MB", endl;
      cerr << "  ", "Shared info mfn ", info.shared_info_frame, endl;
    }

    if (DEBUG) {
      Context ctx;
      setzero(ctx);
      getcontext(0, ctx);

      cerr << "Initial context:", endl;
      cerr << ctx;

#if 0
      Level1PTE* toplevel = (Level1PTE*)map_page(ctx.cr3 >> 12, PROT_READ);
      cerr << "Toplevel page table (mfn ", (ctx.cr3 >> 12), ") mapped at ", toplevel, endl, flush;
      foreach (i, 512) {
        cerr << "  Slot ", intstring(i, 3), ": ", toplevel[i], endl;
      }
#endif
    }
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

    alloc.remote_domain = domain;
    ptlsim_breakout_port = ioctl(evtchnfd, IOCTL_EVTCHN_BIND_UNBOUND_PORT, &alloc);
  }

  //
  // Copy the saved context in ctx (in PTLsim space) into the real
  // context, and save the old context back into ctx.
  //
  void swap_context(bool target_is_ptlsim) {
    int rc;
    // sync();

    if (target_is_ptlsim) {
      foreach (i, vcpu_count) {
        if (!bit(bootinfo->vcpu_ctx_initialized, i)) {
          prep_initial_ptlsim_context(i, ctx[i]);
          setbit(bootinfo->vcpu_ctx_initialized, i);
        }
      }
    }

    // Make sure PTLsim doesn't read the context until we've converted it to PTLsim format
    bootinfo->context_spinlock = 0;
    barrier();

    vcpu_guest_context_t* newctx = new vcpu_guest_context_t[vcpu_count];
    mlock(newctx, sizeof(vcpu_guest_context_t) * vcpu_count);

    vcpu_guest_context_t* oldctx = new vcpu_guest_context_t[vcpu_count];
    mlock(oldctx, sizeof(vcpu_guest_context_t) * vcpu_count);

    vcpu_extended_context_t* oldext = new vcpu_extended_context_t[vcpu_count];
    mlock(oldext, sizeof(vcpu_extended_context_t) * vcpu_count);

    vcpu_extended_context_t* newext = new vcpu_extended_context_t[vcpu_count];
    mlock(newext, sizeof(vcpu_extended_context_t) * vcpu_count);

    mlock(ptlsim_entry_shinfo, PAGE_SIZE);

    foreach (i, vcpu_count) {
      if unlikely (log_ptlsim_boot) {
        cerr << "New VCPU ", i, " context:", endl;
        cerr << ctx[i];
      }

      // PTLsim always starts off running on all VCPUs:
      if (target_is_ptlsim) ctx[i].running = 1;
      ctx[i].saveto(newctx[i]);
      ctx[i].saveto(newext[i]);
    }

    if (target_is_ptlsim) {
      assert(ctx[0].kernel_mode);
      assert(newctx[0].flags & VGCF_in_kernel);
    }

    xen_domctl_t dom0op;
    dom0op.domain = domain;
    dom0op.u.contextswap.vcpumap = bitmask(vcpu_count);
    if (target_is_ptlsim) {
      // native -> PTLsim
      dom0op.u.contextswap.old_shared_info = shadow_shinfo;
      dom0op.u.contextswap.new_shared_info = ptlsim_entry_shinfo; // make sure events are masked on entry
    } else {
      // PTLsim -> native
      dom0op.u.contextswap.old_shared_info = null; // no need to save
      dom0op.u.contextswap.new_shared_info = shadow_shinfo;
    }

    dom0op.u.contextswap.oldctx = oldctx;
    dom0op.u.contextswap.oldext = oldext;

    dom0op.u.contextswap.newctx = newctx;
    dom0op.u.contextswap.newext = newext;
    dom0op.cmd = XEN_DOMCTL_contextswap;

    rc = xc_domctl(xc, &dom0op);

    foreach (i, vcpu_count) {
      ctx[i].restorefrom(oldctx[i]);
      ctx[i].restorefrom(oldext[i]);
    }

    foreach (i, vcpu_count) {
      if (bit(dom0op.u.contextswap.vcpumap, i)) {
        // cerr << "ptlmon: Warning: cannot swap context for vcpu ", i, " (vcpu may not be up yet)", endl, flush;
        clearbit(bootinfo->vcpu_ctx_initialized, i);
        ctx[i].running = 0;
        ctx[i].runstate.state = RUNSTATE_offline;
      }
    }

    // Release PTLsim if it's waiting on the context
    bootinfo->context_spinlock = 1;
    barrier();

    munlock(ptlsim_entry_shinfo, PAGE_SIZE);

    munlock(newext, sizeof(vcpu_extended_context_t) * vcpu_count);
    delete newext;

    munlock(oldext, sizeof(vcpu_extended_context_t) * vcpu_count);
    delete oldext;

    munlock(oldctx, sizeof(vcpu_guest_context_t) * vcpu_count);
    delete oldctx;

    munlock(newctx, sizeof(vcpu_guest_context_t) * vcpu_count);
    delete newctx;
  }

  bool first_time;

  //
  // Switch back to a frozen instance of PTLsim
  //
  void switch_to_ptlsim(bool first_time = false) {
    swap_context(true);

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

  W64 next_upcall_uuid;

  W64 enqueue_upcall(const char* buf, size_t length) {
    PendingRequest* req = new PendingRequest();
    req->uuid = next_upcall_uuid++;
    req->fd = -1;
    req->data = new char[length+1];
    memcpy(req->data, buf, length);
    req->data[length] = 0;
    
    requestq.enqueue(req);
    bootinfo->queued_upcall_count++;
    return req->uuid;
  }

  W64 flush_upcall_queue(W64 uuidlimit = 0) {
    int n = 0;
    PendingRequest* req;
    while ((req = requestq.dequeue())) {
      bootinfo->queued_upcall_count--;
      n++;
      delete req->data;
      req->data = null;
      delete req;
    }

    PendingRequestTable::Iterator iter(&pendingreqs);
    while (req = iter.next()) {
      pendingreqs.remove(req);

      if (req->fd >= 0) {
        stringbuf reply;
        reply << "OK", endl;
        sys_write(req->fd, (char*)reply, strlen(reply));
        sys_close(req->fd);
      }

      delete req->data;
      req->data = null;
      delete req;

      n++;
    }

    return n;
  }

  void complete_upcall(W64 uuid) {
    PendingRequest* req = pendingreqs.get(uuid);

    if (!req) {
      cout << endl;
      // cout << "Warning: PTLxen notified us of an unknown completed request (uuid ", uuid, ")", endl, flush;
      return;
    }

    pendingreqs.remove(req);

    if (req->fd >= 0) {
      stringbuf reply;
      reply << "OK", endl;
      sys_write(req->fd, (char*)reply, strlen(reply));
      sys_close(req->fd);
    }

    delete req->data;
    req->data = null;
    delete req;
  }

  void enqueue_upcall_from_socket(int fd) {
    int rc = -EINVAL;
    int n;
    size_t request_bytes = 0;

    stringbuf sb;
    istream is(fd);
    is >> sb;

    dynarray<char*> list;
    expand_command_list(list, sb);

    //
    // Tell the core to stop the current run at the next cycle, then wait:
    //
    flush_upcall_queue();
    bootinfo->abort_request = 1;

    foreach (i, list.length) {
      enqueue_upcall(list[i], strlen(list[i]));
    }

    free_command_list(list);

    if (xchg(bootinfo->ptlsim_state, (byte)PTLSIM_STATE_RUNNING) == PTLSIM_STATE_NATIVE) {
      cerr << "External mode switch request received", endl, flush;
      switch_to_ptlsim();
      cerr << "  Switched to simulation mode", endl, flush;
    }

    cerr << "Got upcall from socket", endl, flush;

    complete_hostcall();

    return;
  }

  int process_event() {
    int rc;

    //bootinfo->hostreq_spinlock.acquire();
    int op = bootinfo->hostreq.op;
    bootinfo->hostreq.ready = 0;
    // cerr << "process_event: hostreq op ", bootinfo->hostreq.op, ", syscall_id ", bootinfo->hostreq.syscall.syscallid, endl, flush;

    switch (op) {
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
        assert(false);
      }
      bootinfo->hostreq.rc = do_syscall_64bit(syscall,
                                              arg1,
                                              arg2,
                                              arg3,
                                              arg4,
                                              arg5,
                                              arg6);
      // cerr << "  syscall result = ", bootinfo->hostreq.rc, endl, flush;
      break;
    };
    case PTLSIM_HOST_SWITCH_TO_NATIVE: {
      // pause();
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

      swap_context(false);

      bootinfo->ptlsim_state = PTLSIM_STATE_NATIVE;
      cerr << "  Switched to native mode", endl, flush;
      bootinfo->hostreq.rc = 0;
      if (!bootinfo->hostreq.switch_to_native.pause) unpause();

      //bootinfo->hostreq_spinlock.release();

      return 0;
    };
    case PTLSIM_HOST_SHUTDOWN: {
      pause();
      cerr << "ptlmon: Domain ", domain, " has shut down", endl, flush;
      //bootinfo->hostreq_spinlock.release();
      return 1;
    };
    case PTLSIM_HOST_ACCEPT_UPCALL: {
      if ((!requestq.empty()) | (!bootinfo->hostreq.accept_upcall.blocking)) complete_hostcall();
      // Otherwise wait for user to add a request
      //bootinfo->hostreq_spinlock.release();
      return 0;
    }
    case PTLSIM_HOST_COMPLETE_UPCALL: {
      complete_upcall(bootinfo->hostreq.complete_upcall.uuid);
      break;
    }
    case PTLSIM_HOST_INJECT_UPCALL: {
      bootinfo->hostreq.rc = enqueue_upcall(ptlcore_ptr_to_ptlmon_ptr(bootinfo->hostreq.inject_upcall.buf), bootinfo->hostreq.inject_upcall.length);
      break;
    }
    case PTLSIM_HOST_FLUSH_UPCALL_QUEUE: {
      bootinfo->hostreq.rc = flush_upcall_queue(bootinfo->hostreq.flush_upcall_queue.uuid_limit);
      break;
    }
    case PTLSIM_HOST_SETUP_PERFCTRS:
    case PTLSIM_HOST_WRITE_PERFCTRS: {
      if (cpu_type == CPU_TYPE_UNKNOWN) {
        bootinfo->hostreq.rc = -ENOSYS;
        break;
      }

      W32 cpu = bootinfo->hostreq.perfctr.cpu;
      W32 index = bootinfo->hostreq.perfctr.index;
      W64 value = bootinfo->hostreq.perfctr.value;

      W32 setup_msr_base;
      W32 readout_msr_base;
      W32 counter_count;

      switch (cpu_type) {
      case CPU_TYPE_AMD_K8:
        setup_msr_base = 0xc0010000;
        readout_msr_base = 0xc0010004;
        counter_count = 4;
        break;
      case CPU_TYPE_INTEL_CORE2:
      case CPU_TYPE_INTEL_PENTIUM4:
        setup_msr_base = 0x186;
        readout_msr_base = 0xc1;
        counter_count = 2;
        break;
      default:
        // Not supported
        assert(false);
      }

      if (index >= counter_count) {
        cerr << "ptlmon: perfctr request: counter ", index, " is greater than this processor's limit of ", counter_count, endl, flush;
        bootinfo->hostreq.rc = -E2BIG;
        break;
      }

      if ((cpu >= 64) | (!bit(phys_cpu_affinity, cpu))) {
        cerr << "ptlmon: perfctr request: cpu ", cpu, " is not in this domain's affinity set", endl, flush;
        bootinfo->hostreq.rc = -E2BIG;
        break;
      }
      // Hypervisor will check if physical processor <cpu> is valid and online

      if (op == PTLSIM_HOST_SETUP_PERFCTRS) {
        // Make sure the guest can't turn on dangerous things like pin toggling or overflow interrupts
        static const W64 perfctr_safe_mask = ~((1ULL << 21) | (1ULL << 20) | (1ULL << 19));
        value &= perfctr_safe_mask;
        bootinfo->hostreq.rc = wrmsr(xc, cpu, setup_msr_base + index, value);
        // cerr << "ptlmon: setup_perfctrs: cpu ", cpu, ", counter ", index, " (msr ", (void*)(setup_msr_base + index), "), value ", (void*)value, " => rc ", bootinfo->hostreq.rc, endl, flush;
      } else {
        assert(op == PTLSIM_HOST_WRITE_PERFCTRS);
        bootinfo->hostreq.rc = wrmsr(xc, cpu, readout_msr_base + index, value);
        // cerr << "ptlmon: write_perfctrs: cpu ", cpu, ", counter ", index, " (msr ", (void*)(setup_msr_base + index), "), value ", value, " => rc ", bootinfo->hostreq.rc, endl, flush;
      }
      break;
    };
    PTLSIM_HOST_FLUSH_CACHE: {
      // Only dom0 is allowed to do cache flush
      mmuext_op_t fc;
      int ok = 0;
      fc.cmd = MMUEXT_FLUSH_CACHE;
      fc.arg1.linear_addr = 0;
      fc.arg2.vcpuid = 0;
      
      int rc = xc_mmuext_op(xc, &fc, 1, domain);
      assert(rc == 0);
      assert(ok == 1);

      break;
    };
    default:
      bootinfo->hostreq.rc = (W64)-ENOSYS;
    };

    //bootinfo->hostreq_spinlock.release();

    complete_hostcall();
    return 0;
  }

  //
  // Complete a pending request, and unblock the domain
  //
  int complete_hostcall() {
    int op = bootinfo->hostreq.op;

    switch (op) {
    case PTLSIM_HOST_NOP: {
      // nothing pending
      return 0;
    }
    case PTLSIM_HOST_ACCEPT_UPCALL: {
      PendingRequest* req = requestq.dequeue();

      if (req) {
        bootinfo->queued_upcall_count--;
        int n = min(strlen(req->data), bootinfo->hostreq.accept_upcall.length-1);

        strncpy(ptlcore_ptr_to_ptlmon_ptr(bootinfo->hostreq.accept_upcall.buf), req->data, n);
        *(ptlcore_ptr_to_ptlmon_ptr(bootinfo->hostreq.accept_upcall.buf + n)) = 0;
        bootinfo->hostreq.rc = req->uuid;

        pendingreqs.add(req);
      } else {
        if (bootinfo->hostreq.accept_upcall.blocking) {
          return 0;
        }

        // Non-blocking: let caller try again
        bootinfo->hostreq.rc = 0;
      }

      break;
    }
    default: {
      break;
    }
    }

    int rc;

    // cerr << "complete_hostcall(", op, "): notify port ", ptlsim_hostcall_port, endl, flush;
    barrier();
    bootinfo->hostreq.ready = 1;
    barrier();
    //bootinfo->hostreq_spinlock.release();

    wakeup_ptlsim();
    return 0;
  }

  void wakeup_ptlsim() {
    ioctl_evtchn_notify notify;
    notify.port = ptlsim_hostcall_port;
    int rc = ioctl(evtchnfd, IOCTL_EVTCHN_NOTIFY, &notify);
  }

  XenController(int domain) {
    attach(domain);
  }

  int detach() {
    static const bool DEBUG = 0;

    int rc;

    if ((xc < 0) | (domain < 0)) return 0;

    xc_domain_unpause(xc, domain);

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
#if 0
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
#endif
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

  cerr << "ptlsim: Sending request '", request, "' to domain ", domain, "...", flush;

  rc = sys_write(sd, request, strlen(request));
  sys_write(sd, "\n", 1);

  char reply[64];
  rc = sys_read(sd, reply, sizeof(reply)); 
  cout << reply, endl, flush;

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

int atoi_with_check(const char* s) {
  bool all_nums = 1;
  W64 id = 0;
  int n = strlen(s);

  foreach (i, n) {
    char c = s[i];
    all_nums &= inrange(c, '0', '9');
    id = (id * 10) + (int)(c - '0');
  }

  return (all_nums) ? id : -1;
}

int xc_get_domain_from_name(const char* name) {
  int domain = -1;
  xc_dominfo_t list[1024];
  int found = 0;

  int xc = xc_interface_open();
  if unlikely (xc < 0) return -1;
  int n = xc_domain_getinfo(xc, 0, lengthof(list), list);

  xs_handle* xs = xs_daemon_open();
  
  foreach (i, n) {
    xc_dominfo_t& info = list[i];

    char* dompath = xs_get_domain_path(xs, info.domid);
    if unlikely (!dompath) continue;
    stringbuf path;
    path << dompath, '/', "name";
    delete dompath;
    unsigned int len = strlen(path);
    char* data = (char*)xs_read(xs, XBT_NULL, path, &len);
    if unlikely (data && strequal(name, data)) {
      domain = info.domid;
      break;
    }
    if likely (data) delete data;
  }

  if (xs) xs_daemon_close(xs);

  xc_interface_close(xc);

  return domain;
}

int main(int argc, char** argv) {
  int rc;
  argc--; argv++;

  // We need each VCPU context to be exactly one page; it was padded this way in ptlhwdef.h:
  assert(sizeof(Context) == PAGE_SIZE);

  //
  // 32 MB default:
  //
  // IMPORTANT: On machines with more than ~16 GB RAM,
  // this MUST be increased to leave enough room for
  // PTLsim's heap and a sufficient translation cache.
  //
  // The -reservemem 64 option can be used to do this.
  //
  W64 ptlsim_reserved_mb = 128;
  const char* domain_name = null;

  foreach (i, argc) {
    if (strequal(argv[i], "-domain") && (argc > i)) {
      domain_name = argv[i+1];
      domain = atoi_with_check(domain_name);
      // Was it a number? If so, no need to save the domain name:
      if likely (domain >= 0) domain_name = null;
    } else if (strequal(argv[i], "-reservemem")) {
      if (argc > i) { ptlsim_reserved_mb = atoi(argv[i+1]); }
    } else if (strequal(argv[i], "-bootlog")) {
      log_ptlsim_boot = 1;
    }
  }

  if (!argc) {
    print_banner(cerr);
    print_saved_usage(cerr);
    return -1;
  }

  if likely (domain_name) {
    domain = xc_get_domain_from_name(domain_name);
  }

  if (domain < 0) {
    if likely (domain_name) cerr << "Cannot find domain '", domain_name, "'", endl;
    cerr << "Please use the -domain XXX option to specify a Xen domain to access.", endl, endl;
    return -2;
  }

  stringbuf cmdsb;
  merge_string_list(cmdsb, " ", argc, argv);

  rc = send_request_to_ptlmon(domain, cmdsb);

  if (rc < 0) {
    // Inject into guest for first time, or reboot PTLsim within guest
    XenController xc;
    if (!xc.attach(domain)) return -1;
    xc.alloc_control_port();
    if (!xc.inject_ptlsim(ptlsim_reserved_mb)) return -1;

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

#if 0
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sigterm_handler;
    sa.sa_flags = SA_SIGINFO;
    assert(sys_rt_sigaction(SIGINT, &sa, NULL, sizeof(W64)) == 0);
#endif

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

    dynarray<char*> list;
    expand_command_list(list, argc, argv);
    foreach (i, list.length) {
      xc.enqueue_upcall(list[i], strlen(list[i]));
    }
    free_command_list(list);

    if (log_ptlsim_boot) cerr << "  Ready, set, go!", endl, flush;
    xc.switch_to_ptlsim(true);
    if (log_ptlsim_boot) cerr << "  PTLsim is now in control inside domain ", domain, endl, flush;

    for (;;) {
      epoll_event event;
      memset(&event, 0, sizeof(event));
      int rc = epoll_wait(waitfd, &event, 1, 100);
      if (rc < 0) break;

      if (!rc) {
        // kick-start the other domain in case we raced and it missed the last interrupt
        xc.wakeup_ptlsim();
        continue;
      }

      if (event.data.fd == sd) {
        sockaddr_un acceptaddr;
        socklen_t acceptlen = sizeof(acceptaddr);
        int acceptsd = accept(sd, (sockaddr*)&acceptaddr, &acceptlen);
        // NOTE: potential denial of service here, if data hasn't arrived yet (can hold up servicing hostcalls from ptlcore): use a timeout
        xc.enqueue_upcall_from_socket(acceptsd);
        epoll_ctl(waitfd, EPOLL_CTL_DEL, acceptsd, null);
      } else if (event.data.fd == xc.evtchnfd) {
        W32 readyport = 0;
        rc = read(xc.evtchnfd, &readyport, sizeof(readyport));
        // Re-enable it:
        rc = write(xc.evtchnfd, &readyport, sizeof(readyport));

        if (readyport == xc.ptlsim_hostcall_port) {
          int done = xc.process_event();
          
          if (done) {
            cerr << "PTLsim exited", endl, flush;
            cerr << flush;
            break;
          }
        } else if (readyport == xc.ptlsim_breakout_port) {
          // If it's in the native state, switch to PTLsim first, then send the command
          if (xc.bootinfo->ptlsim_state == PTLSIM_STATE_NATIVE) {
            cerr << "Breakout request received from native mode", endl, flush;
            xc.switch_to_ptlsim();
            cerr << "  Switched to simulation mode", endl, flush;
          } else {
            // PTLsim may be in the idle state: send it anyway
            cerr << "ptlmon: Warning: cannot switch to simulation mode: domain ", domain, " was already in state ", xc.bootinfo->ptlsim_state, endl, flush;
          }
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
