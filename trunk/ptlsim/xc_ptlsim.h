// -*- c++ -*-
//
// PTLsim/Xen Integration
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//

typedef unsigned long long W64;
typedef unsigned int W32;
typedef unsigned short W16;
typedef unsigned char byte;

typedef unsigned long pfn_t;
typedef unsigned long mfn_t;
typedef unsigned long pte_t;

#define PTLSIM_VIRT_BASE 0x0LL // base 0 (so all 32-bit offsets fit)
#define PHYS_VIRT_BASE 0x10000000000ULL // (1 << 40), PML4 entry 2

#define PTLSIM_BOOT_PAGE_PFN 0
#define PTLSIM_BOOT_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_BOOT_PAGE_PFN * 4096))
#define PTLSIM_BOOT_PAGE_PADDING 2048 // bytes of pre-padding (where ELF header goes)

#define PTLSIM_HYPERCALL_PAGE_PFN 1
#define PTLSIM_HYPERCALL_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_HYPERCALL_PAGE_PFN * 4096))

#define PTLSIM_SHINFO_PAGE_PFN 2
#define PTLSIM_SHINFO_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_SHINFO_PAGE_PFN * 4096))

#define PTLSIM_ELF_SKIP_START (PTLSIM_BOOT_PAGE_PFN * 4096)
#define PTLSIM_ELF_SKIP_END ((PTLSIM_SHINFO_PAGE_PFN+1) * 4096)

#define INVALID_MFN 0xffffffffffffffffULL

#define PTES_PER_PAGE (PAGE_SIZE / sizeof(pte_t))

#define PTLSIM_STUB_MAGIC 0x4b4f6d69734c5450ULL // "PTLsimOK"
#define PTLSIM_BOOT_PAGE_MAGIC 0x50426d69734c5450ULL // "PTLsimBP"
#define MAX_RESERVED_PAGES 131072 // on 64-bit platforms, this is 512 MB

struct PTLsimBootPageInfo {
  byte padding[PTLSIM_BOOT_PAGE_PADDING];

  W64 magic; // PTLSIM_BOOT_PAGE_MAGIC
  W64 mfn_count;
  W64 avail_mfn_count;
  W64 read_only_break_page;

  struct LongModeLevel2PTE* ptl_pagedir_map;
  struct LongModeLevel4PTE* toplevel_page_table;
  struct LongModeLevel1PTE* ptl_pagedir;
  struct LongModeLevel1PTE* phys_pagedir;
  struct PTLsimBootPageInfo* boot_page;
  struct shared_info* shared_info;

  W64 ptl_pagedir_mfn_count;
  W64 phys_pagedir_mfn_count;

  mfn_t ptl_pagedir_map_mfn;
  mfn_t toplevel_page_table_mfn;
  mfn_t boot_page_mfn;
  mfn_t shared_info_mfn;
};

//
// This structure resides at the very end of the shared info page
//
struct PTLsimStub {
  W64 magic; // PTLSIM_SIGNATURE_MAGIC
  W64 boot_page_mfn;
};

typedef struct LongModeLevel1PTE { W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, d:1, pat:1, g:1, avl:3, phys:51, nx:1; } LongModeLevel1PTE;
typedef struct LongModeLevel2PTE { W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, ign:1, psz:1, mbz:1, avl:3, next:51, nx:1; } LongModeLevel2PTE;
typedef struct LongModeLevel3PTE { W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, ign:1, mbz:2, avl:3, next:51, nx:1; } LongModeLevel3PTE;
typedef struct LongModeLevel4PTE { W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, ign:1, mbz:2, avl:3, next:51, nx:1; } LongModeLevel4PTE;

int setup_ptlsim_space(int xc_handle, uint32_t dom, mfn_t* mfns, int count,
                       shared_info_t* shared_info, mfn_t shared_info_mfn);
