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

#define PML4_SHIFT (12+9+9+9)
#define PTLSIM_VIRT_BASE 0xffffff0000000000ULL // PML4 entry 510
#define PHYS_VIRT_BASE   0xfffffe0000000000ULL // PML4 entry 508 (enough for 2^39 bytes physical RAM)
// PML4 entry 511 is usually occupied by Linux itself

#define virt_is_inside_ptlsim(x) ((((W64)(x)) >> PML4_SHIFT) == (PTLSIM_VIRT_BASE >> PML4_SHIFT))
#define virt_is_inside_physmap(x) ((((W64)(x)) >> PML4_SHIFT) == (PHYS_VIRT_BASE >> PML4_SHIFT))

#define PTLSIM_BOOT_PAGE_PFN 0
#define PTLSIM_BOOT_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_BOOT_PAGE_PFN * 4096))
#define PTLSIM_BOOT_PAGE_PADDING 2048 // bytes of pre-padding (where ELF header goes)

#define PTLSIM_HYPERCALL_PAGE_PFN 1
#define PTLSIM_HYPERCALL_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_HYPERCALL_PAGE_PFN * 4096))

#define PTLSIM_SHINFO_PAGE_PFN 2
#define PTLSIM_SHINFO_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_SHINFO_PAGE_PFN * 4096))

#define PTLSIM_SHADOW_SHINFO_PAGE_PFN 3
#define PTLSIM_SHADOW_SHINFO_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_SHADOW_SHINFO_PAGE_PFN * 4096))

//
// The transfer page is used to copy data *into* the domain, since all
// other pages are mapped as read only. Thunked system calls and other
// utility functions use this facility. PTLsim may need to copy data
// from this buffer to its final destination inside the domain.
//
#define PTLSIM_XFER_PAGE_PFN 4
#define PTLSIM_XFER_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_XFER_PAGE_PFN * 4096))

#define PTLSIM_CTX_PAGE_PFN 5
#define PTLSIM_CTX_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_CTX_PAGE_PFN * 4096))
#define PTLSIM_CTX_PAGE_COUNT 32 // up to 32 VCPUs per domain

#define PTLSIM_FIRST_READ_ONLY_PAGE (PTLSIM_CTX_PAGE_PFN + PTLSIM_CTX_PAGE_COUNT)

//#define PTLSIM_ELF_SKIP_START (PTLSIM_BOOT_PAGE_PFN * 4096)
//#define PTLSIM_ELF_SKIP_END ((PTLSIM_SHINFO_PAGE_PFN+1) * 4096)

#define INVALID_MFN 0xffffffffffffffffULL

#define PTES_PER_PAGE (PAGE_SIZE / sizeof(pte_t))

#define PTLSIM_STUB_MAGIC 0x4b4f6d69734c5450ULL // "PTLsimOK"
#define PTLSIM_BOOT_PAGE_MAGIC 0x50426d69734c5450ULL // "PTLsimBP"
#define MAX_RESERVED_PAGES 131072 // on 64-bit platforms, this is 512 MB

struct Level1PTE;
struct Level2PTE;
struct Level3PTE;
struct Level4PTE;

struct PTLsimBootPageInfo {
  byte padding[PTLSIM_BOOT_PAGE_PADDING];

  W64 magic; // PTLSIM_BOOT_PAGE_MAGIC
  W64 mfn_count;
  W64 avail_mfn_count;
  W64 total_machine_pages;

  struct Level1PTE* ptl_pagedir;
  struct Level2PTE* ptl_pagedir_map;
  struct Level3PTE* ptl_level3_map;
  struct Level4PTE* toplevel_page_table;
  struct PTLsimBootPageInfo* boot_page;
  struct shared_info* shared_info;

  W64 ptl_pagedir_mfn_count;

  mfn_t ptl_pagedir_map_mfn;
  mfn_t ptl_level3_mfn;
  mfn_t toplevel_page_table_mfn;
  mfn_t boot_page_mfn;
  mfn_t shared_info_mfn;
  mfn_t start_info_mfn;
  mfn_t store_mfn;
  mfn_t console_mfn;
  int store_evtchn;
  int console_evtchn;
};

//
// This structure resides at the very end of the shared info page
//
struct PTLsimStub {
  W64 magic; // PTLSIM_SIGNATURE_MAGIC
  W64 boot_page_mfn;
};

#ifndef __cplusplus
typedef struct Level1PTE { W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, d:1, pat:1, g:1, avl:3, mfn:51, nx:1; } Level1PTE;
typedef struct Level2PTE { W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, ign:1, psz:1, mbz:1, avl:3, mfn:51, nx:1; } Level2PTE;
typedef struct Level3PTE { W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, ign:1, mbz:2, avl:3, mfn:51, nx:1; } Level3PTE;
typedef struct Level4PTE { W64 p:1, rw:1, us:1, pwt:1, pcd:1, a:1, ign:1, mbz:2, avl:3, mfn:51, nx:1; } Level4PTE;
#endif

int setup_ptlsim_space(int xc_handle, uint32_t dom, mfn_t* mfns, int count,
                       shared_info_t* shared_info, mfn_t shared_info_mfn,
                       start_info_t* start_info, mfn_t start_info_mfn);
