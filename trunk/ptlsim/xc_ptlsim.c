//
// PTLsim/Xen Integration
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//

#include "xg_private.h"
#include "xc_private.h"
#include <xenctrl.h>

#include <xc_ptlsim.h>

//
// Build structures and reserve physical pages for PTLsim, so it can be
// injected into the domain at a later time
//
#undef DEBUG
int setup_ptlsim_space(int xc_handle, uint32_t dom, mfn_t* mfns, int count,
                       shared_info_t* shared_info, mfn_t shared_info_mfn,
                       start_info_t* start_info, mfn_t start_info_mfn) {
  int i;
  byte* reserved_page_pool;
  int pagedir_pages_required = (count + PTES_PER_PAGE-1) / PTES_PER_PAGE;
  pfn_t next_free_page_pfn;

  struct PTLsimBootPageInfo* bootpage;

  struct PTLsimStub* stub;

  mfn_t bootpage_mfn;

  struct Level1PTE* ptl_level1;
  pfn_t ptl_level1_pfn;

  struct Level2PTE* ptl_level2;
  mfn_t ptl_level2_mfn;

  struct Level3PTE* ptl_level3;
  mfn_t ptl_level3_mfn;

  struct Level4PTE* level4;
  mfn_t level4_mfn;

  W64 total_machine_pages;
  
  total_machine_pages = xc_memory_op(xc_handle, XENMEM_maximum_ram_page, NULL);

  reserved_page_pool = (byte*)xc_map_foreign_batch(xc_handle, dom, PROT_READ | PROT_WRITE, mfns, count);
  if (!reserved_page_pool) return -1;

  memset(reserved_page_pool, 0, count * PAGE_SIZE);

  next_free_page_pfn = count;

#define alloc_page(T, virt, mfn) next_free_page_pfn--; mfn = mfns[next_free_page_pfn]; virt = (T*)(reserved_page_pool + (next_free_page_pfn * PAGE_SIZE))
#define alloc_pages(T, virt, n) next_free_page_pfn -= (n); virt = (T*)(reserved_page_pool + (next_free_page_pfn * PAGE_SIZE))
#define virt_to_pfn(virt) ((((byte*)(virt)) - reserved_page_pool) / PAGE_SIZE)

  bootpage = (struct PTLsimBootPageInfo*)(reserved_page_pool + (PTLSIM_BOOT_PAGE_PFN * PAGE_SIZE));
  bootpage_mfn = mfns[PTLSIM_BOOT_PAGE_PFN];

  bootpage->magic = PTLSIM_BOOT_PAGE_MAGIC;
  bootpage->mfn_count = count;
  bootpage->ptl_pagedir_mfn_count = pagedir_pages_required;
  bootpage->boot_page_mfn = bootpage_mfn;
  bootpage->boot_page = (struct PTLsimBootPageInfo*)(PTLSIM_VIRT_BASE + ((byte*)bootpage - reserved_page_pool));
  bootpage->shared_info_mfn = shared_info_mfn;
  bootpage->total_machine_pages = total_machine_pages;

  alloc_pages(Level1PTE, ptl_level1, pagedir_pages_required);
  memset(ptl_level1, 0, pagedir_pages_required * PAGE_SIZE);

  ptl_level1_pfn = virt_to_pfn(ptl_level1);

  bootpage->ptl_pagedir = (struct Level1PTE*)(PTLSIM_VIRT_BASE + ((byte*)ptl_level1 - reserved_page_pool));

  for (i = 0; i < count; i++) {
    struct Level1PTE* pte = &ptl_level1[i];
    pte->p = 1;
    pte->rw = 1; // writable (unless reset below for pinned page tables)
    pte->us = 1; // supervisor only
    pte->a = 1;
    pte->mfn = mfns[i];
  }

  //
  // Map shared info page in appropriate place
  //
  ptl_level1[PTLSIM_SHINFO_PAGE_PFN].mfn = bootpage->shared_info_mfn;
  bootpage->shared_info = (shared_info_t*)PTLSIM_SHINFO_PAGE_VIRT_BASE;

  alloc_page(Level2PTE, ptl_level2, ptl_level2_mfn);
  memset(ptl_level2, 0, PAGE_SIZE);

  for (i = 0; i < pagedir_pages_required; i++) {
    struct Level2PTE* pte = &ptl_level2[i];
    pte->p = 1;
    pte->rw = 1; // sub-pages are writable unless overridden
    pte->us = 1; // both user and supervisor
    pte->a = 1;
    pte->mfn = mfns[ptl_level1_pfn + i];
  }

  bootpage->ptl_pagedir_map = (struct Level2PTE*)(PTLSIM_VIRT_BASE + ((byte*)ptl_level2 - reserved_page_pool));
  bootpage->ptl_pagedir_map_mfn = ptl_level2_mfn;

  alloc_page(Level3PTE, ptl_level3, ptl_level3_mfn);
  memset(ptl_level3, 0, PAGE_SIZE);

  ptl_level3[0].p = 1;
  ptl_level3[0].rw = 1; // sub-pages are writable unless overridden
  ptl_level3[0].us = 1;
  ptl_level3[0].a = 1;
  ptl_level3[0].mfn = ptl_level2_mfn;

  bootpage->ptl_level3_map = (struct Level3PTE*)(PTLSIM_VIRT_BASE + ((byte*)ptl_level3 - reserved_page_pool));
  bootpage->ptl_level3_mfn = ptl_level3_mfn;

  //
  // Finish toplevel
  //

  alloc_page(Level4PTE, level4, level4_mfn);

  {
    int index = (PTLSIM_VIRT_BASE >> (12+9+9+9)) & 0x1ff;
    struct Level4PTE* top = &level4[index];
    memset(level4, 0, PAGE_SIZE);

    top->p = 1;
    top->rw = 1; // sub-pages are writable unless overridden
    top->us = 1; // both user and supervisor
    top->a = 1;
    top->mfn = ptl_level3_mfn;
  }

  //
  // Finish up bootpage
  //
  bootpage->avail_mfn_count = next_free_page_pfn;
  bootpage->toplevel_page_table = (struct Level4PTE*)(PTLSIM_VIRT_BASE + ((byte*)level4 - reserved_page_pool));
  bootpage->toplevel_page_table_mfn = level4_mfn;

  bootpage->start_info_mfn = start_info_mfn;
  bootpage->store_mfn = start_info->store_mfn;
  bootpage->store_evtchn = start_info->store_evtchn;
  bootpage->console_mfn = start_info->console_mfn;
  bootpage->console_evtchn = start_info->console_evtchn;
    
  //
  // Set up stub
  //
  stub = (struct PTLsimStub*)(((byte*)shared_info) + (PAGE_SIZE - sizeof(struct PTLsimStub)));
  stub->magic = PTLSIM_STUB_MAGIC;
  stub->boot_page_mfn = mfns[virt_to_pfn(bootpage)];

  munmap(reserved_page_pool, count * PAGE_SIZE);

  return 0;
}
