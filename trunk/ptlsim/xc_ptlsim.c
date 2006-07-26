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
                       shared_info_t* shared_info, mfn_t shared_info_mfn) {
  int i;
  byte* reserved_page_pool;
  int pagedir_pages_required = (count + PTES_PER_PAGE-1) / PTES_PER_PAGE;
  pfn_t next_free_page_pfn;
  int rc = 0;
  struct mmuext_op op;
  struct dom0_op dom0op;

  struct PTLsimBootPageInfo* bootpage;

  //start_info_t* start_info_copy;
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

  struct Level1PTE* physmap_level1;
  W64 physmap_level1_pages;
  pfn_t physmap_level1_pfn;

  struct Level2PTE* physmap_level2;
  W64 physmap_level2_pages;
  pfn_t physmap_level2_pfn;

  struct Level3PTE* physmap_level3;
  pfn_t physmap_level3_mfn;

  mfn_t gdt_mfn;
  void* gdt_page;
  
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

  ptl_level1_pfn = virt_to_pfn(ptl_level1);

  bootpage->ptl_pagedir = (struct Level1PTE*)(PTLSIM_VIRT_BASE + ((byte*)ptl_level1 - reserved_page_pool));

  for (i = 0; i < count; i++) {
    struct Level1PTE* pte = &ptl_level1[i];
    pte->p = 1;
    pte->rw = 1; // writable (unless reset below for pinned page tables)
    pte->us = 1; // supervisor only
    pte->a = 1;
    pte->phys = mfns[i];
  }

  //
  // Map shared info page in appropriate place
  //
  ptl_level1[PTLSIM_SHINFO_PAGE_PFN].phys = bootpage->shared_info_mfn;
  bootpage->shared_info = (shared_info_t*)PTLSIM_SHINFO_PAGE_VIRT_BASE;

  alloc_page(Level2PTE, ptl_level2, ptl_level2_mfn);

  for (i = 0; i < pagedir_pages_required; i++) {
    struct Level2PTE* pte = &ptl_level2[i];
    pte->p = 1;
    pte->rw = 1; // sub-pages are writable unless overridden
    pte->us = 1; // both user and supervisor
    pte->a = 1;
    pte->next = mfns[ptl_level1_pfn + i];
  }

  bootpage->ptl_pagedir_map = (struct Level2PTE*)(PTLSIM_VIRT_BASE + ((byte*)ptl_level2 - reserved_page_pool));
  bootpage->ptl_pagedir_map_mfn = ptl_level2_mfn;

  alloc_page(Level3PTE, ptl_level3, ptl_level3_mfn);

  ptl_level3[0].p = 1;
  ptl_level3[0].rw = 1; // sub-pages are writable unless overridden
  ptl_level3[0].us = 1;
  ptl_level3[0].a = 1;
  ptl_level3[0].next = ptl_level2_mfn;

  //
  // Allocate physical RAM maps
  //
  // Note that level 1 starts out totally empty since PTLsim needs
  // to track which pages are part of the target address space;
  // these get faulted in or invalidated on the first access
  //

  physmap_level1_pages = (total_machine_pages + (PTES_PER_PAGE-1)) / PTES_PER_PAGE;

  bootpage->phys_pagedir_mfn_count = physmap_level1_pages;

  alloc_pages(Level1PTE, physmap_level1, physmap_level1_pages);
  physmap_level1_pfn = virt_to_pfn(physmap_level1);

  bootpage->phys_pagedir = (struct Level1PTE*)(PTLSIM_VIRT_BASE + ((byte*)physmap_level1 - reserved_page_pool));

  physmap_level2_pages = (physmap_level1_pages + (PTES_PER_PAGE-1)) / PTES_PER_PAGE;

  alloc_pages(Level2PTE, physmap_level2, physmap_level2_pages);
  bootpage->phys_level2_pagedir = (struct Level2PTE*)(PTLSIM_VIRT_BASE + ((byte*)physmap_level2 - reserved_page_pool));

  physmap_level2_pfn = virt_to_pfn(physmap_level2);

  for (i = 0; i < physmap_level1_pages; i++) {
    struct Level2PTE* pte = &physmap_level2[i];
    pte->p = 0;  // let PTLsim fill it in later
    pte->rw = 1; // sub-pages are writable unless overridden
    pte->us = 1; // both user and supervisor
    pte->a = 1;
    pte->next = mfns[physmap_level1_pfn + i];
  }

  alloc_page(Level3PTE, physmap_level3, physmap_level3_mfn);

  for (i = 0; i < physmap_level2_pages; i++) {
    struct Level3PTE* pte = &physmap_level3[i];
    pte->p = 1;
    pte->rw = 1; // sub-pages are writable unless overridden
    pte->us = 1; // both user and supervisor
    pte->a = 1;
    pte->next = mfns[physmap_level2_pfn + i];
  }

  //
  // Finish toplevel
  //

#define INCLUDE_PHYS_MEM_MAPPINGS

  alloc_page(Level4PTE, level4, level4_mfn);

  {
    int index = PTLSIM_VIRT_BASE >> (12+9+9+9);
    struct Level4PTE* top = &level4[index];

    top->p = 1;
    top->rw = 1; // sub-pages are writable unless overridden
    top->us = 1; // both user and supervisor
    top->a = 1;
    top->next = ptl_level3_mfn;
  }

  {
    int index = PHYS_VIRT_BASE >> (12+9+9+9);
    struct Level4PTE* top = &level4[index];
    top->p = 1;
    top->rw = 1; // sub-pages are writable unless overridden
    top->us = 1; // both user and supervisor
    top->a = 1;
    top->next = physmap_level3_mfn;
  }

  //
  // Copy GDT template page from hypervisor
  //

  alloc_page(void, gdt_page, gdt_mfn);
  bootpage->gdt_mfn = gdt_mfn;
  bootpage->gdt_page = (void*)(PTLSIM_VIRT_BASE + ((byte*)gdt_page - reserved_page_pool));

  {
    mmuext_op_t mmuextop;
    
    mmuextop.cmd = MMUEXT_GET_GDT_TEMPLATE;
    mmuextop.arg1.linear_addr = (unsigned long)gdt_page;
    mmuextop.arg2.nr_ents = PAGE_SIZE;
    rc = xc_mmuext_op(xc_handle, &mmuextop, 1, dom);
  }

  //
  // Finish up bootpage
  //
  bootpage->avail_mfn_count = next_free_page_pfn;
  bootpage->toplevel_page_table = (struct Level4PTE*)(PTLSIM_VIRT_BASE + ((byte*)level4 - reserved_page_pool));
  bootpage->toplevel_page_table_mfn = level4_mfn;

  //
  // Set protections correctly
  //
  for (i = 0; i < next_free_page_pfn; i++) ptl_level1[i].rw = 1;
  for (i = next_free_page_pfn; i < count; i++) ptl_level1[i].rw = 0;

  //
  // Set up hypercall page (always at PTLSIM_VIRT_BASE + 0x1000)
  //
  dom0op.u.hypercall_init.domain = dom;
  dom0op.u.hypercall_init.mfn = mfns[PTLSIM_HYPERCALL_PAGE_PFN];
  dom0op.cmd = DOM0_HYPERCALL_INIT;
  rc = xc_dom0_op(xc_handle, &dom0op);
    
  //
  // Set up stub
  //
  stub = (struct PTLsimStub*)(((byte*)shared_info) + (PAGE_SIZE - sizeof(struct PTLsimStub)));
  stub->magic = PTLSIM_STUB_MAGIC;
  stub->boot_page_mfn = mfns[virt_to_pfn(bootpage)];

  munmap(reserved_page_pool, count * PAGE_SIZE);

  //
  // Try to pin pages
  //
  {
    struct mmuext_op* oparray;
        
    oparray = malloc(pagedir_pages_required * sizeof(struct mmuext_op));
    for (i = 0; i < pagedir_pages_required; i++) {
      oparray[i].cmd = MMUEXT_PIN_L1_TABLE;
      oparray[i].arg1.mfn = mfns[ptl_level1_pfn + i];
    }

    rc = xc_mmuext_op(xc_handle, oparray, pagedir_pages_required, dom);

    free(oparray);
  }

  op.cmd = MMUEXT_PIN_L2_TABLE;
  op.arg1.mfn = ptl_level2_mfn;
  rc = xc_mmuext_op(xc_handle, &op, 1, dom);

  op.cmd = MMUEXT_PIN_L3_TABLE;
  op.arg1.mfn = ptl_level3_mfn;
  rc = xc_mmuext_op(xc_handle, &op, 1, dom);

  {
    struct mmuext_op* oparray;
        
    oparray = malloc(physmap_level1_pages * sizeof(struct mmuext_op));
    for (i = 0; i < physmap_level1_pages; i++) {
      oparray[i].cmd = MMUEXT_PIN_L1_TABLE;
      oparray[i].arg1.mfn = mfns[physmap_level1_pfn + i];
    }

    rc = xc_mmuext_op(xc_handle, oparray, pagedir_pages_required, dom);
        
    free(oparray);
  }

  {
    struct mmuext_op* oparray;

    oparray = malloc(physmap_level2_pages * sizeof(struct mmuext_op));
    for (i = 0; i < physmap_level2_pages; i++) {
      oparray[i].cmd = MMUEXT_PIN_L2_TABLE;
      oparray[i].arg1.mfn = mfns[physmap_level2_pfn + i];
    }

    rc = xc_mmuext_op(xc_handle, oparray, pagedir_pages_required, dom);

    free(oparray);
  }

  op.cmd = MMUEXT_PIN_L3_TABLE;
  op.arg1.mfn = physmap_level3_mfn;
  rc = xc_mmuext_op(xc_handle, &op, 1, dom);

  op.cmd = MMUEXT_PIN_L4_TABLE;
  op.arg1.mfn = level4_mfn;
  rc = xc_mmuext_op(xc_handle, &op, 1, dom);

  return 0;
}

