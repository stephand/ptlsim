/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * Xen 64-bit low level functions
 *
 * Copyright 2005-2008 Matt T. Yourst <yourst@yourst.com>
 */

.text
.intel_syntax

#define __ASM_ONLY__
#include <ptlhwdef.h>

.extern ptlsim_preinit

.section .bootpage
# NOTE: linker can't handle this symbol correctly:
# .global bootinfo
# bootinfo:
.previous

# Make sure it's always at 0x1000 in image (by ptlcore.lds)
.section .hypercall
.global hypercall_page
hypercall_page:
.previous

.extern main
.extern secondary_vcpu_startup

.global ptlsim_preinit_entry
ptlsim_preinit_entry:
  # %rsp is at the top of the per-vcpu stack
  # %rdi points to PTLsimMonitorInfo struct
  # %rsi is the vcpuid (0 = primary, >0 = secondary)
  test %rsi,%rsi
  jnz  1f
  # Primary VCPU
  xor  %edi,%edi # no argc
  xor  %esi,%esi # no argv[]
  call main
  int3

1:
  # Secondary VCPUs
  mov  %rdi,%rsi # vcpuid is first arg
  call secondary_vcpu_startup
  int3

#define __ASSEMBLY__
#include <xen/xen.h>
#include <xen/features.h>

#define force_evtchn_callback() ((void)HYPERVISOR_xen_version(0, 0))

#define __KERNEL_CS  FLAT_KERNEL_CS
#define __KERNEL_DS  FLAT_KERNEL_DS
#define __KERNEL_SS  FLAT_KERNEL_SS

#define TRAP_divide_error      0
#define TRAP_debug             1
#define TRAP_nmi               2
#define TRAP_int3              3
#define TRAP_overflow          4
#define TRAP_bounds            5
#define TRAP_invalid_op        6
#define TRAP_no_device         7
#define TRAP_double_fault      8
#define TRAP_copro_seg         9
#define TRAP_invalid_tss      10
#define TRAP_no_segment       11
#define TRAP_stack_error      12
#define TRAP_gp_fault         13
#define TRAP_page_fault       14
#define TRAP_spurious_int     15
#define TRAP_copro_error      16
#define TRAP_alignment_check  17
#define TRAP_machine_check    18
#define TRAP_simd_error       19
#define TRAP_deferred_nmi     31

#define PTLSIM_VIRT_BASE 0x0000000000000000 // PML4 entry 0

#define PTLSIM_BOOT_PAGE_PFN 16
#define PTLSIM_BOOT_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_BOOT_PAGE_PFN * 4096))

#define PTLSIM_HYPERCALL_PAGE_PFN 17
#define PTLSIM_HYPERCALL_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_HYPERCALL_PAGE_PFN * 4096))

#define PTLSIM_SHINFO_PAGE_PFN 18
#define PTLSIM_SHINFO_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_SHINFO_PAGE_PFN * 4096))

#define offsetof_evtchn_upcall_pending 0
#define offsetof_evtchn_upcall_mask    1

/*
 * Event upcall stack frame:
 *
 * 6:  ss
 * 5:  rsp
 * 4:  flags
 * 3:  cs_and_upcall_mask
 * 2:  rip
 * 1:  r11
 * 0:  rcx
 */

/*
 * Exception with error code stack frame: 
 *
 * 7:  ss
 * 6:  rsp
 * 5:  flags
 * 4:  cs_and_upcall_mask
 * 3:  rip
 * 2:  error_code
 * 1:  r11
 * 0:  rcx
 */

.extern per_vcpu_stack_base

.macro save_regs HAS_ERROR_CODE
  mov   %rcx,[%rsp + 0*8]
  mov   %r11,[%rsp + 1*8]
  sub   %rsp,(8*64)
  mov   [%rsp + 8*REG_rax],%rax
  mov   [%rsp + 8*REG_rcx],%rcx
  mov   [%rsp + 8*REG_rdx],%rdx
  mov   [%rsp + 8*REG_rbx],%rbx
  mov   [%rsp + 8*REG_rsp],%rsp
  mov   [%rsp + 8*REG_rbp],%rbp
  mov   [%rsp + 8*REG_rsi],%rsi
  mov   [%rsp + 8*REG_rdi],%rdi
  mov   [%rsp + 8*REG_r8],%r8
  mov   [%rsp + 8*REG_r9],%r9
  mov   [%rsp + 8*REG_r10],%r10
  mov   [%rsp + 8*REG_r11],%r11
  mov   [%rsp + 8*REG_r12],%r12
  mov   [%rsp + 8*REG_r13],%r13
  mov   [%rsp + 8*REG_r14],%r14
  mov   [%rsp + 8*REG_r15],%r15
  lea   %rbp,[%rsp+(8*64) + (8*2)]

.if (\HAS_ERROR_CODE)
  # Save %error (%ar1)
  mov   %rax,[%rbp]
  mov   [%rsp + 8*REG_ar1],%rax
  add   %rbp,8
.endif
  # Save %rip
  mov   %rax,[%rbp + 8*0]
  mov   [%rsp + 8*REG_rip],%rax
  # Skip cs and upcall mask (+1)
  # Save %flags
  mov   %rax,[%rbp + 8*2]
  mov   [%rsp + 8*REG_flags],%rax
  # Save %rsp
  mov   %rax,[%rbp + 8*3]
  mov   [%rsp + 8*REG_rsp],%rax
  # Skip ss (+4)
  # Make %rdi (call argument 1) point to saved context
  mov   %rdi,%rsp
.endm

.macro restore_regs_and_iret HAS_ERROR_CODE
  mov   %rax,[%rsp + 8*REG_rip]
.if (\HAS_ERROR_CODE)
  mov   [%rsp + (64 + 1+1 + 1)*8],%rax
.else
  mov   [%rsp + (64 + 1+1 + 0)*8],%rax
.endif

  mov   %rax,[%rsp + 8*REG_rax]
# mov   %rcx,[%rsp + 8*REG_rcx]
  mov   %rdx,[%rsp + 8*REG_rdx]
  mov   %rbx,[%rsp + 8*REG_rbx]
# mov   %rsp,[%rsp + 8*REG_rsp]
  mov   %rbp,[%rsp + 8*REG_rbp]
  mov   %rsi,[%rsp + 8*REG_rsi]
  mov   %rdi,[%rsp + 8*REG_rdi]
  mov   %r8,[%rsp + 8*REG_r8]
  mov   %r9,[%rsp + 8*REG_r9]
  mov   %r10,[%rsp + 8*REG_r10]
# mov   %r11,[%rsp + 8*REG_r11] (do later)
  mov   %r12,[%rsp + 8*REG_r12]
  mov   %r13,[%rsp + 8*REG_r13]
  mov   %r14,[%rsp + 8*REG_r14]
  mov   %r15,[%rsp + 8*REG_r15]
  add   %rsp,(8*64)

  # Transfer evtchn_upcall_mask = ~saved_rflags.IF
  test  word ptr [%rsp + 4*8],(1 << 9)
  mov   %rcx,(PTLSIM_SHINFO_PAGE_VIRT_BASE + offsetof_evtchn_upcall_mask)
  setz  byte ptr [%rcx]

  pop   %rcx
  pop   %r11
.if (\HAS_ERROR_CODE)
  # Skip pushed error code
  add   %rsp,8
.endif
  #
  # Direct iret to kernel space: no need to switch page tables
  # back to user base, but we do need to correct CS and SS.
  #
	or    byte ptr [%rsp + 1*8],3
	or    byte ptr [%rsp + 4*8],3
  iretq
.endm

#
# Do not actually do any processing here: defer event
# handling until the next iteration of the main loop,
# so we can selectively forward events to the guest.
#
.global xen_event_callback_entry
.extern event_upcall_pending
xen_event_callback_entry:
  save_regs 0
  call xen_event_callback
  restore_regs_and_iret 0
# We're always in kernel mode:
# or    byte ptr [%rsp + (2+1)*8],3
# or    byte ptr [%rsp + (2+4)*8],3
# pop   %rcx
# pop   %r11
# iretq

.global divide_error_entry
divide_error_entry:
  save_regs 0
  call do_divide_error
  restore_regs_and_iret 0

.global int3_entry
int3_entry:
  save_regs 0
  call do_int3
  restore_regs_and_iret 0

.global overflow_entry
overflow_entry:
  save_regs 0
  call do_overflow
  restore_regs_and_iret 0

.global bounds_entry
bounds_entry:
  save_regs 0
  call do_bounds
  restore_regs_and_iret 0

.global invalid_op_entry
invalid_op_entry:
  save_regs 0
  call do_invalid_op
  restore_regs_and_iret 0

.global device_not_available_entry
device_not_available_entry:
  save_regs 0
  call do_device_not_available
  restore_regs_and_iret 0

.global segment_not_present_entry
segment_not_present_entry:
  save_regs 1
  call do_segment_not_present
  restore_regs_and_iret 1

.global stack_segment_entry
stack_segment_entry:
  save_regs 1
  call do_stack_segment
  restore_regs_and_iret 1

.global general_protection_entry
general_protection_entry:
  save_regs 1
  call do_general_protection
  restore_regs_and_iret 1

.global page_fault_entry
page_fault_entry:
  save_regs 1
  call do_page_fault
  restore_regs_and_iret 1

.global coprocessor_error_entry
coprocessor_error_entry:
  save_regs 0
  call do_coprocessor_error
  restore_regs_and_iret 0

.global simd_coprocessor_error_entry
simd_coprocessor_error_entry:
  save_regs 0
  call do_simd_coprocessor_error
  restore_regs_and_iret 0
