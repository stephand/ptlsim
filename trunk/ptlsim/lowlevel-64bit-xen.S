/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * Xen 64-bit low level functions
 *
 * Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
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

.global ptlsim_preinit_entry
ptlsim_preinit_entry:
  # %rdi already points to PTLsimMonitorInfo struct
  call ptlsim_preinit
  int3

.global get_fs
get_fs:
  xor   %eax,%eax
  mov   %ax,%fs
  ret

.global get_gs
get_gs:
  xor   %eax,%eax
  mov   %ax,%gs
  ret

.extern got_upcall

#define __HYPERVISOR_iret                 23 /* x86 only */

.att_syntax
#define ENTRY(X) .globl X ; X :

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


/* Offsets into shared_info_t. */                
#define evtchn_upcall_pending		/* 0 */
#define evtchn_upcall_mask		1

NMI_MASK = 0x80000000

#define RDI 112
#define ORIG_RAX 120       /* + error_code */ 
#define EFLAGS 144

#define REST_SKIP 6*8			
.macro SAVE_REST
	subq $REST_SKIP,%rsp
#	CFI_ADJUST_CFA_OFFSET	REST_SKIP
	movq %rbx,5*8(%rsp) 
#	CFI_REL_OFFSET	rbx,5*8
	movq %rbp,4*8(%rsp) 
#	CFI_REL_OFFSET	rbp,4*8
	movq %r12,3*8(%rsp) 
#	CFI_REL_OFFSET	r12,3*8
	movq %r13,2*8(%rsp) 
#	CFI_REL_OFFSET	r13,2*8
	movq %r14,1*8(%rsp) 
#	CFI_REL_OFFSET	r14,1*8
	movq %r15,(%rsp) 
#	CFI_REL_OFFSET	r15,0*8
.endm		


.macro RESTORE_REST
	movq (%rsp),%r15
#	CFI_RESTORE r15
	movq 1*8(%rsp),%r14
#	CFI_RESTORE r14
	movq 2*8(%rsp),%r13
#	CFI_RESTORE r13
	movq 3*8(%rsp),%r12
#	CFI_RESTORE r12
	movq 4*8(%rsp),%rbp
#	CFI_RESTORE rbp
	movq 5*8(%rsp),%rbx
#	CFI_RESTORE rbx
	addq $REST_SKIP,%rsp
#	CFI_ADJUST_CFA_OFFSET	-(REST_SKIP)
.endm


#define ARG_SKIP 9*8
.macro RESTORE_ARGS skiprax=0,addskip=0,skiprcx=0,skipr11=0,skipr8910=0,skiprdx=0
	.if \skipr11
	.else
	movq (%rsp),%r11
#	CFI_RESTORE r11
	.endif
	.if \skipr8910
	.else
	movq 1*8(%rsp),%r10
#	CFI_RESTORE r10
	movq 2*8(%rsp),%r9
#	CFI_RESTORE r9
	movq 3*8(%rsp),%r8
#	CFI_RESTORE r8
	.endif
	.if \skiprax
	.else
	movq 4*8(%rsp),%rax
#	CFI_RESTORE rax
	.endif
	.if \skiprcx
	.else
	movq 5*8(%rsp),%rcx
#	CFI_RESTORE rcx
	.endif
	.if \skiprdx
	.else
	movq 6*8(%rsp),%rdx
#	CFI_RESTORE rdx
	.endif
	movq 7*8(%rsp),%rsi
#	CFI_RESTORE rsi
	movq 8*8(%rsp),%rdi
#	CFI_RESTORE rdi
	.if ARG_SKIP+\addskip > 0
	addq $ARG_SKIP+\addskip,%rsp
#	CFI_ADJUST_CFA_OFFSET	-(ARG_SKIP+\addskip)
	.endif
.endm	


.macro HYPERVISOR_IRET flag
#    testb $3,1*8(%rsp)    /* Don't need to do that in Mini-os, as */
#	jnz   2f               /* there is no userspace? */
	testl $NMI_MASK,2*8(%rsp)
	jnz   2f

#	testb $1,(xen_features+XENFEAT_supervisor_mode_kernel)
#	jnz   1f

	/* Direct iret to kernel space. Correct CS and SS. */
	orb   $3,1*8(%rsp)
	orb   $3,4*8(%rsp)
1:	iretq

2:	/* Slow iret via hypervisor. */
	andl  $~NMI_MASK, 16(%rsp)
	pushq $\flag
	jmp  hypercall_page + (__HYPERVISOR_iret * 32)
.endm

/*
 * Exception entry point. This expects an error code/orig_rax on the stack
 * and the exception handler in %rax.	
 */ 		  				
ENTRY(error_entry)
#	_frame RDI
	/* rdi slot contains rax, oldrax contains error code */
	cld	
	subq  $14*8,%rsp
#	CFI_ADJUST_CFA_OFFSET	(14*8)
	movq %rsi,13*8(%rsp)
#	CFI_REL_OFFSET	rsi,RSI
	movq 14*8(%rsp),%rsi	/* load rax from rdi slot */
	movq %rdx,12*8(%rsp)
#	CFI_REL_OFFSET	rdx,RDX
	movq %rcx,11*8(%rsp)
#	CFI_REL_OFFSET	rcx,RCX
	movq %rsi,10*8(%rsp)	/* store rax */ 
#	CFI_REL_OFFSET	rax,RAX
	movq %r8, 9*8(%rsp)
#	CFI_REL_OFFSET	r8,R8
	movq %r9, 8*8(%rsp)
#	CFI_REL_OFFSET	r9,R9
	movq %r10,7*8(%rsp)
#	CFI_REL_OFFSET	r10,R10
	movq %r11,6*8(%rsp)
#	CFI_REL_OFFSET	r11,R11
	movq %rbx,5*8(%rsp) 
#	CFI_REL_OFFSET	rbx,RBX
	movq %rbp,4*8(%rsp) 
#	CFI_REL_OFFSET	rbp,RBP
	movq %r12,3*8(%rsp) 
#	CFI_REL_OFFSET	r12,R12
	movq %r13,2*8(%rsp) 
#	CFI_REL_OFFSET	r13,R13
	movq %r14,1*8(%rsp) 
#	CFI_REL_OFFSET	r14,R14
	movq %r15,(%rsp) 
#	CFI_REL_OFFSET	r15,R15
#if 0        
/*	cmpl $__KERNEL_CS,CS(%rsp)
	je  error_kernelspace */
#endif        
error_call_handler:
	movq %rdi, RDI(%rsp)            
	movq %rsp,%rdi
	movq ORIG_RAX(%rsp),%rsi	# get error code 
	movq $-1,ORIG_RAX(%rsp)
	call *%rax

.macro zeroentry sym
#	INTR_FRAME
    movq (%rsp),%rcx
    movq 8(%rsp),%r11
    addq $0x10,%rsp /* skip rcx and r11 */
	pushq $0	/* push error code/oldrax */ 
#	CFI_ADJUST_CFA_OFFSET 8
	pushq %rax	/* push real oldrax to the rdi slot */ 
#	CFI_ADJUST_CFA_OFFSET 8
	leaq  \sym(%rip),%rax
	jmp error_entry
#	CFI_ENDPROC
.endm	

.macro errorentry sym
#	XCPT_FRAME
        movq (%rsp),%rcx
        movq 8(%rsp),%r11
        addq $0x10,%rsp /* rsp points to the error code */
	pushq %rax
#	CFI_ADJUST_CFA_OFFSET 8
	leaq  \sym(%rip),%rax
	jmp error_entry
#	CFI_ENDPROC
.endm

#define PTLSIM_VIRT_BASE 0x0 // base 0 (so all 32-bit offsets fit)
#define PHYS_VIRT_BASE 0x10000000000 // (1 << 40), PML4 entry 2

#define PTLSIM_BOOT_PAGE_PFN 0
#define PTLSIM_BOOT_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_BOOT_PAGE_PFN * 4096))
#define PTLSIM_BOOT_PAGE_PADDING 2048 // bytes of pre-padding (where ELF header goes)

#define PTLSIM_HYPERCALL_PAGE_PFN 1
#define PTLSIM_HYPERCALL_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_HYPERCALL_PAGE_PFN * 4096))

#define PTLSIM_SHINFO_PAGE_PFN 2
#define PTLSIM_SHINFO_PAGE_VIRT_BASE (PTLSIM_VIRT_BASE + (PTLSIM_SHINFO_PAGE_PFN * 4096))

#define XEN_GET_VCPU_INFO(reg)	movq PTLSIM_SHINFO_PAGE_VIRT_BASE,reg
#define XEN_PUT_VCPU_INFO(reg)
#define XEN_PUT_VCPU_INFO_fixup
#define XEN_LOCKED_BLOCK_EVENTS(reg) movb $1,evtchn_upcall_mask(reg)
#define XEN_LOCKED_UNBLOCK_EVENTS(reg) movb $0,evtchn_upcall_mask(reg)
#define XEN_TEST_PENDING(reg)	testb $0xFF,evtchn_upcall_pending(reg)

#define XEN_BLOCK_EVENTS(reg)	XEN_GET_VCPU_INFO(reg)			; \
                    			XEN_LOCKED_BLOCK_EVENTS(reg)	; \
    				            XEN_PUT_VCPU_INFO(reg)

#define XEN_UNBLOCK_EVENTS(reg)	XEN_GET_VCPU_INFO(reg)			; \
                				XEN_LOCKED_UNBLOCK_EVENTS(reg)	; \
    			            	XEN_PUT_VCPU_INFO(reg)



ENTRY(xen_event_callback_entry)
    zeroentry hypervisor_callback2

ENTRY(hypervisor_callback2)
        movq %rdi, %rsp 
11:
#11:     movq %gs:8,%rax
#        incl %gs:0
#        cmovzq %rax,%rsp         # in PTLsim, we keep the old %rsp since there is only one address space
        pushq %rdi
        call xen_event_callback 
        popq %rsp
#       decl %gs:0
        jmp error_exit

#        ALIGN
restore_all_enable_events:  
	XEN_UNBLOCK_EVENTS(%rsi)        # %rsi is already set up...

scrit:	/**** START OF CRITICAL REGION ****/
	XEN_TEST_PENDING(%rsi)
	jnz  14f			# process more events if necessary...
	XEN_PUT_VCPU_INFO(%rsi)
        RESTORE_ARGS 0,8,0
        HYPERVISOR_IRET 0
        
14:	XEN_LOCKED_BLOCK_EVENTS(%rsi)
	XEN_PUT_VCPU_INFO(%rsi)
	SAVE_REST
        movq %rsp,%rdi                  # set the argument again
	jmp  11b
ecrit:  /**** END OF CRITICAL REGION ****/


retint_kernel:
retint_restore_args:
  # movl EFLAGS-REST_SKIP(%rsp), %eax
	# shr $9, %eax			# EAX[0] == IRET_EFLAGS.IF (generally is set: allow interrupts)
	XEN_GET_VCPU_INFO(%rsi)
	# andb evtchn_upcall_mask(%rsi),%al
  # andb $1,%al			# EAX[0] == IRET_EFLAGS.IF & event_mask
  ##	jnz restore_all_enable_events	#        != 0 => enable event delivery
  jmp restore_all_enable_events       # force interrupts to be enabled at all times
	XEN_PUT_VCPU_INFO(%rsi)
  #++MTY: added this
	#movb $0,evtchn_upcall_mask(%rsi)
		
	RESTORE_ARGS 0,8,0
	HYPERVISOR_IRET 0



error_exit:		
	RESTORE_REST
/*	cli */
	XEN_BLOCK_EVENTS(%rsi)		
	jmp retint_kernel



ENTRY(failsafe_callback)
        popq  %rcx
        popq  %r11
        iretq


.intel_syntax
