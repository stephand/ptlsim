/* -*- asm -*
 *
 * PTLsim: Cycle Accurate x86-64 Simulator
 * PT2x uop common definitions
 *
 * Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
 */

#define __ASM_ONLY__
#include <ptlhwdef.h>
#include <simsynth-offsets.h>

.extern ctx

#
# NOTES: 
# - Registers have been specifically chosen to favor the low 8 for the most common references.
#   In x86-64, r8-r15 may require an extra byte to encode them. Example: %rbp and %rdi
# - FLAG_INV and FLAG_WAIT **MUST** be in the low 8 bits of the flag byte or word. This is
#   used to reduce the code size.
#

/*
	struct IssueState {
	  union {
	    struct {
	      W64 rddata;
	      W32 pad1;
	      W16 pad2;
	      W16 rdflags;
	    } reg;

	    struct {
	      W64 rddata;
	      W64 physaddr:48, flags:16;
	    } ldreg;

	    struct { 
	      W64 riptaken;
	      W64 ripseq;
	    } brreg;

	    SFR st;
	  };
	};
*/

#define IssueState_size       16

#define rstate                rsi               /* (caller arg 2) */
#define IssueState_rddata     %rstate + 0
#define IssueState_rdflags    %rstate + 14

#define IssueState_physaddr   %rstate + 8        /* low 48 bits only! */

#define IssueState_riptaken   %rstate + 0
#define IssueState_ripseq     %rstate + 8

#define rraflags              r15d
#define rrbflags              r13d
#define rrcflags              r9d
#define rsfra                 r11

#define rraflagsw             r15w
#define rrbflagsw             r13w
#define rrcflagsw             r9w

#define rlsi                  r8      /* (load/store info word:  only used for loads and stores) */

/*
 * Cleverness alert: FLAG_INV is bit 1 in both regular ALU flags
 * AND bit 1 in the lowest byte of SFR.physaddr. This is critical
 * to making the synthesized simulator code work efficiently.
 *
 * struct SFR {
 *   W64 data;
 *   W64 pad0:1, invalid:1, pad2:1, physaddr:45, bytemask:8, tag:8;
 * };
 */

#define sfr_data              0
#define sfr_addr              8
#define sfr_mask              14
#define sfr_memid             15
#define sfr_flags             8

#define IssueState_sfrd_data  %rstate + sfr_data
#define IssueState_sfrd_addr  %rstate + sfr_addr
#define IssueState_sfrd_mask  %rstate + sfr_mask
#define IssueState_sfrd_flags %rstate + sfr_flags

.macro invalid a=0 b=0 c=0
  int3
.endm

.macro som label
.align 16
template_\label:
1:
.data
  .quad 1b
.previous
  jc      9f     # If regfetch determined that one or more operands were invalid
.endm

.macro eom label
9:
  add     %rstate,IssueState_size
  ret
1:
.data
  .quad 1b
.previous
.endm

.macro eomret label
9:
  add     %rstate,IssueState_size
  ret
1:
.data
  .quad 1b
.previous
.endm

.macro somnp label
.align 16
template_\label:
1:
.data
  .quad 1b
.previous
.endm

.macro eomnp label
1:
.data
  .quad 1b
.previous
.endm

.macro grouplabel label
.data
templatemap_\label:
.global templatemap_\label
.previous
.endm

/*
  Callee must preserve:
  rbx rsp rbp r12 r13 r14 r15 r15

  Args passed in:
  rdi rsi
*/
