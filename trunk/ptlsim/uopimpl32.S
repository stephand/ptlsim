/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * uop implementation
 *
 * Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
 */

.text
.intel_syntax
.align 4096

#define __ASM_ONLY__
#include <ptlhwdef.h>
#include <simsynth-offsets.h>

.extern ctx

# 32-bit arguments are pushed down stack in reverse syntactic order (hence accessed/popped in the right order), above the 32-bit near return address. 
# Callee-saved: %ebp, %esi, %edi, %ebx are callee-saved
# Caller-saved: all other registers are caller-saved
# %eax is to hold the result, or %edx:%eax for 64-bit results.

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

#define rstate                edi
#define IssueState_rddata     %rstate + 0
#define IssueState_rdflags    %rstate + 14

#define IssueState_physaddr   %rstate + 8        /* low 48 bits only! */
#define IssueState_riptaken   %rstate + 0
#define IssueState_ripseq     %rstate + 8

/*
struct IssueInput {
  W64 ra;
  W64 rb;
  W64 rc;
  W16 rraflags;
  W16 rrbflags;
  W16 rrcflags;
  W32 rlsi;
  SFR sfra;
};
*/

#define rinput                esi

#define IssueInput_ra         %rinput+0
#define IssueInput_rb         %rinput+8
#define IssueInput_rc         %rinput+16
#define IssueInput_raflags    %rinput+24
#define IssueInput_rbflags    %rinput+26
#define IssueInput_rcflags    %rinput+28

.macro invalid a=0 b=0 c=0
  int3
.endm

.macro som LABEL
.align 16
template_\LABEL:
1:
.data
  .long 1b
.previous
  sub     %esp,16
  mov     [%esp+0],%ebp
  mov     [%esp+4],%esi
  mov     [%esp+8],%edi
  mov     [%esp+12],%ebx
  mov     %edi,[%esp+16+4+0]
  mov     %esi,[%esp+16+4+4]
.endm

.macro eom label
9:
  mov     %ebx,[%esp+12]
  mov     %edi,[%esp+8]
  mov     %esi,[%esp+4]
  mov     %ebp,[%esp+0]
  add     %esp,16
  ret
1:
.data
  .long 1b
.previous
.endm

.macro grouplabel label
.data
templatemap_\label:
.global templatemap_\label
.previous
.endm

# rd = (~rd) & ra
.macro andnot rd ra
  not     \rd
  and     \rd,\ra
.endm

# rd = (~rd) & ra
.macro ornot rd ra
  not     \rd
  or      \rd,\ra
.endm

.macro nand rd ra
  and     \rd,\ra
  not     \rd
.endm

.macro nor rd ra
  or      \rd,\ra
  not     \rd
.endm

.macro eqv rd ra
  xor     \rd,\ra
  not     \rd
.endm

.macro bswap16 rd ra
  xchg    %bl,%bh
  mov     %ax,%bx
.endm

.macro bswapx rd ra 
  mov     \rd,\ra
  bswap   \rd
.endm

.macro btx RD RA
  bt      \RD,\RA
  mov     %eax,+1
  mov     %edx,-1
  cmovc   %eax,%edx
.endm

.macro addm RD RA
  add     \RD,\RA
  mov     \RA,1
  mov     %cl,[IssueInput_rc]
  shl     \RA,%cl
  dec     \RA
  and     \RD,\RA
.endm

.macro subm RD RA
  sub     \RD,\RA
  mov     \RA,1
  mov     %cl,[IssueInput_rc]
  shl     \RA,%cl
  dec     \RA
  and     \RD,\RA
.endm

.macro ctpop RD RA
  int3   #++MTY TODO
.endm

#
# ALU operations: 
#

#
# Load flags into IssueState_rdflags
# Uses %bl %cl %dl %al %dh
#
.macro ldflags
  /*
   * Flags format: OF - - - SF ZF - AF - PF - CF
   *               11       7  6    4    2    0
   *               rb       ra ra   ra   ra   rb
   */

  seto    %dh         # %dh = OF  (note: sets bit 0 of dh = bit 8 of dx)
  sets    %al         # %al = SF

  setp    %cl         # %cl = PF
  setc    %bl         # %bl = CF
  setz    %dl         # %dl = ZF

  shl     %dh,3       # OF bit 11 (already in dh bit 0 = dx bit 8, so just shift by 3)
  shl     %al,7       # SF bit 7
  shl     %cl,2       # PF bit 2

  or      %cl,%al     # %cl = PF|SF
  shl     %dl,6       # ZF bit 6

  or      %dl,%bl     # %dl = ZF|CF

  or      %dl,%cl     # %dl = (ZF|CF)|(PF|SF), %dh already contains OF

  mov     word ptr [IssueState_rdflags],%dx
.endm

#
# Load flags of 64-bit result %edx (high), %eax (low) into IssueState_rdflags
#
.macro ldflags64
  /*
   * Flags format: OF - - - SF ZF - AF - PF - CF
   *               11       7  6    4    2    0
   *               rb       ra ra   ra   ra   rb
   */

  # Capture SF, OF, CF directly from high result: all others derived
  setc    %bl         # %bl = CF  (already in bit 0)
  seto    %bh         # %cl = OF  (note: sets bit 0 of dh = bit 8 of dx)
  sets    %cl         # %cl = SF

  # CF is already bit 0, so no need for additional shift
  shl     %bh,3       # OF bit 11 (already in bh bit 0 = bx bit 8, so just shift by 3)
  shl     %cl,7       # SF bit 7: cl[7] = SF
  xor     %ch,%ch     # clear %ch
  or      %ebx,%ecx   # CF|OF|SF all in ebx now

  # Compute parity (PF) of both halves
  test    %eax,%eax   # compute parity of low 32 bits
  setp    %cl         # set low parity
  test    %edx,%edx   # compute parity of high 32 bits
  setp    %ch         # set high parity
  xor     %cl,%ch     # parity = (lo.p ^ hi.p)
  shl     %cl,2       # PF bit 2: cl[2] = p
  or      %bl,%cl     # Merge PF into ebx

  # Compute zero flag (ZF) of both halves
  or      %edx,%eax   # compute zero flag of all bits
  setz    %dl         # %dl = ZF
  shl     %dl,6       # ZF bit 6: dl[6] = z
  or      %bl,%dl     # Merge ZF into ebx

  # ebx has final flags value
  mov     word ptr [IssueState_rdflags],%bx
.endm

grouplabel nop
som nop
  xor     %eax,%eax
  mov     [IssueState_rddata+0],%eax
  mov     [IssueState_rddata+4],%eax
  mov     word ptr [IssueState_rdflags],0
  # (no operation)
  eom nop

.macro generate_two_operand_aluop_one_size PTOPCODE SIZE OP1 REGA REGB SAVEFLAGS MASKRC=0
.if (\SAVEFLAGS)
som \PTOPCODE\SIZE
.else
som nf_\PTOPCODE\SIZE
.endif
  mov     %eax,[IssueInput_ra]
  mov     %ebx,[IssueInput_rb]
  \OP1    %\REGA,%\REGB
.if (\MASKRC)
  and     %\REGA,[IssueInput_rc]
.endif
  mov     [IssueState_rddata],%eax
.if (\SAVEFLAGS)
  ldflags
.endif
.if (\SIZE < 4)
  mov     %edx,[IssueInput_ra+4]
.else
  xor     %edx,%edx
.endif
  mov     [IssueState_rddata+4],%edx
.if (\SAVEFLAGS)
  eom     \PTOPCODE\SIZE
.else
  mov     word ptr [IssueState_rdflags],0
  eom     nf_\PTOPCODE\SIZE
.endif
.endm

.macro generate_two_operand_aluop_sizes_1_2_4 PTOPCODE OPCODE NOBYTE=0 MASKRC=0
.if (\NOBYTE)
  generate_two_operand_aluop_one_size \PTOPCODE 1 invalid al bl 0 \MASKRC
  generate_two_operand_aluop_one_size \PTOPCODE 1 invalid al bl 1 \MASKRC
.else
  generate_two_operand_aluop_one_size \PTOPCODE 1 \OPCODE al bl 0 \MASKRC
  generate_two_operand_aluop_one_size \PTOPCODE 1 \OPCODE al bl 1 \MASKRC
.endif
  generate_two_operand_aluop_one_size \PTOPCODE 2 \OPCODE ax bx 0 \MASKRC
  generate_two_operand_aluop_one_size \PTOPCODE 2 \OPCODE ax bx 1 \MASKRC
  generate_two_operand_aluop_one_size \PTOPCODE 4 \OPCODE eax ebx 0 \MASKRC
  generate_two_operand_aluop_one_size \PTOPCODE 4 \OPCODE eax ebx 1 \MASKRC
.endm

.macro generate_two_operand_aluop_size8 PTOPCODE OPCODE OPCODE2 SAVEFLAGS MASKRC=0
.if (\SAVEFLAGS)
som size8_\PTOPCODE
.else
som nf_size8_\PTOPCODE
.endif
  mov      %eax,[IssueInput_ra]
  mov      %edx,[IssueInput_ra+4]
  \OPCODE  %eax,[IssueInput_rb]
  \OPCODE2 %edx,[IssueInput_rb+4]
.if (\MASKRC)
  and      %eax,[IssueInput_rc]
  and      %edx,[IssueInput_rc+4]
.endif
  mov      [IssueState_rddata+0],%eax
  mov      [IssueState_rddata+4],%edx
.if (\SAVEFLAGS)
  ldflags64
  eom      size8_\PTOPCODE
.else
  mov      word ptr [IssueState_rdflags],0
  eom      nf_size8_\PTOPCODE
.endif
.endm

.macro generate_two_operand_aluop PTOPCODE OPCODE OPCODE2 NOBYTE=0 MASKRC=0
grouplabel \PTOPCODE
  generate_two_operand_aluop_sizes_1_2_4 \PTOPCODE \OPCODE \NOBYTE \MASKRC
  generate_two_operand_aluop_size8 \PTOPCODE \OPCODE \OPCODE2 0 \MASKRC
  generate_two_operand_aluop_size8 \PTOPCODE \OPCODE \OPCODE2 1 \MASKRC
.endm

grouplabel mov
  generate_two_operand_aluop mov mov mov 0

grouplabel bswap
som size1_bswap
  int3
  eom     size1_\PTOPCODE
som size2_bswap
  mov     %eax,[IssueInput_ra]
  xchg    %al,%ah
  mov     [IssueState_rddata],%eax
  mov     %eax,[IssueInput_ra+4]
  mov     [IssueState_rddata+4],%eax
  mov     word ptr [IssueState_rdflags],0
  eom     size2_bswap
som size4_bswap
  mov     %eax,[IssueInput_ra]
  bswap   %eax
  mov     [IssueState_rddata],%eax
  xor     %eax,%eax
  mov     [IssueState_rddata+4],%eax
  mov     word ptr [IssueState_rdflags],0
  eom     size4_\PTOPCODE
som size8_bswap
  mov      %edx,[IssueInput_ra]
  mov      %eax,[IssueInput_ra+4]
  bswap    %eax
  bswap    %edx
  mov      [IssueState_rddata+0],%eax
  mov      [IssueState_rddata+4],%edx
  mov      word ptr [IssueState_rdflags],0
  eom      size8_bswap

generate_two_operand_aluop and and and
generate_two_operand_aluop or or or
generate_two_operand_aluop xor xor xor 
generate_two_operand_aluop andnot andnot andnot
generate_two_operand_aluop ornot ornot ornot
generate_two_operand_aluop nand nand nand
generate_two_operand_aluop nor nor nor
generate_two_operand_aluop eqv eqv eqv
generate_two_operand_aluop add add adc
generate_two_operand_aluop sub sub sbb

.macro generate_two_operand_alu_mask_one_size PTOPCODE SIZE OP1 REGA REGB SAVEFLAGS
.if (\SAVEFLAGS)
som \PTOPCODE\SIZE
.else
som nf_\PTOPCODE\SIZE
.endif
  mov     %eax,[IssueInput_ra]
  mov     %ebx,[IssueInput_rb]
  \OP1    %\REGA,%\REGB
  and     %\REGA,[IssueInput_rc]
  mov     [IssueState_rddata],%eax
.if (\SAVEFLAGS)
  ldflags
.endif
.if (\SIZE < 4)
  mov     %edx,[IssueInput_ra+4]
.else
  xor     %edx,%edx
.endif
  mov     [IssueState_rddata+4],%edx
.if (\SAVEFLAGS)
  eom     \PTOPCODE\SIZE
.else
  mov     word ptr [IssueState_rdflags],0
  eom     nf_\PTOPCODE\SIZE
.endif
.endm

.macro generate_two_operand_aluop_sizes_1_2_4 PTOPCODE OPCODE NOBYTE=0
.if (\NOBYTE)
  generate_two_operand_aluop_one_size \PTOPCODE 1 invalid al bl 0
  generate_two_operand_aluop_one_size \PTOPCODE 1 invalid al bl 1
.else
  generate_two_operand_aluop_one_size \PTOPCODE 1 \OPCODE al bl 0
  generate_two_operand_aluop_one_size \PTOPCODE 1 \OPCODE al bl 1
.endif
  generate_two_operand_aluop_one_size \PTOPCODE 2 \OPCODE ax bx 0
  generate_two_operand_aluop_one_size \PTOPCODE 2 \OPCODE ax bx 1
  generate_two_operand_aluop_one_size \PTOPCODE 4 \OPCODE eax ebx 0
  generate_two_operand_aluop_one_size \PTOPCODE 4 \OPCODE eax ebx 1
.endm

.macro generate_two_operand_aluop_size8 PTOPCODE OPCODE OPCODE2 SAVEFLAGS
.if (\SAVEFLAGS)
som size8_\PTOPCODE
.else
som nf_size8_\PTOPCODE
.endif
  mov      %eax,[IssueInput_ra]
  mov      %edx,[IssueInput_ra+4]
  \OPCODE  %eax,[IssueInput_rb]
  \OPCODE2 %edx,[IssueInput_rb+4]
  mov      [IssueState_rddata+0],%eax
  mov      [IssueState_rddata+4],%edx
.if (\SAVEFLAGS)
  ldflags64
  eom      size8_\PTOPCODE
.else
  mov      word ptr [IssueState_rdflags],0
  eom      nf_size8_\PTOPCODE
.endif
.endm

.macro generate_two_operand_aluop PTOPCODE OPCODE OPCODE2 NOBYTE=0
  generate_two_operand_aluop_sizes_1_2_4 \PTOPCODE \OPCODE \NOBYTE
  generate_two_operand_aluop_size8 \PTOPCODE \OPCODE \OPCODE2 0
  generate_two_operand_aluop_size8 \PTOPCODE \OPCODE \OPCODE2 1
.endm

.macro generate_bittest_aluop_size8 LABEL OPCODE ISBTX
som \LABEL
  mov      %eax,[IssueInput_ra]
  mov      %edx,[IssueInput_ra+4]
  mov      %ecx,[IssueInput_rb]
  cmp      %ecx,32
  jge      1f
  # Low 32 bits
  and      %ecx,31
.if (\ISBTX)
  bt       %eax,%ecx
  mov      %eax,+1 
  mov      %edx,0
  mov      %ecx,-1
  cmovc    %eax,%ecx
  cmovc    %edx,%ecx
.else
  \OPCODE  %eax,%ecx
.endif
  setc     %cl 
  movzx    %ecx,%cl
  jmp      2f
1:
  # High 32 bits
  and      %ecx,31
  \OPCODE  %edx,%ecx
  setc     %cl
  movzx    %ecx,%cl
2:
  mov      [IssueState_rddata+0],%eax
  mov      [IssueState_rddata+4],%edx
  mov      word ptr [IssueState_rdflags],%cx
  eom      \LABEL
.endm

.macro generate_bittest_aluop PTOPCODE OPCODE ISBTX=0
grouplabel \PTOPCODE
  generate_two_operand_aluop_sizes_1_2_4 \PTOPCODE \OPCODE 1
  generate_bittest_aluop_size8 nf_size8_\PTOPCODE \OPCODE \ISBTX
  generate_bittest_aluop_size8 size8_\PTOPCODE \OPCODE \ISBTX
.endm

generate_bittest_aluop bt btx 1
generate_bittest_aluop bts bts 0
generate_bittest_aluop btr btr 0
generate_bittest_aluop btc btc 0

.macro generate_bitscan_aluop_size8 LABEL OPCODE FORWARD
som \LABEL
.if (\FORWARD)
  # Assume ctz (low first, then high)
  # %edx:%eax is input to scan
  test     %eax,%eax
  jz       1f
  # Low part only
  bsf      %eax,%eax
  mov      [IssueState_rddata],%eax
  xor      %ecx,%ecx
  jmp      2f
1:
  # High part only
  mov      %ecx,FLAG_ZF
  bsf      %edx,%edx
  jz       2f           # If both were zero, set ZF
  add      %edx,32
  mov      [IssueState_rddata],%edx
  xor      %ecx,%ecx
2:
.else
# Reverse
  # Assume clz (high first, low high)
  # %edx:%eax is input to scan
  test     %edx,%edx
  jz       1f
  # High part only
  bsr      %edx,%edx
  add      %edx,32
  mov      [IssueState_rddata],%edx
  xor      %ecx,%ecx
  jmp      2f
1:
  # Low part only
  mov      %ecx,FLAG_ZF
  bsr      %eax,%eax
  jz       2f           # If both were zero, set ZF
  mov      [IssueState_rddata],%eax
  xor      %ecx,%ecx
2:
.endif
  mov      dword ptr [IssueState_rddata+4],0
  mov      [IssueState_rdflags],%cx
  eom      \LABEL
.endm

.macro generate_bitscan_aluop PTOPCODE OPCODE FORWARD
grouplabel \PTOPCODE
  generate_two_operand_aluop_sizes_1_2_4 \PTOPCODE \OPCODE 1
  generate_bitscan_aluop_size8 nf_size8_\PTOPCODE \OPCODE \FORWARD
  generate_bitscan_aluop_size8 size8_\PTOPCODE \OPCODE \FORWARD
.endm

generate_bitscan_aluop ctz bsf 1
generate_bitscan_aluop clz bsr 0

.macro generate_three_operand_aluop_one_size_one_shift PTOPCODE SIZE OP1 OP2 REGA REGB SHIFT SAVEFLAGS
.if (\SAVEFLAGS)
som \PTOPCODE\SIZE\SHIFT
.else
som nf_\PTOPCODE\SIZE\SHIFT
.endif
  mov     %eax,[IssueInput_ra]
  \OP1    %\REGA,[IssueInput_rb]
  mov     %ebx,[IssueInput_rc]
.if (\SHIFT > 0)
  shl     %ebx,\SHIFT
.endif
  \OP2    %\REGA,%\REGB
  mov     [IssueState_rddata],%eax
.if (\SAVEFLAGS)
  ldflags
.endif
.if (\SIZE < 4)
  mov     %edx,[IssueInput_ra+4]
.else
  xor     %edx,%edx
.endif
  mov     [IssueState_rddata+4],%edx
.if (\SAVEFLAGS)
  eom     \PTOPCODE\SIZE\SHIFT\PTOPCODE
.else
  mov     word ptr [IssueState_rdflags],0
  eom     nf_\PTOPCODE\SIZE\SHIFT
.endif
.endm

.macro generate_three_operand_aluop_size8_one_shift PTOPCODE OP1 OP2 OP1C OP2C SHIFT SAVEFLAGS
.if (\SAVEFLAGS)
som size8\PTOPCODE\SHIFT
.else
som nf_size8\PTOPCODE\SHIFT
.endif
  mov     %eax,[IssueInput_ra]
  mov     %edx,[IssueInput_ra+4]
  \OP1    %eax,[IssueInput_rb]
  \OP1C   %edx,[IssueInput_rb+4]
  mov     %ebx,[IssueInput_rc]
  mov     %ecx,[IssueInput_rc+4]
.if (\SHIFT > 0)
  shld    %ecx,%ebx,\SHIFT
  shl     %ebx,\SHIFT
.endif
  \OP2    %eax,%ebx
  \OP2C   %edx,%ecx
  mov      [IssueState_rddata+0],%eax
  mov      [IssueState_rddata+4],%edx
.if (\SAVEFLAGS)
  ldflags64
  eom      size8_\PTOPCODE\SHIFT
.else
  mov      word ptr [IssueState_rdflags],0
  eom      nf_size8_\PTOPCODE\SHIFT
.endif
.endm

.macro generate_three_operand_aluop_all_sizes_all_shifts PTOPCODE OP1 OP2 OP1C OP2C
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 1 \OP1 \OP2 al bl 0 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 1 \OP1 \OP2 al bl 0 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 1 \OP1 \OP2 al bl 1 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 1 \OP1 \OP2 al bl 1 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 1 \OP1 \OP2 al bl 2 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 1 \OP1 \OP2 al bl 2 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 1 \OP1 \OP2 al bl 3 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 1 \OP1 \OP2 al bl 3 1

  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 2 \OP1 \OP2 ax bx 0 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 2 \OP1 \OP2 ax bx 0 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 2 \OP1 \OP2 ax bx 1 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 2 \OP1 \OP2 ax bx 1 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 2 \OP1 \OP2 ax bx 2 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 2 \OP1 \OP2 ax bx 2 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 2 \OP1 \OP2 ax bx 3 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 2 \OP1 \OP2 ax bx 3 1

  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 4 \OP1 \OP2 eax ebx 0 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 4 \OP1 \OP2 eax ebx 0 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 4 \OP1 \OP2 eax ebx 1 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 4 \OP1 \OP2 eax ebx 1 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 4 \OP1 \OP2 eax ebx 2 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 4 \OP1 \OP2 eax ebx 2 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 4 \OP1 \OP2 eax ebx 3 0
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 4 \OP1 \OP2 eax ebx 3 1

  generate_three_operand_aluop_size8_one_shift \PTOPCODE \OP1 \OP2 \OP1C \OP2C 0 0
  generate_three_operand_aluop_size8_one_shift \PTOPCODE \OP1 \OP2 \OP1C \OP2C 0 1
  generate_three_operand_aluop_size8_one_shift \PTOPCODE \OP1 \OP2 \OP1C \OP2C 1 0
  generate_three_operand_aluop_size8_one_shift \PTOPCODE \OP1 \OP2 \OP1C \OP2C 1 1
  generate_three_operand_aluop_size8_one_shift \PTOPCODE \OP1 \OP2 \OP1C \OP2C 2 0
  generate_three_operand_aluop_size8_one_shift \PTOPCODE \OP1 \OP2 \OP1C \OP2C 2 1
  generate_three_operand_aluop_size8_one_shift \PTOPCODE \OP1 \OP2 \OP1C \OP2C 3 0
  generate_three_operand_aluop_size8_one_shift \PTOPCODE \OP1 \OP2 \OP1C \OP2C 3 1
.endm

grouplabel adda
  generate_three_operand_aluop_all_sizes_all_shifts adda add add adc adc
grouplabel adds
  generate_three_operand_aluop_all_sizes_all_shifts adds add sub adc sbb
grouplabel suba
  generate_three_operand_aluop_all_sizes_all_shifts suba sub add sbb adc
grouplabel subs
  generate_three_operand_aluop_all_sizes_all_shifts subs sub sub sbb sbb

.macro generate_addsubm PTOPCODE OP1 OP2 OP1C OP2C
grouplabel \PTOPCODE
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 1 \OP1 \OP2 al bl 0 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 2 \OP1 \OP2 ax bx 0 1
  generate_three_operand_aluop_one_size_one_shift \PTOPCODE 4 \OP1 \OP2 eax ebx 0 1
  generate_three_operand_aluop_size8_one_shift \PTOPCODE \OP1 \OP2 \OP1C \OP2C 0 1
.endm

generate_addsubm addm add and adc and
generate_addsubm subm sub and sbb and

.macro imull SZ
.if (\SZ == 1)
  int3    # No 8-bit form of two-operand imul
.endif
.if (\SZ == 2)
  imul    %ax,%bx
.endif
.if (\SZ == 4)
  imul    %eax,%ebx
.endif
.endm

.macro imulh SZ
.if (\SZ == 1)
  imul    %bl          # multiply %al by RA; %ax = product
  mov     %al,%ah
.endif
.if (\SZ == 2)
  imul    %bx          # multiply %ax by RA; %dx:%ax = product
  mov     %ax,%dx
.endif
.if (\SZ == 4)
  imul    %ebx         # multiply %eax by RA; %edx:%eax = product
  mov     %eax,%edx
.endif
.endm

.macro umulh SZ
.if (\SZ == 1)
  mul    %bl          # multiply %al by RA; %ax = product
  mov    %al,%ah
.endif
.if (\SZ == 2)
  mul    %bx          # multiply %ax by RA; %dx:%ax = product
  mov     %ax,%dx
.endif
.if (\SZ == 4)
  mul    %ebx         # multiply %eax by RA; %edx:%eax = product
  mov    %eax,%edx
.endif
.endm

.macro generate_mulop PTOPCODE OPCODE SIZE SAVEFLAGS
.if (\SAVEFLAGS)
som \PTOPCODE\SIZE
.else
som nf_\PTOPCODE\SIZE
.endif
  mov     %eax,[IssueInput_ra]
  mov     %ebx,[IssueInput_rb]
  \OPCODE \SIZE
  mov     [IssueState_rddata],%eax
  mov     dword ptr [IssueState_rddata+4],0
.if (\SAVEFLAGS)
  ldflags
  eom     \PTOPCODE\SIZE
.else
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     nf_\PTOPCODE\SIZE
.endif
.endm

.macro generate_mulop_allsize_setflags PTOPCODE OPCODE
grouplabel \PTOPCODE
  generate_mulop \PTOPCODE \OPCODE 1 0
  generate_mulop \PTOPCODE \OPCODE 1 1
  generate_mulop \PTOPCODE \OPCODE 2 0
  generate_mulop \PTOPCODE \OPCODE 2 1
  generate_mulop \PTOPCODE \OPCODE 4 0
  generate_mulop \PTOPCODE \OPCODE 4 1
  generate_mulop \PTOPCODE \OPCODE 8 0
  generate_mulop \PTOPCODE \OPCODE 8 1
.endm

generate_mulop_allsize_setflags mull imull
generate_mulop_allsize_setflags mulh imulh
generate_mulop_allsize_setflags mulhu umulh

.macro generate_three_operand_aluop_rcflags_one_size PTOPCODE SIZE OP1 REGA SAVEFLAGS SHIFTROT=0
.if (\SAVEFLAGS)
som \PTOPCODE\SIZE
.else
som nf_\PTOPCODE\SIZE
.endif
  pushd   [IssueInput_rcflags]
  popfd
  mov     %eax,[IssueInput_ra]
.if (\SHIFTROT == 0)
  \OP1    %\REGA,[IssueInput_rb]
.else
  mov     %cl,[IssueInput_rb]
  \OP1    %\REGA,%cl
.endif
  mov     [IssueState_rddata],%eax
.if (\SAVEFLAGS)
  ldflags
.endif
.if (\SIZE < 4)
  mov     %edx,[IssueInput_ra+4]
.else
  xor     %edx,%edx
.endif
  mov     [IssueState_rddata+4],%edx
.if (\SAVEFLAGS)
  eom     \PTOPCODE\SIZE
.else
  mov     word ptr [IssueState_rdflags],0
  eom     nf_\PTOPCODE\SIZE
.endif
.endm

.macro generate_three_operand_aluop_rcflags_size8 PTOPCODE OP1 OP1C SAVEFLAGS SHIFTROT=0
.if (\SAVEFLAGS)
som size8_\PTOPCODE
.else
som nf_size8_\PTOPCODE
.endif
  pushd   [IssueInput_rcflags]
  popfd
  mov     %eax,[IssueInput_ra]
  mov     %edx,[IssueInput_ra+4]
.if (\SHIFTROT == 0)
  # non-shift
  \OP1    %eax,[IssueInput_rb]
  \OP1C   %edx,[IssueInput_rb+4]
.endif
.if (\SHIFTROT == 1)
  # right shift
  mov     %cl,[IssueInput_rb]
  shrd    %eax,%edx,%cl
  shr     %edx,%cl
.endif
.if (\SHIFTROT == -1)
  # left shift
  mov     %cl,[IssueInput_rb]
  shld    %edx,%eax,%cl
  shl     %eax,%cl
.endif
.if (\SHIFTROT == -2)
  # invalid (not supported in PTLsim32)
  int3
.endif
  mov     [IssueState_rddata+0],%eax
  mov     [IssueState_rddata+4],%edx
.if (\SAVEFLAGS)
  ldflags
  eom     size8_\PTOPCODE
.else
  mov     word ptr [IssueState_rdflags],0
  eom     nf_size8_\PTOPCODE
.endif
.endm

.macro generate_three_operand_aluop_rcflags_all_sizes PTOPCODE OP1 OP1C SHIFTROT=0
grouplabel \PTOPCODE
  generate_three_operand_aluop_rcflags_one_size \PTOPCODE 1 \OP1 al 0 \SHIFTROT
  generate_three_operand_aluop_rcflags_one_size \PTOPCODE 1 \OP1 al 1 \SHIFTROT
  generate_three_operand_aluop_rcflags_one_size \PTOPCODE 2 \OP1 ax 0 \SHIFTROT
  generate_three_operand_aluop_rcflags_one_size \PTOPCODE 2 \OP1 ax 1 \SHIFTROT
  generate_three_operand_aluop_rcflags_one_size \PTOPCODE 4 \OP1 eax 0 \SHIFTROT
  generate_three_operand_aluop_rcflags_one_size \PTOPCODE 4 \OP1 eax 1 \SHIFTROT
  generate_three_operand_aluop_rcflags_size8 \PTOPCODE \OP1 \OP1C 0 \SHIFTROT
  generate_three_operand_aluop_rcflags_size8 \PTOPCODE \OP1 \OP1C 1 \SHIFTROT
.endm

generate_three_operand_aluop_rcflags_all_sizes addc adc adc
generate_three_operand_aluop_rcflags_all_sizes subc sbb sbb

generate_three_operand_aluop_rcflags_all_sizes rotl rol invalid -2
generate_three_operand_aluop_rcflags_all_sizes rotr ror invalid -2
generate_three_operand_aluop_rcflags_all_sizes rotcl rcl invalid -2
generate_three_operand_aluop_rcflags_all_sizes rotcr rcr invalid -2
generate_three_operand_aluop_rcflags_all_sizes shl shl invalid -1
generate_three_operand_aluop_rcflags_all_sizes shr shr invalid 1
generate_three_operand_aluop_rcflags_all_sizes sar sar invalid -2

.macro generate_select CC SIZE REG
som sel\CC\SIZE
  pushd   [IssueInput_raflags]
  popfd                                   # Latch associated flags
  mov     %eax,[IssueInput_rb]            # Fetch false case data
.if (\SIZE == 1)
  # x86 has no byte-sized conditional move, so emulate it here:
  j\CC    1f                              # Merge rc iff condition is true
  jmp     2f                              # False condition: no operation
1:
  mov     %\REG,[IssueInput_rc]           # Merge rc
2:
.else
  cmov\CC %\REG,[IssueInput_rc]           # Conditionally merge true case operand
.endif
  mov     [IssueState_rddata],%eax        # Store back result
  mov     %eax,[IssueInput_rbflags]       # Fetch false case flags
  cmov\CC %eax,[IssueInput_rcflags]       # Conditionally merge true case flags
  and     %eax,FLAG_NOT_WAIT_INV          # Clear invalid and wait flags
  mov     [IssueState_rdflags],%ax        # Store back flags
.if (\SIZE < 2)
  mov     %eax,[IssueInput_rb+4]          # Copy high 32 bits
.else
  xor     %eax,%eax                       # Clear high 32 bits for size 4
.endif
  mov     [IssueState_rddata+4],%eax
  eom     sel\CC\SIZE
.endm

.macro generate_select_size8 CC
som size8_sel\CC
  pushd   [IssueInput_raflags]
  popfd                                   # Latch associated flags
  mov     %eax,[IssueInput_rb]            # Fetch false case data
  mov     %edx,[IssueInput_rb+4]          # Fetch false case data
  cmov\CC %eax,[IssueInput_rc]            # Conditionally merge true case operand
  cmov\CC %edx,[IssueInput_rc+4]          # Conditionally merge true case flags
  mov     [IssueState_rddata],%eax        # Store back result
  mov     [IssueState_rddata+4],%edx      # Store back result
  mov     %eax,[IssueInput_rbflags]       # Fetch false case flags
  cmov\CC %eax,[IssueInput_rcflags]       # Conditionally merge true case flags
  and     %eax,FLAG_NOT_WAIT_INV          # Clear invalid and wait flags
  mov     [IssueState_rdflags],%ax        # Store back flags
  eom     size8_sel\CC
.endm

.macro generate_select_allsize COND
  generate_select \COND 1 al
  generate_select \COND 2 ax
  generate_select \COND 4 eax
  generate_select_size8 \COND
.endm

.macro generate_set CC SIZE R1 R2
som set\CC\SIZE
  xor     %edx,%edx                       # Make zero
  pushd   [IssueInput_raflags]
  popfd                                   # Latch associated flags
  set\CC  %dl                             # Set or reset low byte
  mov     %eax,[IssueInput_rb]            # Fetch base data
  mov     %\R1,%\R2                       # Merge according to size
  mov     [IssueState_rddata],%eax        # Store back result
  movzx   %eax,%al                        # Translate to CF (bit 0 in flags)
  mov     word ptr [IssueState_rdflags],%ax # Store back flags (CF set iff select was true)
.if (\SIZE < 2)
  mov     %eax,[IssueInput_rb+4]          # Copy high 32 bits
.else
  xor     %eax,%eax                       # Clear high 32 bits for size 4
.endif
  mov     [IssueState_rddata+4],%eax
  eom     set\CC\SIZE
.endm

.macro generate_set_allsize COND
  generate_set \COND 1 al dl
  generate_set \COND 2 ax dx
  generate_set \COND 4 eax edx
  generate_set \COND 8 eax edx
.endm

.macro generate_all_condcodes SUBMACRO
  \SUBMACRO o
  \SUBMACRO no
  \SUBMACRO c
  \SUBMACRO nc
  \SUBMACRO e
  \SUBMACRO ne
  \SUBMACRO be
  \SUBMACRO nbe
  \SUBMACRO s
  \SUBMACRO ns
  \SUBMACRO p
  \SUBMACRO np
  \SUBMACRO l
  \SUBMACRO nl
  \SUBMACRO le
  \SUBMACRO nle
.endm

.macro generate_all_condcodes_numeric SUBMACRO
  \SUBMACRO 0
  \SUBMACRO 1
  \SUBMACRO 2
  \SUBMACRO 3
  \SUBMACRO 4
  \SUBMACRO 5
  \SUBMACRO 6
  \SUBMACRO 7
  \SUBMACRO 8
  \SUBMACRO 9
  \SUBMACRO 10
  \SUBMACRO 11
  \SUBMACRO 12
  \SUBMACRO 13
  \SUBMACRO 14
  \SUBMACRO 15
.endm

grouplabel sel
  generate_all_condcodes generate_select_allsize

grouplabel set
  generate_all_condcodes generate_set_allsize

#
# Branch according to flags associated with ra and possibly rb operands (if flags are split):
# - ra always contains the ZAPS flags (or REG_zero)
# - rb always contains either REG_of or REG_cf depending on the branch sense
#
/*
#define FLAG_CF 0x001       // (1 << 0)
#define FLAG_PF 0x004       // (1 << 2)
#define FLAG_AF 0x010       // (1 << 4)
#define FLAG_ZF 0x040       // (1 << 6)
#define FLAG_SF 0x080       // (1 << 7)
#define FLAG_OF 0x800       // (1 << 11)
#define FLAG_SF_ZF 0xc0     // (1 << 7) | (1 << 6)
#define FLAG_ZAPS 0xd4      // 000011010100

# PTL-specific flags:
#define FLAG_INV  0x0008     // (1 << 3) 
#define FLAG_WAIT 0x0002     // (1 << 1)
*/

#
# Evaluate flags in single register
#
.macro eval_single_cond REG FLAG COND
  mov      %ax,[\REG]
  test     %ax,\FLAG
  set\COND %dl
.endm

/*
#
# Evaluate up to three flags involving ZF,SF in ra and OF in rb:
#
# Truth table
# O S Z =   l  nl le nle
#           
# 0 0 0  =  0  1  0  1
# 1 0 0  =  0  1  1  0
# 0 1 0  =  1  0  1  0
# 1 1 0  =  1  0  1  0
# 0 0 1  =  1  0  1  0
# 1 0 1  =  1  0  1  0
# 0 1 1  =  0  1  0  1
# 1 1 1  =  0  1  1  0
# Patterns: 0x3c, 0xc3, 0xbe, 0x41
#
# W64 zso = ((zaps & (FLAG_SF|FLAG_ZF)) >> 6) | ((cfof & FLAG_OF) >> (11-2));
# (zso <= 7);
# W64 eval = (PATTERN >> zso);
#
# Translation into 4 cycles:
#
*/
.macro eval_triple_cond PATTERN
  mov    %eax,[IssueInput_raflags]
  mov    %ebx,[IssueInput_rbflags]

  and    %eax,FLAG_SF_ZF
  and    %ebx,FLAG_OF

  shr    %eax,6
  shr    %ebx,9

  or     %eax,%ebx
  mov    %edx,\PATTERN

  mov    %ecx,%eax
  shr    %edx,%cl

  and    %edx,1

#
# Alternative: !zf && (sf == of)
# test   rax,FLAG_SF     test   rbx,FLAG_OF
# setz   cl              setz   dl
# cmp    cl,dl
# sete   cl              test   rax,FLAG_ZF
#                        sete   dl
# and    cl,dl
#
.endm

#
# Conditions:
#
.macro eval_cond_o
  eval_single_cond IssueInput_rbflags FLAG_OF nz
.endm

.macro eval_cond_no
  eval_single_cond IssueInput_rbflags FLAG_OF z
.endm

.macro eval_cond_c
  eval_single_cond IssueInput_rbflags FLAG_CF nz
.endm

.macro eval_cond_nc
  eval_single_cond IssueInput_rbflags FLAG_CF z
.endm

.macro eval_cond_e
  eval_single_cond IssueInput_raflags FLAG_ZF nz
.endm

.macro eval_cond_ne
  eval_single_cond IssueInput_raflags FLAG_ZF z
.endm

.macro eval_cond_be   # cf|zf jbe jna
  mov      %ax,[IssueInput_raflags]
  test     %ax,FLAG_ZF
  setnz    %cl
  mov      %bx,[IssueInput_rbflags]
  test     %bx,FLAG_CF
  setnz    %dl
  or       %dl,%cl
.endm

.macro eval_cond_nbe  # !cf & !zf jnbe ja
  mov      %ax,[IssueInput_raflags]
  test     %ax,FLAG_ZF
  setz     %cl
  mov      %bx,[IssueInput_rbflags]
  test     %bx,FLAG_CF
  setz     %dl
  and      %dl,%cl
.endm

.macro eval_cond_s
  eval_single_cond IssueInput_raflags FLAG_SF nz
.endm

.macro eval_cond_ns
  eval_single_cond IssueInput_raflags FLAG_SF z
.endm

.macro eval_cond_p
  eval_single_cond IssueInput_rbflags FLAG_PF nz
.endm

.macro eval_cond_np
  eval_single_cond IssueInput_rbflags FLAG_PF z
.endm

.macro eval_cond_l
  eval_triple_cond 0x3c
.endm

.macro eval_cond_nl
  eval_triple_cond 0xc3
.endm

.macro eval_cond_le
  eval_triple_cond 0xbe
.endm

.macro eval_cond_nle
  eval_triple_cond 0x41
.endm

/*
const CondCodeToFlagRegs cond_code_to_flag_regs[16] = {
  {0, REG_zero, REG_of},   // of:               jo
  {0, REG_zero, REG_of},   // !of:              jno
  {0, REG_zero, REG_cf},   // cf:               jb jc jnae
  {0, REG_zero, REG_cf},   // !cf:              jnb jnc jae
  {0, REG_zf,   REG_zero}, // zf:               jz je
  {0, REG_zf,   REG_zero}, // !zf:              jnz jne
  {1, REG_zf,   REG_cf},   // cf|zf:            jbe jna
  {1, REG_zf,   REG_cf},   // !cf & !zf:        jnbe ja
  {0, REG_zf,   REG_zero}, // sf:               js 
  {0, REG_zf,   REG_zero}, // !sf:              jns
  {0, REG_zf,   REG_zero}, // pf:               jp jpe
  {0, REG_zf,   REG_zero}, // !pf:              jnp jpo
  {1, REG_zf,   REG_of},   // sf != of:         jl jnge (*)
  {1, REG_zf,   REG_of},   // sf == of:         jnl jge (*)
  {1, REG_zf,   REG_of},   // zf | (sf != of):  jle jng (*)
  {1, REG_zf,   REG_of},   // !zf & (sf == of): jnle jg (*)
  //
  // (*) Technically three flags are involved in the comparison here,
  // however as pursuant to the ZAPS trick, zf/af/pf/sf are always
  // either all written together or not written at all. Hence the
  // last writer of SF will also deliver ZF in the same result.
  //
};
*/

.macro generate_br_any CC EXCEPT
.if (\EXCEPT)
som br_ex_\CC
.else
som br_\CC
.endif
  xor     %edx,%edx                  # Clear %rdx
  eval_cond_\CC                      # Evaluate condition: result is in %rdx
  mov     %eax,[IssueState_ripseq]   # Load sequential path RIP
  test    %edx,1                     # Is the condition true?
  cmovnz  %eax,[IssueState_riptaken] # Select the correct RIP: if taken, load taken path RIP
  mov     [IssueState_rddata],%eax   # Write back that rip
  xor     %eax,%eax
  mov     [IssueState_rddata+4],%eax # Write back high rip (always 0 in PTLsim32)
  mov     word ptr [IssueState_rdflags],0 # No exceptions for this version
.if (\EXCEPT)
  eom br_ex_\CC
.else
  eom br_\CC
.endif
.endm

.macro generate_br CC
  generate_br_any \CC 0
  generate_br_any \CC 1
.endm

grouplabel br
  generate_all_condcodes generate_br

#
# chk.cc uop
#
.macro generate_chk CC
som chk\CC
  xor     %edx,%edx
.if (\CC == COND_o)
  int3                               # Not implemented for register operand
.endif
.if (\CC == COND_no)
  int3                               # Not implemented for register operand
.endif
.if (\CC == COND_c)
  int3                               # Not implemented for register operand
.endif
.if (\CC == COND_nc)
  int3                               # Not implemented for register operand
.endif
.if (\CC == COND_e)
  cmp     %eax,%edx
  sete    %dl
.endif
.if (\CC == COND_ne)
  cmp     %eax,%edx
  setne   %dl
.endif
.if (\CC == COND_be)
  cmp     %eax,%edx
  setbe   %dl
.endif
.if (\CC == COND_nbe)
  cmp     %eax,%edx
  setnbe  %dl
.endif
.if (\CC == COND_s)
  int3                               # Not implemented for register operand
.endif
.if (\CC == COND_ns)
  int3                               # Not implemented for register operand
.endif
.if (\CC == COND_p)
  int3                               # Not implemented for register operand
.endif
.if (\CC == COND_np)
  int3                               # Not implemented for register operand
.endif
.if (\CC == COND_l)
  cmp     %eax,%edx
  setl    %dl
.endif
.if (\CC == COND_nl)
  cmp     %eax,%edx
  setnl   %dl
.endif
.if (\CC == COND_le)
  cmp     %eax,%edx
  setle   %dl
.endif
.if (\CC == COND_nle)
  cmp     %eax,%edx
  setnle  %dl
.endif
  shl     %edx,1                     # Move comparison result into invalid flag position
  mov     [IssueState_ripseq],%ebx   # Save recovery RIP (note: this overlaps and high 16 bits are overwritten by rdflags below)
  mov     [IssueState_rdflags],%dx   # Save flags
  test    %edx,%edx                  # Was there an error?
  jz      1f                         # No: skip ahead
  mov     %edx,%ecx                  # Save exception type (from rcimm)
1:
  mov     [IssueState_rddata],%edx
  xor     %edx,%edx
  mov     [IssueState_rddata+4],%edx
  eom     chk\CC
.endm

grouplabel chk
  generate_all_condcodes_numeric generate_chk

grouplabel bru
som bru
  mov     %eax,[IssueState_riptaken] # Select the correct RIP: if taken, load taken path (off-trace) RIP
  mov     [IssueState_rddata],%eax   # Write back that rip
  xor     %eax,%eax
  mov     [IssueState_rddata+4],%eax
  mov     word ptr [IssueState_rdflags],0   # Write back flags
  eom     bru

grouplabel brp
som brp
  mov     %eax,[IssueState_riptaken] # Select the RIP within PTL
  mov     [IssueState_rddata],%eax   # Write back that rip
  xor     %eax,%eax
  mov     [IssueState_rddata+4],%eax
  mov     word ptr [IssueState_rdflags],0   # Write back flags
  eom     brp

# collcc rd = zaps,cf,of
grouplabel collcc
som collcc
  movzx   %eax,word ptr [IssueInput_raflags]
  movzx   %ebx,word ptr [IssueInput_rbflags]
  movzx   %ecx,word ptr [IssueInput_rcflags]

  and     %eax,FLAG_ZAPS
  and     %ebx,FLAG_CF
  and     %ecx,FLAG_OF
  or      %eax,%ebx
  or      %eax,%ecx
  mov     [IssueState_rdflags],%ax
  mov     [IssueState_rddata],%eax
  xor     %eax,%eax
  mov     [IssueState_rddata+4],%eax
  eom     collcc

# Register to flags: 
grouplabel movrcc
som movrcc
  mov     %eax,[IssueInput_ra]
  mov     [IssueState_rddata],%eax
  mov     [IssueState_rdflags],%ax
  xor     %eax,%eax
  mov     [IssueState_rddata+4],%eax
  eom     movrcc

# Flags to register:
grouplabel movccr
som movccr
  xor     %edx,%edx
  movzx   %eax,word ptr [IssueInput_raflags]
  mov     [IssueState_rddata],%eax
  mov     [IssueState_rdflags],%ax
  xor     %eax,%eax
  mov     [IssueState_rddata+4],%eax
  eom     movccr

.macro ccornot rd ra
  not     \ra
  or      \rd,\ra
.endm

.macro generate_condcode_logic PTOPCODE OPCODE
grouplabel \PTOPCODE
som \PTOPCODE
  movzx   %eax,word ptr [IssueInput_raflags]
  movzx   %ebx,word ptr [IssueInput_rbflags]
  \OPCODE %eax,%ebx
  and     %eax,FLAG_NOT_WAIT_INV
  mov     word ptr [IssueState_rdflags],%ax
  mov     [IssueState_rddata],%eax
  eom     \PTOPCODE
.endm

generate_condcode_logic orcc or
generate_condcode_logic ornotcc ccornot
generate_condcode_logic andcc and
generate_condcode_logic xorcc xor

#
# Indirect branching
#

grouplabel jmp
# rareg (jump target), rbreg (expected jump target as scheduled)
som jmp
  mov     %eax,[IssueInput_ra+0] # Load expected destination
  mov     %edx,[IssueInput_ra+4] # Load expected destination
  mov     [IssueState_rddata+0],%eax   # Write back real rip
  mov     [IssueState_rddata+4],%edx   # Write back real rip
  mov     word ptr [IssueState_rdflags],0 # Write back flags (ignore mismatch)
  eom     jmp
som jmp_excepting
  mov     %eax,[IssueInput_ra+0] # Load expected destination
  mov     %edx,[IssueInput_ra+4] # Load expected destination
  mov     [IssueState_rddata+0],%eax   # Write back real rip
  mov     [IssueState_rddata+4],%edx   # Write back real rip
  mov     word ptr [IssueState_rdflags],0 # Write back flags (ignore mismatch)
  eom     jmp_excepting

#
# mask uop is implemented externally...
#

#define assistarg (REG_sr2 * 8)
 
.macro assist NAME
.global assist_\NAME
assist_\NAME:
.endm

.macro assistret
  # Copy rip following assisted insn into return rip 
  mov     %edx,[ctx + 8*REG_sr1]
  mov     [ctx + 8*REG_rip],%edx
  ret
.endm

#
# See x86-64 spec (abi.pdf) page 21 for register conventions
# Usable by us: %rax, %rcx, %rdx, %rsi, %rdi, %r8-%r11
# Must preserve %r12-%r15, %rsp, %rbp, %rbx
#

.extern ctx

.macro generate_muldiv insn op8 op16 op32 op64
assist \op8
  # Input:  A in %ax, B in sr2
  # Output: (A%B):(A/B) in %ah:%al
  pushw   [ctx + 8*REG_flags]
  popfw
  mov     %eax,[ctx + 8*REG_rax]
  mov     %ebx,[ctx + 8*REG_sr2]
  \insn   %bl
  mov     [ctx + 8*REG_rax],%eax
  mov     dword ptr [ctx + 8*REG_rax + 4],0

  pushfw
  popw    %dx
  and     %dx,FLAG_NOT_WAIT_INV
  mov     [ctx + 8*REG_flags],%dx
  assistret
assist \op16
  # Input:  A in %dx:%ax, B in sr2
  # Output: (A%B):(A/B) in %dx:%ax
  pushw   [ctx + 8*REG_flags]
  popfw
  mov     %edx,[ctx + 8*REG_rdx]
  mov     %eax,[ctx + 8*REG_rax]
  mov     %ebx,[ctx + 8*REG_sr2]
  \insn   %bx
  mov     [ctx + 8*REG_rdx],%edx
  mov     [ctx + 8*REG_rax],%eax
  mov     dword ptr [ctx + 8*REG_rdx],0
  mov     dword ptr [ctx + 8*REG_rax],0
  pushfw
  popw    %dx
  and     %dx,FLAG_NOT_WAIT_INV
  mov     [ctx + 8*REG_flags],%dx
  assistret
assist \op32
  # Input:  A in %edx:%eax, B in sr2
  # Output: (A%B):(A/B) in %edx:%eax
  pushw   [ctx + 8*REG_flags]
  popfw
  mov     %edx,[ctx + 8*REG_rdx]
  mov     %eax,[ctx + 8*REG_rax]
  mov     %ebx,[ctx + 8*REG_sr2]
  \insn   %ebx
  mov     [ctx + 8*REG_rdx],%edx
  mov     [ctx + 8*REG_rax],%eax
  mov     dword ptr [ctx + 8*REG_rdx],0
  mov     dword ptr [ctx + 8*REG_rax],0
  pushfw
  popw    %dx
  and     %dx,FLAG_NOT_WAIT_INV
  mov     [ctx + 8*REG_flags],%dx
  assistret
assist \op64
  # Not supported in PTLsim32
  int3
  assistret
.endm

# Generate templates for div idiv

  generate_muldiv div div8 div16 div32 div64
  generate_muldiv idiv idiv8 idiv16 idiv32 idiv64

/*
 * Floating Point
 */
.end

