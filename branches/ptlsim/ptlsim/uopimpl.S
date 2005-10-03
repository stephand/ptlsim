/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * uop implementation
 *
 * Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
 */

.text
.intel_syntax
.align 4096

#include <uopimpl.h>

# Load sign extended 32 bit constant
.macro ldcsxt destreg loreg imm
  mov     \loreg,\imm
  movzx   \destreg,\loreg
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

# NOTE:  We still need to synthesize nops, so the timing is correct:
grouplabel nop
som nop
  xor     %eax,%eax
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0
  # (no operation)
  eom nop

.macro generate_aluop PTOPCODE OPCODE SIZE REG REGB
som \PTOPCODE\SIZE
  \OPCODE %\REG,%\REGB
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0
  eom     \PTOPCODE\SIZE
.endm

.macro generate_aluop_allsize PTOPCODE OPCODE
grouplabel mov
  generate_aluop \PTOPCODE \OPCODE 1 al bl
  generate_aluop \PTOPCODE \OPCODE 2 ax bx
  generate_aluop \PTOPCODE \OPCODE 4 eax ebx
  generate_aluop \PTOPCODE \OPCODE 8 rax rbx
.endm

generate_aluop_allsize mov mov

grouplabel bswap
  generate_aluop bswap mov 1 al bl
  generate_aluop bswap bswap16 2 ax bx
  generate_aluop bswap bswapx 4 eax ebx
  generate_aluop bswap bswapx 8 rax rbx

#
# Load flags into %dx
# Uses %bl %cl %dl %bpl %dh
#
.macro ldflags
  /*
   * Flags format: OF - - - SF ZF - AF - PF - CF
   *               11       7  6    4    2    0
   *               rb       ra ra   ra   ra   rb
   *
   * NOTE: The aux flag is apparently used ONLY
   * with BCD arithmetic instructions; everything
   * else sets it to zero. This is rare enough
   * that we can treat it like special cases
   * like the direction flag. Besides, there is
   * no way to test for it in any of the branch,
   * cmov, setcc, etc. instructions. 
   */

  seto    %dh         # %dh = OF  (note: sets bit 0 of dh = bit 8 of dx)
  sets    %bpl        # %bpl = SF

  setp    %cl         # %cl = PF
  setc    %bl         # %bl = CF
  setz    %dl         # %dl = ZF

  shl     %dh,3       # OF bit 11 (already in dh bit 0 = dx bit 8, so just shift by 3)
  shl     %bpl,7      # SF bit 7
  shl     %cl,2       # PF bit 2

  or      %cl,%bpl    # %cl = PF|SF
  shl     %dl,6       # ZF bit 6

  or      %dl,%bl     # %dl = ZF|CF

  or      %dl,%cl     # %dl = (ZF|CF)|(PF|SF), %dh already contains OF
.endm

.macro stflags ADDR
/*
  mov     %r15,%rsp
  lea     %rsp,[\ADDR + 2]
  pushfw
  mov     %rsp,%r15
*/
  # eflags = 0x10246  [ 01x0 x1x0 = PF ZF ]
  ldflags             # Load flags into %dx
  mov     [\ADDR],%dx
.endm

.macro btx RD RA
  bt      \RD,\RA
  mov     %rax,+1
  mov     %rdx,-1
  cmovc   %rax,%rdx
.endm

.macro btsx RD RA
  bts     \RD,\RA
.endm

.macro btrx RD RA
  btr     \RD,\RA
.endm

.macro btcx RD RA
  btc     \RD,\RA
.endm

# dupbit rd = ra,rb,rc
# duplicate bit <rc> of <rb> into entire register and merge with <ra>:
.macro dupbit RD RA
  bt      %rbx,%rcx
  mov     %rbx,0x0000000000000000
  mov     %rdx,0xffffffffffffffff
  cmovc   %rbx,%rdx
  mov     \RD,\RA
.endm

.macro ctpop RD RA
  int3   #++MTY TODO
.endm

.macro generate_dummyop_setflags PTOPCODE OPCODE SIZE REG REGB
som nf_\PTOPCODE\SIZE
  int3
  eom     nf_\PTOPCODE\SIZE
som \PTOPCODE\SIZE
  int3
  eom     \PTOPCODE\SIZE
.endm

.macro generate_aluop_setflags PTOPCODE OPCODE SIZE REG REGB
som nf_\PTOPCODE\SIZE
  \OPCODE %\REG,%\REGB
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     nf_\PTOPCODE\SIZE
som \PTOPCODE\SIZE
  \OPCODE %\REG,%\REGB
  mov     [IssueState_rddata],%rax
  stflags IssueState_rdflags
  eom     \PTOPCODE\SIZE
.endm

.macro generate_aluop_allsize_setflags PTOPCODE OPCODE NOBYTE=0
grouplabel \PTOPCODE
.if (\NOBYTE)
som nf_dummy_\PTOPCODE
  int3
  eom     nf_dummy_\PTOPCODE
som dummy_\PTOPCODE
  int3
  eom     dummy_\PTOPCODE
.else
  generate_aluop_setflags \PTOPCODE \OPCODE 1 al bl
.endif
  generate_aluop_setflags \PTOPCODE \OPCODE 2 ax bx
  generate_aluop_setflags \PTOPCODE \OPCODE 4 eax ebx
  generate_aluop_setflags \PTOPCODE \OPCODE 8 rax rbx
.endm

generate_aluop_allsize_setflags and and
generate_aluop_allsize_setflags or or
generate_aluop_allsize_setflags xor xor
generate_aluop_allsize_setflags andnot andnot
generate_aluop_allsize_setflags ornot ornot
generate_aluop_allsize_setflags nand nand
generate_aluop_allsize_setflags nor nor
generate_aluop_allsize_setflags eqv eqv
generate_aluop_allsize_setflags add add
generate_aluop_allsize_setflags sub sub
generate_aluop_allsize_setflags bt btx 1
generate_aluop_allsize_setflags bts bts 1
generate_aluop_allsize_setflags btr btr 1
generate_aluop_allsize_setflags btc btc 1
generate_aluop_allsize_setflags dupbit dupbit
generate_aluop_allsize_setflags ctz bsf 1
generate_aluop_allsize_setflags clz bsr 1
generate_aluop_allsize_setflags ctpop ctpop 1

.macro generate_aluop_and_mask PTOPCODE OPCODE SIZE REG REGB
som nf_\PTOPCODE\SIZE
  \OPCODE %\REG,%\REGB
  mov     %ebx,1
  shl     %rbx,%cl
  dec     %rbx
  and     %\REG,%\REGB
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     nf_\PTOPCODE\SIZE
som \PTOPCODE\SIZE
  \OPCODE %\REG,%\REGB
  mov     %ebx,1
  shl     %rbx,%cl
  dec     %rbx
  and     %\REG,%\REGB
  mov     [IssueState_rddata],%rax
  stflags IssueState_rdflags
  eom     \PTOPCODE\SIZE
.endm

.macro generate_aluop_and_mask_allsize_setflags PTOPCODE OPCODE
grouplabel \PTOPCODE
  generate_aluop_and_mask \PTOPCODE \OPCODE 1 al bl
  generate_aluop_and_mask \PTOPCODE \OPCODE 2 ax bx
  generate_aluop_and_mask \PTOPCODE \OPCODE 4 eax ebx
  generate_aluop_and_mask \PTOPCODE \OPCODE 8 rax rbx
.endm

generate_aluop_and_mask_allsize_setflags addm add
generate_aluop_and_mask_allsize_setflags subm sub

.macro generate_aluop3_setflags PTOPCODE OPCODE1 OPCODE2 SIZE REG REGB REGC
som nf_\PTOPCODE\SIZE
  \OPCODE1 %\REG,%\REGB
  \OPCODE2 %\REG,%\REGC
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     nf_\PTOPCODE\SIZE
som \PTOPCODE\SIZE
  \OPCODE1 %\REG,%\REGB
  \OPCODE2 %\REG,%\REGC
  mov     [IssueState_rddata],%rax
  stflags IssueState_rdflags
  eom     \PTOPCODE\SIZE
.endm

.macro generate_aluop3_allsize_setflags PTOPCODE OPCODE1 OPCODE2
grouplabel \PTOPCODE
  generate_aluop3_setflags \PTOPCODE \OPCODE1 \OPCODE2 1 al bl cl
  generate_aluop3_setflags \PTOPCODE \OPCODE1 \OPCODE2 2 ax bx cx
  generate_aluop3_setflags \PTOPCODE \OPCODE1 \OPCODE2 4 eax ebx ecx
  generate_aluop3_setflags \PTOPCODE \OPCODE1 \OPCODE2 8 rax rbx rcx
.endm

# (ra OP1 rb) OP2 (rc << SHIFT)
.macro generate_aluop3_shift_setflags PTOPCODE OPCODE1 OPCODE2 SIZE REG REGB REGC SHIFT
som nf_\PTOPCODE\SIZE\SHIFT
  shl      %\REGC,\SHIFT
  \OPCODE1 %\REG,%\REGB
  \OPCODE2 %\REG,%\REGC
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     nf_\PTOPCODE\SIZE\SHIFT
som \PTOPCODE\SIZE\SHIFT
  shl      %\REGC,\SHIFT
  \OPCODE1 %\REG,%\REGB
  \OPCODE2 %\REG,%\REGC
  mov     [IssueState_rddata],%rax
  stflags IssueState_rdflags
  eom     \PTOPCODE\SIZE\SHIFT
.endm

.macro generate_aluop3_shift_allsize_setflags PTOPCODE OPCODE1 OPCODE2
grouplabel \PTOPCODE
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 1 al bl cl 0
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 1 al bl cl 1
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 1 al bl cl 2
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 1 al bl cl 3

  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 2 ax bx cx 0
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 2 ax bx cx 1
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 2 ax bx cx 2
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 2 ax bx cx 3

  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 4 eax ebx ecx 0
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 4 eax ebx ecx 1
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 4 eax ebx ecx 2
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 4 eax ebx ecx 3

  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 8 rax rbx rcx 0
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 8 rax rbx rcx 1
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 8 rax rbx rcx 2
  generate_aluop3_shift_setflags \PTOPCODE \OPCODE1 \OPCODE2 8 rax rbx rcx 3
.endm

generate_aluop3_shift_allsize_setflags adda add add
generate_aluop3_shift_allsize_setflags adds add sub
generate_aluop3_shift_allsize_setflags suba sub add
generate_aluop3_shift_allsize_setflags subs sub sub

.macro imull SZ RD RA
.if (\SZ == 1)
  int3    # No 8-bit form of two-operand imul
.else
  imul    \RD,\RA
.endif
.endm

.macro imulh SZ RD RA
.if (\SZ == 1)
  imul    %bl         # multiply %al by RA; %ax = product
.endif
.if (\SZ == 2)
  imul    %bx         # multiply %ax by RA; %dx:%ax = product
  mov     %ax,%dx
.endif
.if (\SZ == 4)
  imul    %ebx         # multiply %eax by RA; %edx:%eax = product
  mov     %eax,%edx
.endif
.if (\SZ == 8)
  imul    %rbx         # multiply %rax by RA; %rdx:%rax = product
  mov     %rax,%rdx
.endif
.endm

.macro generate_mulop_setflags PTOPCODE OPCODE SIZE REG REGB
som nf_\PTOPCODE\SIZE
  \OPCODE \SIZE,%\REG,%\REGB
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     nf_\PTOPCODE\SIZE
som \PTOPCODE\SIZE
  \OPCODE \SIZE,%\REG,%\REGB
  mov     [IssueState_rddata],%rax
  stflags IssueState_rdflags
  eom     \PTOPCODE\SIZE
.endm

.macro generate_mulop_allsize_setflags PTOPCODE OPCODE
grouplabel \PTOPCODE
  generate_mulop_setflags \PTOPCODE \OPCODE 1 al bl
  generate_mulop_setflags \PTOPCODE \OPCODE 2 ax bx
  generate_mulop_setflags \PTOPCODE \OPCODE 4 eax ebx
  generate_mulop_setflags \PTOPCODE \OPCODE 8 rax rbx
.endm

generate_mulop_allsize_setflags mull imull
generate_mulop_allsize_setflags mulh imulh

.macro generate_aluop_setflags_useflags_rc PTOPCODE OPCODE SIZE REG REGB
som nf_\PTOPCODE\SIZE
  pushw   %rrcflagsw
  popfw
  \OPCODE %\REG,%\REGB
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     nf_\PTOPCODE\SIZE
som \PTOPCODE\SIZE
  pushw   %rrcflagsw
  popfw
  \OPCODE %\REG,%\REGB
  mov     [IssueState_rddata],%rax
  stflags IssueState_rdflags
  eom     \PTOPCODE\SIZE
.endm

.macro generate_aluop_allsize_setflags_useflags_rc PTOPCODE OPCODE
grouplabel \PTOPCODE
  generate_aluop_setflags_useflags_rc \PTOPCODE \OPCODE 1 al bl
  generate_aluop_setflags_useflags_rc \PTOPCODE \OPCODE 2 ax bx
  generate_aluop_setflags_useflags_rc \PTOPCODE \OPCODE 4 eax ebx
  generate_aluop_setflags_useflags_rc \PTOPCODE \OPCODE 8 rax rbx
.endm

# Technically only the carry flag needs to be set here:
generate_aluop_allsize_setflags_useflags_rc addc adc
generate_aluop_allsize_setflags_useflags_rc subc sbb

.macro generate_shiftrot_setflags_useflags_rc PTOPCODE OPCODE SIZE REG
som nf_\PTOPCODE\SIZE
  pushw   %rrcflagsw     
  popfw
  mov     %rcx,%rbx
  \OPCODE %\REG,%cl
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant  
  eom     nf_\PTOPCODE\SIZE
som \PTOPCODE\SIZE
  pushw   %rrcflagsw     
  popfw
  mov     %rcx,%rbx
  \OPCODE %\REG,%cl
  mov     [IssueState_rddata],%rax
  stflags IssueState_rdflags
  eom     \PTOPCODE\SIZE
.endm

.macro generate_shiftrot_allsize_setflags_useflags_rc PTOPCODE OPCODE
grouplabel \PTOPCODE
  generate_shiftrot_setflags_useflags_rc \PTOPCODE \OPCODE 1 al
  generate_shiftrot_setflags_useflags_rc \PTOPCODE \OPCODE 2 ax
  generate_shiftrot_setflags_useflags_rc \PTOPCODE \OPCODE 4 eax
  generate_shiftrot_setflags_useflags_rc \PTOPCODE \OPCODE 8 rax
.endm

generate_shiftrot_allsize_setflags_useflags_rc rotl rol
generate_shiftrot_allsize_setflags_useflags_rc rotr ror
generate_shiftrot_allsize_setflags_useflags_rc rotcl rcl
generate_shiftrot_allsize_setflags_useflags_rc rotcr rcr
generate_shiftrot_allsize_setflags_useflags_rc shl shl
generate_shiftrot_allsize_setflags_useflags_rc shr shr
generate_shiftrot_allsize_setflags_useflags_rc sar sar

.macro generate_select CC SIZE REG REGB
som sel\CC\SIZE
  pushw    %rraflagsw
  popfw                                   # Latch associated flags
  mov     %edx,%rrbflags                  # Fetch false case flags
.if \SIZE == 1
  int3                                    # x86 doesn't support 8-bit cmov
.else
  cmov\CC %\REG,%\REGB                    # Conditionally merge true case operand
  cmov\CC %edx,%rrcflags                  # Conditionally merge true case flags
.endif
  mov     [IssueState_rddata],%rbx        # Store back result
  mov     %rax,%rbx                       # Result must always end up in %rax
  and     %dx,FLAG_NOT_WAIT_INV           # Clear invalid and wait flags
  mov     [IssueState_rdflags],%dx        # Store back flags
  eom     sel\CC\SIZE
.endm

.macro generate_select_allsize COND
  generate_select \COND 1 bl cl
  generate_select \COND 2 bx cx
  generate_select \COND 4 ebx ecx
  generate_select \COND 8 rbx rcx
.endm

# const char* cond_code_names[16] = { "o", "no", "c", "nc", "e", "ne", "be", "nbe", "s", "ns", "pe", "po", "l", "nl", "le", "nle" };

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

.macro generate_set CC SIZE R1 R2
som set\CC\SIZE
  xor     %rdx,%rdx
  pushw   %rraflagsw                        # Fetch condition
  popfw                                     # Latch associated flags
  set\CC  %dl                               # Set or reset low byte
  mov     %rax,%rbx                         # Fetch original operand to merge with
  mov     %\R1,%\R2                         # Merge if needed
  mov     [IssueState_rddata],%rax          # Store back result
  mov     word ptr [IssueState_rdflags],0   # Store back flags
  eom     set\CC\SIZE
.endm

.macro generate_set_allsize COND
  generate_set \COND 1 al dl
  generate_set \COND 2 ax dx
  generate_set \COND 4 eax edx
  generate_set \COND 8 rax rdx
.endm

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
.macro eval_single_cond reg flag t
  test     %\reg,\flag
  set\t    %dl
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
.macro eval_triple_cond pattern
  and    %rraflags,FLAG_SF_ZF
  and    %rrbflags,FLAG_OF
  # ;;
  shr    %rraflags,6
  shr    %rrbflags,9
  # ;;
  or     %rraflags,%rrbflags
  mov    %rdx,\pattern
  # ;;
  mov    %ecx,%rraflags
  shr    %rdx,%cl
  # ;;
  and    %rdx,1

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
  eval_single_cond rrbflags FLAG_OF nz
.endm

.macro eval_cond_no
  eval_single_cond rrbflags FLAG_OF z
.endm

.macro eval_cond_c
  eval_single_cond rrbflags FLAG_CF nz
.endm

.macro eval_cond_nc
  eval_single_cond rrbflags FLAG_CF z
.endm

.macro eval_cond_e
  eval_single_cond rraflags FLAG_ZF nz
.endm

.macro eval_cond_ne
  eval_single_cond rraflags FLAG_ZF z
.endm

.macro eval_cond_be   # cf|zf jbe jna
  test     %rraflags,FLAG_ZF
  setnz    %cl
  test     %rrbflags,FLAG_CF
  setnz    %dl
  or       %dl,%cl
.endm

.macro eval_cond_nbe  # !cf & !zf jnbe ja
  test     %rraflags,FLAG_ZF
  setz     %cl
  test     %rrbflags,FLAG_CF
  setz     %dl
  and      %dl,%cl
.endm

.macro eval_cond_s
  eval_single_cond rraflags FLAG_SF nz
.endm

.macro eval_cond_ns
  eval_single_cond rraflags FLAG_SF z
.endm

.macro eval_cond_p
  eval_single_cond rrbflags FLAG_PF nz
.endm

.macro eval_cond_np
  eval_single_cond rrbflags FLAG_PF z
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

.macro generate_br_noexcept CC
som br_\CC
  xor     %rdx,%rdx                  # Clear %rdx
  mov     %r10,%rcx                  # Save %rcx (branch index) for later
  eval_cond_\CC                      # Evaluate condition: result is in %rdx
  mov     %rax,[IssueState_ripseq]   # Load sequential path RIP
  test    %rdx,1                     # Is the condition true?
  cmovnz  %rax,[IssueState_riptaken] # Select the correct RIP: if taken, load taken path RIP
  mov     [IssueState_rddata],%rax   # Write back that rip
  mov     word ptr [IssueState_rdflags],0 # No exceptions for this version
  # %rcx = branchid
  xor     %dl,1                      # Invert branch state: only not-taken branches are excepting
  mov     %rcx,%r10                  # Restore rcx
  shl     %rdx,%cl                   # Shift branch group into position
  eomret  br_\CC
.endm

.macro generate_br_except CC
som br_ex_\CC
  xor     %rdx,%rdx                  # Clear %rdx
  mov     %r10,%rcx                  # Save %rcx (branch index) for later
  eval_cond_\CC                      # Evaluate condition: result is in %rdx
  test    %rdx,1                     # Is the condition true?
  jnz     1f                         # True condition = OK
  # Branch off trace: exception
  # %rcx = branchid
  mov     %eax,1                     # Invert branch state: only not-taken branches are excepting
  mov     %rcx,%r10                  # Restore rcx
  shl     %rax,%cl                   # Shift branch group status into position
  mov     %eax,EXCEPTION_BranchMispredict
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],2 # Set invalid bit
  jmp     2f
1:
  # Branch on trace: correct
  mov     %rax,[IssueState_riptaken] # Load taken path (i.e. on-trace) RIP
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0
2:
  eomret  br_ex_\CC
.endm

.macro generate_br CC
  generate_br_noexcept \CC
  generate_br_except \CC
.endm

grouplabel br
  generate_all_condcodes generate_br

.macro generate_br_alu_noexcept CMPTYPE CC NCC SIZESHIFT
som br_\CMPTYPE\CC\SIZESHIFT
  xor      %edx,%edx
.if (\SIZESHIFT == 0)
  \CMPTYPE %al,%bl
.endif
.if (\SIZESHIFT == 1)
  \CMPTYPE %ax,%bx
.endif
.if (\SIZESHIFT == 2)
  \CMPTYPE %eax,%ebx
.endif
.if (\SIZESHIFT == 3)
  \CMPTYPE %rax,%rbx
.endif
  mov      %rax,[IssueState_ripseq]               # Load sequential path RIP
  cmov\CC  %rax,[IssueState_riptaken]             # Select the correct RIP: if taken, load taken path (off-trace) RIP
  mov      [IssueState_rddata],%rax               # Write back that rip
  set\NCC  %dl                                    # Was the branch NOT taken?
  pushfw                                          # Save flags
  popw     %bx                                    # Get flags into %bx
  and      %ebx,FLAG_NOT_WAIT_INV                 # Mask off unrelated flags
  mov      [IssueState_rdflags],%bx               # Save those flags
  # %rcx = groupid
  eomret  br_\CMPTYPE\CC\SIZESHIFT
.endm

.macro generate_br_alu_except CMPTYPE CC NCC SIZESHIFT
som br_ex_\CMPTYPE\CC\SIZESHIFT
  xor      %edx,%edx
  xor      %ebp,%ebp
.if (\SIZESHIFT == 0)
  \CMPTYPE %al,%bl
.endif
.if (\SIZESHIFT == 1)
  \CMPTYPE %ax,%bx
.endif
.if (\SIZESHIFT == 2)
  \CMPTYPE %eax,%ebx
.endif
.if (\SIZESHIFT == 3)
  \CMPTYPE %rax,%rbx
.endif
  mov      %rax,[IssueState_riptaken]             # Load taken path RIP
  mov      %rbx,EXCEPTION_BranchMispredict        # Load possible exception
  cmov\NCC %rax,%rbx                              # Was the branch invalid?
  mov      [IssueState_rddata],%rax               # Write back that rip
  set\NCC  %dl                                    # Was the branch NOT taken?
  set\NCC  %bpl                                   # Was the branch NOT taken? (dup for later)
  pushfw                                          # Save flags
  popw     %bx                                    # Get flags into %bx
  and      %ebx,FLAG_NOT_WAIT_INV                 # Mask off unrelated flags
  shl      %bpl,1                                 # Move possible invalid flag into bit 1
  or       %ebx,%ebp                              # Merge it into the true flags
  mov      word ptr [IssueState_rdflags],%bx      # Save those flags
  # %rcx = branchid
  eomret  br_ex_\CMPTYPE\CC\SIZESHIFT
.endm

.macro generate_br_sub CC NCC
  generate_br_alu_noexcept cmp \CC \NCC 0
  generate_br_alu_except   cmp \CC \NCC 0
  generate_br_alu_noexcept cmp \CC \NCC 1
  generate_br_alu_except   cmp \CC \NCC 1
  generate_br_alu_noexcept cmp \CC \NCC 2
  generate_br_alu_except   cmp \CC \NCC 2
  generate_br_alu_noexcept cmp \CC \NCC 3
  generate_br_alu_except   cmp \CC \NCC 3
.endm

.macro generate_br_and CC NCC
  generate_br_alu_noexcept test \CC \NCC 0
  generate_br_alu_except   test \CC \NCC 0
  generate_br_alu_noexcept test \CC \NCC 1
  generate_br_alu_except   test \CC \NCC 1
  generate_br_alu_noexcept test \CC \NCC 2
  generate_br_alu_except   test \CC \NCC 2
  generate_br_alu_noexcept test \CC \NCC 3
  generate_br_alu_except   test \CC \NCC 3
.endm

.macro generate_all_condcodes_and_inverses SUBMACRO
  \SUBMACRO o no
  \SUBMACRO no o
  \SUBMACRO c nc
  \SUBMACRO nc c
  \SUBMACRO e ne
  \SUBMACRO ne e
  \SUBMACRO be nbe
  \SUBMACRO nbe be
  \SUBMACRO s ns
  \SUBMACRO ns s
  \SUBMACRO p np
  \SUBMACRO np p
  \SUBMACRO l nl
  \SUBMACRO nl l
  \SUBMACRO le nle
  \SUBMACRO nle le
.endm

grouplabel br_sub
  generate_all_condcodes_and_inverses generate_br_sub

grouplabel br_and
  generate_all_condcodes_and_inverses generate_br_and

.macro generate_chk CC
som chk\CC
  xor     %rdx,%rdx
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
  cmp     %rax,%rdx
  sete    %dl
.endif
.if (\CC == COND_ne)
  cmp     %rax,%rdx
  setne   %dl
.endif
.if (\CC == COND_be)
  cmp     %rax,%rdx
  setbe   %dl
.endif
.if (\CC == COND_nbe)
  cmp     %rax,%rdx
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
  cmp     %rax,%rdx
  setl    %dl
.endif
.if (\CC == COND_nl)
  cmp     %rax,%rdx
  setnl   %dl
.endif
.if (\CC == COND_le)
  cmp     %rax,%rdx
  setle   %dl
.endif
.if (\CC == COND_nle)
  cmp     %rax,%rdx
  setnle  %dl
.endif
  shl     %rdx,1                     # Move comparison result into invalid flag position
  mov     [IssueState_ripseq],%rbx   # Save recovery RIP (note: this overlaps and high 16 bits are overwritten by rdflags below)
  mov     [IssueState_rdflags],%dx   # Save flags
  test    %edx,%edx                  # Was there an error?
  jz      1f                         # No: skip ahead
  mov     %rdx,%rcx                  # Save exception type (from rcimm)
1:
  mov     [IssueState_rddata],%rdx
  eomret  br_\CC
.endm

grouplabel chk
  generate_all_condcodes_numeric generate_chk

grouplabel bru
som bru
  mov     %rax,[IssueState_riptaken] # Select the correct RIP: if taken, load taken path (off-trace) RIP
  mov     [IssueState_rddata],%rax   # Write back that rip
  mov     word ptr [IssueState_rdflags],0   # Write back flags
  eomret  bru

grouplabel brp
som brp
  mov     %rax,[IssueState_riptaken] # Select the RIP within PTL
  mov     [IssueState_rddata],%rax   # Write back that rip
  mov     word ptr [IssueState_rdflags],0   # Write back flags
  eomret  brp

/*
.macro generate_adda RDSIZE RBSCALE RCSCALE
# adda rd = ra, rb*S, rc
som adda\RDSIZE\RBSCALE\RCSCALE
  lea     %rax,[%rax + %rbx*\RBSCALE]    # Calculate
  lea     %rax,[%rax + %rcx*\RCSCALE]    # Calculate
.if \RDSIZE == 4
  mov     %eax,%eax                      # Zero out high 32 bits according to x86 semantics
.endif
  mov     [IssueState_rddata],%rax        # Store back result
  mov     word ptr [IssueState_rdflags],0 # Store back flags (none set)
  eom     adda\RDSIZE\RBSCALE\RCSCALE
.endm

.macro generate_adda_allsizes RDSIZE
  generate_adda   \RDSIZE 1 1
  generate_adda   \RDSIZE 1 2
  generate_adda   \RDSIZE 1 4
  generate_adda   \RDSIZE 1 8
  generate_adda   \RDSIZE 2 1
  generate_adda   \RDSIZE 2 2
  generate_adda   \RDSIZE 2 4
  generate_adda   \RDSIZE 2 8
  generate_adda   \RDSIZE 4 1
  generate_adda   \RDSIZE 4 2
  generate_adda   \RDSIZE 4 4
  generate_adda   \RDSIZE 4 8
  generate_adda   \RDSIZE 8 1
  generate_adda   \RDSIZE 8 2
  generate_adda   \RDSIZE 8 4
  generate_adda   \RDSIZE 8 8
.endm

grouplabel adda
generate_adda_allsizes 8
grouplabel addad
generate_adda_allsizes 4
*/

#
# Byte operations
#

grouplabel inshb
som inshb
  mov     %ah,%bl
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0
  eom     inshb

grouplabel exthb
som exthb
  mov     %al,%ah
  movzx   %rax,%al
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0
  eom     exthb

grouplabel movhb
som movhb
  mov     %ah,%bh
  mov     [IssueState_rddata],%rax
  eom     movhb

# collcc rd = zaps,cf,of
grouplabel collcc
som collcc
  and     %rraflags,FLAG_ZAPS
  and     %rrbflags,FLAG_CF
  and     %rrcflags,FLAG_OF
  or      %rraflags,%rrbflags
  or      %rraflags,%rrcflags
  mov     [IssueState_rdflags],%rraflags
  mov     [IssueState_rddata],%rraflags
  eom     collcc

# Register to flags: 
grouplabel movrcc
som movrcc
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],%ax
  eom     movrcc

# Flags to register:
grouplabel movccr
som movccr
  xor     %rdx,%rdx
  mov     %eax,%rraflags
  mov     [IssueState_rddata],%rax
  mov     [IssueState_rdflags],%dx
  eom     movccr

grouplabel orcc
som orcc
  xor     %rdx,%rdx
  or      %rraflags,%rrbflags
  and     %rraflags,FLAG_NOT_WAIT_INV
  mov     word ptr [IssueState_rdflags],%rraflagsw
  mov     [IssueState_rddata],%rdx
  eom     orcc

grouplabel ornotcc
som ornotcc
  xor     %rdx,%rdx
  not     %rrbflags
  or      %rraflags,%rrbflags
  and     %rraflags,FLAG_NOT_WAIT_INV
  mov     word ptr [IssueState_rdflags],%rraflagsw
  mov     [IssueState_rddata],%rdx
  eom     ornotcc

grouplabel andcc
som andcc
  xor     %rdx,%rdx
  and     %rraflags,%rrbflags
  and     %rraflags,FLAG_NOT_WAIT_INV
  mov     word ptr [IssueState_rdflags],%rraflagsw
  mov     [IssueState_rddata],%rdx
  eom     andcc

grouplabel xorcc
som xorcc
  xor     %rdx,%rdx
  xor     %rraflags,%rrbflags
  and     %rraflags,FLAG_NOT_WAIT_INV
  mov     word ptr [IssueState_rdflags],%rraflagsw
  mov     [IssueState_rddata],%rdx
  eom     xorcc

# Set high 32 bits to ra, low 32 bits to rb
grouplabel movhl
som movhl
  shl     %rax,32          # put ra in high 32 bits
  mov     %ebx,%ebx        # zero high 32 bits of rb
  or      %rax,%rbx        # merge
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0
  eom     movhl

# Set low 32 bits to rb, leave high 32 bits as in ra
grouplabel movl
som movl
  shr     %rax,32          # zero out low 32 bits of ra
  shl     %rax,32          # zero out low 32 bits of ra
  mov     %ebx,%ebx        # zero high 32 bits of rb
  or      %rax,%rbx        # merge the two
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0
  eom     movl

#
# Sign and zero extensions
#
.macro generate_ext PTOPCODE RDSIZE RASIZE OPCODE REGD REGA REGB
som \PTOPCODE\RDSIZE\RASIZE
  \OPCODE %\REGD,%\REGA            # Do extension
  mov     [IssueState_rddata],%rax # Store back result
  mov     word ptr [IssueState_rdflags],0
  eom     \PTOPCODE\RDSIZE\RASIZE
.endm

grouplabel zxt
  generate_ext   zxt 1 1 mov al bl
  generate_ext   zxt 1 2 invalid x x
  generate_ext   zxt 1 4 invalid x x
  generate_ext   zxt 1 8 invalid x x
  generate_ext   zxt 2 1 movzx ax bl
  generate_ext   zxt 2 2 mov ax bx
  generate_ext   zxt 2 4 invalid x x
  generate_ext   zxt 2 8 invalid x x
  generate_ext   zxt 4 1 movzx eax bl
  generate_ext   zxt 4 2 movzx eax bx
  generate_ext   zxt 4 4 mov eax ebx
  generate_ext   zxt 4 8 invalid x x
  generate_ext   zxt 8 1 movzx rax bl
  generate_ext   zxt 8 2 movzx rax bx
  generate_ext   zxt 8 4 mov eax ebx
  generate_ext   zxt 8 8 mov rax rbx

grouplabel sxt
  generate_ext   sxt 1 1 mov al bl
  generate_ext   sxt 1 2 invalid x x
  generate_ext   sxt 1 4 invalid x x
  generate_ext   sxt 1 8 invalid x x
  generate_ext   sxt 2 1 movsx ax bl
  generate_ext   sxt 2 2 mov ax bx
  generate_ext   sxt 2 4 invalid x x
  generate_ext   sxt 2 8 invalid x x
  generate_ext   sxt 4 1 movsx eax bl
  generate_ext   sxt 4 2 movsx eax bx
  generate_ext   sxt 4 4 mov eax ebx
  generate_ext   sxt 4 8 invalid x x
  generate_ext   sxt 8 1 movsx rax bl
  generate_ext   sxt 8 2 movsx rax bx
  generate_ext   sxt 8 4 movsxd rax ebx
  generate_ext   sxt 8 8 mov rax rbx

#
# Indirect branching
#

grouplabel jmp
# rareg (jump target), rbreg (expected jump target as scheduled)
som jmp
  xor     %rdx,%rdx                  # Clear %rdx
  mov     %rbx,[IssueState_riptaken] # Load expected destination
  mov     [IssueState_rddata],%rax   # Write back real rip
  cmp     %rax,%rbx                  # Check correctness
  setne   %dl                        # Generate invalid bit if mismatch
  # %rcx = branchid
  mov     %eax,%edx                  # Save correctness state for later
  shl     %rdx,%cl                   # Shift branch status into position
  mov     word ptr [IssueState_rdflags],0 # Write back flags (ignore mismatch)
  eom     jmp
som jmp_excepting
  xor     %rdx,%rdx                  # Clear %rdx
  mov     %rbx,[IssueState_riptaken] # Load expected destination
  cmp     %rax,%rbx                  # Do we have a match?
  je      1f                         # Yes: on trace, no exception
  # Off-trace: exception
  mov     %eax,1                     # Get low bit
  shl     %rdx,%cl                   # Shift branch status into position
  mov     %eax,EXCEPTION_BranchMispredict
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],2 # Set invalid flag
  jmp     2f
1:  
  # On-trace: OK
  mov     [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0
2:
  eom     jmp_excepting

/*
 * Floating point and vector operations
 */
.macro fpinvalid PTOPCODE OPCODE
  int3
.endm


.macro cvtsi2sdtest RD RA
  cvtsi2sd \RD,\RA
  int3
.endm

.macro generate_fp_aluop PTOPCODE OPCODE SIZECODE
som \PTOPCODE\SIZECODE
  movd    %xmm0,%rax
  movd    %xmm1,%rbx
  \OPCODE %xmm0,%xmm1
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     \PTOPCODE\SIZECODE
.endm

.macro simple_fp_convop_ra PTOPCODE OPCODE HIPART=0
grouplabel \PTOPCODE
som \PTOPCODE
  movd    %xmm0,%rax
  \OPCODE %xmm0,%xmm0
.if (\HIPART)
  movhlps %xmm0,%xmm0
.endif
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     \PTOPCODE
.endm

.macro simple_fp_convop_ins PTOPCODE OPCODE HIPART=0
grouplabel \PTOPCODE
som \PTOPCODE
  movd    %xmm0,%rax
  movd    %xmm1,%rbx
  \OPCODE %xmm0,%xmm1
.if (\HIPART)
  movhlps %xmm0,%xmm0
.endif
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     \PTOPCODE
.endm

# high part in ra, low part in rb
.macro simple_fp_convop_collect PTOPCODE OPCODE
grouplabel \PTOPCODE
som \PTOPCODE
  movd    %xmm1,%rax
  movd    %xmm0,%rbx
  movlhps %xmm0,%xmm1
  \OPCODE %xmm0,%xmm0
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     \PTOPCODE
.endm

.macro simple_fp_convop_intsrc PTOPCODE OPCODE SIZE64=0
grouplabel \PTOPCODE
som \PTOPCODE
  movd    %xmm0,%rax
.if (\SIZE64)
  \OPCODE %xmm0,%rbx
.else
  \OPCODE %xmm0,%ebx
.endif
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     \PTOPCODE
.endm

.macro simple_fp_convop_ra_intsrc PTOPCODE OPCODE SIZE64=0
grouplabel \PTOPCODE
som \PTOPCODE
.if (\SIZE64)
  \OPCODE %xmm0,%rax
.else
  \OPCODE %xmm0,%eax
.endif
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     \PTOPCODE
.endm

# This is really a pair of templates: one with rounding, one with truncation!
.macro simple_fp_convop_intdest PTOPCODE OPCODEROUND OPCODETRUNC SIZE64=0
grouplabel \PTOPCODE
som round_\PTOPCODE
  movd    %xmm0,%rax
.if (\SIZE64)
  \OPCODEROUND %rax,%xmm0
.else
  \OPCODEROUND %eax,%xmm0
.endif
  mov     qword ptr [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     round_\PTOPCODE
som trunc_\PTOPCODE
  movd    %xmm0,%rax
.if (\SIZE64)
  \OPCODETRUNC %rax,%xmm0
.else
  \OPCODETRUNC %eax,%xmm0
.endif
  mov     qword ptr [IssueState_rddata],%rax
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     trunc_\PTOPCODE
.endm

.macro simple_fp_convop_trunctype PTOPCODE OPCODEROUND OPCODETRUNC
grouplabel \PTOPCODE
som round_\PTOPCODE
  movd    %xmm0,%rax
  \OPCODEROUND %xmm0,%xmm0
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     round_\PTOPCODE
som trunc_\PTOPCODE
  movd    %xmm0,%rax
  \OPCODETRUNC %xmm0,%xmm0
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     trunc_\PTOPCODE
.endm

# {"cvtf.i2s.ins",   OPCLASS_FP_ALU,        F, ANYFPU}, // one W32s <rb> to single, insert into low 32 bits of <ra> (for cvtsi2ss)
simple_fp_convop_intsrc cvtf_i2s_ins cvtsi2ss 0
# {"cvtf.i2s.p",     OPCLASS_FP_ALU,        F, ANYFPU}, // pair of W32s <ra> to pair of singles <rd> (for cvtdq2ps, cvtpi2ps)
simple_fp_convop_ra cvtf_i2s_p cvtdq2ps
# {"cvtf.i2d.lo",    OPCLASS_FP_ALU,        F, ANYFPU}, // low W32s in <ra> to double in <rd>, <ra> ignored (for cvtdq2pd part 1, cvtpi2pd part 1, cvtsi2sd)
simple_fp_convop_ra cvtf_i2d_lo cvtdq2pd 0
# {"cvtf.i2d.hi",    OPCLASS_FP_ALU,        F, ANYFPU}, // high W32s in <ra> to double in <rd>, <ra> ignored (for cvtdq2pd part 2, cvtpi2pd part 2)
simple_fp_convop_ra cvtf_i2d_hi cvtdq2pd 1
# {"cvtf.q2s.ins",   OPCLASS_FP_ALU,        F, ANYFPU}, // one W64s <rb> to single, insert into low 32 bits of <ra> (for cvtsi2ss with REX.mode64 prefix)
simple_fp_convop_intsrc cvtf_q2s_ins cvtsi2ss 1
# {"cvtf.q2d",       OPCLASS_FP_ALU,        F, ANYFPU}, // one W64s <rb> to double in <rd>, ignore <ra> (for cvtsi2sd with REX.mode64 prefix)
simple_fp_convop_ra_intsrc cvtf_q2d cvtsi2sd 1
# {"cvtf.s2i",       OPCLASS_FP_ALU,        F, ANYFPU}, // one single <ra> to W32s in <rd> (for cvtss2si, cvttss2si)
simple_fp_convop_intdest cvtf_s2i cvtss2si cvttss2si 0
# {"cvtf.s2q",       OPCLASS_FP_ALU,        F, ANYFPU}, // one single <ra> to W64s in <rd> (for cvtss2si, cvttss2si with REX.mode64 prefix)
simple_fp_convop_intdest cvtf_s2q cvtss2si cvttss2si 1
# {"cvtf.s2i.p",     OPCLASS_FP_ALU,        F, ANYFPU}, // pair of singles in <ra> to pair of W32s in <rd> (for cvtps2pi, cvttps2pi, cvtps2dq, cvttps2dq)
simple_fp_convop_trunctype cvtf_s2i_p cvtps2dq cvttps2dq
# {"cvtf.d2i",       OPCLASS_FP_ALU,        F, ANYFPU}, // one double <ra> to W32s in <rd> (for cvtsd2si, cvttsd2si)
simple_fp_convop_intdest cvtf_d2i cvtsd2si cvttsd2si 0
# {"cvtf.d2q",       OPCLASS_FP_ALU,        F, ANYFPU}, // one double <ra> to W64s in <rd> (for cvtsd2si with REX.mode64 prefix)
simple_fp_convop_intdest cvtf_d2q cvtsd2si cvttsd2si 1
# {"cvtf.d2i.p",     OPCLASS_FP_ALU,        F, ANYFPU}, // pair of doubles in <ra> to pair of W32s in <rd> (for cvtpd2pi, cvttpd2pi, cvtpd2dq, cvttpd2dq), clear high 64 bits of dest xmm
simple_fp_convop_trunctype cvtf_d2i_p cvtpd2dq cvttpd2dq
# {"cvtf.d2s.ins",   OPCLASS_FP_ALU,        F, ANYFPU}, // double in <rb> to single, insert into low 32 bits of <ra> (for cvtsd2ss)
simple_fp_convop_ins cvtf_d2s_ins cvtsd2ss
# {"cvtf.d2s.p",     OPCLASS_FP_ALU,        F, ANYFPU}, // pair of doubles in <ra> (high), <rb> (low) to pair of singles in <rd> (for cvtpd2ps)
simple_fp_convop_collect cvtf_d2s_p cvtpd2ps
# {"cvtf.s2d.lo",    OPCLASS_FP_ALU,        F, ANYFPU}, // low single in <ra> to double in <rd> (for cvtps2pd, part 1, cvtss2sd)
simple_fp_convop_ra cvtf_s2d_lo cvtps2pd 0
# {"cvtf.s2d.hi",    OPCLASS_FP_ALU,        F, ANYFPU}, // high single in <ra> to double in <rd> (for cvtps2pd, part 2)
simple_fp_convop_ra cvtf_s2d_hi cvtps2pd 1

/*
 * uop.size:
 * 00: single precision, scalar (preserve high 32 bits of ra)
 * 01: single precision, packed (two 32-bit floats)
 * 1x: double precision, scalar or packed (use two uops to process 128-bit xmm)
 */

.macro generate_fp_aluop_alltype PTOPCODE OP1 OP2 OP3 OP4
grouplabel \PTOPCODE
  generate_fp_aluop \PTOPCODE \OP1 0
  generate_fp_aluop \PTOPCODE \OP2 1
  generate_fp_aluop \PTOPCODE \OP3 2
  generate_fp_aluop \PTOPCODE \OP4 3
.endm

generate_fp_aluop_alltype addf addss addps addsd addsd
generate_fp_aluop_alltype subf subss subps subsd subsd
generate_fp_aluop_alltype mulf mulss mulps mulsd mulsd
generate_fp_aluop_alltype divf divss divps divsd divsd
generate_fp_aluop_alltype sqrtf sqrtss sqrtps sqrtsd sqrtsd
generate_fp_aluop_alltype minf minss minps minsd minsd
generate_fp_aluop_alltype maxf maxss maxps maxsd maxsd
generate_fp_aluop_alltype rsqrtf rsqrtss rsqrtps fpinvalid fpinvalid
generate_fp_aluop_alltype rcpf rcpss rcpps fpinvalid fpinvalid

.macro generate_fp_mac_aluop PTOPCODE OPCODE1 OPCODE2 SIZECODE
som \PTOPCODE\SIZECODE
  movd    %xmm0,%rax
  movd    %xmm1,%rbx
  movd    %xmm2,%rcx
  \OPCODE1 %xmm0,%xmm1
  \OPCODE2 %xmm0,%xmm2
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     \PTOPCODE\SIZECODE
.endm

grouplabel maddf
  generate_fp_mac_aluop maddf mulss addss 0
  generate_fp_mac_aluop maddf mulps addps 1
  generate_fp_mac_aluop maddf mulsd addsd 2
  generate_fp_mac_aluop maddf mulsd addsd 3

grouplabel msubf
  generate_fp_mac_aluop msubf mulss subss 0
  generate_fp_mac_aluop msubf mulps subps 1
  generate_fp_mac_aluop msubf mulsd subsd 2
  generate_fp_mac_aluop msubf mulsd subsd 3

grouplabel addaf
  generate_fp_mac_aluop addaf addss addss 0
  generate_fp_mac_aluop addaf addps addps 1
  generate_fp_mac_aluop addaf addsd addsd 2
  generate_fp_mac_aluop addaf addsd addsd 3

grouplabel addsf
  generate_fp_mac_aluop addsf addss subss 0
  generate_fp_mac_aluop addsf addps subps 1
  generate_fp_mac_aluop addsf addsd subsd 2
  generate_fp_mac_aluop addsf addsd subsd 3

grouplabel subaf
  generate_fp_mac_aluop subaf subss addss 0
  generate_fp_mac_aluop subaf subps addps 1
  generate_fp_mac_aluop subaf subsd addsd 2
  generate_fp_mac_aluop subaf subsd addsd 3

grouplabel subsf
  generate_fp_mac_aluop subsf subss subss 0
  generate_fp_mac_aluop subsf subps subps 1
  generate_fp_mac_aluop subsf subsd subsd 2
  generate_fp_mac_aluop subsf subsd subsd 3

#
# Compares are special because they require rc to be an imm8
# specifying the type of comparison. We cannot easily encode
# this in a preformed template, so just use a jump table for
# this case (assumed to be hopefully somewhat rare):
#
.macro generate_fp_cmp PTOPCODE OPCODE SIZECODE COND
som \PTOPCODE\SIZECODE\COND
  movd    %xmm0,%rax
  movd    %xmm1,%rbx
  \OPCODE %xmm0,%xmm1,\COND
  movq    qword ptr [IssueState_rddata],%xmm0
  mov     word ptr [IssueState_rdflags],0 # Don't set flags in this variant
  eom     \PTOPCODE\SIZECODE\COND
.endm

.macro generate_fp_cmp_allconds OPCODE SIZECODE
  generate_fp_cmp cmpf \OPCODE \SIZECODE 0
  generate_fp_cmp cmpf \OPCODE \SIZECODE 1
  generate_fp_cmp cmpf \OPCODE \SIZECODE 2
  generate_fp_cmp cmpf \OPCODE \SIZECODE 3
  generate_fp_cmp cmpf \OPCODE \SIZECODE 4
  generate_fp_cmp cmpf \OPCODE \SIZECODE 5
  generate_fp_cmp cmpf \OPCODE \SIZECODE 6
  generate_fp_cmp cmpf \OPCODE \SIZECODE 7
.endm

grouplabel cmpf
  generate_fp_cmp_allconds cmpss 0
  generate_fp_cmp_allconds cmpps 1
  generate_fp_cmp_allconds cmpsd 2
  generate_fp_cmp_allconds cmppd 3

.macro generate_cmpccf OPCODE SIZECODE
som cmpccf\SIZECODE
  movd    %xmm0,%rax
  movd    %xmm1,%rbx
  xor     %eax,%eax
  xor     %ebx,%ebx
  xor     %ecx,%ecx
  \OPCODE %xmm0,%xmm1
/*
 * comisX and ucomisX set {zf pf cf} according to the comparison,
 * and always set {of sf af} to zero.
 * 
 * Flags format: OF - - - SF ZF - AF - PF - CF
 *               11       7  6    4    2    0
 *               rb       ra ra   ra   ra   rb
 */
  setc    %al         # %al = CF
  setp    %bl         # %bl = PF
  setz    %cl         # %cl = ZF
  shl     %bl,2       # Get PF into bit 2
  shl     %cl,6       # Get ZF into bit 6
  or      %al,%bl     # CF|PF
  or      %al,%cl     # CF|PF|ZF
  movq    [IssueState_rddata],%rax
  mov     [IssueState_rdflags],%ax
  eom     fcmpcc\SIZECODE
.endm

grouplabel cmpccf
  generate_cmpccf comiss  0
  generate_cmpccf ucomiss 1
  generate_cmpccf comisd  2
  generate_cmpccf ucomisd 3

#
# Simple assists which can directly use the x86 insns to get perfectly preserve native semantics:
#

#define assistarg (REG_sr2 * 8)

#define rctx r8
 
.macro assist NAME
.global assist_\NAME
assist_\NAME:
  lea     %rctx,[ctx]
.endm

.macro assistret
  # Copy rip following assisted insn into return rip 
  mov     %r10,[%rctx + 8*REG_sr1]
  mov     [%rctx + 8*REG_rip],%r10
  ret
.endm

#
# See x86-64 spec (abi.pdf) page 21 for register conventions
# Usable by us: %rax, %rcx, %rdx, %rsi, %rdi, %r8-%r11
# Must preserve %r12-%r15, %rsp, %rbp, %rbx
#

.macro generate_muldiv insn op8 op16 op32 op64

assist \op8
  # Input:  A in %ax, B in sr2
  # Output: (A%B):(A/B) in %ah:%al
  pushw   [%rctx + 8*REG_flags]
  popfw
  mov     %rax,[%rctx + 8*REG_rax]
  mov     %r10,[%rctx + 8*REG_sr2]
  \insn   %r10b
  mov     [%rctx + 8*REG_rax],%rax
  pushfw
  popw    %dx
  and     %dx,FLAG_NOT_WAIT_INV
  mov     [%rctx + 8*REG_flags],%dx
  assistret

assist \op16
  # Input:  A in %dx:%ax, B in sr2
  # Output: (A%B):(A/B) in %dx:%ax
  pushw   [%rctx + 8*REG_flags]
  popfw
  mov     %rdx,[%rctx + 8*REG_rdx]
  mov     %rax,[%rctx + 8*REG_rax]
  mov     %r10,[%rctx + 8*REG_sr2]
  \insn   %r10w
  mov     [%rctx + 8*REG_rdx],%rdx
  mov     [%rctx + 8*REG_rax],%rax
  pushfw
  popw    %dx
  and     %dx,FLAG_NOT_WAIT_INV
  mov     [%rctx + 8*REG_flags],%dx
  assistret

assist \op32
  # Input:  A in %edx:%eax, B in sr2
  # Output: (A%B):(A/B) in %edx:%eax
  pushw   [%rctx + 8*REG_flags]
  popfw
  mov     %rdx,[%rctx + 8*REG_rdx]
  mov     %rax,[%rctx + 8*REG_rax]
  mov     %r10,[%rctx + 8*REG_sr2]
  \insn   %r10d
  mov     [%rctx + 8*REG_rdx],%rdx
  mov     [%rctx + 8*REG_rax],%rax
  pushfw
  popw    %dx
  and     %dx,FLAG_NOT_WAIT_INV
  mov     [%rctx + 8*REG_flags],%dx
  assistret

assist \op64
  # Input:  A in %rdx:%rax, B in sr2
  # Output: (A%B):(A/B) in %rdx:%rax
  pushw   [%rctx + 8*REG_flags]
  popfw
  mov     %rdx,[%rctx + 8*REG_rdx]
  mov     %rax,[%rctx + 8*REG_rax]
  mov     %r10,[%rctx + 8*REG_sr2]
  \insn   %r10
  mov     [%rctx + 8*REG_rdx],%rdx
  mov     [%rctx + 8*REG_rax],%rax
  pushfw
  popw    %dx
  and     %dx,FLAG_NOT_WAIT_INV
  mov     [%rctx + 8*REG_flags],%dx
  assistret
.endm


# Generate templates for mul imul div idiv

  generate_muldiv mul mul8 mul16 mul32 mul64
  generate_muldiv imul imul8 imul16 imul32 imul64
  generate_muldiv div div8 div16 div32 div64
  generate_muldiv idiv idiv8 idiv16 idiv32 idiv64

grouplabel prepush
somnp prepush 
  push %rbx
  push %rbp
  push %r12
  push %r13
  push %r14
  push %r15
  eomnp prepush

grouplabel postpop
somnp postpop
  pop  %r15
  pop  %r14
  pop  %r13
  pop  %r12
  pop  %rbp
  pop  %rbx
  ret
  eomnp postpop

/*

See x86-64 spec (abi-0.92.pdf) page 21 for register conventions: 

  Callee must preserve: rbx rsp rbp r12 r13 r14 r15
  Args passed in:       rdi rsi rdx rcx r8 r9
  Available:            rax r10 r11

Execute functions need: 

  %rstate      rsi
  %rdest       rax
  %rra         rax
  %rrb         rbx
  %rrc         rcx
  %rraflags    r15
  %rrbflags    r13
  %rrcflags    r9
  %rsfra       r11
  %rlsi        r8

Not currently used anywhere: 

  r12 r14

Note: if we want to eventually convert PTLsim to 32-bit x86, it would be better to
just copy things to a structure in memory rather than on the stack: 

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

NOTE: 
  regparm (number) 
  On the Intel 386, the regparm attribute causes the compiler to pass up to number integer arguments in registers EAX, EDX, and ECX instead of on the stack. Functions that take a variable number of arguments will continue to be passed all of their arguments on the stack.

*/

#define rinput                rdi
#define rfunc                 rdx

#define IssueInput_ra         %rinput+0
#define IssueInput_rb         %rinput+8
#define IssueInput_rc         %rinput+16
#define IssueInput_raflags    %rinput+24
#define IssueInput_rbflags    %rinput+26
#define IssueInput_rcflags    %rinput+28

# void call_exec_func(const IssueInput& input, IssueState& output, void* func);         //W64 ra, W64 rb, W64 rc, W64 raflags, W64 rbflags, W64 rcflags)
.globl call_exec_func
call_exec_func:
  push      %rbx
  push      %r13
  push      %r15
  push      %rbp

  mov       %rax,[IssueInput_ra]
  mov       %rbx,[IssueInput_rb]
  mov       %rcx,[IssueInput_rc]
  movzx     %rraflags,word ptr [IssueInput_raflags]
  movzx     %rrbflags,word ptr [IssueInput_rbflags]
  movzx     %rrcflags,word ptr [IssueInput_rcflags]
  clc
  call      %rfunc
  pop       %rbp
  pop       %r15
  pop       %r13
  pop       %rbx
  ret

.end

