/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * 64-bit low level functions
 *
 * Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
 */

.text
.intel_syntax

#define __ASM_ONLY__
#include <ptlhwdef.h>

.extern ctx

.extern ptlsim_init
.extern _start

.global ptlsim_preinit_entry
ptlsim_preinit_entry:
  #
  # We may be a 64-bit process running in a 32-bit address space,
  # which means argv, argc, etc. will be in 32-bit format and need
  # to be converted before any initialization routines.
  #
  mov   %rdi,%rsp            # origrsp
  mov   %rsi,offset _start   # next_init_func
  call  ptlsim_preinit
  mov   %rsp,%rax            # update to new stack pointer
  jmp   _start

/*
 * struct ThreadState {
 *   ThreadState* self;
 *   void* stack;
 *   ...
 * };
 */

#define ThreadState_self                              8*0
#define ThreadState_rsp                               8*1
#define ThreadState_simcall                           8*2

.extern ctx
.extern save_context_switch_to_sim
.extern x87state
.extern basetls
.extern fsreg
.extern gsreg

.global save_context_switch_to_sim_lowlevel
save_context_switch_to_sim_lowlevel:
  mov      [ctx + 8*REG_rax + 8*0],%rax
  mov      [ctx + 8*REG_rax + 8*1],%rcx
  mov      [ctx + 8*REG_rax + 8*2],%rdx
  mov      [ctx + 8*REG_rax + 8*3],%rbx
  mov      [ctx + 8*REG_rax + 8*4],%rsp
  mov      [ctx + 8*REG_rax + 8*5],%rbp
  mov      [ctx + 8*REG_rax + 8*6],%rsi
  mov      [ctx + 8*REG_rax + 8*7],%rdi
  mov      [ctx + 8*REG_rax + 8*8],%r8
  mov      [ctx + 8*REG_rax + 8*9],%r9
  mov      [ctx + 8*REG_rax + 8*10],%r10
  mov      [ctx + 8*REG_rax + 8*11],%r11
  mov      [ctx + 8*REG_rax + 8*12],%r12
  mov      [ctx + 8*REG_rax + 8*13],%r13
  mov      [ctx + 8*REG_rax + 8*14],%r14
  mov      [ctx + 8*REG_rax + 8*15],%r15

  mov      %rax,[%rsp]                           # Get return %rip (if we got here through a CALL insn)
  mov      [ctx + 8*REG_rip],%rax                # Save %rip
  mov      %rsp,[basetls + ThreadState_rsp]      # Switch to private thread stack
  and      %rsp,-16
  pushfq                                         # Save rflags
  pop      qword ptr [ctx + 8*REG_flags + 8]     # Put flags into structure

  # SSE registers
  movlpd   [ctx + 8*REG_xmml0],%xmm0
  movlpd   [ctx + 8*REG_xmml1],%xmm1
  movlpd   [ctx + 8*REG_xmml2],%xmm2
  movlpd   [ctx + 8*REG_xmml3],%xmm3
  movlpd   [ctx + 8*REG_xmml4],%xmm4
  movlpd   [ctx + 8*REG_xmml5],%xmm5
  movlpd   [ctx + 8*REG_xmml6],%xmm6
  movlpd   [ctx + 8*REG_xmml7],%xmm7
  movlpd   [ctx + 8*REG_xmml8],%xmm8
  movlpd   [ctx + 8*REG_xmml9],%xmm9
  movlpd   [ctx + 8*REG_xmml10],%xmm10
  movlpd   [ctx + 8*REG_xmml11],%xmm11
  movlpd   [ctx + 8*REG_xmml12],%xmm12
  movlpd   [ctx + 8*REG_xmml13],%xmm13
  movlpd   [ctx + 8*REG_xmml14],%xmm14
  movlpd   [ctx + 8*REG_xmml15],%xmm15

  movhpd   [ctx + 8*REG_xmmh0],%xmm0
  movhpd   [ctx + 8*REG_xmmh1],%xmm1
  movhpd   [ctx + 8*REG_xmmh2],%xmm2
  movhpd   [ctx + 8*REG_xmmh3],%xmm3
  movhpd   [ctx + 8*REG_xmmh4],%xmm4
  movhpd   [ctx + 8*REG_xmmh5],%xmm5
  movhpd   [ctx + 8*REG_xmmh6],%xmm6
  movhpd   [ctx + 8*REG_xmmh7],%xmm7
  movhpd   [ctx + 8*REG_xmmh8],%xmm8
  movhpd   [ctx + 8*REG_xmmh9],%xmm9
  movhpd   [ctx + 8*REG_xmmh10],%xmm10
  movhpd   [ctx + 8*REG_xmmh11],%xmm11
  movhpd   [ctx + 8*REG_xmmh12],%xmm12
  movhpd   [ctx + 8*REG_xmmh13],%xmm13
  movhpd   [ctx + 8*REG_xmmh14],%xmm14
  movhpd   [ctx + 8*REG_xmmh15],%xmm15

  # a24-a31: REG_rip, REG_flags, REG_fpflags, REG_sseflags, REG_tr0, REG_tr1, REG_tr2, REG_zero
  stmxcsr  [ctx + 8*REG_mxcsr]                   # Save SSE flags

  # Save x87 state
  fsave    x87state

  # (skip tr0/tr1/tr2)
  mov      qword ptr [ctx + 8*REG_zero],0        # Save %zero

  mov      [fsreg],%fs
  mov      [gsreg],%gs

  sub      %rsp,64
  and      %rsp,-16
  call     save_context_switch_to_sim

.data
switch_to_native_restore_context_temp_64_to_64:
  .quad 0

switch_to_native_restore_context_temp_64_to_32:
  .long 0
  .word 0x23   # selector for 32-bit x86 code

switch_to_native_restore_context_temp_64_or_32_func: 
  .quad 0

.previous

# extern "C" void switch_to_native_restore_context_lowlevel(const UserContext& ctx, int switch_64_to_32);
# %rdi = ctx
# %rsi = switch_64_to_32
.global switch_to_native_restore_context_lowlevel
switch_to_native_restore_context_lowlevel:
  # Calling convention:
  # %rdi = pointer to state to restore
  # %rsi = set if switching from 64-bit to 32-bit mode

  frstor   x87state

  mov      %fs,[fsreg]
  mov      %gs,[gsreg]

  mov      %rcx,offset switch_to_native_restore_context_64_to_64
  mov      %rdx,offset switch_to_native_restore_context_64_to_32
  test     %rsi,1 # Is user thread 64-bit?
  cmovnz   %rcx,%rdx
  mov      [switch_to_native_restore_context_temp_64_or_32_func],%rcx

  mov      %rax,[%rdi + 8*REG_rip]        # Load %rip
  mov      [switch_to_native_restore_context_temp_64_to_64],%rax  # Save %rip for final jump
  mov      [switch_to_native_restore_context_temp_64_to_32],%eax  # Save %rip for final jump

  lea      %rsp,[%rdi + 8*REG_flags]      # Load address of flags
  popfq                                   # Restore flags
  mov      %rsp,[%rdi + 8*REG_rsp]        # Restore user %rsp; now on user stack

  mov      %rax,[%rdi + 8*REG_rax + 8*0]
  mov      %rcx,[%rdi + 8*REG_rax + 8*1]
  mov      %rdx,[%rdi + 8*REG_rax + 8*2]
  mov      %rbx,[%rdi + 8*REG_rax + 8*3]
# mov      %rsp,[%rdi + 8*REG_rax + 8*4]              # (already done)
  mov      %rbp,[%rdi + 8*REG_rax + 8*5]
  mov      %rsi,[%rdi + 8*REG_rax + 8*6]
# mov      %rdi,[%rdi + 8*REG_rax + 8*7]              # (done at very end)
  mov      %r8,[%rdi + 8*REG_rax + 8*8]
  mov      %r9,[%rdi + 8*REG_rax + 8*9]
  mov      %r10,[%rdi + 8*REG_rax + 8*10]
  mov      %r11,[%rdi + 8*REG_rax + 8*11]
  mov      %r12,[%rdi + 8*REG_rax + 8*12]
  mov      %r13,[%rdi + 8*REG_rax + 8*13]
  mov      %r14,[%rdi + 8*REG_rax + 8*14]
  mov      %r15,[%rdi + 8*REG_rax + 8*15]

  # a24-a31: REG_rip, REG_flags, REG_fpflags, REG_sseflags, REG_tr0, REG_tr1, REG_tr2, REG_zero
# mov      %rip,[%rdi + 8*REG_rip]      # (do later)
# mov      %rflags,[%rdi + 8*REG_flags] # (already done)
# fldsw    [%rdi + 8*REG_mxcsr + 4]     # Restore FP status word     ++MTY FIXME there is a fstsw but no corresponding fldsw
#  fldcw    [%rdi + 8*REG_mxcsr + 6]     # Restore FP control word
  ldmxcsr  [%rdi + 8*REG_mxcsr]         # Restore SSE flags
  # (No need to restore %tr0, %tr1, %tr2, %zero

  movlpd   %xmm0,[%rdi + 8*REG_xmml0]
  movlpd   %xmm1,[%rdi + 8*REG_xmml1]
  movlpd   %xmm2,[%rdi + 8*REG_xmml2]
  movlpd   %xmm3,[%rdi + 8*REG_xmml3]
  movlpd   %xmm4,[%rdi + 8*REG_xmml4]
  movlpd   %xmm5,[%rdi + 8*REG_xmml5]
  movlpd   %xmm6,[%rdi + 8*REG_xmml6]
  movlpd   %xmm7,[%rdi + 8*REG_xmml7]
  movlpd   %xmm8,[%rdi + 8*REG_xmml8]
  movlpd   %xmm9,[%rdi + 8*REG_xmml9]
  movlpd   %xmm10,[%rdi + 8*REG_xmml10]
  movlpd   %xmm11,[%rdi + 8*REG_xmml11]
  movlpd   %xmm12,[%rdi + 8*REG_xmml12]
  movlpd   %xmm13,[%rdi + 8*REG_xmml13]
  movlpd   %xmm14,[%rdi + 8*REG_xmml14]
  movlpd   %xmm15,[%rdi + 8*REG_xmml15]

  movhpd   %xmm0,[%rdi + 8*REG_xmmh0]
  movhpd   %xmm1,[%rdi + 8*REG_xmmh1]
  movhpd   %xmm2,[%rdi + 8*REG_xmmh2]
  movhpd   %xmm3,[%rdi + 8*REG_xmmh3]
  movhpd   %xmm4,[%rdi + 8*REG_xmmh4]
  movhpd   %xmm5,[%rdi + 8*REG_xmmh5]
  movhpd   %xmm6,[%rdi + 8*REG_xmmh6]
  movhpd   %xmm7,[%rdi + 8*REG_xmmh7]
  movhpd   %xmm8,[%rdi + 8*REG_xmmh8]
  movhpd   %xmm9,[%rdi + 8*REG_xmmh9]
  movhpd   %xmm10,[%rdi + 8*REG_xmmh10]
  movhpd   %xmm11,[%rdi + 8*REG_xmmh11]
  movhpd   %xmm12,[%rdi + 8*REG_xmmh12]
  movhpd   %xmm13,[%rdi + 8*REG_xmmh13]
  movhpd   %xmm14,[%rdi + 8*REG_xmmh14]
  movhpd   %xmm15,[%rdi + 8*REG_xmmh15]

  mov      %rdi,[%rdi + 8*REG_rdi]      # Restore %rdi

  jmp      [switch_to_native_restore_context_temp_64_or_32_func]

switch_to_native_restore_context_64_to_32:
  ljmp     [switch_to_native_restore_context_temp_64_to_32]

switch_to_native_restore_context_64_to_64:
  jmp      [switch_to_native_restore_context_temp_64_to_64]


.global inside_sim_escape_code_template_64bit
.global inside_sim_escape_code_template_64bit_end

inside_sim_escape_code_template_64bit:
# Pass args are already in registers: rdi rsi rdx rcx r8 r9
  # Undocumented x86 escape opcode to do PTL calls
  .byte 0x0f
  .byte 0x37
  ret
inside_sim_escape_code_template_64bit_end:

