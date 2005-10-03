/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * 32-bit low level functions
 *
 * Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
 */

.text
.intel_syntax

.global inside_sim_escape_code_template_32bit
.global inside_sim_escape_code_template_32bit_end

inside_sim_escape_code_template_32bit:
# Pass args in registers: rdi rsi rdx rcx r8 r9
  push    %edi
  push    %esi
  push    %edx
  push    %ecx

  mov     %edi,[%esp+(4+1+0)*4]
  mov     %esi,[%esp+(4+1+1)*4]
  mov     %edx,[%esp+(4+1+2)*4]
  mov     %ecx,[%esp+(4+1+3)*4]

  # Undocumented x86 escape opcode to do PTL calls
  .byte 0x0f
  .byte 0x37

  pop     %ecx
  pop     %edx
  pop     %esi
  pop     %edi
  ret
inside_sim_escape_code_template_32bit_end:

.end
