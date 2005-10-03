/* Generated automatically by the program `genopinit'
from the machine description file `md'.  */

#include "config.h"
#include "rtl.h"
#include "flags.h"
#include "insn-flags.h"
#include "insn-codes.h"
#include "insn-config.h"
#include "recog.h"
#include "expr.h"
#include "reload.h"

void
init_all_optabs ()
{
  cmp_optab->handlers[(int) SImode].insn_code = CODE_FOR_cmpsi;
  cmp_optab->handlers[(int) SFmode].insn_code = CODE_FOR_cmpsf;
  cmp_optab->handlers[(int) DFmode].insn_code = CODE_FOR_cmpdf;
  setcc_gen_code[(int) EQ] = CODE_FOR_seq;
  setcc_gen_code[(int) NE] = CODE_FOR_sne;
  setcc_gen_code[(int) GT] = CODE_FOR_sgt;
  setcc_gen_code[(int) GTU] = CODE_FOR_sgtu;
  setcc_gen_code[(int) LT] = CODE_FOR_slt;
  setcc_gen_code[(int) LTU] = CODE_FOR_sltu;
  setcc_gen_code[(int) GE] = CODE_FOR_sge;
  setcc_gen_code[(int) GEU] = CODE_FOR_sgeu;
  setcc_gen_code[(int) LE] = CODE_FOR_sle;
  setcc_gen_code[(int) LEU] = CODE_FOR_sleu;
  bcc_gen_fctn[(int) EQ] = gen_beq;
  bcc_gen_fctn[(int) NE] = gen_bne;
  bcc_gen_fctn[(int) GT] = gen_bgt;
  bcc_gen_fctn[(int) GTU] = gen_bgtu;
  bcc_gen_fctn[(int) LT] = gen_blt;
  bcc_gen_fctn[(int) LTU] = gen_bltu;
  bcc_gen_fctn[(int) GE] = gen_bge;
  bcc_gen_fctn[(int) GEU] = gen_bgeu;
  bcc_gen_fctn[(int) LE] = gen_ble;
  bcc_gen_fctn[(int) LEU] = gen_bleu;
  mov_optab->handlers[(int) SImode].insn_code = CODE_FOR_movsi;
  reload_in_optab[(int) SImode] = CODE_FOR_reload_insi;
  mov_optab->handlers[(int) HImode].insn_code = CODE_FOR_movhi;
  mov_optab->handlers[(int) QImode].insn_code = CODE_FOR_movqi;
  mov_optab->handlers[(int) DImode].insn_code = CODE_FOR_movdi;
  mov_optab->handlers[(int) DFmode].insn_code = CODE_FOR_movdf;
  mov_optab->handlers[(int) SFmode].insn_code = CODE_FOR_movsf;
  movstr_optab[(int) SImode] = CODE_FOR_movstrsi;
  extendtab[(int) SImode][(int) HImode][1] = CODE_FOR_zero_extendhisi2;
  extendtab[(int) HImode][(int) QImode][1] = CODE_FOR_zero_extendqihi2;
  extendtab[(int) SImode][(int) QImode][1] = CODE_FOR_zero_extendqisi2;
  extendtab[(int) DImode][(int) SImode][0] = CODE_FOR_extendsidi2;
  extendtab[(int) SImode][(int) HImode][0] = CODE_FOR_extendhisi2;
  extendtab[(int) HImode][(int) QImode][0] = CODE_FOR_extendqihi2;
  extendtab[(int) SImode][(int) QImode][0] = CODE_FOR_extendqisi2;
  extendtab[(int) DFmode][(int) SFmode][0] = CODE_FOR_extendsfdf2;
  floattab[(int) DFmode][(int) SImode][0] = CODE_FOR_floatsidf2;
  floattab[(int) SFmode][(int) SImode][0] = CODE_FOR_floatsisf2;
  fixtrunctab[(int) DFmode][(int) SImode][0] = CODE_FOR_fix_truncdfsi2;
  fixtrunctab[(int) SFmode][(int) SImode][0] = CODE_FOR_fix_truncsfsi2;
  add_optab->handlers[(int) SImode].insn_code = CODE_FOR_addsi3;
  add_optab->handlers[(int) DFmode].insn_code = CODE_FOR_adddf3;
  add_optab->handlers[(int) SFmode].insn_code = CODE_FOR_addsf3;
  add_optab->handlers[(int) DImode].insn_code = CODE_FOR_adddi3;
  sub_optab->handlers[(int) SImode].insn_code = CODE_FOR_subsi3;
  sub_optab->handlers[(int) DFmode].insn_code = CODE_FOR_subdf3;
  sub_optab->handlers[(int) SFmode].insn_code = CODE_FOR_subsf3;
  sub_optab->handlers[(int) DImode].insn_code = CODE_FOR_subdi3;
  smul_optab->handlers[(int) SImode].insn_code = CODE_FOR_mulsi3;
  smul_optab->handlers[(int) DFmode].insn_code = CODE_FOR_muldf3;
  smul_optab->handlers[(int) SFmode].insn_code = CODE_FOR_mulsf3;
  sdiv_optab->handlers[(int) SImode].insn_code = CODE_FOR_divsi3;
  udiv_optab->handlers[(int) SImode].insn_code = CODE_FOR_udivsi3;
  flodiv_optab->handlers[(int) DFmode].insn_code = CODE_FOR_divdf3;
  flodiv_optab->handlers[(int) SFmode].insn_code = CODE_FOR_divsf3;
  and_optab->handlers[(int) SImode].insn_code = CODE_FOR_andsi3;
  and_optab->handlers[(int) DImode].insn_code = CODE_FOR_anddi3;
  ior_optab->handlers[(int) SImode].insn_code = CODE_FOR_iorsi3;
  ior_optab->handlers[(int) DImode].insn_code = CODE_FOR_iordi3;
  xor_optab->handlers[(int) SImode].insn_code = CODE_FOR_xorsi3;
  xor_optab->handlers[(int) DImode].insn_code = CODE_FOR_xordi3;
  one_cmpl_optab->handlers[(int) SImode].insn_code = CODE_FOR_one_cmplsi2;
  one_cmpl_optab->handlers[(int) DImode].insn_code = CODE_FOR_one_cmpldi2;
  ashl_optab->handlers[(int) SImode].insn_code = CODE_FOR_ashlsi3;
  ashr_optab->handlers[(int) SImode].insn_code = CODE_FOR_ashrsi3;
  lshr_optab->handlers[(int) SImode].insn_code = CODE_FOR_lshrsi3;
  rotl_optab->handlers[(int) SImode].insn_code = CODE_FOR_rotlsi3;
  rotr_optab->handlers[(int) SImode].insn_code = CODE_FOR_rotrsi3;
  ffs_optab->handlers[(int) SImode].insn_code = CODE_FOR_ffssi2;
  neg_optab->handlers[(int) SImode].insn_code = CODE_FOR_negsi2;
  neg_optab->handlers[(int) DFmode].insn_code = CODE_FOR_negdf2;
  neg_optab->handlers[(int) SFmode].insn_code = CODE_FOR_negsf2;
  abs_optab->handlers[(int) DFmode].insn_code = CODE_FOR_absdf2;
  abs_optab->handlers[(int) SFmode].insn_code = CODE_FOR_abssf2;
}
