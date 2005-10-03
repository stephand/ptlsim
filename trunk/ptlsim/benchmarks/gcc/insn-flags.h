/* Generated automatically by the program `genflags'
from the machine description file `md'.  */

#define HAVE_m88k_rcs_id 1
#define HAVE_test 1
#define HAVE_cmpsi 1
#define HAVE_cmpsf 1
#define HAVE_cmpdf 1
#define HAVE_seq 1
#define HAVE_sne 1
#define HAVE_sgt 1
#define HAVE_sgtu 1
#define HAVE_slt 1
#define HAVE_sltu 1
#define HAVE_sge 1
#define HAVE_sgeu 1
#define HAVE_sle 1
#define HAVE_sleu 1
#define HAVE_bcnd 1
#define HAVE_bxx 1
#define HAVE_beq 1
#define HAVE_bne 1
#define HAVE_bgt 1
#define HAVE_bgtu 1
#define HAVE_blt 1
#define HAVE_bltu 1
#define HAVE_bge 1
#define HAVE_bgeu 1
#define HAVE_ble 1
#define HAVE_bleu 1
#define HAVE_locate1 1
#define HAVE_locate2 1
#define HAVE_movsi 1
#define HAVE_reload_insi 1
#define HAVE_movhi 1
#define HAVE_movqi 1
#define HAVE_movdi 1
#define HAVE_movdf 1
#define HAVE_movsf 1
#define HAVE_movstrsi 1
#define HAVE_call_block_move 1
#define HAVE_call_movstrsi_loop 1
#define HAVE_zero_extendhisi2 1
#define HAVE_zero_extendqihi2 1
#define HAVE_zero_extendqisi2 1
#define HAVE_extendsidi2 1
#define HAVE_extendhisi2 1
#define HAVE_extendqihi2 1
#define HAVE_extendqisi2 1
#define HAVE_extendsfdf2 1
#define HAVE_truncdfsf2 1
#define HAVE_floatsidf2 1
#define HAVE_floatsisf2 1
#define HAVE_fix_truncdfsi2 1
#define HAVE_fix_truncsfsi2 1
#define HAVE_addsi3 1
#define HAVE_adddf3 1
#define HAVE_addsf3 1
#define HAVE_adddi3 1
#define HAVE_subsi3 1
#define HAVE_subdf3 1
#define HAVE_subsf3 1
#define HAVE_subdi3 1
#define HAVE_mulsi3 1
#define HAVE_muldf3 1
#define HAVE_mulsf3 1
#define HAVE_trap_divide_by_zero 1
#define HAVE_tcnd_divide_by_zero 1
#define HAVE_divsi3 1
#define HAVE_udivsi3 1
#define HAVE_divdf3 1
#define HAVE_divsf3 1
#define HAVE_andsi3 1
#define HAVE_anddi3 1
#define HAVE_iorsi3 1
#define HAVE_iordi3 1
#define HAVE_xorsi3 1
#define HAVE_xordi3 1
#define HAVE_one_cmplsi2 1
#define HAVE_one_cmpldi2 1
#define HAVE_tbnd 1
#define HAVE_ashlsi3 1
#define HAVE_ashrsi3 1
#define HAVE_lshrsi3 1
#define HAVE_rotlsi3 1
#define HAVE_rotrsi3 1
#define HAVE_ffssi2 1
#define HAVE_extv 1
#define HAVE_extzv 1
#define HAVE_negsi2 1
#define HAVE_negdf2 1
#define HAVE_negsf2 1
#define HAVE_absdf2 1
#define HAVE_abssf2 1
#define HAVE_casesi 1
#define HAVE_casesi_jump 1
#define HAVE_casesi_enter 1
#define HAVE_call 1
#define HAVE_call_value 1
#define HAVE_nop 1
#define HAVE_return (reload_completed)
#define HAVE_prologue 1
#define HAVE_epilogue (! null_prologue ())
#define HAVE_blockage 1
#define HAVE_indirect_jump 1
#define HAVE_jump 1
#define HAVE_decrement_and_branch_until_zero (find_reg_note (insn, REG_NONNEG, 0))
#define HAVE_dummy 1

#ifndef NO_MD_PROTOTYPES
extern rtx gen_m88k_rcs_id                     PROTO((rtx));
extern rtx gen_test                            PROTO((rtx, rtx));
extern rtx gen_cmpsi                           PROTO((rtx, rtx));
extern rtx gen_cmpsf                           PROTO((rtx, rtx));
extern rtx gen_cmpdf                           PROTO((rtx, rtx));
extern rtx gen_seq                             PROTO((rtx));
extern rtx gen_sne                             PROTO((rtx));
extern rtx gen_sgt                             PROTO((rtx));
extern rtx gen_sgtu                            PROTO((rtx));
extern rtx gen_slt                             PROTO((rtx));
extern rtx gen_sltu                            PROTO((rtx));
extern rtx gen_sge                             PROTO((rtx));
extern rtx gen_sgeu                            PROTO((rtx));
extern rtx gen_sle                             PROTO((rtx));
extern rtx gen_sleu                            PROTO((rtx));
extern rtx gen_bcnd                            PROTO((rtx, rtx));
extern rtx gen_bxx                             PROTO((rtx, rtx));
extern rtx gen_beq                             PROTO((rtx));
extern rtx gen_bne                             PROTO((rtx));
extern rtx gen_bgt                             PROTO((rtx));
extern rtx gen_bgtu                            PROTO((rtx));
extern rtx gen_blt                             PROTO((rtx));
extern rtx gen_bltu                            PROTO((rtx));
extern rtx gen_bge                             PROTO((rtx));
extern rtx gen_bgeu                            PROTO((rtx));
extern rtx gen_ble                             PROTO((rtx));
extern rtx gen_bleu                            PROTO((rtx));
extern rtx gen_locate1                         PROTO((rtx, rtx));
extern rtx gen_locate2                         PROTO((rtx, rtx));
extern rtx gen_movsi                           PROTO((rtx, rtx));
extern rtx gen_reload_insi                     PROTO((rtx, rtx, rtx));
extern rtx gen_movhi                           PROTO((rtx, rtx));
extern rtx gen_movqi                           PROTO((rtx, rtx));
extern rtx gen_movdi                           PROTO((rtx, rtx));
extern rtx gen_movdf                           PROTO((rtx, rtx));
extern rtx gen_movsf                           PROTO((rtx, rtx));
extern rtx gen_movstrsi                        PROTO((rtx, rtx, rtx, rtx));
extern rtx gen_call_block_move                 PROTO((rtx, rtx, rtx, rtx, rtx, rtx));
extern rtx gen_call_movstrsi_loop              PROTO((rtx, rtx, rtx, rtx, rtx, rtx, rtx));
extern rtx gen_zero_extendhisi2                PROTO((rtx, rtx));
extern rtx gen_zero_extendqihi2                PROTO((rtx, rtx));
extern rtx gen_zero_extendqisi2                PROTO((rtx, rtx));
extern rtx gen_extendsidi2                     PROTO((rtx, rtx));
extern rtx gen_extendhisi2                     PROTO((rtx, rtx));
extern rtx gen_extendqihi2                     PROTO((rtx, rtx));
extern rtx gen_extendqisi2                     PROTO((rtx, rtx));
extern rtx gen_extendsfdf2                     PROTO((rtx, rtx));
extern rtx gen_truncdfsf2                      PROTO((rtx, rtx));
extern rtx gen_floatsidf2                      PROTO((rtx, rtx));
extern rtx gen_floatsisf2                      PROTO((rtx, rtx));
extern rtx gen_fix_truncdfsi2                  PROTO((rtx, rtx));
extern rtx gen_fix_truncsfsi2                  PROTO((rtx, rtx));
extern rtx gen_addsi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_adddf3                          PROTO((rtx, rtx, rtx));
extern rtx gen_addsf3                          PROTO((rtx, rtx, rtx));
extern rtx gen_adddi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_subsi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_subdf3                          PROTO((rtx, rtx, rtx));
extern rtx gen_subsf3                          PROTO((rtx, rtx, rtx));
extern rtx gen_subdi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_mulsi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_muldf3                          PROTO((rtx, rtx, rtx));
extern rtx gen_mulsf3                          PROTO((rtx, rtx, rtx));
extern rtx gen_trap_divide_by_zero             PROTO((void));
extern rtx gen_tcnd_divide_by_zero             PROTO((rtx, rtx));
extern rtx gen_divsi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_udivsi3                         PROTO((rtx, rtx, rtx));
extern rtx gen_divdf3                          PROTO((rtx, rtx, rtx));
extern rtx gen_divsf3                          PROTO((rtx, rtx, rtx));
extern rtx gen_andsi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_anddi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_iorsi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_iordi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_xorsi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_xordi3                          PROTO((rtx, rtx, rtx));
extern rtx gen_one_cmplsi2                     PROTO((rtx, rtx));
extern rtx gen_one_cmpldi2                     PROTO((rtx, rtx));
extern rtx gen_tbnd                            PROTO((rtx, rtx));
extern rtx gen_ashlsi3                         PROTO((rtx, rtx, rtx));
extern rtx gen_ashrsi3                         PROTO((rtx, rtx, rtx));
extern rtx gen_lshrsi3                         PROTO((rtx, rtx, rtx));
extern rtx gen_rotlsi3                         PROTO((rtx, rtx, rtx));
extern rtx gen_rotrsi3                         PROTO((rtx, rtx, rtx));
extern rtx gen_ffssi2                          PROTO((rtx, rtx));
extern rtx gen_extv                            PROTO((rtx, rtx, rtx, rtx));
extern rtx gen_extzv                           PROTO((rtx, rtx, rtx, rtx));
extern rtx gen_negsi2                          PROTO((rtx, rtx));
extern rtx gen_negdf2                          PROTO((rtx, rtx));
extern rtx gen_negsf2                          PROTO((rtx, rtx));
extern rtx gen_absdf2                          PROTO((rtx, rtx));
extern rtx gen_abssf2                          PROTO((rtx, rtx));
extern rtx gen_casesi                          PROTO((rtx, rtx, rtx, rtx, rtx));
extern rtx gen_casesi_jump                     PROTO((rtx, rtx, rtx, rtx));
extern rtx gen_casesi_enter                    PROTO((rtx, rtx, rtx));
extern rtx gen_nop                             PROTO((void));
extern rtx gen_return                          PROTO((void));
extern rtx gen_prologue                        PROTO((void));
extern rtx gen_epilogue                        PROTO((void));
extern rtx gen_blockage                        PROTO((void));
extern rtx gen_indirect_jump                   PROTO((rtx));
extern rtx gen_jump                            PROTO((rtx));
extern rtx gen_decrement_and_branch_until_zero PROTO((rtx, rtx, rtx, rtx));
extern rtx gen_dummy                           PROTO((rtx));

#ifdef MD_CALL_PROTOTYPES
extern rtx gen_call                            PROTO((rtx, rtx));
extern rtx gen_call_value                      PROTO((rtx, rtx, rtx));

#else /* !MD_CALL_PROTOTYPES */
extern rtx gen_call ();
extern rtx gen_call_value ();
#endif /* !MD_CALL_PROTOTYPES */

#else  /* NO_MD_PROTOTYPES */
extern rtx gen_m88k_rcs_id ();
extern rtx gen_test ();
extern rtx gen_cmpsi ();
extern rtx gen_cmpsf ();
extern rtx gen_cmpdf ();
extern rtx gen_seq ();
extern rtx gen_sne ();
extern rtx gen_sgt ();
extern rtx gen_sgtu ();
extern rtx gen_slt ();
extern rtx gen_sltu ();
extern rtx gen_sge ();
extern rtx gen_sgeu ();
extern rtx gen_sle ();
extern rtx gen_sleu ();
extern rtx gen_bcnd ();
extern rtx gen_bxx ();
extern rtx gen_beq ();
extern rtx gen_bne ();
extern rtx gen_bgt ();
extern rtx gen_bgtu ();
extern rtx gen_blt ();
extern rtx gen_bltu ();
extern rtx gen_bge ();
extern rtx gen_bgeu ();
extern rtx gen_ble ();
extern rtx gen_bleu ();
extern rtx gen_locate1 ();
extern rtx gen_locate2 ();
extern rtx gen_movsi ();
extern rtx gen_reload_insi ();
extern rtx gen_movhi ();
extern rtx gen_movqi ();
extern rtx gen_movdi ();
extern rtx gen_movdf ();
extern rtx gen_movsf ();
extern rtx gen_movstrsi ();
extern rtx gen_call_block_move ();
extern rtx gen_call_movstrsi_loop ();
extern rtx gen_zero_extendhisi2 ();
extern rtx gen_zero_extendqihi2 ();
extern rtx gen_zero_extendqisi2 ();
extern rtx gen_extendsidi2 ();
extern rtx gen_extendhisi2 ();
extern rtx gen_extendqihi2 ();
extern rtx gen_extendqisi2 ();
extern rtx gen_extendsfdf2 ();
extern rtx gen_truncdfsf2 ();
extern rtx gen_floatsidf2 ();
extern rtx gen_floatsisf2 ();
extern rtx gen_fix_truncdfsi2 ();
extern rtx gen_fix_truncsfsi2 ();
extern rtx gen_addsi3 ();
extern rtx gen_adddf3 ();
extern rtx gen_addsf3 ();
extern rtx gen_adddi3 ();
extern rtx gen_subsi3 ();
extern rtx gen_subdf3 ();
extern rtx gen_subsf3 ();
extern rtx gen_subdi3 ();
extern rtx gen_mulsi3 ();
extern rtx gen_muldf3 ();
extern rtx gen_mulsf3 ();
extern rtx gen_trap_divide_by_zero ();
extern rtx gen_tcnd_divide_by_zero ();
extern rtx gen_divsi3 ();
extern rtx gen_udivsi3 ();
extern rtx gen_divdf3 ();
extern rtx gen_divsf3 ();
extern rtx gen_andsi3 ();
extern rtx gen_anddi3 ();
extern rtx gen_iorsi3 ();
extern rtx gen_iordi3 ();
extern rtx gen_xorsi3 ();
extern rtx gen_xordi3 ();
extern rtx gen_one_cmplsi2 ();
extern rtx gen_one_cmpldi2 ();
extern rtx gen_tbnd ();
extern rtx gen_ashlsi3 ();
extern rtx gen_ashrsi3 ();
extern rtx gen_lshrsi3 ();
extern rtx gen_rotlsi3 ();
extern rtx gen_rotrsi3 ();
extern rtx gen_ffssi2 ();
extern rtx gen_extv ();
extern rtx gen_extzv ();
extern rtx gen_negsi2 ();
extern rtx gen_negdf2 ();
extern rtx gen_negsf2 ();
extern rtx gen_absdf2 ();
extern rtx gen_abssf2 ();
extern rtx gen_casesi ();
extern rtx gen_casesi_jump ();
extern rtx gen_casesi_enter ();
extern rtx gen_nop ();
extern rtx gen_return ();
extern rtx gen_prologue ();
extern rtx gen_epilogue ();
extern rtx gen_blockage ();
extern rtx gen_indirect_jump ();
extern rtx gen_jump ();
extern rtx gen_decrement_and_branch_until_zero ();
extern rtx gen_dummy ();
extern rtx gen_call ();
extern rtx gen_call_value ();
#endif  /* NO_MD_PROTOTYPES */
