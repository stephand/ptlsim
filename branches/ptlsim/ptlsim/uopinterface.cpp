//
// PTLsim: Cycle Accurate x86-64 Simulator
// Interface to uop implementations
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>

extern "C" {
  extern const AddrPair templatemap_nop[1];
  extern const AddrPair templatemap_mov[4];
  extern const AddrPair templatemap_and[4][2];
  extern const AddrPair templatemap_or[4][2];
  extern const AddrPair templatemap_xor[4][2];
  extern const AddrPair templatemap_andnot[4][2];
  extern const AddrPair templatemap_ornot[4][2];
  extern const AddrPair templatemap_nand[4][2];
  extern const AddrPair templatemap_nor[4][2];
  extern const AddrPair templatemap_eqv[4][2];
  extern const AddrPair templatemap_add[4][2];
  extern const AddrPair templatemap_sub[4][2];
  extern const AddrPair templatemap_adda[4][4][2];
  extern const AddrPair templatemap_adds[4][4][2];
  extern const AddrPair templatemap_suba[4][4][2];
  extern const AddrPair templatemap_subs[4][4][2];
  extern const AddrPair templatemap_addm[4][2];
  extern const AddrPair templatemap_subm[4][2];
  extern const AddrPair templatemap_addc[4][2];
  extern const AddrPair templatemap_subc[4][2];
  extern const AddrPair templatemap_rotl[4][2];
  extern const AddrPair templatemap_rotr[4][2];
  extern const AddrPair templatemap_rotcl[4][2];
  extern const AddrPair templatemap_rotcr[4][2];
  extern const AddrPair templatemap_shl[4][2];
  extern const AddrPair templatemap_shr[4][2];
  extern const AddrPair templatemap_sar[4][2];
  extern const AddrPair templatemap_mull[4][2];
  extern const AddrPair templatemap_mulh[4][2];
  extern const AddrPair templatemap_bt[4][2];
  extern const AddrPair templatemap_bts[4][2];
  extern const AddrPair templatemap_btr[4][2];
  extern const AddrPair templatemap_btc[4][2];
  extern const AddrPair templatemap_dupbit[4][2];
  extern const AddrPair templatemap_ctz[4][2];
  extern const AddrPair templatemap_clz[4][2];
  extern const AddrPair templatemap_ctpop[4][2];
  extern const AddrPair templatemap_sel[16][4]; // [cond][size]
  extern const AddrPair templatemap_set[16][4]; // [cond][size]
  extern const AddrPair templatemap_br_sub[16][4][2]; // [cond][size][except]
  extern const AddrPair templatemap_br_and[16][4][2]; // [cond][size][except]
  extern const AddrPair templatemap_br[16][2];
  extern const AddrPair templatemap_chk[16];
  extern const AddrPair templatemap_zxt[4][4]; // [rdsize][rbsize]
  extern const AddrPair templatemap_sxt[4][4]; // [rdsize][rbsize]
  extern const AddrPair templatemap_bswap[4];
  extern const AddrPair templatemap_inshb[1];
  extern const AddrPair templatemap_exthb[1];
  extern const AddrPair templatemap_movhb[1];
  extern const AddrPair templatemap_movccr[1];
  extern const AddrPair templatemap_movrcc[1];
  extern const AddrPair templatemap_andcc[1];
  extern const AddrPair templatemap_orcc[1];
  extern const AddrPair templatemap_ornotcc[1];
  extern const AddrPair templatemap_xorcc[1];
  extern const AddrPair templatemap_jmp[2];
  extern const AddrPair templatemap_bru[1];
  extern const AddrPair templatemap_brp[1];
  extern const AddrPair templatemap_collcc[1];
  extern const AddrPair templatemap_movhl[1];
  extern const AddrPair templatemap_movl[1];  

  extern const AddrPair templatemap_addf[4];
  extern const AddrPair templatemap_subf[4];
  extern const AddrPair templatemap_addaf[4];
  extern const AddrPair templatemap_addsf[4];
  extern const AddrPair templatemap_subaf[4];
  extern const AddrPair templatemap_subsf[4];
  extern const AddrPair templatemap_mulf[4];
  extern const AddrPair templatemap_maddf[4];
  extern const AddrPair templatemap_msubf[4];
  extern const AddrPair templatemap_divf[4];
  extern const AddrPair templatemap_sqrtf[4];
  extern const AddrPair templatemap_rcpf[4];
  extern const AddrPair templatemap_rsqrtf[4];
  extern const AddrPair templatemap_minf[4];
  extern const AddrPair templatemap_maxf[4];
  extern const AddrPair templatemap_cmpf[4][8];
  extern const AddrPair templatemap_cmpccf[4];
  extern const AddrPair templatemap_cvtf_i2s_ins[1];
  extern const AddrPair templatemap_cvtf_i2s_p[1];
  extern const AddrPair templatemap_cvtf_i2d_lo[1];
  extern const AddrPair templatemap_cvtf_i2d_hi[1];
  extern const AddrPair templatemap_cvtf_q2s_ins[1];
  extern const AddrPair templatemap_cvtf_q2d[1];
  extern const AddrPair templatemap_cvtf_s2i[2];
  extern const AddrPair templatemap_cvtf_s2q[2];
  extern const AddrPair templatemap_cvtf_s2i_p[2];
  extern const AddrPair templatemap_cvtf_d2i[2];
  extern const AddrPair templatemap_cvtf_d2q[2];
  extern const AddrPair templatemap_cvtf_d2i_p[2];
  extern const AddrPair templatemap_cvtf_d2s_ins[1];
  extern const AddrPair templatemap_cvtf_d2s_p[1];
  extern const AddrPair templatemap_cvtf_s2d_lo[1];
  extern const AddrPair templatemap_cvtf_s2d_hi[1];
}

const AddrPair* get_synthcode_for_uop(int op, int size, bool setflags, int cond, int extshift, int sfra, int cachelevel, bool except, bool internal) {
  const AddrPair* cp = null;

  switch (op) {
  case OP_nop:
    cp = &templatemap_nop[0]; break;
  case OP_mov: 
    cp = &templatemap_mov[size]; break;
  case OP_and:
    cp = &templatemap_and[size][setflags]; break;
  case OP_or: 
    cp = &templatemap_or[size][setflags]; break;
  case OP_xor: 
    cp = &templatemap_xor[size][setflags]; break;
  case OP_andnot: 
    cp = &templatemap_andnot[size][setflags]; break;
  case OP_ornot: 
    cp = &templatemap_ornot[size][setflags]; break;
  case OP_nand: 
    cp = &templatemap_nand[size][setflags]; break;
  case OP_nor: 
    cp = &templatemap_nor[size][setflags]; break;
  case OP_eqv: 
    cp = &templatemap_eqv[size][setflags]; break;
  case OP_add: 
    cp = &templatemap_add[size][setflags]; break;
  case OP_sub: 
    cp = &templatemap_sub[size][setflags]; break;
  case OP_adda:
    cp = &templatemap_adda[size][extshift][setflags]; break;
  case OP_adds:
    cp = &templatemap_adds[size][extshift][setflags]; break;
  case OP_suba:
    cp = &templatemap_suba[size][extshift][setflags]; break;
  case OP_subs:
    cp = &templatemap_subs[size][extshift][setflags]; break;
  case OP_addm:
    cp = &templatemap_addm[size][setflags]; break;
  case OP_subm: 
    cp = &templatemap_subm[size][setflags]; break;
  case OP_addc: 
    cp = &templatemap_addc[size][setflags]; break;
  case OP_subc: 
    cp = &templatemap_subc[size][setflags]; break;
  case OP_rotl: 
    cp = &templatemap_rotl[size][setflags]; break;
  case OP_rotr: 
    cp = &templatemap_rotr[size][setflags]; break;
  case OP_rotcl: 
    cp = &templatemap_rotcl[size][setflags]; break;
  case OP_rotcr: 
    cp = &templatemap_rotcr[size][setflags]; break;
  case OP_shl: 
    cp = &templatemap_shl[size][setflags]; break;
  case OP_shr: 
    cp = &templatemap_shr[size][setflags]; break;
  case OP_sar:
    cp = &templatemap_sar[size][setflags]; break;
  case OP_mull:
    cp = &templatemap_mull[size][setflags]; break;
  case OP_mulh:
    cp = &templatemap_mulh[size][setflags]; break;
  case OP_bt:
    cp = &templatemap_bt[size][setflags]; break;
  case OP_bts:
    cp = &templatemap_bts[size][setflags]; break;
  case OP_btr:
    cp = &templatemap_btr[size][setflags]; break;
  case OP_btc:
    cp = &templatemap_btc[size][setflags]; break;
  case OP_dupbit:
    cp = &templatemap_dupbit[size][0]; break;
  case OP_ctz: 
    cp = &templatemap_ctz[size][setflags]; break;
  case OP_clz: 
    cp = &templatemap_clz[size][setflags]; break;
  case OP_ctpop:
    cp = &templatemap_ctpop[size][setflags]; break;
  case OP_sel:
    cp = &templatemap_sel[cond][size]; break;
  case OP_set:
    cp = &templatemap_set[cond][size]; break;
  case OP_br_sub:
    cp = &templatemap_br_sub[cond][size][except]; break;
  case OP_br_and:
    cp = &templatemap_br_and[cond][size][except]; break;
  case OP_br:
    cp = &templatemap_br[cond][except]; break;
  case OP_chk:
    cp = &templatemap_chk[cond]; break;
  case OP_bru:
    cp = &templatemap_bru[0]; break;
  case OP_brp:
    cp = &templatemap_brp[0]; break;
    //
    // Loads and stores are handled specially in the out-of-order core:
    //
  case OP_ld:
  case OP_ldx:
  case OP_ld_pre:
  case OP_st:
    cp = &templatemap_nop[0]; break;
  case OP_zxt:
    cp = &templatemap_zxt[size][cond]; break;
  case OP_sxt:
    cp = &templatemap_sxt[size][cond]; break;
  case OP_bswap:
    cp = &templatemap_bswap[size]; break;
  case OP_inshb:
    cp = &templatemap_inshb[0]; break;
  case OP_exthb:
    cp = &templatemap_exthb[0]; break;
  case OP_movhb:
    cp = &templatemap_movhb[0]; break;
  case OP_movccr:
    cp = &templatemap_movccr[0]; break;
  case OP_movrcc:
    cp = &templatemap_movrcc[0]; break;
  case OP_andcc:
    cp = &templatemap_andcc[0]; break;
  case OP_orcc:
    cp = &templatemap_orcc[0]; break;
  case OP_ornotcc:
    cp = &templatemap_ornotcc[0]; break;
  case OP_xorcc:
    cp = &templatemap_xorcc[0]; break;
  case OP_jmp:
    cp = &templatemap_jmp[except]; break;
  case OP_collcc:
    cp = &templatemap_collcc[0]; break;
  case OP_movhl:
    cp = &templatemap_movhl[0]; break;
  case OP_movl:
    cp = &templatemap_movl[0]; break;
  case OP_addf:
    cp = &templatemap_addf[size]; break;
  case OP_subf:
    cp = &templatemap_subf[size]; break;
  case OP_addaf:
    cp = &templatemap_addaf[size]; break;
  case OP_addsf:
    cp = &templatemap_addsf[size]; break;
  case OP_subaf:
    cp = &templatemap_subaf[size]; break;
  case OP_subsf:
    cp = &templatemap_subsf[size]; break;
  case OP_mulf:
    cp = &templatemap_mulf[size]; break;
  case OP_maddf:
    cp = &templatemap_maddf[size]; break;
  case OP_msubf:
    cp = &templatemap_msubf[size]; break;
  case OP_divf:
    cp = &templatemap_divf[size]; break;
  case OP_sqrtf:
    cp = &templatemap_sqrtf[size]; break;
  case OP_rcpf:
    cp = &templatemap_rcpf[size]; break;
  case OP_rsqrtf:
    cp = &templatemap_rsqrtf[size]; break;
  case OP_minf:
    cp = &templatemap_minf[size]; break;
  case OP_maxf:
    cp = &templatemap_maxf[size]; break;
  case OP_cmpf:
    cp = &templatemap_cmpf[size][cond]; break;
  case OP_cmpccf:
    cp = &templatemap_cmpccf[size]; break;
  case OP_cvtf_i2s_ins:
    cp = &templatemap_cvtf_i2s_ins[0]; break;
  case OP_cvtf_i2s_p:
    cp = &templatemap_cvtf_i2s_p[0]; break;
  case OP_cvtf_i2d_lo:
    cp = &templatemap_cvtf_i2d_lo[0]; break;
  case OP_cvtf_i2d_hi:
    cp = &templatemap_cvtf_i2d_hi[0]; break;
  case OP_cvtf_q2s_ins:
    cp = &templatemap_cvtf_q2s_ins[0]; break;
  case OP_cvtf_q2d:
    cp = &templatemap_cvtf_q2d[0]; break;
  case OP_cvtf_s2i:
    cp = &templatemap_cvtf_s2i[size]; break;
  case OP_cvtf_s2q:
    cp = &templatemap_cvtf_s2q[size]; break;
  case OP_cvtf_s2i_p:
    cp = &templatemap_cvtf_s2i_p[size]; break;
  case OP_cvtf_d2i:
    cp = &templatemap_cvtf_d2i[size]; break;
  case OP_cvtf_d2q:
    cp = &templatemap_cvtf_d2q[size]; break;
  case OP_cvtf_d2i_p:
    cp = &templatemap_cvtf_d2i_p[size]; break;
  case OP_cvtf_d2s_ins:
    cp = &templatemap_cvtf_d2s_ins[0]; break;
  case OP_cvtf_d2s_p:
    cp = &templatemap_cvtf_d2s_p[0]; break;
  case OP_cvtf_s2d_lo:
    cp = &templatemap_cvtf_s2d_lo[0]; break;
  case OP_cvtf_s2d_hi:
    cp = &templatemap_cvtf_s2d_hi[0]; break;
  default:
    logfile << "Unknown uop opcode ", op, flush, " (", nameof(op), ")", endl, flush;
    assert(false);
  }

  return cp;
}

void synth_uops_for_bb(BasicBlock& bb) {
  const byte* p = bb.data;
  bb.synthops = new const byte*[bb.count];
  foreach (i, bb.count) {
    TransOp transop;
    p = transop.expand(p);
    int sfra = 0;
    bool except = 0;

    const AddrPair* cp = get_synthcode_for_uop(transop.opcode, transop.size, transop.setflags, transop.cond, transop.extshift, sfra, transop.cachelevel, except, transop.internal);
    bb.synthops[i] = cp->start;
  }
}

const byte* get_synthcode_for_cond_branch(int opcode, int cond, int size, bool except) {
  const AddrPair* cp;

  switch (opcode) {
  case OP_br_sub:
    cp = &templatemap_br_sub[cond][size][except]; break;
  case OP_br_and:
    cp = &templatemap_br_and[cond][size][except]; break;
  case OP_br:
    cp = &templatemap_br[cond][except]; break;
  default:
    assert(false);
  }

  return cp->start;
}
