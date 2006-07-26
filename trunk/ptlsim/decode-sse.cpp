//
// PTLsim: Cycle Accurate x86-64 Simulator
// Decoder for SSE/SSE2/SSE3/MMX and misc instructions
//
// Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <decode.h>

static const byte sse_float_datatype_to_ptl_datatype[4] = {DATATYPE_FLOAT, DATATYPE_VEC_FLOAT, DATATYPE_DOUBLE, DATATYPE_VEC_DOUBLE};

bool TraceDecoder::decode_sse() {
  DecodedOperand rd;
  DecodedOperand ra;

  switch (op) {
    //
    // SSE Logical
    //
  case 0x5db:   // pand      66 0f db
  case 0x5df:   // pandn     66 0f df
  case 0x5eb:   // por       66 0f eb
  case 0x5ef: { // pxor      66 0f ef
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();

    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      rareg = REG_temp0;
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_VEC_128BIT);
      ra.mem.offset += 8;
      operand_load(REG_temp1, ra, OP_ld, DATATYPE_VEC_128BIT);
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    int opcode = (op == 0x5db) ? OP_and : (op == 0x5df) ? OP_andnot : (op == 0x5eb) ? OP_or : (op == 0x5ef) ? OP_xor : OP_nop;

    this << TransOp(opcode, rdreg+0, rdreg+0, rareg+0, REG_zero, 3);
    this << TransOp(opcode, rdreg+1, rdreg+1, rareg+1, REG_zero, 3);
    break;
  }

    /*
      0x2xx   0xf3  OPpd
      0x3xx   none  OPps
      0x4xx   0xf2  OPsd
      0x5xx   0x66  OPpd
    */

    //
    // SSE Arithmetic
    //

    // 0x2xx = XXXss:
  case 0x251: // sqrt
  case 0x252: // rsqrt
  case 0x253: // rcp
    //case 0x254: // and (scalar version does not exist)
    //case 0x255: // andn
    //case 0x256: // or
    //case 0x257: // xor
  case 0x258: // add
  case 0x259: // mul
    // 0x25a, 0x25b are conversions with different form
  case 0x25c: // sub
  case 0x25d: // min
  case 0x25e: // div
  case 0x25f: // max
  case 0x2c2: // cmp (has imm byte at end for compare type)

    // 0x3xx = XXXps
  case 0x351: // sqrt
  case 0x352: // rsqrt
  case 0x353: // rcp
  case 0x354: // and
  case 0x355: // andn
  case 0x356: // or
  case 0x357: // xor
  case 0x358: // add
  case 0x359: // mul
    // 0x35a, 0x25b are conversions with different form
  case 0x35c: // sub
  case 0x35d: // min
  case 0x35e: // div
  case 0x35f: // max
  case 0x3c2: // cmp (has imm byte at end for compare type)

    // 0x4xx = XXXsd
  case 0x451: // sqrt
  case 0x452: // rsqrt
  case 0x453: // rcp
    //case 0x454: // and (scalar version does not exist)
    //case 0x455: // andn
    //case 0x456: // or
    //case 0x457: // xor
  case 0x458: // add
  case 0x459: // mul
    // 0x45a, 0x25b are conversions with different form
  case 0x45c: // sub
  case 0x45d: // min
  case 0x45e: // div
  case 0x45f: // max
  case 0x4c2: // cmp (has imm byte at end for compare type)

    // 0x5xx = XXXpd
  case 0x551: // sqrt
  case 0x552: // rsqrt
  case 0x553: // rcp
  case 0x554: // and
  case 0x555: // andn
  case 0x556: // or
  case 0x557: // xor
  case 0x558: // add
  case 0x559: // mul
    // 0x55a, 0x25b are conversions with different form
  case 0x55c: // sub
  case 0x55d: // min
  case 0x55e: // div
  case 0x55f: 
  case 0x5c2: { // cmp (has imm byte at end for compare type)
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();

    bool cmp = (lowbits(op, 8) == 0xc2);
    DecodedOperand imm;
    imm.imm.imm = 0;
    if (cmp) {
      // cmpXX has imm8 at end to specify 3 bits of compare type:
      DECODE(iform, imm, b_mode);
      CheckInvalid();
    }

    int destreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];

    // XXXss: 0x2xx 00
    // XXXps: 0x3xx 01
    // XXXsd: 0x4xx 10
    // XXXpd: 0x5xx 11

    byte sizetype = (op >> 8) - 2; // put into 0x{2-5}00 -> 2-5 range, then set to 0-3 range
    bool packed = bit(sizetype, 0);
    bool dp = bit(sizetype, 1);

    static const byte opcode_to_uop[16] = {OP_nop, OP_sqrtf, OP_rsqrtf, OP_rcpf, OP_and, OP_andnot, OP_or, OP_xor, OP_addf, OP_mulf, OP_nop, OP_nop, OP_subf, OP_minf, OP_divf, OP_maxf};

    int uop = (lowbits(op, 8) == 0xc2) ? OP_cmpf : opcode_to_uop[lowbits(op, 4)];
    int datatype = sse_float_datatype_to_ptl_datatype[sizetype];

    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      rareg = REG_temp0;
      operand_load(REG_temp0, ra, OP_ld, datatype);
      if (packed) {
        ra.mem.offset += 8;
        operand_load(REG_temp1, ra, OP_ld, datatype);
      }
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    TransOp lowop(uop, rdreg+0, rdreg+0, rareg+0, REG_zero, isclass(uop, OPCLASS_LOGIC) ? 3 : sizetype);
    lowop.cond = imm.imm.imm;
    lowop.datatype = datatype;
    this << lowop;

    if (packed) {
      TransOp highop(uop, rdreg+1, rdreg+1, rareg+1, REG_zero, isclass(uop, OPCLASS_LOGIC) ? 3 : sizetype);
      highop.cond = imm.imm.imm;
      highop.datatype = datatype;
      this << highop;
    }
    break;
  }

  case 0x57c: // haddps
  case 0x57d: { // hsubpd
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();

    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      rareg = REG_temp0;
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_VEC_DOUBLE);
      ra.mem.offset += 8;
      operand_load(REG_temp1, ra, OP_ld, DATATYPE_VEC_DOUBLE);
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    int uop = (op == 0x57d) ? OP_subf : OP_addf;
    TransOp lowop(uop, rdreg+0, rdreg+0, rdreg+1, REG_zero, 3);
    lowop.datatype = DATATYPE_VEC_DOUBLE;
    this << lowop;

    TransOp highop(uop, rdreg+1, rareg+1, rareg+1, REG_zero, 3);
    highop.datatype = DATATYPE_VEC_DOUBLE;
    this << highop;

    break;
  }

  case 0x22a: { // cvtsi2ss with W32 or W64 source
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, v_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      ra.mem.size = (rex.mode64) ? 3 : 2;
      operand_load(REG_temp0, ra, OP_ld);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    TransOp uop((rex.mode64) ? OP_cvtf_q2s_ins : OP_cvtf_i2s_ins, rdreg, rdreg, rareg, REG_zero, 3);
    uop.datatype = DATATYPE_FLOAT;
    this << uop;
    break;
  }

  case 0x42a: { // cvtsi2sd with W32 or W64 source
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, v_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      ra.mem.size = (rex.mode64) ? 3 : 2;
      operand_load(REG_temp0, ra, OP_ld);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    TransOp uop((rex.mode64) ? OP_cvtf_q2d : OP_cvtf_i2d_lo, rdreg, REG_zero, rareg, REG_zero, 3);
    uop.datatype = DATATYPE_DOUBLE;
    this << uop;
    break;
  }

  case 0x2e6: // cvtdq2pd
  case 0x52a: { // cvtpi2pd
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      ra.mem.size = (rex.mode64) ? 3 : 2;
      operand_load(REG_temp0, ra, OP_ld);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    TransOp uoplo(OP_cvtf_i2d_lo, rdreg+0, REG_zero, rareg, REG_zero, 3); uoplo.datatype = DATATYPE_VEC_DOUBLE; this << uoplo;
    TransOp uophi(OP_cvtf_i2d_hi, rdreg+1, REG_zero, rareg, REG_zero, 3); uophi.datatype = DATATYPE_VEC_DOUBLE; this << uophi;
    break;
  }

  case 0x35b: { // cvtdq2ps
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld);
      ra.mem.offset += 8;
      operand_load(REG_temp1, ra, OP_ld);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    TransOp uoplo(OP_cvtf_i2s_p, rdreg+0, REG_zero, rareg+0, REG_zero, 3); uoplo.datatype = DATATYPE_VEC_FLOAT; this << uoplo;
    TransOp uophi(OP_cvtf_i2s_p, rdreg+1, REG_zero, rareg+1, REG_zero, 3); uophi.datatype = DATATYPE_VEC_FLOAT; this << uophi;
    break;
  }

  case 0x4e6: // cvtpd2dq
  case 0x5e6: { // cvttpd2dq
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_VEC_DOUBLE);
      ra.mem.offset += 8;
      operand_load(REG_temp1, ra, OP_ld, DATATYPE_VEC_DOUBLE);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    this << TransOp(OP_cvtf_d2i_p, rdreg+0, rareg+1, rareg+0, REG_zero, ((op >> 8) == 5));
    this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3);
    break;
  }

    // cvtpd2pi has mmx target: skip for now

  case 0x55a: { // cvtpd2ps
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_VEC_DOUBLE);
      ra.mem.offset += 8;
      operand_load(REG_temp1, ra, OP_ld, DATATYPE_VEC_DOUBLE);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }
      
    TransOp uop(OP_cvtf_d2s_p, rdreg+0, rareg+1, rareg+0, REG_zero, 3); uop.datatype = DATATYPE_VEC_FLOAT; this << uop;
    this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3);
    break;
  }

  case 0x32a: { // cvtpi2ps
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld);
      ra.mem.offset += 8;
      operand_load(REG_temp1, ra, OP_ld);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    TransOp uop(OP_cvtf_i2s_p, rdreg+0, REG_zero, rareg+0, REG_zero, 3); uop.datatype = DATATYPE_VEC_FLOAT; this << uop;
    this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3);
    break;
  }

  case 0x55b: // cvtps2dq
  case 0x25b: { // cvttps2dq
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_VEC_FLOAT);
      ra.mem.offset += 8;
      operand_load(REG_temp1, ra, OP_ld, DATATYPE_VEC_FLOAT);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    this << TransOp(OP_cvtf_s2i_p, rdreg+0, rareg+0, rareg+0, REG_zero, ((op >> 8) == 2));
    this << TransOp(OP_cvtf_s2i_p, rdreg+1, rareg+1, rareg+1, REG_zero, ((op >> 8) == 2));
    break;
  }

    // cvtps2pi/cvttps2pi: uses mmx so ignore for now

  case 0x42d: // cvtsd2si
  case 0x42c: { // cvttsd2si
    DECODE(gform, rd, v_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_DOUBLE);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    this << TransOp((rex.mode64) ? OP_cvtf_d2q : OP_cvtf_d2i, rdreg, REG_zero, rareg, REG_zero, (lowbits(op, 8) == 0x2c));
    break;
  }

  case 0x22d: // cvtss2si
  case 0x22c: { // cvttss2si
    DECODE(gform, rd, v_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_FLOAT);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    this << TransOp((rex.mode64) ? OP_cvtf_s2q : OP_cvtf_s2i, rdreg, REG_zero, rareg, REG_zero, (lowbits(op, 8) == 0x2c));
    break;
  }

  case 0x25a: { // cvtss2sd
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_FLOAT);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    TransOp uop(OP_cvtf_s2d_lo, rdreg, REG_zero, rareg, REG_zero, 3); uop.datatype = DATATYPE_DOUBLE; this << uop;
    break;
  }

  case 0x35a: { // cvtps2pd
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_FLOAT);
      rareg = REG_temp0;
      ra.mem.offset += 8;
      operand_load(REG_temp1, ra, OP_ld, DATATYPE_FLOAT);
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    TransOp uoplo(OP_cvtf_s2d_lo, rdreg+0, REG_zero, rareg, REG_zero, 3); uoplo.datatype = DATATYPE_VEC_DOUBLE; this << uoplo;
    TransOp uophi(OP_cvtf_s2d_hi, rdreg+1, REG_zero, rareg, REG_zero, 3); uophi.datatype = DATATYPE_VEC_DOUBLE; this << uophi;
    break;
  }

  case 0x45a: { // cvtsd2ss
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_DOUBLE);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    TransOp uop(OP_cvtf_d2s_ins, rdreg, rdreg, rareg, REG_zero, 3); uop.datatype = DATATYPE_FLOAT; this << uop;
    break;
  }

  case 0x328: // movaps load 
  case 0x528: // movapd load
  case 0x310: // movups load
  case 0x510: // movupd load
  case 0x56f: // movdqa load
  case 0x26f: { // movdqu load
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    if (ra.type == OPTYPE_MEM) {
      // Load
      // This is still idempotent since if the second one was unaligned, the first one must be too
      operand_load(rdreg+0, ra, OP_ld, datatype);
      ra.mem.offset += 8;
      operand_load(rdreg+1, ra, OP_ld, datatype);
    } else {
      // Move
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      TransOp uoplo(OP_mov, rdreg+0, REG_zero, rareg+0, REG_zero, 3); uoplo.datatype = datatype; this << uoplo;
      TransOp uophi(OP_mov, rdreg+1, REG_zero, rareg+1, REG_zero, 3); uophi.datatype = datatype; this << uophi;
    }
    break;
  }

  case 0x329: // movaps store
  case 0x529: // movapd store
  case 0x311: // movups store
  case 0x511: // movupd store
  case 0x57f: // movdqa store
  case 0x27f: { // movdqu store
    DECODE(eform, rd, x_mode);
    DECODE(gform, ra, x_mode);
    CheckInvalid();
    int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    if (rd.type == OPTYPE_MEM) {
      // Store
      // This is still idempotent since if the second one was unaligned, the first one must be too
      result_store(rareg+0, REG_temp0, rd, datatype);
      rd.mem.offset += 8;
      result_store(rareg+1, REG_temp1, rd, datatype);
    } else {
      // Move
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      TransOp uoplo(OP_mov, rdreg+0, REG_zero, rareg+0, REG_zero, 3); uoplo.datatype = datatype; this << uoplo;
      TransOp uophi(OP_mov, rdreg+1, REG_zero, rareg+1, REG_zero, 3); uophi.datatype = datatype; this << uophi;
    }
    break;
  };

  case 0x210: // movss load
  case 0x410: { // movsd load
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    bool isdouble = ((op >> 8) == 0x4);
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    if (ra.type == OPTYPE_MEM) {
      // Load
      ra.mem.size = (isdouble) ? 3 : 2;
      operand_load(rdreg+0, ra, OP_ld, datatype);
      TransOp uop(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); uop.datatype = datatype; this << uop; // zero high 64 bits
    } else {
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      // Strange semantics: iff the source operand is a register, insert into low 32 bits only; leave high 32 bits and bits 64-127 alone
      if (isdouble) {
        TransOp uop(OP_mov, rdreg, REG_zero, rareg, REG_zero, 3); uop.datatype = datatype; this << uop;
      } else {
        TransOp uop(OP_maskb, rdreg, rdreg, rareg, REG_imm, 3, 0, MaskControlInfo(0, 32, 0)); uop.datatype = datatype; this << uop;
      }
    }
    break;
  }

  case 0x211: // movss store
  case 0x411: { // movsd store
    DECODE(eform, rd, x_mode);
    DECODE(gform, ra, x_mode);
    CheckInvalid();
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    bool isdouble = ((op >> 8) == 0x4);
    int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    if (rd.type == OPTYPE_MEM) {
      // Store
      rd.mem.size = (isdouble) ? 3 : 2;
      result_store(rareg, REG_temp0, rd, datatype);
    } else {
      // Register to register
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      // Strange semantics: iff the source operand is a register, insert into low 32 bits only; leave high 32 bits and bits 64-127 alone
      if (isdouble) {
        TransOp uop(OP_mov, rdreg, REG_zero, rareg, REG_zero, 3); uop.datatype = datatype; this << uop;
      } else {
        TransOp uop(OP_maskb, rdreg, rdreg, rareg, REG_imm, 3, 0, MaskControlInfo(0, 32, 0)); uop.datatype = datatype; this << uop;
      }
    }
    break;
  }

    /*
      0x2xx   0xf3  OPpd
      0x3xx   none  OPps
      0x4xx   0xf2  OPsd
      0x5xx   0x66  OPpd
    */
  case 0x5d3: // psrlq xmm|mem
  case 0x5f3: // psllq xmm|mem
  case 0x5d4: // paddq xmm|mem
  case 0x5fb: { // psubq xmm|mem
    //++MTY TODO According to the SSE2 spec, the count is NOT masked;
    // any counts >= 64 result in the register being cleared.
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();

    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      rareg = REG_temp0;
      operand_load(rareg+0, ra, OP_ld, DATATYPE_VEC_64BIT);
      ra.mem.offset += 8;
      operand_load(rareg+1, ra, OP_ld, DATATYPE_VEC_64BIT);
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    int opcode;
    switch (op) {
    case 0x5d3: opcode = OP_shr; break;
    case 0x5f3: opcode = OP_shl; break;
    case 0x5d4: opcode = OP_add; break;
    case 0x5fb: opcode = OP_sub; break;
    default: opcode = OP_nop; break;
    }

    if (opcode == OP_nop) MakeInvalid();

    int add_to_second_reg = ((opcode == OP_shr) | (opcode == OP_shl)) ? 0 : 1;
    this << TransOp(opcode, rdreg+0, rdreg+0, rareg, REG_zero, 3);
    this << TransOp(opcode, rdreg+1, rdreg+1, rareg + add_to_second_reg, REG_zero, 3);
    break;
  }

  case 0x573: { // psrlq|psllq imm8
    DECODE(gform, rd, x_mode);
    DECODE(iform, ra, b_mode);
    CheckInvalid();

    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];

    static const int modrm_reg_to_opcode[8] = {OP_nop, OP_nop, OP_shr, OP_nop, OP_nop, OP_nop, OP_shl, OP_nop};

    int opcode = modrm_reg_to_opcode[modrm.reg];
    if (opcode == OP_nop) MakeInvalid();

    this << TransOp(opcode, rdreg+0, rdreg+0, REG_imm, REG_zero, 3, ra.imm.imm);
    this << TransOp(opcode, rdreg+1, rdreg+1, REG_imm, REG_zero, 3, ra.imm.imm);
    break;
  }

  case 0x5c5: { // pextrw
    DECODE(gform, rd, w_mode);
    DECODE(eform, ra, x_mode);
    DecodedOperand imm;
    DECODE(iform, imm, b_mode);
    CheckInvalid();

    int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];

    int which = bit(imm.imm.imm, 2);
    int shift = lowbits(imm.imm.imm, 3) * 16;
    this << TransOp(OP_maskb, rdreg, REG_zero, rareg + which, REG_imm, 3, 0, MaskControlInfo(0, 16, lowbits(shift, 6)));
    break;
  }

  case 0x5c4: { // pinsrw
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, w_mode);
    DecodedOperand imm;
    DECODE(iform, imm, b_mode);
    CheckInvalid();

    int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];

    int which = bit(imm.imm.imm, 2);
    int shift = lowbits(imm.imm.imm, 3) * 16;

    this << TransOp(OP_maskb, rdreg + which, rdreg + which, rareg, REG_imm, 3, 0, MaskControlInfo(64 - shift, 16, 64 - lowbits(shift, 6)));
    break;
  }
  
  case 0x570: // pshufd
  case 0x3c6: { // shufps
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    DecodedOperand imm;
    DECODE(iform, imm, b_mode);
    CheckInvalid();

    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      rareg = REG_temp0;
      operand_load(rareg+0, ra, OP_ld, (op == 0x570) ? DATATYPE_VEC_32BIT : DATATYPE_VEC_FLOAT);
      ra.mem.offset += 8;
      operand_load(rareg+1, ra, OP_ld, (op == 0x570) ? DATATYPE_VEC_32BIT : DATATYPE_VEC_FLOAT);
    } else {
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    bool mix = (op == 0x3c6); // both rd and ra are used as sources for shufps

    int base0 = bits(imm.imm.imm, 0*2, 2) * 4;
    int base1 = bits(imm.imm.imm, 1*2, 2) * 4;
    int base2 = bits(imm.imm.imm, 2*2, 2) * 4;
    int base3 = bits(imm.imm.imm, 1*2, 2) * 4;

    this << TransOp(OP_permb, rdreg+0, ((mix) ? rdreg+0 : rareg+0), ((mix) ? rdreg+1 : rareg+1), REG_imm, 3, 0, PermbControlInfo(base1+3, base1+2, base1+1, base1+0, base0+3, base0+2, base0+1, base0+0));
    this << TransOp(OP_permb, rdreg+1, ((mix) ? rareg+0 : rareg+0), ((mix) ? rareg+1 : rareg+1), REG_imm, 3, 0, PermbControlInfo(base3+3, base3+2, base3+1, base3+0, base2+3, base2+2, base2+1, base2+0));

    break;
  }

  case 0x5c6: { // shufpd
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    DecodedOperand imm;
    DECODE(iform, imm, b_mode);
    CheckInvalid();

    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      rareg = REG_temp0;
      operand_load(rareg+0, ra, OP_ld, DATATYPE_VEC_DOUBLE);
      ra.mem.offset += 8;
      operand_load(rareg+1, ra, OP_ld, DATATYPE_VEC_DOUBLE);
    } else {
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    this << TransOp(OP_mov, rdreg+0, REG_zero, rdreg + bit(imm.imm.imm, 0), REG_imm, 3);
    this << TransOp(OP_mov, rdreg+1, REG_zero, rareg + bit(imm.imm.imm, 1), REG_imm, 3);
    break;
  }

  case 0x32f: // comiss
  case 0x32e: // ucomiss
  case 0x52f: // comisd
  case 0x52e: { // ucomisd
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int rareg;

    if (ra.type == OPTYPE_MEM) {
      operand_load(REG_temp0, ra, OP_ld, 1);
      rareg = REG_temp0;
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    int sizecode;
    switch (op) {
    case 0x32f: sizecode = 0; break;
    case 0x32e: sizecode = 1; break;
    case 0x52f: sizecode = 2; break;
    case 0x52e: sizecode = 3; break;
    }

    //
    // comisX and ucomisX set {zf pf cf} according to the comparison,
    // and always set {of sf af} to zero.
    //
    this << TransOp(OP_cmpccf, REG_temp0, rdreg, rareg, REG_zero, sizecode, 0, 0, FLAGS_DEFAULT_ALU);
    break;
  };

  case 0x516: // movhpd load
  case 0x316: // movhps load or movlhps
  case 0x512: // movlpd load
  case 0x312: { // movlps load or movhlps
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    if (ra.type == OPTYPE_MEM) {
      // movhpd/movhps/movlpd/movlps
      operand_load(rdreg + ((lowbits(op, 8) == 0x16) ? 1 : 0), ra, OP_ld, datatype);
    } else {
      // movlhps/movhlps
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      switch (op) {
      case 0x312: { // movhlps
        TransOp uop(OP_mov, rdreg, REG_zero, rareg+1, REG_zero, 3); uop.datatype = datatype; this << uop; break;
      }
      case 0x316: { // movlhps
        TransOp uop(OP_mov, rdreg+1, REG_zero, rareg, REG_zero, 3); uop.datatype = datatype; this << uop; break;
      }
      }
    }
    break;
  }

  case 0x517: // movhpd store
  case 0x317: // movhps store
  case 0x513: // movlpd store
  case 0x313: { // movlps store
    DECODE(eform, rd, x_mode);
    DECODE(gform, ra, x_mode);
    CheckInvalid();
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    if (rd.type != OPTYPE_MEM) MakeInvalid();
    result_store(rareg + ((lowbits(op, 8) == 0x17) ? 1 : 0), REG_temp0, rd, datatype);
    break;
  }

    /*
      0x2xx   0xf3  OPpd
      0x3xx   none  OPps
      0x4xx   0xf2  OPsd
      0x5xx   0x66  OPpd

    */

  case 0x514: // unpcklpd
  case 0x515: { // unpckhpd
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    if (ra.type == OPTYPE_MEM) {
      switch (op) {
      case 0x514: // unpcklpd
        operand_load(rdreg+1, ra, OP_ld, datatype); break;
      case 0x515: { // unpckhpd
        TransOp uop(OP_mov, rdreg+0, REG_zero, rdreg+1, REG_zero, 3); uop.datatype = datatype; this << uop;
        ra.mem.offset += 8;
        operand_load(rdreg+1, ra, OP_ld, datatype); break;
      }
      }
    } else {
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      switch (op) {
      case 0x514: { // unpcklpd
        TransOp uoplo(OP_mov, rdreg+1, REG_zero, rareg+0, REG_zero, 3); uoplo.datatype = datatype; this << uoplo; break;
      }
      case 0x515: { // unpckhpd
        TransOp uoplo(OP_mov, rdreg+0, REG_zero, rdreg+1, REG_zero, 3); uoplo.datatype = datatype; this << uoplo; 
        TransOp uophi(OP_mov, rdreg+1, REG_zero, rareg+1, REG_zero, 3); uophi.datatype = datatype; this << uophi; break;
      }
      }
    }
    break;
  }

  case 0x314: // unpcklps
  case 0x315: { // unpckhps
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    int rareg;
    if (ra.type == OPTYPE_MEM) {
      rareg = REG_temp0;
      operand_load(rareg+0, ra, OP_ld, datatype);
      ra.mem.offset += 8;
      operand_load(rareg+1, ra, OP_ld, datatype);
    } else {
      rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    }

    switch (op) {
    case 0x314: { // unpcklps:
      TransOp uophi(OP_permb, rdreg+1, rareg+0, rdreg+0, REG_imm, 3, 0, PermbControlInfo(7, 6, 5, 4, 15, 14, 13, 12)); // rd+1 (d3, d2) = a1 d1
      uophi.datatype = DATATYPE_VEC_FLOAT; this << uophi;
      TransOp uoplo(OP_permb, rdreg+0, rareg+0, rdreg+0, REG_imm, 3, 0, PermbControlInfo(3, 2, 1, 0, 11, 10, 9, 8)); // rd+0 = (d1, d0) a0 d0
      uoplo.datatype = DATATYPE_VEC_FLOAT; this << uoplo;
      break;
    }
    case 0x315: { // unpckhps:
      TransOp uoplo(OP_permb, rdreg+0, rareg+1, rdreg+1, REG_imm, 3, 0, PermbControlInfo(3, 2, 1, 0, 11, 10, 9, 8)); // rd+0 (d1, d0) = a2 d2
      uoplo.datatype = DATATYPE_VEC_FLOAT; this << uoplo;
      TransOp uophi(OP_permb, rdreg+1, rareg+1, rdreg+1, REG_imm, 3, 0, PermbControlInfo(7, 6, 5, 4, 15, 14, 13, 12)); // rd+1 (d3, d2) = a3 d3
      uophi.datatype = DATATYPE_VEC_FLOAT; this << uophi;
      break;
    }
    default:
      MakeInvalid();
    }

    break;
  }

    /*
      0x2xx   0xf3  OPpd
      0x3xx   none  OPps
      0x4xx   0xf2  OPsd
      0x5xx   0x66  OPpd

    */

  case 0x56e: { // movd xmm,rm32/rm64
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, v_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    if (ra.type == OPTYPE_MEM) {
      // Load
      operand_load(rdreg+0, ra, OP_ld, datatype);
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
    } else {
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      int rashift = reginfo[ra.reg.reg].sizeshift;
      this << TransOp(OP_mov, rdreg+0, REG_zero, rareg, REG_zero, rashift);
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
    }
    break;
  }

  case 0x57e: { // movd rm32/rm64,xmm
    DECODE(eform, rd, v_mode);
    DECODE(gform, ra, x_mode);
    CheckInvalid();
    int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    if (rd.type == OPTYPE_MEM) {
      result_store(rareg, REG_temp0, rd, datatype);
    } else {
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int rdshift = reginfo[rd.reg.reg].sizeshift;
      this << TransOp(OP_mov, rdreg, (rdshift < 3) ? rdreg : REG_zero, rareg, REG_zero, rdshift);
    }
    break;
  }

  case 0x27e: { // movq xmm,xmmlo|mem64 with zero extension
    DECODE(gform, rd, x_mode);
    DECODE(eform, ra, x_mode);
    CheckInvalid();
    int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    if (ra.type == OPTYPE_MEM) {
      // Load
      operand_load(rdreg+0, ra, OP_ld, datatype);
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
    } else {
      // Move from xmm to xmm
      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      this << TransOp(OP_mov, rdreg+0, REG_zero, rareg, REG_zero, 3);
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
    }
    break;
  }

  case 0x5d6: { // movd xmmlo|mem64,xmm with zero extension
    DECODE(eform, rd, v_mode);
    DECODE(gform, ra, x_mode);
    CheckInvalid();
    int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
    int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
    if (rd.type == OPTYPE_MEM) {
      result_store(rareg, REG_temp0, rd, datatype);
    } else {
      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      this << TransOp(OP_mov, rdreg, REG_zero, rareg, REG_zero, 3);
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
    }
    break;
  }

  default: {
    MakeInvalid();
    break;
  }
  }

  return true;
}
