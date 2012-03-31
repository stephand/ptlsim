//
// PTLsim: Cycle Accurate x86-64 Simulator
// Decoder for ASF-Extensions to AMD64 instruction set.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
// 02110-1301, USA.
//
// Copyright (c) 2007-2010 Advanced Micro Devices, Inc.
// Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
//

#include <decode.h>
#include <superstl.h>
#include <ptlhwdef.h>

/**
 * Scans backwards through the TransOp-buffer to find the last x-µop and flags it as having
 * ASF side effects. This allows us to use PTLsim's standard infrastructure for generation of
 * ops even for ASF's LOCKed loads and prefetches.
 * @param opcode The opcode which is to be scanned for and should be flagged.
 */
void TraceDecoder::scan_transb_and_flag_asf(byte opcode) {
  bool found_op = false;
  int i;

  for (i =  transbufcount-1; i >= 0; i--) {
    found_op = (transbuf[i].opcode == opcode);
    if (found_op) break;
  }
  assert(found_op);
  /* Flag the found op as being ASF, let the core handle the associated special functionality */
  transbuf[i].is_asf = 1;
}

enum {
  XOP_NONE = 0,
  XOP_ASF = 1,
};

// TODO: Complete this table for proper XOP decoding
const static byte xop_class[256] = {
    /* 00 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, XOP_ASF, /* 00 */
    /* 10 */  0, 0, XOP_ASF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 10 */
    /* 20 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 20 */
    /* 30 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 30 */
    /* 40 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 40 */
    /* 50 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 50 */
    /* 60 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 60 */
    /* 70 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 70 */
    /* 80 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80 */
    /* 90 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 90 */
    /* a0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* a0 */
    /* b0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* b0 */
    /* c0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* c0 */
    /* d0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* d0 */
    /* e0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* e0 */
    /* f0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  /* f0 */
};

/**
 * Decode XOP instruction
 * @return true, when further decoding is possible, false, if not
 */
bool TraceDecoder::decode_xop() {
  // Translate the XOP extension bytes to the REX equivalents
  rex.extbase  = !xop2.extbaseinv;
  rex.extindex = !xop2.extindexinv;
  rex.extreg   = !xop2.extreginv;
  rex.mode64   =  xop3.mode64;

  switch (xop_class[op & 0xFF]) {
    case XOP_ASF:
      return decode_asf();
    // TODO: Add proper decoding for all the other XOP instructions
    default:
      MakeInvalid();
  }
  return false;
}
static const byte sse_float_datatype_to_ptl_datatype[4] = {DATATYPE_FLOAT, DATATYPE_VEC_FLOAT, DATATYPE_DOUBLE, DATATYPE_VEC_DOUBLE};
/**
 * Decodes a single ASF instruction
 * @return true, when further decoding is possible, false, if not
 */
bool TraceDecoder::decode_asf() {
  DecodedOperand ra;
  DecodedOperand rd;
  /* This is an ugly hack to check whether we run in an ASF enabled model. */
  bool isasfcore = (PTLsimMachine::getcurrent() == PTLsimMachine::getmachine("asfooo"));

  // TODO: Proper decoding of the source / target register instead of hard-wired RAX
  switch (op) {
    case 0x70F: {
      /* SPECULATE, ABORT & COMMIT */
      if (!isasfcore) MakeInvalid();
      DECODE(gform, ra, v_mode);
      EndOfDecode();

      assert (ra.type == OPTYPE_REG);
      int reg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      int sizeshift = reginfo[ra.reg.reg].sizeshift;
      // These ASF primitives work with RAX only (for now)
      if (reg != REG_rax) MakeInvalid();

      switch (modrm.rm) {
        /* SPECULATE */
        case 0x5: {
          /* Decode into a new µop */
          TransOp spec(OP_spec, reg, REG_rsp, REG_zero, REG_zero, sizeshift, 0, 0, FLAGS_DEFAULT_ALU);
          spec.is_asf = true; this << spec;
          // prevent LOCKed memops to issue before SPECulate is commited
          TransOp mf(OP_mf, REG_temp0, REG_zero, REG_zero, REG_zero, 0);
          mf.extshift = MF_TYPE_LFENCE | MF_TYPE_SFENCE;
          mf.is_asf = true; this << mf;
          break;
        }
        /* ABORT */
        case 0x6: {
          /* Decode into an assist */
          this << TransOp(OP_mov, REG_ar1, REG_zero, reg, REG_zero, sizeshift);
          microcode_assist(ASSIST_ASF_ABORT, ripstart, rip);
          break;
        }
        /* COMMIT */
        case 0x7: {
          /* Decode into a new µop */
          TransOp com(OP_com, reg, REG_zero, REG_zero, REG_zero, 3, 0, 0, FLAGS_DEFAULT_ALU);
          com.is_asf = true; this << com;
          /* this is a special ASF-LFENCE, it will only sort memops which
             try to access data still protected by an ongoing ASF-CS. */
          TransOp mf(OP_mf, REG_temp0, REG_zero, REG_zero, REG_zero, 0);
          mf.extshift = MF_TYPE_LFENCE | MF_TYPE_SFENCE;
          mf.is_asf = true; this << mf;
          break;
        }
        default: {
          cerr << __FILE__,"@",__LINE__,": Unknown ModR/M (", modrm.rm, ") for opcode 0x70f\n";
          cerr.flush();
          MakeInvalid();
          break;
        }
        return true;
      }
      break;
    }

    /* RELEASE */
    case 0x712: {
      if (!isasfcore) MakeInvalid();

      DECODE(eform, ra, b_mode);
      EndOfDecode();

      logfile << "Saw ASF 2.0 release\n", ra, endl;
      if (ra.type != OPTYPE_MEM) MakeInvalid();

      /* Decode into a new µop */
      operand_load(REG_temp0, ra, OP_rel);
      scan_transb_and_flag_asf(OP_rel);
      break;
    }


    case 0x88 ... 0x8b: {
      /* LOCKed MOVs */
      if (!isasfcore) MakeInvalid();
      /* Remove the LOCK prefix, as it was just used to flag the ASFness of this load */
      assert(prefixes & PFX_LOCK);
      prefixes &= ~PFX_LOCK;

      int bytemode = bit(op, 0) ? v_mode : b_mode;
      switch (bit(op, 1)) {
        case 0: DECODE(eform, rd, bytemode); DECODE(gform, ra, bytemode); break;
        case 1: DECODE(gform, rd, bytemode); DECODE(eform, ra, bytemode); break;
      }
      /* ASF permits only locked memory operations! */
      if (ra.type != OPTYPE_MEM && rd.type != OPTYPE_MEM ) MakeInvalid();
      EndOfDecode();

      move_reg_or_mem(rd, ra);
      /* search for and flag the ld-µop as ASF */
      if (ra.type == OPTYPE_MEM ) scan_transb_and_flag_asf(OP_ld);
      else if (rd.type == OPTYPE_MEM ) scan_transb_and_flag_asf(OP_st);
      break;
    }
    case 0xa0 ... 0xa3: {
      // mov rAX,Ov and vice versa
      if (!isasfcore) MakeInvalid();
      assert(prefixes & PFX_LOCK);
      prefixes &= ~PFX_LOCK;
      rd.gform_ext(*this, (op & 1) ? v_mode : b_mode, REG_rax);
      DECODE(iform64, ra, (use64 ? q_mode : addrsize_prefix ? w_mode : d_mode));
      EndOfDecode();

      ra.mem.offset = ra.imm.imm;
      ra.mem.offset = (use64) ? ra.mem.offset : lowbits(ra.mem.offset, (addrsize_prefix) ? 16 : 32);
      ra.mem.basereg = APR_zero;
      ra.mem.indexreg = APR_zero;
      ra.mem.scale = APR_zero;
      ra.mem.size = reginfo[rd.reg.reg].sizeshift;
      ra.type = OPTYPE_MEM;

      if (inrange(op, 0xa2, 0xa3)) {
        result_store(REG_rax, REG_temp0, ra);
        scan_transb_and_flag_asf(OP_st);
      } else {
        operand_load(REG_rax, ra);
        scan_transb_and_flag_asf(OP_ld);
      }
      break;
    }

    // LOCKed vector loads (NOTE: Copy'n'pasted mostly from decode-sse.cpp)
    case 0x56e: { // LOCK movd xmm,rm32/rm64
      if (!isasfcore) MakeInvalid();
      assert(prefixes & PFX_LOCK);
      prefixes &= ~PFX_LOCK;
      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, v_mode);
      EndOfDecode();

      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
      if (ra.type != OPTYPE_MEM) MakeInvalid();

      // Load
      operand_load(rdreg+0, ra, OP_ld, datatype);
      /* search for and flag the ld-µop as ASF */
      scan_transb_and_flag_asf(OP_ld);
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
      break;
    }

    case 0x57e: { // movd rm32/rm64,xmm
      if (!isasfcore) MakeInvalid();
      assert(prefixes & PFX_LOCK);
      prefixes &= ~PFX_LOCK;
      DECODE(eform, rd, v_mode);
      DECODE(gform, ra, x_mode);
      EndOfDecode();

      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];
      if (rd.type != OPTYPE_MEM) MakeInvalid();
      result_store(rareg, REG_temp0, rd, datatype);
      scan_transb_and_flag_asf(OP_st);
      break;
    }

    case 0x56f: // movdqa load
    case 0x26f: { // movdqu load
      if (!isasfcore) MakeInvalid();
      assert(prefixes & PFX_LOCK);
      prefixes &= ~PFX_LOCK;

      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      EndOfDecode();

      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];

      if (ra.type != OPTYPE_MEM) MakeInvalid();

      // Load
      // This is still idempotent since if the second one was unaligned, the first one must be too
      operand_load(rdreg+0, ra, OP_ld, datatype);
      /* just flag the first load as being ASF */
      scan_transb_and_flag_asf(OP_ld);
      ra.mem.offset += 8;
      operand_load(rdreg+1, ra, OP_ld, datatype);
      break;
    }

    case 0x57f: // movdqa store
    case 0x27f: { // movdqu store
      if (!isasfcore) MakeInvalid();
      assert(prefixes & PFX_LOCK);
      prefixes &= ~PFX_LOCK;

      DECODE(eform, rd, x_mode);
      DECODE(gform, ra, x_mode);
      EndOfDecode();

      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];

      if (rd.type != OPTYPE_MEM) MakeInvalid();

      // Store
      // This is still idempotent since if the second one was unaligned, the first one must be too
      result_store(rareg+0, REG_temp0, rd, datatype);
      /* just flag the first store as being ASF TODO: What happens, when data lies on two cachelines? */
      scan_transb_and_flag_asf(OP_st);
      rd.mem.offset += 8;
      result_store(rareg+1, REG_temp1, rd, datatype);
      break;
    };


    case 0x27e: { // LOCK movq xmm,xmmlo|mem64 with zero extension
      if (!isasfcore) MakeInvalid();
      assert(prefixes & PFX_LOCK);
      prefixes &= ~PFX_LOCK;

      DECODE(gform, rd, x_mode);
      DECODE(eform, ra, x_mode);
      EndOfDecode();

      int rdreg = arch_pseudo_reg_to_arch_reg[rd.reg.reg];
      int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];

      if (ra.type != OPTYPE_MEM) MakeInvalid();

      // Load
      operand_load(rdreg+0, ra, OP_ld, datatype);
      /* search for and flag the ld-µop as ASF */
      scan_transb_and_flag_asf(OP_ld);
      this << TransOp(OP_mov, rdreg+1, REG_zero, REG_zero, REG_zero, 3); // zero high 64 bits
      break;
    }

    case 0x5d6: { // movq xmmlo|mem64,xmm with zero extension
      if (!isasfcore) MakeInvalid();
      assert(prefixes & PFX_LOCK);
      prefixes &= ~PFX_LOCK;

      DECODE(eform, rd, x_mode);
      DECODE(gform, ra, x_mode);
      EndOfDecode();

      int rareg = arch_pseudo_reg_to_arch_reg[ra.reg.reg];
      int datatype = sse_float_datatype_to_ptl_datatype[(op >> 8) - 2];

      if (rd.type != OPTYPE_MEM) MakeInvalid();

      rd.mem.size = 3; // quadword
      result_store(rareg, REG_temp0, rd, datatype);
      /* search for and flag the st-µop as ASF */
      scan_transb_and_flag_asf(OP_st);
      break;
    }

    case 0x10d: {
      // prefetch(w) [eform] (NOTE: this is an AMD-only insn from K6 onwards)
      if (!isasfcore) MakeInvalid();
      DECODE(eform, ra, b_mode);
      EndOfDecode();

      int level = 2;
      assert(prefixes & PFX_LOCK);
      prefixes &= ~PFX_LOCK;
      operand_load(REG_temp0, ra, OP_ld, DATATYPE_INT, level, (modrm.reg == 1));
      /* search for and flag the ld-µop as ASF */
      scan_transb_and_flag_asf(OP_ld);
      break;
    }

    default:
      if (logable(3)) logfile << __FILE__,"@",__LINE__,": Unknown opcode ", hexstring(op, 32), " in ASF decoder\n";
      MakeInvalid();
      break;
  }
  return true;
}
