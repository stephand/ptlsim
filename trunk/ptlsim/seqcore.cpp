//
// PTLsim: Cycle Accurate x86-64 Simulator
// Sequential Core Simulator
//
// Copyright 2003-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>
#include <branchpred.h>
#include <dcache.h>
#include <datastore.h>

// With these disabled, simulation is faster
//#define ENABLE_CHECKS
//#define ENABLE_LOGGING

#ifndef ENABLE_CHECKS
#undef assert
#define assert(x) (x)
#endif

#undef logable
#ifdef ENABLE_LOGGING
#define logable(level) (loglevel >= level)
#else
#define logable(level) (0)
#endif

// This is an internal MSR required to correctly truncate ld/st pointers in 32-bit mode
extern W64 virt_addr_mask;

extern W64 total_uops_committed;
extern W64 total_user_insns_committed;
extern W64 sim_cycle;

namespace SequentialCore {

  BasicBlock* current_basic_block = null;
  Waddr current_basic_block_rip = 0;
  int current_basic_block_transop_index = 0;
  int bytes_in_current_insn = 0;
  int current_uop_in_macro_op;
  W64 current_uuid;

  // (n/a):
  W64 fetch_blocks_fetched;
  W64 fetch_uops_fetched;
  W64 fetch_user_insns_fetched;

  W64 bbcache_inserts;
  W64 bbcache_removes;
  
  W64 fetch_opclass_histogram[OPCLASS_COUNT];

  //
  // Make these local to the sequential core namespace
  // to avoid confusing the other core models:
  //
  W64 last_stats_captured_at_cycle = 0;

  CycleTimer ctseq;
  CycleTimer ctfetch;
  CycleTimer ctissue;
  CycleTimer ctcommit;

  //
  // Shadow flags are maintained for each archreg to simulate renaming,
  // since the x86 decoder assumes renaming will be done and hence may
  // specify some uops as "don't update user flags".
  //
  W64 arf[TRANSREG_COUNT];
  W64 arflags[TRANSREG_COUNT];

  ostream& print_state(ostream& os) {
    os << "General state:", endl;
    os << "  RIP:                ", (void*)(Waddr)arf[REG_rip], endl;
    os << "  Flags:              ", hexstring(arf[REG_flags], 16), " ", flagstring(arf[REG_flags]), endl;
    os << "  UUID:               ", current_uuid, endl;
    os << "  Bytes in macro-op:  ", bytes_in_current_insn, endl;
    os << "  Uop in macro-op:    ", current_uop_in_macro_op, endl;
    os << "Basic block state:", endl;
    os << "  Basic block RIP:    ", (void*)current_basic_block_rip, endl;
    os << "  BBcache block:      ", current_basic_block, endl;
    os << "  uop in basic block: ", current_basic_block_transop_index, endl;
    os << "  uop count in block: ", (current_basic_block) ? current_basic_block->count : 0, endl;
    os << "Register state:       ", endl;

    static const int width = 4;
    foreach (i, TRANSREG_COUNT) {
      stringbuf flagsb; flagsb << flagstring(arflags[i]);
      os << "    ", padstring(arch_reg_names[i], -6), " 0x", hexstring(arf[i], 64), "|", padstring(flagsb, -6), "  ";
      if ((i % width) == (width-1)) os << endl;
    }

    return os;
  }

  void reset_fetch(W64 realrip) {
    arf[REG_rip] = realrip;
    current_basic_block = null;
    current_basic_block_rip = 0;
    current_basic_block_transop_index = 0;
  }

  enum {
    ISSUE_COMPLETED = 1,
    ISSUE_REFETCH = 0,
    ISSUE_EXCEPTION = -1,
  };

  inline int check_access_alignment(W64 addr, AddressSpace::spat_t top, bool annul, int sizeshift, bool internal, int exception) {
    if (lowbits(addr, sizeshift))
      return EXCEPTION_UnalignedAccess;

    //
    // This load/store was the high part of an unaligned store but the actual user
    // address did not touch the high 64 bits. Since it is perfectly legal to do
    // an unaligned store to the very end of the page such that the next 64 bit
    // chunk is not mapped to a valid page, we must not do any further checks:
    //
    if (annul | internal)
      return 0;
      
    bool ok = asp.fastcheck(addr, top);

    return (ok) ? 0 : exception;
  }

  int issuestore(const TransOp& uop, SFR& state, W64 ra, W64 rb, W64 rc) {
    int sizeshift = uop.size;
    int aligntype = uop.cond;
    bool internal = uop.internal;

    Waddr rip = arf[REG_rip];

    W64 raddr = ra + rb;
    raddr &= virt_addr_mask;
    W64 origaddr = raddr;
    bool annul = 0;

    switch (aligntype) {
    case LDST_ALIGN_NORMAL:
      break;
    case LDST_ALIGN_LO:
      raddr = floor(raddr, 8); break;
    case LDST_ALIGN_HI:
      //
      // Is the high load ever even used? If not, don't check for exceptions;
      // otherwise we may erroneously flag page boundary conditions as invalid
      //
      raddr = floor(raddr, 8);
      annul = (floor(origaddr + ((1<<sizeshift)-1), 8) == raddr);
      raddr += 8;
      break;
    }

    W64 addr = lowbits(raddr, VIRT_ADDR_BITS);
    state.physaddr = addr >> 3;
    state.invalid = 0;
    //
    // Notice that datavalid is not set until both the rc operand to
    // store is ready AND any inherited SFR data is ready to merge.
    //
    state.datavalid = 0;
    state.addrvalid = 1;

    //
    // Special case: if no part of the actual user load/store falls inside
    // of the high 64 bits, do not perform the access and do not signal
    // any exceptions if that page was invalid.
    //
    // However, we must be extremely careful if we're inheriting an SFR
    // from an earlier store: the earlier store may have updated some
    // bytes in the high 64-bit chunk even though we're not updating
    // any bytes. In this case we still must do the write since it
    // could very well be the final commit to that address. In any
    // case, the SFR mismatch and LSAT must still be checked.
    //
    // The store commit code checks if the bytemask is zero and does
    // not attempt the actual store if so. This will always be correct
    // for high stores as described in this scenario.
    //

    bool ready;
    byte bytemask;

    W64 exception = check_access_alignment(addr, asp.writemap, annul, uop.size, uop.internal, EXCEPTION_PageFaultOnWrite);

    if (exception) {
      state.invalid = 1;
      state.data = exception;
      state.datavalid = 1;

      if (exception == EXCEPTION_UnalignedAccess) {
        //
        // If we have an unaligned access, mark all loads and stores at this 
        // macro-op's rip as being unaligned and remove the basic block from
        // the bbcache so it gets retranslated with properly split loads
        // and stores after we resume fetching.
        //
        // As noted elsewhere, the bbcache is for simulator purposes only;
        // the real hardware would detect unaligned uops in the fetch stage
        // and split them up on the fly. For simulation, it's more efficient
        // to just split them once in the bbcache; this has no performance
        // effect on the cycle accurate results.
        //
        if (logable(1)) {
          logfile << intstring(current_uuid, 20), " stalgn", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ",
            "0x", hexstring(addr, 48), " size ", (1<<uop.size), " ", uop, endl;
        }

        return ISSUE_REFETCH;
      }

      if (logable(1)) logfile << intstring(current_uuid, 20), " store ", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ", state, " ", uop, endl;

      return ISSUE_EXCEPTION;
    }

    //
    // At this point all operands are valid, so merge the data and mark the store as valid.
    //

    switch (aligntype) {
    case LDST_ALIGN_NORMAL:
    case LDST_ALIGN_LO:
      bytemask = ((1 << (1 << sizeshift))-1) << (lowbits(origaddr, 3));
      rc <<= 8*lowbits(origaddr, 3);
      break;
    case LDST_ALIGN_HI:
      bytemask = ((1 << (1 << sizeshift))-1) >> (8 - lowbits(origaddr, 3));
      rc >>= 8*(8 - lowbits(origaddr, 3));
    }

    state.invalid = 0;
    state.data = rc;
    state.bytemask = bytemask;
    state.datavalid = 1;

    if (logable(1)) {
      logfile << intstring(current_uuid, 20), " store ", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ", state, " ", uop;
      if (uop.eom) logfile << " [EOM #", total_user_insns_committed, "]";
      logfile << endl;
    }

    return ISSUE_COMPLETED;
  }

  static inline W64 loaddata(void* target, int SIZESHIFT, bool SIGNEXT) {
    W64 data;
    switch (SIZESHIFT) {
    case 0:
      data = (SIGNEXT) ? (W64s)(*(W8s*)target) : (*(W8*)target); break;
    case 1:
      data = (SIGNEXT) ? (W64s)(*(W16s*)target) : (*(W16*)target); break;
    case 2:
      data = (SIGNEXT) ? (W64s)(*(W32s*)target) : (*(W32*)target); break;
    case 3:
      data = *(W64*)target; break;
    }
    return data;
  }

  CycleTimer ctload;

  int issueload(const TransOp& uop, SFR& state, W64 ra, W64 rb, W64 rc) {
    static const bool DEBUG = 0;

    int sizeshift = uop.size;
    int aligntype = uop.cond;
    bool internal = uop.internal;
    bool signext = (uop.opcode == OP_ldx);

    Waddr rip = arf[REG_rip];

    W64 raddr = (aligntype == LDST_ALIGN_NORMAL) ? ra + rb : ra;
    // if (aligntype == LDST_ALIGN_NORMAL) raddr += (rc << uop.extshift);
    raddr &= virt_addr_mask;
    W64 origaddr = raddr;
    bool annul = 0;

    switch (aligntype) {
    case LDST_ALIGN_NORMAL:
      break;
    case LDST_ALIGN_LO:
      raddr = floor(raddr, 8); break;
    case LDST_ALIGN_HI:
      //
      // Is the high load ever even used? If not, don't check for exceptions;
      // otherwise we may erroneously flag page boundary conditions as invalid
      //
      raddr = floor(raddr, 8);
      annul = (floor(origaddr + ((1<<sizeshift)-1), 8) == raddr);
      raddr += 8; 
      break;
    }

    W64 addr = lowbits(raddr, VIRT_ADDR_BITS);

    state.physaddr = addr >> 3;
    state.addrvalid = 1;
    state.datavalid = 1;
    state.invalid = 0;

    W64 exception = check_access_alignment(addr, asp.readmap, annul, uop.size, uop.internal, EXCEPTION_PageFaultOnRead);

    if (exception) {
      state.invalid = 1;
      state.data = exception;

      if (exception == EXCEPTION_UnalignedAccess) {
        // (see notes above for issuestore case)
        if (logable(1)) {
          logfile << intstring(current_uuid, 20), " ldalgn", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ",
            "0x", hexstring(addr, 48), " size ", (1<<sizeshift), " ", uop, endl;
        }

        return ISSUE_REFETCH;
      }

      logfile << intstring(current_uuid, 20), " load  ", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ", state, " ", uop, endl;

      return ISSUE_EXCEPTION;
    }

    W64 data;

    if (aligntype == LDST_ALIGN_HI) {
      //
      // Concatenate the aligned data from a previous ld.lo uop provided in rb
      // with the currently loaded data D as follows:
      //
      // rb | D
      //
      // Example:
      //
      // floor(a) floor(a)+8
      // ---rb--  --DD---
      // 0123456701234567
      //    XXXXXXXX
      //    ^ origaddr
      //
      if (!annul) {
        data = *((W64*)(Waddr)floor(addr, 8));
      
        struct {
          W64 lo;
          W64 hi;
        } aligner;
      
        aligner.lo = rb;
        aligner.hi = data;
      
        W64 offset = lowbits(origaddr - floor(origaddr, 8), 4);

        data = loaddata(((byte*)&aligner) + offset, sizeshift, signext);
      } else {
        //
        // annulled: we need no data from the high load anyway; only use the low data
        // that was already checked for exceptions and forwarding:
        //
        W64 offset = lowbits(origaddr, 3);
        state.data = loaddata(((byte*)&rb) + offset, sizeshift, signext);
        state.invalid = 0;
        state.datavalid = 1;

        if (logable(1)) {
          logfile << intstring(current_uuid, 20), " load  ", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ",
            "0x", hexstring(addr, 48), " was annulled (high unaligned load)", endl;
        }

        return ISSUE_COMPLETED;
      }
    } else {
      // x86-64 requires virtual addresses to be canonical: if bit 47 is set, all upper 16 bits must be set
      W64 realaddr = (W64)signext64(addr, 48);
      data = loaddata((void*)(Waddr)realaddr, sizeshift, signext);
    }

    //
    // NOTE: Technically the data is valid right now for simulation purposes
    // only; in reality it may still be arriving from the cache.
    //
    state.data = data;
    state.invalid = 0;
    state.datavalid = 1;
    state.bytemask = 0xff;

    if (logable(1)) {
      logfile << intstring(current_uuid, 20), " load  ", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ", "0x", hexstring(state.data, 64), "|     ", " ", uop;
      if (uop.eom) logfile << " [EOM #", total_user_insns_committed, "]";
      logfile << endl;
    }

    return ISSUE_COMPLETED;
  }

  //
  // Do we need to update REG_cf/REG_sf/REG_zf/etc. here too? Yes.
  //

  byte archreg_remap_table[TRANSREG_COUNT] = {
    REG_rax,  REG_rcx,  REG_rdx,  REG_rbx,  REG_rsp,  REG_rbp,  REG_rsi,  REG_rdi,
    REG_r8,  REG_r9,  REG_r10,  REG_r11,  REG_r12,  REG_r13,  REG_r14,  REG_r15,

    REG_xmml0,  REG_xmmh0,  REG_xmml1,  REG_xmmh1,  REG_xmml2,  REG_xmmh2,  REG_xmml3,  REG_xmmh3,
    REG_xmml4,  REG_xmmh4,  REG_xmml5,  REG_xmmh5,  REG_xmml6,  REG_xmmh6,  REG_xmml7,  REG_xmmh7,

    REG_xmml8,  REG_xmmh8,  REG_xmml9,  REG_xmmh9,  REG_xmml10,  REG_xmmh10,  REG_xmml11,  REG_xmmh11,
    REG_xmml12,  REG_xmmh12,  REG_xmml13,  REG_xmmh13,  REG_xmml14,  REG_xmmh14,  REG_xmml15,  REG_xmmh15,

    REG_fptos,  REG_fpsw,  REG_fpcw,  REG_fptags,  REG_fp4,  REG_fp5,  REG_fp6,  REG_fp7,

    REG_rip,  REG_flags,  REG_sr3,  REG_mxcsr,  REG_sr0,  REG_sr1,  REG_sr2,  REG_zero,

    REG_temp0,  REG_temp1,  REG_temp2,  REG_temp3,  REG_temp4,  REG_temp5,  REG_temp6,  REG_temp7,

    // Notice how these (REG_zf, REG_cf, REG_of) are all mapped to REG_flags in an in-order processor:
    REG_flags,  REG_flags,  REG_flags,  REG_imm,  REG_mem,  REG_temp8,  REG_temp9,  REG_temp10,
  };

  void external_to_core_state() {
    foreach (i, ARCHREG_COUNT) {
      arf[i] = ctx.commitarf[i];
      arflags[i] = 0;
    }
    for (int i = ARCHREG_COUNT; i < TRANSREG_COUNT; i++) {
      arf[i] = 0;
      arflags[i] = 0;
    }
  }

  void core_to_external_state() {
    foreach (i, ARCHREG_COUNT) {
      ctx.commitarf[i] = arf[i];
    }
  }

  bool handle_barrier() {
    core_to_external_state();
    assist_func_t assist = (assist_func_t)(Waddr)ctx.commitarf[REG_rip];

    if (logable(1)) logfile << "Barrier (", (void*)assist, " ", assist_name(assist), " called from ", (void*)(Waddr)ctx.commitarf[REG_sr1],
      ") at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;

    if (logable(1)) logfile << "Calling assist function at ", (void*)assist, "...", endl, flush; 

    update_assist_stats(assist);
    assist();
    ctx.commitarf[REG_rip] = ctx.commitarf[REG_sr1];
    if (logable(1)) {
      logfile << "Done with assist", endl;
      logfile << "New state:", endl;
      logfile << ctx.commitarf;
    }

    reset_fetch(ctx.commitarf[REG_sr1]);
    external_to_core_state();

    if (requested_switch_to_native) {
      logfile << "PTL call requested switch to native mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], endl;
      return false;
    }

    return true;
  }

  bool handle_exception() {
    core_to_external_state();

    if (logable(1)) 
      logfile << "Exception (", exception_name(ctx.exception), " called from ", (void*)(Waddr)ctx.commitarf[REG_rip], 
        ") at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;

    stringbuf sb;
    sb << exception_name(ctx.exception), " detected at fault rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " @ ", 
      total_user_insns_committed, " commits (", total_uops_committed, " uops): genuine user exception (",
      exception_name(ctx.exception), "); aborting";
    logfile << sb, endl, flush;
    cerr << sb, endl, flush;
    logfile << flush;

    logfile << "Aborting...", endl, flush;
    abort();

    return false;
  }

  W64 seq_total_basic_blocks;
  W64 seq_total_uops_committed;
  W64 seq_total_user_insns_committed;
  W64 seq_total_cycles;

  BasicBlock* fetch_or_translate_basic_block(Waddr rip) {
    BasicBlock** bb = bbcache(rip);
    
    if (bb) {
      current_basic_block = *bb;
      current_basic_block_rip = rip;
    } else {
      current_basic_block = translate_basic_block((byte*)rip);
      current_basic_block_rip = rip;
      assert(current_basic_block);
      synth_uops_for_bb(*current_basic_block);
      
      if (logable(1)) logfile << padstring("", 20), " xlate  rip ", (void*)rip, ": BB ", current_basic_block, " of ", current_basic_block->count, " uops", endl;
      bbcache_inserts++;
    }
    
    current_basic_block_transop_index = 0;

    return current_basic_block;
  }

  //
  // Execute one basic block sequentially
  //

  int execute_sequential(BasicBlock* bb, W64 insnlimit) {
    arf[REG_rip] = bb->rip;
    
    //
    // Fetch
    //
    
    bool barrier = 0;

    if (logable(1)) logfile << endl, "Sequentially executing basic block ", bb, " (rip ", (void*)(Waddr)bb->rip, ", ", bb->count, " uops), insn limit ", insnlimit, endl, flush;
    if (!bb->synthops) synth_uops_for_bb(*bb);
    bb->hitcount++;

    TransOpBuffer unaligned_ldst_buf;
    unaligned_ldst_buf.index = -1;

    int uopindex = 0;
    int current_uop_in_macro_op = 0;

    int user_insns = 0;

    seq_total_basic_blocks++;
    total_basic_blocks_committed++;

    while ((uopindex < bb->count) & (user_insns < insnlimit)) {
      if (!asp.fastcheck((byte*)(Waddr)arf[REG_rip], asp.execmap)) {
        if (logable(1)) logfile << padstring("", 20), " fetch  rip 0x", (void*)(Waddr)arf[REG_rip], ": bogus RIP", endl;
        ctx.exception = EXCEPTION_PageFaultOnExec;
        return SEQEXEC_INVALIDRIP;
      }

      TransOp uop;
      uopimpl_func_t synthop = null;

      if (!unaligned_ldst_buf.get(uop, synthop)) {
        uop = bb->transops[uopindex];
        synthop = bb->synthops[uopindex];
      }

      assert(uopindex < bb->count);

      if (uop.unaligned) {
        if (logable(1)) logfile << padstring("", 20), " fetch  rip 0x", (void*)(Waddr)arf[REG_rip], ": split unaligned load or store ", uop, endl;
        split_unaligned(uop, unaligned_ldst_buf);
        assert(unaligned_ldst_buf.get(uop, synthop));
      }
  
      if (uop.som) {
        current_uop_in_macro_op = 0;
        bytes_in_current_insn = uop.bytes;
        fetch_user_insns_fetched++;
      }

      fetch_uops_fetched++;

      fetch_opclass_histogram[opclassof(uop.opcode)]++;

      //
      // Issue
      //
      IssueState state;
      state.reg.rdflags = 0;
      ctx.exception = 0;

      IssueInput input;
      W64 radata = arf[archreg_remap_table[uop.ra]];
      W64 rbdata = (uop.rb == REG_imm) ? uop.rbimm : arf[archreg_remap_table[uop.rb]];
      W64 rcdata = (uop.rc == REG_imm) ? uop.rcimm : arf[archreg_remap_table[uop.rc]];

      W16 raflags = arflags[archreg_remap_table[uop.ra]];
      W16 rbflags = arflags[archreg_remap_table[uop.rb]];
      W16 rcflags = arflags[archreg_remap_table[uop.rc]];

      bool ld = isload(uop.opcode);
      bool st = isstore(uop.opcode);
      bool br = isbranch(uop.opcode);

      SFR sfr;
      
      bool refetch = 0;

      if (ld|st) {
        int status = (ld) ? issueload(uop, sfr, radata, rbdata, rcdata) : issuestore(uop, sfr, radata, rbdata, rcdata);
        
        state.reg.rddata = sfr.data;
        state.reg.rdflags = 0;

        if (status == ISSUE_EXCEPTION) {
          ctx.exception = state.reg.rddata;
          return SEQEXEC_EXCEPTION;
        } else if (status == ISSUE_REFETCH) {
          if (logable(1)) {
            logfile << intstring(current_uuid, 20), " algnfx", " rip ", (void*)(Waddr)arf[REG_rip], ":", intstring(current_uop_in_macro_op, -2), " ", 
              uop, ": set unaligned bit for uop index ", uopindex, " at iteration ", iterations, endl;
          }
          bb->transops[uopindex].unaligned = 1;
          continue;
        }
      } else if (br) {
        state.brreg.riptaken = uop.riptaken;
        state.brreg.ripseq = uop.ripseq;
        assert((void*)synthop);
        synthop(state, radata, rbdata, rcdata, raflags, rbflags, rcflags); 

        if ((!isclass(uop.opcode, OPCLASS_BARRIER)) && (!asp.fastcheck((void*)(Waddr)state.reg.rddata, asp.execmap))) {
          if (logable(1)) logfile << padstring("", 20), " fetch  rip 0x", (void*)(Waddr)arf[REG_rip], ": bogus RIP at branch target", endl;
          ctx.exception = EXCEPTION_PageFaultOnExec;
          return SEQEXEC_INVALIDRIP;
        }
        
        if (logable(1)) {
          stringbuf rdstr; print_value_and_flags(rdstr, state.reg.rddata, state.reg.rdflags);
          logfile << intstring(current_uuid, 20), (ctx.exception ? " except" : " issue "), " rip ", (void*)(Waddr)arf[REG_rip], ":", intstring(current_uop_in_macro_op, -2), " ", rdstr, " ", uop;
          if (uop.eom) logfile << " [EOM #", total_user_insns_committed, "]";
          logfile << endl;
        }

        bb->predcount += (uop.opcode == OP_jmp) ? 1 : (state.reg.rddata == uop.riptaken);
      } else {
        assert((void*)synthop);
        synthop(state, radata, rbdata, rcdata, raflags, rbflags, rcflags);
        if (state.reg.rdflags & FLAG_INV) ctx.exception = state.reg.rddata;
        
        if (logable(1)) {
          stringbuf rdstr; print_value_and_flags(rdstr, state.reg.rddata, state.reg.rdflags);
          logfile << intstring(current_uuid, 20), (ctx.exception ? " except" : " issue "), " rip ", (void*)(Waddr)arf[REG_rip], ":", intstring(current_uop_in_macro_op, -2), " ", rdstr, " ", uop;
          if (uop.eom) logfile << " [EOM #", total_user_insns_committed, "]";
          logfile << endl;
        }

        if (ctx.exception) {
          if (isclass(uop.opcode, OPCLASS_CHECK) & (ctx.exception == EXCEPTION_SkipBlock)) {
            W64 chk_recovery_rip = arf[REG_rip] + bytes_in_current_insn;
            if (logable(1)) logfile << "SkipBlock exception commit: advancing rip ", (void*)(Waddr)arf[REG_rip], " by ", bytes_in_current_insn, " bytes to ", 
                              (void*)(Waddr)chk_recovery_rip, endl;
            current_uuid++;
            arf[REG_rip] = chk_recovery_rip;
            return SEQEXEC_SKIPBLOCK;
          } else {
            return SEQEXEC_EXCEPTION;
          }
        }
      }

      //
      // Commit
      //

      total_uops_committed++;
      seq_total_uops_committed++;

      assert(!ctx.exception);

      if (st) {
        commitstore_unlocked(sfr);
      } else if (uop.rd != REG_zero) {
        arf[uop.rd] = state.reg.rddata;
        arflags[uop.rd] = state.reg.rdflags;
        
        if (!uop.nouserflags) {
          W64 flagmask = setflags_to_x86_flags[uop.setflags];
          arf[REG_flags] = (arf[REG_flags] & ~flagmask) | (state.reg.rdflags & flagmask);
          arflags[REG_flags] = arf[REG_flags];
        }
      }

      barrier = isclass(uop.opcode, OPCLASS_BARRIER);

      if (uop.eom) arf[REG_rip] = (uop.rd == REG_rip) ? state.reg.rddata : (arf[REG_rip] + bytes_in_current_insn);

      seq_total_user_insns_committed += uop.eom;
      total_user_insns_committed += uop.eom;
      user_insns += uop.eom;

      current_uuid++;
      // Don't advance on cracked loads/stores:
      uopindex += unaligned_ldst_buf.empty();
      current_uop_in_macro_op++;
      iterations++;
      sim_cycle++;
      seq_total_cycles++;

      if (logable(1) & 0) {
        logfile << "Core State after exec:", endl;
        logfile << ctx.commitarf;
      }
    }

    return (barrier) ? SEQEXEC_BARRIER : (insnlimit < bb->user_insn_count) ? SEQEXEC_EARLY_EXIT : SEQEXEC_OK;
  }

  int sequential_core_toplevel_loop() {
    logfile << "Starting sequential core toplevel loop at cycle ", sim_cycle, ", commits ", total_user_insns_committed, endl, flush;

    external_to_core_state();
    print_state(logfile);
    logfile << endl;
    
    int oldloglevel = loglevel;
    if (start_log_at_iteration != infinity) loglevel = 0;

    bool exiting = false;

    W64 stop_at_user_insns_limit = sequential_mode_insns;

    ctseq.start();

    W64 last_printed_status_at_cycle = 0;

    requested_switch_to_native = 0;

    while ((iterations < stop_at_iteration) & (total_user_insns_committed < stop_at_user_insns_limit)) {
      if ((iterations >= start_log_at_iteration) & (!loglevel)) {
        loglevel = oldloglevel;
        logfile << "Start logging (level ", loglevel, ") at cycle ", sim_cycle, endl, flush;
      }

      Waddr rip = arf[REG_rip];

      if ((sim_cycle - last_printed_status_at_cycle) >= 200000) {
        logfile << "Completed ", sim_cycle, " cycles, ", total_user_insns_committed, " commits (rip sample ", (void*)rip, "), ", iterations, " basic blocks", endl, flush;
        last_printed_status_at_cycle = sim_cycle;
      }

      if ((sim_cycle - last_stats_captured_at_cycle) >= snapshot_cycles) {
        last_stats_captured_at_cycle = sim_cycle;
      }

      //
      // Fetch
      //

      if (!asp.fastcheck((byte*)rip, asp.execmap)) {
        if (logable(1)) logfile << padstring("", 20), " fetch  rip 0x", (void*)rip, ": bogus RIP", endl;
        ctx.exception = EXCEPTION_PageFaultOnExec;
        if (!handle_exception()) break;
        return false;
      }

      current_basic_block = fetch_or_translate_basic_block(rip);

      int result = execute_sequential(current_basic_block, (stop_at_user_insns_limit - total_user_insns_committed));

      switch (result) {
      case SEQEXEC_OK:
      case SEQEXEC_SKIPBLOCK:
        // no action required
        break;
      case SEQEXEC_EARLY_EXIT:
        exiting = 1;
        break;
      case SEQEXEC_EXCEPTION:
      case SEQEXEC_INVALIDRIP:
        ctseq.stop();
        exiting = (!handle_exception());
        ctseq.start();
        break;
      case SEQEXEC_BARRIER:
        ctseq.stop();
        exiting = (!handle_barrier());
        ctseq.start();
        break;
      default:
        assert(false);
      }

      if (requested_switch_to_native) exiting = 1;

      if (exiting) break;
    }

    ctseq.stop();

    core_to_external_state();

    logfile << "Exiting sequential mode at ", total_user_insns_committed, " instructions, ", total_uops_committed, " uops and ", iterations, " iterations", endl;
    logfile << "Core State:", endl;
    logfile << ctx.commitarf;

    logfile << flush;

    // Start counting from zero in out of order core (only if desired)
    // total_uops_committed = 0;
    // total_user_insns_committed = 0;
    // sim_cycle = 0;

    return exiting;
  }

  void seq_capture_stats(DataStoreNode& root) {
    DataStoreNode& summary = root("summary"); {
      summary.add("basicblocks", seq_total_basic_blocks);
      summary.add("cycles", seq_total_cycles);
      summary.add("uops", seq_total_uops_committed);
      summary.add("insns", seq_total_user_insns_committed);
    }

    DataStoreNode& simulator = root("simulator"); {
      DataStoreNode& cycles = simulator("cycles"); {
        cycles.summable = 1;
        cycles.addfloat("exec", ctseq.seconds());
      }

      DataStoreNode& rate = simulator("rate"); {
        rate.addfloat("total-secs", ctseq.seconds());
        double seconds = ctseq.seconds();
        rate.addfloat("commits-per-sec", (double)seq_total_uops_committed / seconds);
        rate.addfloat("user-commits-per-sec", (double)seq_total_user_insns_committed / seconds);
      }

      DataStoreNode& bbcache = simulator("bbcache"); {
        bbcache.add("count", bbcache.count);
        bbcache.add("inserts", bbcache_inserts);
        bbcache.add("removes", bbcache_removes);
      }

      root.histogram("opclass", opclass_names, fetch_opclass_histogram, OPCLASS_COUNT);
      save_assist_stats(root("assist"));
    }
  }
};

int sequential_core_toplevel_loop() {
  return SequentialCore::sequential_core_toplevel_loop();
}

int execute_sequential(BasicBlock* bb) {
  SequentialCore::external_to_core_state();
  int rc = SequentialCore::execute_sequential(bb, bb->count);
  SequentialCore::core_to_external_state();
  return rc;
}

void seq_capture_stats(DataStoreNode& root) {
  SequentialCore::seq_capture_stats(root);
}
