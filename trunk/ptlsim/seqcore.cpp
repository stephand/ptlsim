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
#include <stats.h>

// With these disabled, simulation is faster
//#define ENABLE_CHECKS
//#define ENABLE_LOGGING

#ifndef ENABLE_CHECKS
#undef assert
#define assert(x) (x)
#endif

#ifndef ENABLE_LOGGING
#undef logable
#define logable(level) (0)
#endif

static const byte archreg_remap_table[TRANSREG_COUNT] = {
  REG_rax,  REG_rcx,  REG_rdx,  REG_rbx,  REG_rsp,  REG_rbp,  REG_rsi,  REG_rdi,
  REG_r8,  REG_r9,  REG_r10,  REG_r11,  REG_r12,  REG_r13,  REG_r14,  REG_r15,

  REG_xmml0,  REG_xmmh0,  REG_xmml1,  REG_xmmh1,  REG_xmml2,  REG_xmmh2,  REG_xmml3,  REG_xmmh3,
  REG_xmml4,  REG_xmmh4,  REG_xmml5,  REG_xmmh5,  REG_xmml6,  REG_xmmh6,  REG_xmml7,  REG_xmmh7,

  REG_xmml8,  REG_xmmh8,  REG_xmml9,  REG_xmmh9,  REG_xmml10,  REG_xmmh10,  REG_xmml11,  REG_xmmh11,
  REG_xmml12,  REG_xmmh12,  REG_xmml13,  REG_xmmh13,  REG_xmml14,  REG_xmmh14,  REG_xmml15,  REG_xmmh15,

  REG_fptos,  REG_fpsw,  REG_fptags,  REG_fpstack,  REG_tr4,  REG_tr5,  REG_tr6, REG_ctx,

  REG_rip,  REG_flags,  REG_iflags, REG_selfrip, REG_nextrip, REG_ar1, REG_ar2, REG_zero,

  REG_temp0,  REG_temp1,  REG_temp2,  REG_temp3,  REG_temp4,  REG_temp5,  REG_temp6,  REG_temp7,

  // Notice how these (REG_zf, REG_cf, REG_of) are all mapped to REG_flags in an in-order processor:
  REG_flags,  REG_flags,  REG_flags,  REG_imm,  REG_mem,  REG_temp8,  REG_temp9,  REG_temp10,
};

struct SequentialCore {
  SequentialCore(): ctx(contextof(0)) { }

  Context& ctx;

  SequentialCore(Context& ctx_): ctx(ctx_) { }

  BasicBlock* current_basic_block;
  int current_basic_block_transop_index;
  int bytes_in_current_insn;
  int current_uop_in_macro_op;
  W64 current_uuid;

  // (n/a):
  W64 fetch_blocks_fetched;
  W64 fetch_uops_fetched;
  W64 fetch_user_insns_fetched;

  W64 bbcache_inserts;
  W64 bbcache_removes;
  
  W64 fetch_opclass_histogram[OPCLASS_COUNT];

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
    current_basic_block_transop_index = 0;
  }

  enum {
    ISSUE_COMPLETED = 1,
    ISSUE_REFETCH = 0,
    ISSUE_EXCEPTION = -1,
  };

  //
  // Address generation common to both loads and stores
  //
  template <int STORE>
  void* addrgen(const TransOp& uop, SFR& state, Waddr& origaddr, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate, Waddr& addr, int& exception, PageFaultErrorCode& pfec, bool& annul) {
    int sizeshift = uop.size;
    int aligntype = uop.cond;
    bool internal = uop.internal;
    bool signext = (uop.opcode == OP_ldx);

    Waddr rip = arf[REG_rip];

    addr = (STORE) ? (ra + rb) : ((aligntype == LDST_ALIGN_NORMAL) ? (ra + rb) : ra);
    //
    // x86-64 requires virtual addresses to be canonical: if bit 47 is set, 
    // all upper 16 bits must be set. If this is not true, we need to signal
    // a general protection fault.
    //
    addr = (W64)signext64(addr, 48);
    addr &= ctx.virt_addr_mask;
    origaddr = addr;
    annul = 0;

    switch (aligntype) {
    case LDST_ALIGN_NORMAL:
      break;
    case LDST_ALIGN_LO:
      addr = floor(addr, 8); break;
    case LDST_ALIGN_HI:
      //
      // Is the high load ever even used? If not, don't check for exceptions;
      // otherwise we may erroneously flag page boundary conditions as invalid
      //
      addr = floor(addr, 8);
      annul = (floor(origaddr + ((1<<sizeshift)-1), 8) == addr);
      addr += 8; 
      break;
    }

    state.physaddr = addr >> 3;
    state.invalid = 0;
    state.addrvalid = 1;
    state.datavalid = 0;

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

    exception = 0;

    void* mapped = (annul) ? null : ctx.check_and_translate(addr, uop.size, STORE, uop.internal, exception, pfec, pteupdate);
    return mapped;
  }

  //
  // Handle exceptions common to both loads and stores
  //
  template <bool STORE>
  int handle_common_exceptions(const TransOp& uop, SFR& state, Waddr& origaddr, Waddr& addr, int& exception, PageFaultErrorCode& pfec) {
    if likely (!exception) return ISSUE_COMPLETED;

    int aligntype = uop.cond;

    state.invalid = 1;
    state.data = exception | ((W64)pfec << 32);
    state.datavalid = 1;

    if likely (exception == EXCEPTION_UnalignedAccess) {
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
      if (logable(6)) {
        logfile << intstring(current_uuid, 20), (STORE ? " stalgn" : " ldalgn"), " rip ",
          (void*)(Waddr)arf[REG_rip], ":", intstring(current_uop_in_macro_op, -2), "  ",
          "0x", hexstring(addr, 48), " size ", (1<<uop.size), " ", uop, endl;
      }

      return ISSUE_REFETCH;
    }

    if unlikely (((exception == EXCEPTION_PageFaultOnRead) | (exception == EXCEPTION_PageFaultOnWrite)) && (aligntype == LDST_ALIGN_HI)) {
      //
      // If we have a page fault on an unaligned access, and this is the high
      // half (ld.hi / st.hi) of that access, the page fault address recorded
      // in CR2 must be at the very first byte of the second page the access
      // overlapped onto (otherwise the kernel will repeatedly fault in the
      // first page, even though that one is already present.
      //
      origaddr = addr;
    }

    if (logable(6)) {
      logfile << intstring(current_uuid, 20), (STORE ? " store " : " load  "), " rip ",
        (void*)(Waddr)arf[REG_rip], ":", intstring(current_uop_in_macro_op, -2), "  ", state, " ", uop, endl;
    }

    return ISSUE_EXCEPTION;
  }

  int issuestore(const TransOp& uop, SFR& state, Waddr& origaddr, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate) {
    int status;
    Waddr rip = arf[REG_rip];
    int sizeshift = uop.size;
    int aligntype = uop.cond;

    Waddr addr;
    int exception = 0;
    PageFaultErrorCode pfec;
    bool annul;

    void* mapped = addrgen<1>(uop, state, origaddr, ra, rb, rc, pteupdate, addr, exception, pfec, annul);

    if unlikely ((status = handle_common_exceptions<1>(uop, state, origaddr, addr, exception, pfec)) != ISSUE_COMPLETED) return status;

    //
    // At this point all operands are valid, so merge the data and mark the store as valid.
    //
    state.physaddr = (annul) ? 0xffffffffffffffffULL : (mapped_virt_to_phys(mapped) >> 3);

    bool ready;
    byte bytemask;

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
    state.datavalid = !annul;

    if (logable(6)) {
      logfile << intstring(current_uuid, 20), " store ", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ", state, " ", uop;
#ifdef PTLSIM_HYPERVISOR
      logfile << " (orig @ 0x", hexstring(origaddr, 64), ")";
#endif
      if (uop.eom) logfile << " [EOM #", total_user_insns_committed, "]";
      logfile << endl;
    }

    return ISSUE_COMPLETED;
  }

  static inline W64 extract_bytes(void* target, int SIZESHIFT, bool SIGNEXT) {
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

  int issueload(const TransOp& uop, SFR& state, Waddr& origaddr, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate) {
    int status;
    Waddr rip = arf[REG_rip];
    int sizeshift = uop.size;
    int aligntype = uop.cond;
    bool signext = (uop.opcode == OP_ldx);
    Waddr addr;
    int exception = 0;
    PageFaultErrorCode pfec;
    bool annul;

    void* mapped = addrgen<0>(uop, state, origaddr, ra, rb, rc, pteupdate, addr, exception, pfec, annul);

    if unlikely ((status = handle_common_exceptions<0>(uop, state, origaddr, addr, exception, pfec)) != ISSUE_COMPLETED) return status;

    state.physaddr = (annul) ? 0xffffffffffffffffULL : (mapped_virt_to_phys(mapped) >> 3);

    W64 data = (annul) ? 0 : *((W64*)(Waddr)floor(signext64((Waddr)mapped, 48), 8));

    if unlikely (aligntype == LDST_ALIGN_HI) {
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
      if likely (!annul) {
        struct {
          W64 lo;
          W64 hi;
        } aligner;

        aligner.lo = rb;
        aligner.hi = data;

        W64 offset = lowbits(origaddr - floor(origaddr, 8), 4);

        data = extract_bytes(((byte*)&aligner) + offset, sizeshift, signext);
      } else {
        //
        // annulled: we need no data from the high load anyway; only use the low data
        // that was already checked for exceptions and forwarding:
        //
        W64 offset = lowbits(origaddr, 3);
        state.data = extract_bytes(((byte*)&rb) + offset, sizeshift, signext);
        state.invalid = 0;
        state.datavalid = 1;

        if (logable(6)) {
          logfile << intstring(current_uuid, 20), " load  ", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ",
            "0x", hexstring(addr, 48), " was annulled (high unaligned load)", endl;
        }

        return ISSUE_COMPLETED;
      }
    } else {
      data = extract_bytes(((byte*)&data) + lowbits(addr, 3), sizeshift, signext);
    }

    //
    // NOTE: Technically the data is valid right now for simulation purposes
    // only; in reality it may still be arriving from the cache.
    //
    state.data = data;
    state.invalid = 0;
    state.datavalid = 1;
    state.bytemask = 0xff;

    if (logable(6)) {
      logfile << intstring(current_uuid, 20), " load  ", " rip ", (void*)rip, ":", intstring(current_uop_in_macro_op, -2), "  ", "0x", hexstring(state.data, 64), "|     ", " ", uop;
      logfile << " @ 0x", hexstring(addr, 64);
#ifdef PTLSIM_HYPERVISOR
      logfile << " (phys 0x", hexstring(state.physaddr << 3, 64), ")";
#endif
      if (uop.eom) logfile << " [EOM #", total_user_insns_committed, "]";
      logfile << endl;
    }

    return ISSUE_COMPLETED;
  }

  void external_to_core_state() {
    foreach (i, ARCHREG_COUNT) {
      arf[i] = ctx.commitarf[i];
      arflags[i] = 0;
    }
    for (int i = ARCHREG_COUNT; i < TRANSREG_COUNT; i++) {
      arf[i] = 0;
      arflags[i] = 0;
    }

    arflags[REG_flags] = ctx.commitarf[REG_flags];
  }

  void core_to_external_state() {
    foreach (i, ARCHREG_COUNT) {
      ctx.commitarf[i] = arf[i];
    }
  }

  bool handle_barrier() {
    core_to_external_state();
    assist_func_t assist = (assist_func_t)(Waddr)ctx.commitarf[REG_rip];

    if (logable(4)) {
      logfile << "Barrier (", (void*)assist, " ", assist_name(assist), " called from ",
        (RIPVirtPhys(ctx.commitarf[REG_selfrip]).update(ctx)), "; return to ", (void*)(Waddr)ctx.commitarf[REG_nextrip],
        ") at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;
    }

    if (logable(6)) logfile << "Calling assist function at ", (void*)assist, "...", endl, flush; 

    update_assist_stats(assist);
    if (logable(6)) {
      logfile << "Before assist:", endl, ctx, endl;
#ifdef PTLSIM_HYPERVISOR
      logfile << sshinfo, endl;
#endif
    }

    assist(ctx);

    if (logable(6)) {
      logfile << "Done with assist", endl;
      logfile << "New state:", endl;
      logfile << ctx;
#ifdef PTLSIM_HYPERVISOR
      logfile << sshinfo;
#endif
    }

    reset_fetch(ctx.commitarf[REG_rip]);
    external_to_core_state();
#ifndef PTLSIM_HYPERVISOR
    if (requested_switch_to_native) {
      logfile << "PTL call requested switch to native mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], endl;
      return false;
    }
#endif
    return true;
  }

  bool handle_exception() {
    core_to_external_state();

#ifdef PTLSIM_HYPERVISOR
    if (logable(4)) {
      logfile << "PTL Exception ", exception_name(ctx.exception), " called from rip ", (void*)(Waddr)ctx.commitarf[REG_rip], 
        " at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;
    }

    //
    // Map PTL internal hardware exceptions to their x86 equivalents,
    // depending on the context. The error_code field should already
    // be filled out.
    //
    switch (ctx.exception) {
    case EXCEPTION_PageFaultOnRead:
    case EXCEPTION_PageFaultOnWrite:
    case EXCEPTION_PageFaultOnExec:
      ctx.x86_exception = EXCEPTION_x86_page_fault; break;
    case EXCEPTION_FloatingPointNotAvailable:
      ctx.x86_exception = EXCEPTION_x86_fpu_not_avail; break;
    case EXCEPTION_FloatingPoint:
      ctx.x86_exception = EXCEPTION_x86_fpu; break;
    default:
      logfile << "Unsupported internal exception type ", exception_name(ctx.exception), endl, flush;
      abort();
    }

    if (logable(4)) {
      logfile << ctx;
      logfile << sshinfo;
    }

    ctx.propagate_x86_exception(ctx.x86_exception, ctx.error_code, ctx.cr2);

    external_to_core_state();

    return true;
#else
    if (logable(6)) 
      logfile << "Exception (", exception_name(ctx.exception), " called from ", (void*)(Waddr)ctx.commitarf[REG_rip], 
        ") at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;

    stringbuf sb;
    logfile << exception_name(ctx.exception), " detected at fault rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " @ ", 
      total_user_insns_committed, " commits (", total_uops_committed, " uops): genuine user exception (",
      exception_name(ctx.exception), "); aborting", endl;
    logfile << ctx, endl;
    logfile << flush;

    logfile << "Aborting...", endl, flush;
    cerr << "Aborting...", endl, flush;

    abort();
    return false;
#endif
  }

#ifdef PTLSIM_HYPERVISOR
  bool handle_interrupt() {
    core_to_external_state();

    if (logable(6)) {
      logfile << "Interrupts pending at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;
      logfile << "Context at interrupt:", endl;
      logfile << ctx;
      logfile << sshinfo;
      logfile.flush();
    }

    ctx.event_upcall();

    if (logable(6)) {
      logfile << "After interrupt redirect:", endl;
      logfile << ctx;
      logfile << sshinfo;
      logfile.flush();
    }

    reset_fetch(ctx.commitarf[REG_rip]);
    external_to_core_state();

    return true;
  }
#endif

  W64 seq_total_basic_blocks;
  W64 seq_total_uops_committed;
  W64 seq_total_user_insns_committed;
  W64 seq_total_cycles;

  BasicBlock* fetch_or_translate_basic_block(Waddr rip) {
    RIPVirtPhys rvp(rip);

    rvp.update(ctx);

    BasicBlock* bb = bbcache(rvp);

    if likely (bb) {
      current_basic_block = bb;
    } else {
      current_basic_block = bbcache.translate(ctx, rvp);
      assert(current_basic_block);
      synth_uops_for_bb(*current_basic_block);
      
      if (logable(6)) logfile << padstring("", 20), " xlate  rip ", rvp, ": BB ", current_basic_block, " of ", current_basic_block->count, " uops", endl;
      bbcache_inserts++;
    }
    
    current_basic_block_transop_index = 0;

    current_basic_block->use(sim_cycle);
    return current_basic_block;
  }

  //
  // Execute one basic block sequentially
  //

  int execute(BasicBlock* bb, W64 insnlimit) {
    arf[REG_rip] = bb->rip;
    
    //
    // Fetch
    //
    
    bool barrier = 0;

    if (logable(5)) logfile << "Sequentially executing basic block ", bb->rip, " (", bb->count, " uops), insn limit ", insnlimit, endl, flush;

    if unlikely (!bb->synthops) synth_uops_for_bb(*bb);
    bb->hitcount++;

    TransOpBuffer unaligned_ldst_buf;
    unaligned_ldst_buf.index = -1;

    int uopindex = 0;
    int current_uop_in_macro_op = 0;

    int user_insns = 0;

    seq_total_basic_blocks++;
    total_basic_blocks_committed++;

    RIPVirtPhys rvp(arf[REG_rip]);

    assert(bb->rip.rip == arf[REG_rip]);

    // See comment below about idempotent updates
    W64 saved_flags = 0;

    while ((uopindex < bb->count) & (user_insns < insnlimit)) {
      TransOp uop;
      uopimpl_func_t synthop = null;

      if unlikely (arf[REG_rip] == config.stop_at_rip) {
        return SEQEXEC_EARLY_EXIT;
      }

      if unlikely (arf[REG_rip] == config.start_log_at_rip) {
        config.start_log_at_iteration = 0;
        logenable = 1;
      }

      if likely (!unaligned_ldst_buf.get(uop, synthop)) {
        uop = bb->transops[uopindex];
        synthop = bb->synthops[uopindex];
      }

      assert(uopindex < bb->count);

      if unlikely (uop.unaligned) {
        if (logable(6)) logfile << padstring("", 20), " fetch  rip 0x", (void*)(Waddr)arf[REG_rip], ": split unaligned load or store ", uop, endl;
        split_unaligned(uop, unaligned_ldst_buf);
        assert(unaligned_ldst_buf.get(uop, synthop));
      }
  
      if likely (uop.som) {
        current_uop_in_macro_op = 0;
        bytes_in_current_insn = uop.bytes;
        fetch_user_insns_fetched++;
        // Update the span of bytes to watch for SMC:
        rvp.update(ctx, uop.bytes);
        //
        // Save the flags at the start of this x86 insn in
        // case an ALU uop inside the macro-op updates the
        // flags before all exceptions (i.e. from stores)
        // can be detected. All other registers are updated
        // idempotently.
        //
        saved_flags = arf[REG_flags];
      }

      //
      // Check for self modifying code (SMC) by checking if any previous
      // instruction has dirtied the page(s) on which the current instruction
      // resides. The SMC check is done first since it's perfectly legal for a
      // store to overwrite its own instruction bytes, but this update only
      // becomes visible after the store has committed.
      //
      if unlikely (smc_isdirty(rvp.mfnlo) | (smc_isdirty(rvp.mfnhi))) {
        logfile << "Self-modifying code at rip ", rvp, " detected: mfn was dirty (invalidate and retry)", endl;
        bbcache.invalidate_page(rvp.mfnlo, INVALIDATE_REASON_SMC);
        if (rvp.mfnlo != rvp.mfnhi) bbcache.invalidate_page(rvp.mfnhi, INVALIDATE_REASON_SMC);
        return SEQEXEC_SMC;
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

      PTEUpdate pteupdate = 0;
      Waddr origvirt = 0;
      PageFaultErrorCode pfec = 0;

      bool force_fpu_not_avail_fault = 0;

#ifdef PTLSIM_HYPERVISOR
      if unlikely (uop.is_sse|uop.is_x87) {
        force_fpu_not_avail_fault = ctx.cr0.ts | (uop.is_x87 & ctx.cr0.em);
      }
#endif
      if unlikely (force_fpu_not_avail_fault) {
        if (logable(6)) {
          logfile << intstring(current_uuid, 20), " fpuchk", " rip ", (void*)(Waddr)arf[REG_rip], ":", intstring(current_uop_in_macro_op, -2), " ", 
            uop, ": FPU not available fault", endl;
        }
        ctx.exception = EXCEPTION_FloatingPointNotAvailable;
        ctx.error_code = 0;
        arf[REG_flags] = saved_flags;
        return SEQEXEC_EXCEPTION;
      } else if unlikely (ld|st) {
        int status;
        if likely (ld) {
          status = issueload(uop, sfr, origvirt, radata, rbdata, rcdata, pteupdate);
        } else if unlikely (uop.opcode == OP_mf) {
          // Memory fences are NOPs on the in-order core:
          status = ISSUE_COMPLETED;
          sfr.data = 0;
        } else {
          assert(st);
          status = issuestore(uop, sfr, origvirt, radata, rbdata, rcdata, pteupdate);
        }

        state.reg.rddata = sfr.data;
        state.reg.rdflags = 0;

        if (status == ISSUE_EXCEPTION) {
          ctx.exception = LO32(state.reg.rddata);
          ctx.error_code = HI32(state.reg.rddata); // page fault error code
#ifdef PTLSIM_HYPERVISOR
          ctx.cr2 = origvirt;
#endif
          arf[REG_flags] = saved_flags;
          return SEQEXEC_EXCEPTION;
        } else if (status == ISSUE_REFETCH) {
          if (logable(6)) {
            logfile << intstring(current_uuid, 20), " algnfx", " rip ", (void*)(Waddr)arf[REG_rip], ":", intstring(current_uop_in_macro_op, -2), " ", 
              uop, ": set unaligned bit for uop index ", uopindex, " at iteration ", iterations, endl;
          }
          bb->transops[uopindex].unaligned = 1;
          continue;
        }
      } else if unlikely (br) {
        state.brreg.riptaken = uop.riptaken;
        state.brreg.ripseq = uop.ripseq;
        assert((void*)synthop);
        synthop(state, radata, rbdata, rcdata, raflags, rbflags, rcflags); 

        if (logable(6)) {
          stringbuf rdstr; print_value_and_flags(rdstr, state.reg.rddata, state.reg.rdflags);
          logfile << intstring(current_uuid, 20), (ctx.exception ? " except" : " issue "), " rip ", (void*)(Waddr)arf[REG_rip], ":", intstring(current_uop_in_macro_op, -2), " ", rdstr, " ", uop;
          if (uop.eom) logfile << " [EOM #", total_user_insns_committed, "]";
          logfile << endl;
        }

        bb->predcount += (uop.opcode == OP_jmp) ? (state.reg.rddata == bb->lasttarget) : (state.reg.rddata == uop.riptaken);
        bb->lasttarget = state.reg.rddata;
      } else {
        assert((void*)synthop);
        synthop(state, radata, rbdata, rcdata, raflags, rbflags, rcflags);
        if unlikely (state.reg.rdflags & FLAG_INV) ctx.exception = LO32(state.reg.rddata);

        if (logable(6)) {
          stringbuf rdstr; print_value_and_flags(rdstr, state.reg.rddata, state.reg.rdflags);
          logfile << intstring(current_uuid, 20), (ctx.exception ? " except" : " issue "), " rip ", (void*)(Waddr)arf[REG_rip], ":", intstring(current_uop_in_macro_op, -2), " ", rdstr, " ", uop;
          if (uop.eom) logfile << " [EOM #", total_user_insns_committed, "]";
          logfile << endl;
        }

        if unlikely (ctx.exception) {
          if (isclass(uop.opcode, OPCLASS_CHECK) & (ctx.exception == EXCEPTION_SkipBlock)) {
            W64 chk_recovery_rip = arf[REG_rip] + bytes_in_current_insn;
            if (logable(6)) logfile << "SkipBlock exception commit: advancing rip ", (void*)(Waddr)arf[REG_rip], " by ", bytes_in_current_insn, " bytes to ", 
                              (void*)(Waddr)chk_recovery_rip, endl;
            current_uuid++;
            arf[REG_rip] = chk_recovery_rip;
            return SEQEXEC_SKIPBLOCK;
          } else {
            arf[REG_flags] = saved_flags;
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

      if unlikely (uop.opcode == OP_st) {
        if (sfr.bytemask) {
          storemask(sfr.physaddr << 3, sfr.data, sfr.bytemask);
          Waddr mfn = (sfr.physaddr << 3) >> 12;
          smc_setdirty(mfn);
        }
      } else if likely (uop.rd != REG_zero) {
        arf[uop.rd] = state.reg.rddata;
        arflags[uop.rd] = state.reg.rdflags;
        
        if (!uop.nouserflags) {
          W64 flagmask = setflags_to_x86_flags[uop.setflags];
          arf[REG_flags] = (arf[REG_flags] & ~flagmask) | (state.reg.rdflags & flagmask);
          arflags[REG_flags] = arf[REG_flags];
        }
      }

      if unlikely (pteupdate) ctx.update_pte_acc_dirty(origvirt, pteupdate);

      barrier = isclass(uop.opcode, OPCLASS_BARRIER);

      if (uop.eom) arf[REG_rip] = (uop.rd == REG_rip) ? state.reg.rddata : (arf[REG_rip] + bytes_in_current_insn);

      seq_total_user_insns_committed += uop.eom;
      total_user_insns_committed += uop.eom;
      user_insns += uop.eom;
      stats.summary.insns += uop.eom;
      stats.summary.uops++;

      current_uuid++;
      // Don't advance on cracked loads/stores:
      uopindex += unaligned_ldst_buf.empty();
      current_uop_in_macro_op++;
    }

    if (barrier) return SEQEXEC_BARRIER;

    return (insnlimit < bb->user_insn_count) ? SEQEXEC_EARLY_EXIT : SEQEXEC_OK;
  }

  int execute() {
    Waddr rip = arf[REG_rip];
    
    current_basic_block = fetch_or_translate_basic_block(rip);

    bool exiting = 0;

    int result = execute(current_basic_block, (config.stop_at_user_insns - total_user_insns_committed));
    
    switch (result) {
    case SEQEXEC_OK:
    case SEQEXEC_SMC:
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
#ifdef PTLSIM_HYPERVISOR
    case SEQEXEC_INTERRUPT:
      ctseq.stop();
      handle_interrupt();
      ctseq.start();
      break;
#endif
    default:
      assert(false);
    }

    return exiting;
  }
};

struct SequentialMachine: public PTLsimMachine {
  SequentialCore* cores[MAX_CONTEXTS];
  bool init_done;

  SequentialMachine(const char* name) {
    // Add to the list of available core types
    addmachine(name, this);
    init_done = 0;
  }

  //
  // Construct all the structures necessary to configure
  // the cores. This function is only called once, after
  // all other PTLsim subsystems are brought up.
  //
  virtual bool init(PTLsimConfig& config) {
    if (init_done) return true;

    foreach (i, contextcount) {
      cores[i] = new SequentialCore(contextof(i));
      //
      // Note: in a real cycle accurate model, config may
      // specify various ways of slicing contextcount up
      // into threads, cores and sockets; the appropriate
      // interconnect and cache hierarchy parameters may
      // be specified here.
      //
    }

    init_done = 1;
    return true;
  }

  //
  // Run the processor model, until a stopping point
  // is hit (as configured elsewhere in config).
  //
  virtual int run(PTLsimConfig& config) {
    logfile << "Starting sequential core toplevel loop at cycle ", sim_cycle, ", commits ", total_user_insns_committed, endl, flush;

    foreach (i, contextcount) {
      SequentialCore& core =* cores[i];
      Context& ctx = contextof(i);

      core.external_to_core_state();

      if (logable(100)) {
        logfile << "VCPU ", i, " initial state:", endl;
        core.print_state(logfile);
        logfile << endl;
      }
    }

#ifdef PTLSIM_HYPERVISOR
    if (logable(100)) {
      logfile << "Shared info at start:", endl;
      logfile << sshinfo;
    }
#endif

    bool exiting = false;

    while ((iterations < config.stop_at_iteration) & (total_user_insns_committed < config.stop_at_user_insns)) {
      if unlikely (iterations >= config.start_log_at_iteration) {
        logenable = 1;
      }

      update_progress();
      inject_events();

      foreach (i, contextcount) {
        SequentialCore& core =* cores[i];
        Context& ctx = contextof(i);

#ifdef PTLSIM_HYPERVISOR
        if unlikely (ctx.check_events()) core.handle_interrupt();
        if unlikely (!ctx.running) continue;
#endif
        exiting |= core.execute();
      }

      exiting |= check_for_async_sim_break();

      iterations++;
      sim_cycle++;
      stats.summary.cycles++;

      if unlikely (exiting) break;
    }

    logfile << "Exiting sequential mode at ", total_user_insns_committed, " commits, ", total_uops_committed, " uops and ", iterations, " iterations (cycles)", endl;

    foreach (i, contextcount) {
      SequentialCore& core =* cores[i];
      Context& ctx = contextof(i);

      core.core_to_external_state();

      if (logable(100)) {
        logfile << "Core State at end:", endl;
        logfile << ctx;
      }
    }

    return exiting;
  }

  //
  // Update any statistics in stats in preparation
  // for writing it somewhere. The model may also
  // directly update the global stats structure
  // while it runs; this is only for cleanup tasks
  // or computing derived values.
  //
  virtual void update_stats(PTLsimStats& stats) {
    // (nop)
  }

  int execute_sequential(Context& ctx) {
    SequentialCore& core = *cores[ctx.vcpuid];

    core.external_to_core_state();
    Waddr rip = ctx.commitarf[REG_rip];
    BasicBlock* bb = core.fetch_or_translate_basic_block(rip);
    int result = core.execute(bb, limits<W64>::max);
    core.core_to_external_state();

    return result;
  }
};

SequentialMachine seqmodel("seq");

int execute_sequential(Context& ctx) {
  if (!seqmodel.init_done) seqmodel.init(config);
  return seqmodel.execute_sequential(ctx);
}
