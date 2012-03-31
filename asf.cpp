/**
 * Support for AMD's experimental Advanced Synchronization Facility (ASF) for
 * PTLsim's out-of-order core model.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * Copyright (c) 2008-2012 Advanced Micro Devices, Inc.
 * Contributed by Stephan Diestelhorst <stephan.diestelhorst@amd.com>
 *
 * @author stephan.diestelhorst@amd.com
 * @date 01.12.2008
 */

#include <asf.h>
#include <ooocore.h>
#include <decode.h>

template <typename T> byte x86_genflags(T r);

#ifdef ENABLE_ASF_CACHE_BASED
ASFContext::ASFContext(LockedLineBuffer *l, OutOfOrderModel::OutOfOrderCore& core) :
  llb(l),l1_spec(&core.caches.L1),vcpuid_(core.coreid) {}
#else
ASFContext::ASFContext(LockedLineBuffer *l, OutOfOrderModel::OutOfOrderCore& core) :
  llb(l),vcpuid_(core.coreid){}
#endif

/**
 * Merges the ASF related context information into the general PTLsim architecture context
 * on aborts.
 * @param c Context to modify
 * @param commitrc Commit return code of the committing instruction.
 * @return Should the core continue with an assist after calling this?
 */
bool ASFContext::to_sim_context(Context& c, bool is_assist) {

  if (logable(5)) logfile << "[vcpu ", c.vcpuid,"]"__FILE__,__LINE__,
    ": Restoring context to contain",
    " RSP=", (void*)saved_rsp,
    " RIP=", (void*)abort_rip.rip,
    " RAX=", (void*)(((W64)software_abort << 16) | ((W64) (nest_level-1) << 8) | (status_code & 0xFF)),
    " (swab=", software_abort, " nest=", nest_level-1, " status=", status_code & 0xFF,")", endl;

  assert((nest_level > 0) && (nest_level <= 256));

  c.commitarf[REG_rax]   = ((W64)software_abort << 16) | ((W64) (nest_level-1) << 8) | (status_code & 0xFF);
  c.commitarf[REG_rsp]   = saved_rsp;
  c.commitarf[REG_flags] = x86_genflags(c.commitarf[REG_rax]);
  if (imprecise) {
    c.commitarf[REG_flags] |= ASF_IMPRECISE;
    //TODO: How do we access MSRs (to store the actual RIP of the exception)?
    //   -> They are specifically hard-coded into RDMSR / WRMSR assists :(
    // magic_msr = real_fault_rip;
  }

  switch (status_code) {
    case (ASF_CONTENTION):
    case (ASF_CAPACITY):
      break;
    case (ASF_DISALLOWED_OP):
      /* Use the assist_gp_fault to generate the GP fault. */
      is_assist            = false;
#if (0)
      // SD: Disable generation of GP exceptions for now.
      is_assist            = true;
      c.commitarf[REG_rip] = ASSIST_GP_FAULT;
#endif
      break;
  }

  /* Assists put the assist-ID into rip and use either selfrip or nextrip to
   * return to. Setting both to the same value forces assists that "consume"
   * the instruction and those that don't to return to behind speculate.
   */
  if (!is_assist) {
    c.commitarf[REG_rip] = abort_rip;
  } else {
    c.commitarf[REG_selfrip] = abort_rip;
    c.commitarf[REG_nextrip] = abort_rip;
  }

  return is_assist;
}

/**
 * Clears all ASF context.
 */
void ASFContext::reset() {
  software_abort  = 0;
  nest_level      = 0;
  status_code     = ASF_SUCCESS;
  abort_rip       = RIPVirtPhys::INVALID;
  saved_rsp       = 0;
  real_fault_rip  = 0;
  imprecise       = false;
  in_spec_reg     = false;
}

/**
 * Enters a ASF speculative region.
 */
void ASFContext::enter_spec_region(const Context& c) {
  assert(in_spec_reg == (nest_level > 0));
  if (nest_level >= ASF_MAX_NESTING_DEPTH)
    // TODO: Generate proper error here
    assert(false);

  // just prevent nesting different types for now, otherwise we need a
  // bit state per level
  if (nest_level > 1) {
    assert(false == inverted);
  }
  nest_level++;

  if (nest_level == 1) {
    in_spec_reg = true;
    inverted = false;
    llb->clear();
#ifdef ENABLE_ASF_CACHE_BASED
    l1_spec->start();
#endif
    /* Store context for later roll-back */
    abort_rip   = c.commitarf[REG_rip] + 5; // FIXME: This relies on knowing the length of the SPECULATE AMD64 instruction
    saved_rsp   = c.commitarf[REG_rsp];
    if (logable(5)) logfile << __FILE__,__LINE__,": SPECULATE stores ",abort_rip, " and RSP=",(void*)saved_rsp, endl;
  }
}

/**
 * Enters a ASF speculative region with inverted default semantics.
 */
void ASFContext::enter_spec_inv_region(const Context& c) {
  assert(in_spec_reg == (nest_level > 0));
  if (nest_level >= ASF_MAX_NESTING_DEPTH)
    // TODO: Generate proper error here
    assert(false);

  // just prevent nesting different types for now, otherwise we need a
  // bit state per level
  if (nest_level > 1) {
    assert(true == inverted);
  }
  nest_level++;

  if (nest_level == 1) {
    in_spec_reg = true;
    inverted = true;
    llb->clear();
#ifdef ENABLE_ASF_CACHE_BASED
    l1_spec->start();
#endif
    /* Store context for later roll-back */
    abort_rip   = c.commitarf[REG_rip] + 5; // FIXME: This relies on knowing the length of the SPECULATE AMD64 instruction
    saved_rsp   = c.commitarf[REG_rsp];
    if (logable(5)) logfile << __FILE__,__LINE__,": SPECULATE stores ",abort_rip, " and RSP=",(void*)saved_rsp, endl;
  }
}

/**
 * Leaves a speculative region
 */
void ASFContext::leave_spec_region() {
  assert(in_spec_reg == (nest_level > 0));
  assert(nest_level <= ASF_MAX_NESTING_DEPTH);

  nest_level--;
  if (!nest_level) {
    in_spec_reg = false;
    llb->commit();
#ifdef ENABLE_ASF_CACHE_BASED
    l1_spec->commit();
#endif
  }
}

/**
 * Sets the fields to a capacity error.
 * @param rip  Address of the instruction causing the error.
 * @param addr Virtual address that was accessed with that instruction.
 */
void ASFContext::capacity_error(W64 rip, Waddr addr) {
  if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
    ": Capacity overflow on ", (void*)addr, " in spec region @ ",(void*) rip,
    " Aborting!", endl;

  status_code     = ASF_CAPACITY;
}

/**
 * Sets the fields for a far control transfer.
 * @param rip
 */
void ASFContext::interrupt(W64 rip) {
  if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
    ": Interrupt in spec region @ ",(void*) rip," Aborting!", endl;

  status_code = ASF_FAR;
  imprecise   = false;
}

/**
 * Sets the fields for an assist.
 * @param rip Address of the instruction causing the exception.
 */
void ASFContext::exception(W64 rip) {
  if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
    ": Exeption in spec region @ ",(void*) rip," Aborting!", endl;

  status_code    = ASF_FAR;
  imprecise      = true;
  real_fault_rip = rip;
}
/**
 * Sets the fields for a disallowed instruction.
 * @param rip Actual address of the offending instruction.
 */
void ASFContext::disallowed(W64 rip) {
  if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
    ": Illegal opcode in spec region @ ",(void*) rip," Aborting!", endl;

  status_code    = ASF_DISALLOWED_OP;
  imprecise      = true;
  real_fault_rip = rip;
}
void ASFContext::contention(W64 rip, Waddr addr) {
  if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
    ": Contention on ", (void*) addr," in spec region @ ",(void*) rip,
    " Aborting!", endl;

  status_code = ASF_CONTENTION;
}
void ASFContext::user_abort(W64 rip, W64 abort_code) {
  if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
    ": User abort (code=",(W16)abort_code,") in spec region @ ",(void*) rip,
    " Aborting!", endl;

  status_code    = ASF_ABORT;
  software_abort = (W16) abort_code;
}

/**
 * Assist to abort an ongoing ASF speculative region.
 * @param context The context at the time of the assist.
 */
void assist_asf_abort(Context& ctx) {
  // User-abort code in ar1
  assert(ctx.asf_context->in_spec_region());

  ctx.asf_context->user_abort(ctx.commitarf[REG_selfrip], ctx.commitarf[REG_ar1]);
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

namespace OutOfOrderModel {
  inline int ASFPipelineIntercept::vcpuid() const { return thread->ctx.vcpuid; }

  int ASFPipelineIntercept::issue_mem(ReorderBufferEntry& rob, LoadStoreQueueEntry& state, LoadStoreQueueEntry* sfra) {
    assert(rob.uop.is_asf);
    // NOTE: This can fail thanks to the asynchronous nature of the actual
    // pipeline flush
    //assert(asf_context->in_spec_region());
    if unlikely (!asf_context->in_spec_region()) return ISSUE_MISSPECULATED;

    /* Memops might be replayed, but have already an associated LLB-line */
    if (rob.llbline) return ISSUE_COMPLETED;

    // TODO: Refactor this code into a proper interface!
#ifdef ENABLE_ASF_CACHE_BASED
    // With cache-based ASF loads do not need an LLB entry, they just set the
    // SR bit in the cache.
    if likely (isload(rob.uop.opcode)) {
      if (logable(5))
        logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
          ": rob ", rob.uop.uuid, " issues load from ", (void*)rob.virtpage, " / ", (void*) (state.physaddr << 3), endl;

      // Flag present L1 lines as speculative early on

      CacheSubsystem::L1CacheLineSpecRead *line;
      CacheSubsystem::CacheHierarchy&      caches = thread->core.caches;
      CacheSubsystem::L1Cache&             L1 = caches.L1;

      line = L1.probe(state.physaddr << 3, rob.virtpage);
      if (logable(6))
        logfile << "[vcpu ", vcpuid(),"]",__FILE__,__LINE__," line ", (line?"":"not "),
          "present for ", (void*)rob.virtpage," ", (void*)(state.physaddr << 3), " sr: ",
          (line ? line->sr() : false), endl;

      if likely (line) {
        line->set_sr();
      } else {
        // The data for this load may have come in through a SFR and thus a
        // cache-miss might not be created...
        if unlikely (sfra &&
          caches.probe_cache_and_sfr(state.physaddr << 3, rob.virtpage, sfra, rob.uop.size)) {
          // L1 miss, but SFRA-hit!
          //Options: a) Add an empty (valid = 0) cache-line for this element with sr = true.
          //         b) Check if the store has put the address into the LLB, if not do a)
          L1.validate(state.physaddr << 3, rob.virtpage, 0, true);

          line = L1.probe(state.physaddr << 3, rob.virtpage);
          assert(line);
          if (logable(5))
            logfile << "[vcpu ", vcpuid(),"]",__FILE__,__LINE__, " ASF load with",
              " fwd data -> selected dummy line for ", (void*)rob.virtpage, " ",
              (void*)(state.physaddr << 3), " sr: ", line->sr(), endl;
        }
        // NOTE: This is an ugly hack below!
        else if unlikely (!caches.dtlb.probe(rob.virtpage, rob.threadid)) {
          // Cache and TLB miss: The data has been read already (issueload), so
          // we need to have ASF protection on the line. However, a MB-entry
          // that would protect the data is not setup until the TLB miss is
          // resolved. Hence we need a dummy entry too that uses the L1 cache to
          // track the validity of the data.
          // FIXME: Reading data after TLB / cache-miss handling would eliminate
          //        the problem!
          L1.validate(state.physaddr << 3, rob.virtpage, 0, true);

          line = L1.probe(state.physaddr << 3, rob.virtpage);
          assert(line);
          if (logable(5))
            logfile << "[vcpu ", vcpuid(),"]",__FILE__,__LINE__, " ASF load with",
              " TLB miss -> selected dummy line for ", (void*)rob.virtpage, " ",
              (void*)(state.physaddr << 3), " sr: ", line->sr(), endl;
        }
      }
      // if not present in the cache, we rely on the fill method to flag the
      // line, when it is brought into L1
      return ISSUE_COMPLETED;
    }
#endif // Note: All loads captured here, if ENABLE_ASF_CACHE_BASED was defined!
#ifdef ENABLE_ASF_CACHE_WRITE_SET
    // With cache-based write-set tracking, ASF stores do not need an LLB entry,
    // set the SW bit in the cache and take a snapshot
    if likely (isstore(rob.uop.opcode)) {
      // Flag present L1 lines as speculative early on

      CacheSubsystem::L1CacheLineSpecRW *line;
      CacheSubsystem::CacheHierarchy&    caches = thread->core.caches;
      CacheSubsystem::L1Cache&           L1 = caches.L1;

      // TODO: How about adding to the cache at store / commit time?
      // return ISSUE_COMPLETED;

      line = L1.select(state.physaddr << 3, rob.virtpage);
      assert(line);
      // TODO: How about doing this at commit-time?
      line->set_sr();
      line->set_sw();

      if (logable(5)) logfile << "[vcpu ", vcpuid(), "]"__FILE__,
        __LINE__,": Hi we: ", rob, "@", rob.uop.rip, " add spec entry to the cache !", endl;

      // NOTE: Capacity check happens through the call-backs,
      //       creating the actual backup-copy during commit of the store
      return ISSUE_COMPLETED;
    }
#endif // Note: All stores captured here, if ENABLE_ASF_CACHE_WRITE_SET was defined!

    /* Add the address to the LLB */
    if (logable(5)) logfile << "[vcpu ", vcpuid(), "]"__FILE__,
      __LINE__,": Hi we: ", rob, "@", rob.uop.rip, " add to the LLB!", endl;

    rob.llbline = llb->add_location(state.physaddr << 3, true);

    if likely (rob.llbline) return ISSUE_COMPLETED;

    // If we did not get a speculative line in the LLB, check if we can claim
    // one of the lines reserved for non-speculative uops.
    bool in_head_macro = false;

    foreach_forward(thread->ROB, i) {
      if (&thread->ROB[i] == &rob) {in_head_macro = true; break;}
      if (thread->ROB[i].uop.eom) break;
    }
    if unlikely (in_head_macro) {
      rob.llbline = llb->add_location(state.physaddr << 3, false);
      if likely (rob.llbline) return ISSUE_COMPLETED;

      /* This uop is at the head of the ROB, no (mis-speculated) locked-loads,
         might be before it. Hence this load is _really_ exceeding the LLB's
         capacity! -> Abort (or exception, depending on MSR)*/
      // TODO: Proper MSR treatment

      // This will trigger at the outer check for any ASF-related errors
      asf_context->capacity_error(rob.uop.rip.rip, rob.origvirt);

      if (logable(5)) logfile << "[vcpu ", vcpuid(), "]"__FILE__,
        __LINE__,": We exceed the LLB's capacity (for sure)!", endl;
    }
    // Try again, if there was an error above, it will be caught later
    rob.replay();
    rob.load_store_second_phase = 1;
    return ISSUE_NEEDS_REPLAY;
  }

  /**
   * Issues the ASF release operation on the core.
   * This is somewhat similar to PTLsim's treatment of normal load / store ops
   * and duplicates some code. However, folding this into one of these ops
   * creates strange intertwining which is tedious to separate later on.
   *
   * Multiple in-flight releases to the same line track each other by chaining
   * the old value through the rc operand.
   * TODO: This might be too complicated! Alternatives:
   * a) track number of spec releases to each line
   * b) order loads with respect to the commit of previous release operations
   */
  int ASFPipelineIntercept::issue_release(ReorderBufferEntry& rob,
      LoadStoreQueueEntry& state, Waddr& origaddr, W64 ra, W64 rb, W64 rc,
      PTEUpdate& pteupdate) {
    Queue<LoadStoreQueueEntry, LSQ_SIZE>& LSQ = thread->LSQ;
    Queue<ReorderBufferEntry, ROB_SIZE>& ROB  = thread->ROB;

    assert(rob.uop.size == 0);
    assert(rob.uop.cond == LDST_ALIGN_NORMAL);

    Waddr addr;
    int exception = 0;
    PageFaultErrorCode pfec;
    bool annul;

    Waddr physaddr = rob.addrgen(state, origaddr, rob.virtpage, ra, rb, rc, pteupdate, addr, exception, pfec, annul);

    if unlikely (exception) {
      state.data      = rc; // Do not drop any lines at commit. -> become a no-op
      state.datavalid = 1;
      return ISSUE_COMPLETED;
    }

    assert(!annul);
    state.physaddr = (physaddr >> 3);

    if (logable(5))
      logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__, "RELEASE "\
        "of ", (void*)physaddr, endl;


    // Scan backwards through the LSQ and find all ASF-memops and adds a
    // dependency to the closest one with matching / unknown address.
    LoadStoreQueueEntry* predep  = null;
    foreach_backward_before(LSQ, rob.lsq, i) {
      LoadStoreQueueEntry& buf = LSQ[i];

      // Skip over non-ASF instructions.
      if likely (!buf.rob->uop.is_asf) continue;
      // Ignore all fences.
      if unlikely (buf.lfence | buf.sfence) continue;

      if likely (buf.addrvalid) {
        if (floor(buf.physaddr << 3, LLB_LINE_SIZE) == floor(state.physaddr << 3, LLB_LINE_SIZE)) {
          predep = &buf;
          break;
        }
      } else {
        predep = &buf;
        break;
      }
    }

    if (predep && predep->addrvalid) {
      assert(floor(predep->physaddr << 3, LLB_LINE_SIZE) == floor(state.physaddr << 3, LLB_LINE_SIZE));
      assert(predep->rob->uop.uuid < rob.uop.uuid);
    }

    if (predep && logable(5))
      logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__, "Found earlier "\
        "ASF-mem op with identical address: ", *predep, *predep->rob, endl;

    //
    // Always update deps in case redispatch is required
    // because of a future speculation failure: we must
    // know which loads and stores inherited bogus values
    //
    bool ready;
    if (predep && (predep->rob->uop.opcode == OP_rel) && predep->addrvalid) {
      // Enforce the proper chaining of counts through releases to the same line
      rob.operands[RC]->unref(rob, thread->threadid);
      rob.operands[RC] = (predep) ? predep->rob->physreg : &thread->core.physregfiles[0][PHYS_REG_NULL];
      rob.operands[RC]->addref(rob, thread->threadid);
      if (predep->datavalid) rc = predep->data;
      ready = predep->datavalid;
    } else {
      rob.operands[RS]->unref(rob, thread->threadid);
      rob.operands[RS] = (predep) ? predep->rob->physreg : &thread->core.physregfiles[0][PHYS_REG_NULL];
      rob.operands[RS]->addref(rob, thread->threadid);

      ready = predep->rob->llbline;
    }
    ready = (!predep || (predep && predep->addrvalid && ready));

    if unlikely (!ready) {
      rob.replay();
      rob.load_store_second_phase = 1;
      return ISSUE_NEEDS_REPLAY;
    }

    // Scan forwards (later in program-order) to find any ASF-memops that access
    // the same cache-line and have issued before this release operation.
    // Drop this release in such a case!
    // NOTE: We might drop too many RELEASES that way, as we might find bogus
    // ASF-memops, but that is perfectly in line with the spec!
    foreach_forward_after (LSQ, rob.lsq, i) {
      LoadStoreQueueEntry& buf = LSQ[i];
      // Skip over non-ASF instructions.
      if likely (!buf.rob->uop.is_asf) continue;
      // Ignore all fences.
      if unlikely (buf.lfence | buf.sfence) continue;

      if likely (buf.addrvalid) {
        if ((floor(buf.physaddr << 3, LLB_LINE_SIZE) == floor(state.physaddr << 3, LLB_LINE_SIZE))
            && (buf.rob->llbline)) {

          if (logable(5))
            logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__, "Found later "\
              "ASF-mem op with identical address: ", buf, *buf.rob, " dropping"\
              " this release!", endl;

          state.data      = rc; // Do not drop any lines at commit. -> become a no-op
          state.datavalid = 1;
          return ISSUE_COMPLETED;
        }
      }
    }

    rob.llbline     = llb->add_location(state.physaddr << 3);
    state.data      = (rob.llbline) ? llb->get_refcount(rob.llbline) : rc;
    state.invalid   = 0;
    state.datavalid = 1;

    if (logable(5))
      logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__, "RELEASE "\
        "saw ", state.data, " references of which ", rc, " are tracked by an "\
        "earlier RELEASE to the same line.", endl;

    if (state.data - rc == 1) {
      // The release operation was the one adding the line to the LLB
      // -> drop immediately
      llb->remove_ref(rob.llbline, 1);
      rob.llbline = 0;
      state.data  = rc;
    }

    rob.load_store_second_phase = 1;

    return ISSUE_COMPLETED;
  }

  /**
   * Issues an non-memory ASF operation on the core.
   * NOTE: For now this is fairly trivial, but a future more realistic
   * implementation could do more work at the issue stage of the instruction.
   * @param rob ROB that issues, must be a propoer ASF instruction.
   * @param state Issue state held in the unit.
   * @param rbdata Second parameter, used for ASF 1 implementation (number of lines).
   * @return ISSUE_* enum
   */
  int ASFPipelineIntercept::issue(ReorderBufferEntry& rob, IssueState& state, W64 radata, W64 rbdata, W64 rcdata) {
    //if likely (isload(rob.uop.opcode))
    //  return issue_load(rob, state);
    int res;
    if (logable(5))
      logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__, "Issueing ", rob, endl;

    switch(rob.uop.opcode) {
      case (OP_val):
      case (OP_spec):
      case (OP_spec_inv):
      case (OP_com):
        state.reg.rddata  = 0;
        state.reg.rdflags = x86_genflags<W64>(state.reg.rddata);
        res = ISSUE_COMPLETED;
        break;

      case (OP_rel):
        res = issue_release(rob, *rob.lsq, rob.origvirt, radata, rbdata, rcdata, rob.pteupdate);
        state.reg.rddata = rob.lsq->data;
        state.reg.rdflags = (rob.lsq->invalid << log2(FLAG_INV)) |
                            ((!rob.lsq->datavalid) << log2(FLAG_WAIT));
        break;
      default:
        assert(false);
    }
    return res;
  }

  /**
   * Commits a load from the core and thus marks it an non-speculative.
   * @return True, if successful.
   */
  bool ASFPipelineIntercept::commit_load(ReorderBufferEntry& rob, Waddr physaddr, Waddr virtaddr) {
    assert(asf_context->in_spec_region());

#ifdef ENABLE_ASF_CACHE_BASED
    // With cache-based ASF read set tracking, reads do not need an LLB-line anymore.
    // Outer code will find out if a speculative line has been displaced and abort ASF.
    CacheSubsystem::L1CacheLineSpecRead *line;
    line = thread->core.caches.L1.probe(physaddr, virtaddr);
    assert(line);
    assert(line->sr());
    if (logable(5))
      logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
        ": rob ", rob.uop.uuid, " loads from ", (void*)virtaddr, " / ", (void*) physaddr, endl;

    return true;
#else
    /* Additional check for ASF's maximum capacity. */
    if unlikely (!rob.llbline || !llb->mark_nonspec(rob.llbline)) {
      if (logable(5)) {
        logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
          ": detected too large ASF-CS: ", llb->size(), " vs. ", ASF_MAX_LINES;
        if (rob.llbline)
          logfile << "llbline=", *rob.llbline;
        logfile << endl;
      }
      asf_context->capacity_error(rob.uop.rip.rip, virtaddr);
      return false;
    }

    assert(rob.llbline);
    llb->snapshot(rob.llbline);
    return true;
#endif

  }

  /**
   * Commits a store from the core and thus marks it an non-speculative.
   * @param physaddr Physical address of the store.
   */
  bool ASFPipelineIntercept::commit_store(ReorderBufferEntry& rob, Waddr physaddr, Waddr virtaddr) {
    assert(asf_context->in_spec_region());
    if (!rob.lsq->bytemask) return true;
#ifdef ENABLE_ASF_CACHE_WRITE_SET
    CacheSubsystem::L1CacheLineSpecRW *line;
    CacheSubsystem::CacheHierarchy&    caches = thread->core.caches;
    CacheSubsystem::L1Cache&           L1 = caches.L1;

    // TODO: One could also *select* the entry here!
    physaddr = floor(physaddr, CacheSubsystem::L1_LINE_SIZE);
    line = L1.probe(physaddr, virtaddr);

    /* Capacity issues etc are handled by the callbacks before the commit. */
    assert(line);
    assert(line->sr() && line->sw());
    if (!line->has_backup())
      line->copy_from_phys(physaddr);
    // TODO: One could also just set the bits here!
    //line->set_sr();
    //line->set_sw();
    return true;
#endif
    /* Additional check for ASF's maximum capacity. */
    if unlikely (!rob.llbline || !llb->mark_nonspec(rob.llbline)) {
      if (logable(5)) {
        logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
          ": detected too large ASF-CS: ", llb->size(), " vs. ", ASF_MAX_LINES;
        if (rob.llbline)
          logfile << "llbline=", *rob.llbline;
        logfile << endl;
      }
      asf_context->capacity_error(rob.uop.rip.rip, virtaddr);
      return false;
    }

    assert(rob.llbline);
    llb->snapshot(rob.llbline);

    // NOTE: The actual store happens later in CacheHierarchy::commitstore
    llb->mark_written(physaddr);

    return true;
  }

  /**
   * Notifies ASF of any probes issued by the local core.
   * @param physaddr Physical address of the probe (word aligned)
   * @param invalidting Invalidating or non-invalidating probe
   * @param out_data The returned data, left alone, in case no new data is available.
   * @return Has this produced new data?
   */
  bool ASFPipelineIntercept::issue_probe_and_merge(W64 physaddr, bool invalidating, W64& out_data, ReorderBufferEntry *rob) {
    Waddr llb_phys = floor(physaddr, LLB_LINE_SIZE);

    // FIXME: For using the L1 caches as ASF data-tracker, and working
    //        notifications, all of this could be provided in a decentralised
    //        manner, by extending the external_probe functions and extending
    //        the notifications.
    //        However, this is hampered by the fact that the caches get probed
    //        *after* the data has been read for the loads!

    // NOTE: Read-set tracking already works, as commit-store invalidates the
    //       other caches at commit-time.
#ifdef ENABLE_ASF_CACHE_WRITE_SET
    // Ugly hack: Move the cross-cache-probing routine in here to ensure data correctness.
    if (logable(5))
      logfile << __FILE__,__LINE__, " issue probe and merge for ", (void*)physaddr, endl;
    thread->core.caches.probe_other_caches(physaddr, invalidating);
    W64 in_data = out_data;
    out_data    = loadphys(physaddr);
    return (in_data != out_data);
#endif
    /* Probe other LLBs, where the original contents of speculatively (in
     * ASF-CS) modified memory is located.
     * In case the line is modified somewhere else, we will receive a pointer to
     * the backed up data. In real hardware, the other LLB would reply with the
     * original data directly from the LLB, in response to our (invalidating)
     * probe / or would delay the response until it has finished its rollback.
     * In the simulator however, data is written w/o waiting for the cache miss
     * to be served. Hence, do the forwarding in instant fashion, too.
     *
     * [DESIGN OPTION]
     * NOTE: One could refine this policy later, as loads might be still
     * speculative here and could replay until they are not speculative anymore
     * if something was found. This might be too sophisticated for real
     * hardware though.
     */

    LLBLine* orig_line = llb->probe_other_LLBs(llb_phys, invalidating, rob);
    if unlikely (orig_line)  {
        /* options: a) we could either wait until all other CS have been rolled
         *             back, but that could stall this store forever, if no
         *             contention control is employed
         * hence:   b) merge the data from the other LLB and store the entire
         *             updated cacheline. We then have to ensure that the line
         *             is _NOT_ overwritten by the back-rolling CS We also have
         *             to write back the entire $-line, in case there have been
         *             any other modifications.
         */

      orig_line->copy_to_phys(llb_phys);
      llb->mark_clean_others(llb_phys);
      assert(!orig_line->is_dirty());

      if (logable(5))
        logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
                   ": Forwarding value directly from other LLB", orig_line, endl;

      out_data = orig_line->data(physaddr);
      return true;
    }
    return false;
  }
  /**
   * Commit a single ASF instruction.
   */
  bool ASFPipelineIntercept::commit(const Context &ctx, ReorderBufferEntry& rob) {
    assert(rob.uop.is_asf);

    if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,": Commiting ASF instruction ", rob,
        " LLB: ", llb->size(), endl;

    if unlikely(rob.uop.opcode == OP_spec) {
      /* SPECULATE always returns zero. */
      assert(!rob.physreg->data);
      asf_context->enter_spec_region(ctx);
      return true;
    }

    if unlikely(rob.uop.opcode == OP_spec_inv) {
      /* SPECULATE_INV always returns zero. */
      assert(!rob.physreg->data);
      asf_context->enter_spec_inv_region(ctx);
      return true;
    }

    else if unlikely (rob.uop.opcode == OP_com) {
      // TODO Proper exception creation
      assert(asf_context->in_spec_region());

      /* Do a final check on the sanity of this transaction! */
      W64 llb_err = llb->consistency_error();
      if unlikely(llb_err) {
        if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,": COMMIT found a LATE error: ", llb_err, endl;
        // The generic outer code will catch the contention and abort the
        // speculative region!
        return false;
      }
      asf_context->leave_spec_region();
      return true;
    }

    else if unlikely (rob.uop.opcode == OP_rel) {
      // ASF 2.0 Release: drop the line if it was unmodified
      // TODO: Proper exception generation.
      assert(asf_context->in_spec_region());

      if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
        ": RELEASE has line ", rob.llbline, " with ", rob.physreg->data,
        "references, of which ", rob.operands[RC]->data, " are old.", endl;

      // Ignore releases that did not release a line.
      W64 n_release = rob.physreg->data - rob.operands[RC]->data;
      if (!rob.llbline || !n_release) return true;
      llb->remove_ref(rob.llbline, n_release);
      if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
        "REL LLB: ", llb->get_nonspec_locations(), "/", ASF_MAX_LINES, " ",
        llb->get_spec_locations(), "/", ASF_MAX_SPEC_LINES, endl;

      return true;
    }

    else if (isclass(rob.uop.opcode, OPCLASS_LOAD | OPCLASS_PREFETCH)) {
      // TODO: Proper exception generation instead of assertion
      assert(asf_context->in_spec_region());

      bool res = commit_load(rob, rob.lsq->physaddr << 3, rob.origvirt);

      if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
        "LLD LLB: ", llb->get_nonspec_locations(), "/", ASF_MAX_LINES, " ",
        llb->get_spec_locations(), "/", ASF_MAX_SPEC_LINES, endl;

      return res;
    }

    else if (isclass(rob.uop.opcode, OPCLASS_STORE)) {
      // ignore ASF memory fences
      if (rob.lsq && (rob.lsq->lfence | rob.lsq->sfence)) return true;

      // Proper exception generation!
      assert(asf_context->in_spec_region());
      if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
        ": Commiting store instruction ", rob, "LSQ: ", rob.lsq, *rob.lsq,
        " SF: ",rob.lsq->sfence, " LF: ",rob.lsq->lfence;

      bool res = commit_store(rob, rob.lsq->physaddr << 3, rob.origvirt);

      if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,
        "LST LLB: ", llb->get_nonspec_locations(), "/", ASF_MAX_LINES, " ",
        llb->get_spec_locations(), "/", ASF_MAX_SPEC_LINES, endl;

      return res;
    }


    assert(false);
  }

  /**
   * Notifies ASF of an annulment, replay or redispatch condition.
   * @param rob ROB entry that is replayed, anulled or redispatched.
   */
  void ASFPipelineIntercept::annul_replay_redispatch(ReorderBufferEntry& rob){
    // NOTE: ASF 2 tags all loads and stores
    assert(rob.uop.is_asf);
    /* NOTE: Annulment handling of spec ASF lines happens in
       LoadFillReqQueue::annul_asf_spec_lfr for better MB / LFR handling
       integration */
    if (rob.llbline) {
      if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,": Removing reference to line ", rob.llbline, endl;
      if unlikely (rob.uop.opcode == OP_rel)
        llb->remove_ref(rob.llbline, 1
            // NOTE: Drop only the own reference upon replay of this release!
            //rob.physreg->data - rob.operands[RC]->data
            );
      else
        llb->remove_ref(rob.llbline);
      if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,": ", *rob.llbline, endl;
      rob.llbline = (LLBLine*)null;
    }
  }

  /**
   * Notifies ASF that an in-flight speculative load has been hit by an incoming
   * invalidating probe.
   * @return True, if successful.
   */
  void ASFPipelineIntercept::reprobe_load(ReorderBufferEntry& rob) {
    assert(asf_context->in_spec_region());
    asf_context->contention(rob.uop.rip.rip, rob.lsq->physaddr << 3);
  }

  /**
   * TODO
   */
  int ASFPipelineIntercept::pre_commit(Context &ctx, int commitrc) {
    if likely (! asf_context->in_spec_region()) return commitrc;

    /* Check for conflicts of the ongoing critical section */
    if likely ((commitrc == COMMIT_RESULT_OK) || (commitrc == COMMIT_RESULT_NONE)) {
      /* check for normal interference from other cores.. */
      commitrc = check_conflicts(ctx, commitrc);
    }
    return commitrc;
  }

  /**
   * Allow ASF to see any effects of the stages of the CPU just before the cycle ends and
   * things such as exceptions are processed.
   * @param commitrc Return code of the commit operation, used to tweak exception handling
   *                 when inside ASF's critical sections.
   * @return New commitrc, possibly tweaked to mask exceptions!
   */
  int ASFPipelineIntercept::post_commit(Context &ctx, int commitrc) {
    if likely (! asf_context->in_spec_region()) {
      /* we're not inside a critical section! */
      return commitrc;
    }

    /* Check for conflicts of the ongoing critical section */
    if likely ((commitrc == COMMIT_RESULT_OK) || (commitrc == COMMIT_RESULT_NONE)) {
      /* check for normal interference from other cores.. */
      // Moved to pre_commit!
      //commitrc = check_conflicts(ctx, commitrc);
    } else {
      /* Handle all nasty far control transfers within speculative regions. */
      commitrc = handle_far_control_transfer(ctx, commitrc);
    }

    /* Trigger all present errors */
    if (asf_context->has_error()) {
      if (logable(5))
        logfile << "[vcpu ", vcpuid(),"]"__FILE__,":",__LINE__,"@",sim_cycle,
          "found an error during ASF execution. Aborting the ongoing speuclative region.", endl, flush;

      llb->abort();
#ifdef ENABLE_ASF_CACHE_BASED
      thread->core.caches.L1.abort();
#endif

      bool needs_assist = asf_context->to_sim_context(ctx, (commitrc == COMMIT_RESULT_BARRIER) );
      if unlikely (needs_assist)
        commitrc = COMMIT_RESULT_BARRIER;
      if likely ((commitrc == COMMIT_RESULT_OK) || (commitrc == COMMIT_RESULT_NONE))
        commitrc = COMMIT_RESULT_OK_FLUSH;

      // Log abort event
      if unlikely (config.event_log_enabled) {
        OutOfOrderCoreEvent *e = thread->core.eventlog.add(EVENT_ASF_ABORT);
        if (e) {
          e->abort.abort_reason          = ctx.commitarf[REG_rax];
          e->abort.total_insns_committed = thread->total_insns_committed;
        }
      }

      /* Prepare all ASF state for next iteration */
      asf_context->reset();

      // NOTE: The actual pipeline flush may occur later and some in-flight ops
      //       might get issued beforehand!
    }

    return commitrc;
  }

  /**
   * Process all non-local control transfers and calculate their effect on ASF
   * state. External agents can then check for present errors through the
   * has_error() function of the ASF context if anything bad happened and
   * roll-back state accordingly.
   */
  int ASFPipelineIntercept::handle_far_control_transfer(Context &ctx, int commitrc) {
    if unlikely (commitrc == COMMIT_RESULT_INTERRUPT) {
      //TODO: Add proper interrupt deferal treatment!
      logfile << "[vcpu ", vcpuid(),"]"__FILE__,":",__LINE__,"@",sim_cycle,
        "Interrupt at rip ", (void*)(Waddr)ctx.commitarf[REG_rip],
        " faking at speculate. ", endl, flush;

      asf_context->interrupt(ctx.commitarf[REG_rip]);
    }

    else if unlikely (commitrc == COMMIT_RESULT_EXCEPTION) {
      /* Exceptions trigger, but as if they were caused after the SPECULATE! */
      if (ctx.exception != EXCEPTION_SkipBlock) {
        logfile << "[vcpu ", vcpuid(),"]"__FILE__,":",__LINE__,"@",sim_cycle," Exception ", exception_name(ctx.exception),
          " called from rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " faking it at the last speculate!", endl, flush;

        asf_context->exception(ctx.commitarf[REG_rip]);
      }
    }

    else if unlikely (commitrc == COMMIT_RESULT_BARRIER) {
      int assistid = ctx.commitarf[REG_rip];

      /* Far control flow movements are illegal with speculative regions */
      if (inrange(assistid, (int)ASSIST_INT, (int)ASSIST_RDTSC) ||
          inrange(assistid, (int)ASSIST_POPF, (int)ASSIST_IOPORT_OUT)) {
        logfile << "[vcpu ", vcpuid(),"]"__FILE__,":",__LINE__,"@",sim_cycle,
                   " Assist ", assist_names[assistid];
        if (assistid == ASSIST_SYSCALL)
          logfile << "(syscall id=", ctx.commitarf[REG_rax], ")";
        logfile << " called from rip ", (void*)(Waddr)ctx.commitarf[REG_selfrip],
                   " is illegal within a ASF speculative region.", endl, flush;

        asf_context->disallowed(ctx.commitarf[REG_rip]);

        // SD: Hide the caused assists and just flush the core
        commitrc = COMMIT_RESULT_NONE;
      } else if (inrange(assistid, (int)ASSIST_INVALID_OPCODE, (int)ASSIST_GP_FAULT)) {
        /* These are actually just exceptions so they'll be treated as those */
        logfile << "[vcpu ", vcpuid(),"]"__FILE__,":",__LINE__,"@",sim_cycle," Exception ", assist_names[assistid],
          " called from rip ", (void*)(Waddr)ctx.commitarf[REG_selfrip], " faking it at the last speculate!", endl, flush;

        asf_context->exception(ctx.commitarf[REG_selfrip]);

      } else {
        /* All other assists just proceed as normal and do not interfere with ASF. */

      }
    }

    return commitrc;
  }

  /**
   * When the core is running in an ASF transaction check for conflicting accesses from other cores
   * and abort the currently running transaction (in optimistic mode) if detected!
   * @return True, if core needs to flush the pipeline.
   */
  int ASFPipelineIntercept::check_conflicts(Context &ctx, int commitrc) {
    int asf_err = llb->consistency_error();
#ifdef ENABLE_ASF_CACHE_BASED
    // TODO: Integrate nicely!
    if unlikely (thread->core.caches.L1.capacity_error()) {
      asf_context->capacity_error(ctx.commitarf[REG_rip], 0);
      return COMMIT_RESULT_OK_FLUSH;
    }

    if likely(!asf_err) asf_err = thread->core.caches.L1.consistency_error();
#endif

    if likely (!asf_err) return commitrc;
    if (logable(5)) logfile << "[vcpu ", vcpuid(),"]"__FILE__,__LINE__,": Error ", hexstring(asf_err, 64),
                       " found! Aborting the transaction!", endl;

    asf_context->contention(ctx.commitarf[REG_rip], 0);

    return COMMIT_RESULT_OK_FLUSH;
  }

  /**
   * Removes all addresses and their associated undo data from the LLB.
   */
  void LockedLineBuffer::clear() {
    if likely(empty()) return;
    if (logable(5))  logfile <<"[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,": Clearing the LLB! Locations: ",size(), endl;
    num_spec_locations = 0;
    num_nonspec_locations = 0;
    lasterr = 0;
    reset();
  }

  /**
    * Adds an address to the locked-line buffer (LLB).
    *
    * @param addr The physical address of the data to be stored in the LLB.
    *             NULL, if there is no more space in the LLB.
    */
   LLBLine* LockedLineBuffer::add_location(Waddr addr, bool spec) {
     Waddr cache_line_phys_addr = floor(addr, LLB_LINE_SIZE);

     int& num_locations = (spec) ? num_spec_locations : num_nonspec_locations;

     /* Touch the line now, fill it later */
     LLBLine* line = probe(cache_line_phys_addr);
     if unlikely (!line && at_capacity_limit(spec)) return NULL;

     if (!line) {
       line = select(cache_line_phys_addr);
       line->speculative = spec;
       num_locations++;
     }
     line->refcount++;

     if (logable(5))
       logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,": Adding ",
       (spec) ? "spec" : "non-spec","location ",hexstring(addr,64),
        " locations: ",num_locations, " ", *line, endl;

     return line;
   }
   /**
    * Marks a given line in the LLB as non-speculative in terms of out-of-order
    * execution.
    * @param line LLBline to mark
    * @return True on success, false otherwise (due to capacity reasons)
    */
   bool LockedLineBuffer::mark_nonspec(LLBLine* line) {
     assert(line);
     int i = line - data;
     assert ((0 <= i) && (i < ASF_MAX_SPEC_LINES + ASF_MAX_LINES));

     /* Line might be non-speculative already */
     if (!line->speculative) return true;

     if (at_nonspec_capacity_limit()) return false;
     line->speculative = 0;
     num_nonspec_locations++;
     num_spec_locations--;
     return true;
   }
  /**
   * Creates a snapshot of a specific line in the LLB.
   * @param llbline The line to snapshot.
   */
  void LockedLineBuffer::snapshot(LLBLine *llbline) {
    assert(llbline);

    int i = llbline - data;
    assert ((0 <= i) && (i < ASF_MAX_SPEC_LINES + ASF_MAX_LINES));

    // Do not overwrite existing backup copies.
    if (llbline->datavalid) return;

    /* Fetch the cacheline from the given address */
    if (logable(5)) {
      logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,
      ": Fetching LLB line ", i, " from address ", hexstring(tags[i],64), endl;
    }

    data[i].copy_from_phys(tags[i]);
    llbline->datavalid = true;

    if (logable(5)) {
      logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,
      ": Fetched ", data[i], endl;
    }
  }

  /**
   * Write the lines from the LLB back to the caches, undoing any changes made to
   * them.
   */
  void LockedLineBuffer::undo() {
    int c = 0;
    for (int i = 0; i < ASF_MAX_SPEC_LINES + ASF_MAX_LINES; i++) {
      if likely (tags[i] != tags.INVALID) {
        /* Write the cacheline back to its position. */
        if (logable(5))
          logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,
          ":Restoring LLB line ", i, " at address ", hexstring(tags[i],64),
              " Data :", endl, bytestring((byte*)data[i].orig_data, LLB_LINE_SIZE), endl;

        if (data[i].written) {
          if (logable(5))
            logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,": Copying ", sizeof(data[i].orig_data),
              " bytes from ",  data[i].orig_data, " to ",phys_to_mapped_virt(tags[i]), endl;
              data[i].copy_to_phys(tags[i]);
            data[i].written = false;
        } else {
          if (logable(5))
            logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,": Ignoring ", sizeof(data[i].orig_data),
              " unmodified bytes from ",  data[i].orig_data, " @ ",phys_to_mapped_virt(tags[i]), endl;
        }
        c++;
      }
    }
    if (c != size()) {
      logfile << "Expected ", size(), " locations but just saw ", c, endl;
      assert(c == size());
    }
  }

  /**
   * Notifies the LLB, that a reference to one of its lines has been dropped.
   * This can occur when a ROBEntry gets redispatched / annuled and thus must
   * get removed from the LLB.
   *
   * @param line Pointer to the line inside the LLB which is to be removed.
   * @param n_refs Number of references to drop for this line (default 1)
   */
  void LockedLineBuffer::remove_ref(LLBLine* line, int n_refs) {
    Waddr tag = tagof(line);

    if unlikely (tag == tags.INVALID) {
      if (logable(5)) logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,
          ": Line not in LLB anymore. Ignoring remove request!", endl;
      return;
    }
    assert(line->refcount >= n_refs);
    if (logable(5))
      logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,": Removing ",
      n_refs, "references to line ",line," tag: ",tagof(line)," refcount: ",
      line->refcount, endl;

    line->refcount -= n_refs;

    /* Remove a line which does not belong to any valid instructions any longer! */
    if (!line->refcount) {
      if (logable(5)) logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,": No more references to line ",line,
         ". Removing it!", endl, flush;
      if (line->speculative) num_spec_locations--;
      else num_nonspec_locations--;

      invalidate_line(line);
    }
  }

  /**
   * Incoming probe from another core. Checks our own LLB for any conflicting cachelines.
   * Either of the two accesses has to be aborted / stalled. Will provide a pointer to the
   * backed up data for short-circuit forwarding of the original content!
   * @param addr Address of the cacheline to probe.
   * @param invalidating True, if the incoming probe is an invalidating one, eg from a write access.
   * @return Pointer to original data, if speculative updates have occured to that line! Null, if
   *         line not touched / present in LLB.
   */
  LLBLine* LockedLineBuffer::external_probe(Waddr addr, bool invalidating, ReorderBufferEntry *rob) {
    /* For now just implement the policy of aborting ourselves. */
    Waddr cache_line_phys_addr = floor(addr, LLB_LINE_SIZE);
    LLBLine* l = probe(cache_line_phys_addr);

    if likely (!l) return null;                                   // Line not in LLB
    if likely (!l->written && !invalidating) return null;         // multiple readers ok!

    if unlikely (config.event_log_enabled) {
      OutOfOrderCoreEvent* event = thread.core.eventlog.add(EVENT_ASF_CONFLICT, rob);
      if unlikely (event) {
        // NOTE: Thid does not work with threads..
        event->conflict.src_id = rob->coreid;
        event->conflict.dst_id = thread.getcore().coreid;
        event->conflict.inv    = invalidating;
        event->conflict.phys_addr = addr;
        event->conflict.virt_addr = rob->origvirt;
      }
    }
    if (logable(5)) logfile << "[vcpu ", thread.ctx.vcpuid,"]"__FILE__,__LINE__,
      ": ",invalidating ? "Inv-" : "", "probe hit on ", (void*)addr, endl;

    /* Either invalidating probe or modified data read before commit:
       we (callee) will abort our ASF-CS! */
    lasterr = cache_line_phys_addr;

    /* In case we had the line modified, forward the unmodified data! */
    if unlikely(l->written) return l;
    return null;
  }

  /**
   * Probe the LLBs of all other cores in the system with a given address
   * and access mode, finds one unmodified copy in the system.
   * @param addr Address of the cacheline to probe.
   * @param invalidating True, if the incoming probe is an invalidating one,
   *                     eg from a write access.
   * @return Pointer to one copy of the original data. Null, if line not touched
   *         / present in no LLB.
   */
  LLBLine* LockedLineBuffer::probe_other_LLBs(Waddr addr, bool invalidating, ReorderBufferEntry *rob) {
    OutOfOrderMachine& m = thread.core.machine;
    LLBLine* orig_line = null;
    LLBLine* res;

    foreach(cid, m.corecount) {
      OutOfOrderCore& c = *m.cores[cid];
      foreach(tid, c.threadcount) {
        ThreadContext& t = *c.threads[tid];
        if (&t == &thread) continue;
        res = t.locked_line_buffer.external_probe(addr, invalidating, rob);
        // ASF guarantees that there is only a single modified LLB entry
        assert(! (res && orig_line));
        if (!orig_line) orig_line = res;
      }
    }
    return orig_line;
  }

  /**
   * Marks the given cache-line as clean in this LLB.
   * No write-back will occur on eviction.
   * @param addr Address of the cacheline to mark.
   * @return Previous written-state of the line.
   */
  bool LockedLineBuffer::mark_clean(Waddr addr) {
    Waddr cache_line_phys_addr = floor(addr, LLB_LINE_SIZE);
    LLBLine* l = probe(cache_line_phys_addr);
    bool old_written = false;
    if (l) {
      old_written = l->written;
      l->written  = false;
    }
    return old_written;
  }

  /**
   * Marks the given cache-line as clean in all LLBs of other cores in
   * the system. No write-back will occur on eviction.
   * @param addr Address of the cacheline to mark.
   * @return Dirty line found
   */
  bool LockedLineBuffer::mark_clean_others(Waddr addr) {
    OutOfOrderMachine& m = thread.core.machine;
    bool dirty = false;

    foreach(cid, m.corecount) {
      OutOfOrderCore& c = *m.cores[cid];
      foreach(tid, c.threadcount) {
        ThreadContext& t = *c.threads[tid];
        if (&t == &thread) continue;

        if (t.locked_line_buffer.mark_clean(addr)) {
          // There only can be one.
          assert(!dirty);
          dirty = true;
        }
      }
    }
    return dirty;
  }

  /**
   * Marks the given cache-line as dirty in this LLB.
   * Write-back will occur on eviction.
   * @param addr Address of the cacheline to mark.
   */
  void LockedLineBuffer::mark_written(Waddr addr) {
    Waddr cache_line_phys_addr = floor(addr, LLB_LINE_SIZE);
    LLBLine* l = probe(cache_line_phys_addr);

    assert(l);
    l->written = true;
  }

  template <>
  ostream& LLBLine::toString(ostream& os) const{
    os << "LLB line: ", this, " refcount: ",refcount, written ? "dirty":"", speculative ? "spec":"", endl;
    if (datavalid)
      os << "Data:", bytestring((byte*)orig_data, sizeof(orig_data));
    else
      os << "Data: <invalid>";
    return os;
  }

  ostream& operator <<(ostream& os, const LLBLine& llbline) {
    return llbline.toString(os);
  }
}
