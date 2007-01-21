//
// PTLsim: Cycle Accurate x86-64 Simulator
// Out-of-Order Core Simulator
//
// Copyright 2003-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <elf.h>
#include <ptlsim.h>
#include <branchpred.h>
#include <datastore.h>
#include <logic.h>
#include <dcache.h>

#define INSIDE_OOOCORE
#define DECLARE_STRUCTURES
#include <ooocore.h>
#include <stats.h>

#ifndef ENABLE_CHECKS
#undef assert
#define assert(x) (x)
#endif

#ifndef ENABLE_LOGGING
#undef logable
#define logable(level) (0)
#endif

using namespace OutOfOrderModel;

namespace OutOfOrderModel {
  byte uop_executable_on_cluster[OP_MAX_OPCODE];
  W32 forward_at_cycle_lut[MAX_CLUSTERS][MAX_FORWARDING_LATENCY+1];
};

//
// Initialize lookup tables used by the simulation
//
static void init_luts() {
  // Initialize opcode maps
  foreach (i, OP_MAX_OPCODE) {
    W32 allowedfu = fuinfo[i].fu;
    W32 allowedcl = 0;
    foreach (cl, MAX_CLUSTERS) {
      if (clusters[cl].fu_mask & allowedfu) setbit(allowedcl, cl);
    }
    uop_executable_on_cluster[i] = allowedcl;
  }
  
  // Initialize forward-at-cycle LUTs
  foreach (srcc, MAX_CLUSTERS) {
    foreach (destc, MAX_CLUSTERS) {
      foreach (lat, MAX_FORWARDING_LATENCY+1) {
        if (lat == intercluster_latency_map[srcc][destc]) {
          setbit(forward_at_cycle_lut[srcc][lat], destc);
        }
      }
    }
  }
}

void OutOfOrderCore::init_generic() {
  //
  // ROB states
  //
  rob_free_list("free", rob_states, 0);
  rob_frontend_list("frontend", rob_states, ROB_STATE_PRE_READY_TO_DISPATCH);
  rob_ready_to_dispatch_list("ready-to-dispatch", rob_states, 0);
  InitClusteredROBList(rob_dispatched_list, "dispatched", ROB_STATE_IN_ISSUE_QUEUE),
    InitClusteredROBList(rob_ready_to_issue_list, "ready-to-issue", ROB_STATE_IN_ISSUE_QUEUE);
  InitClusteredROBList(rob_ready_to_store_list, "ready-to-store", ROB_STATE_IN_ISSUE_QUEUE);
  InitClusteredROBList(rob_ready_to_load_list, "ready-to-load", ROB_STATE_IN_ISSUE_QUEUE);
  InitClusteredROBList(rob_issued_list, "issued", 0);
  InitClusteredROBList(rob_completed_list, "completed", ROB_STATE_READY);
  InitClusteredROBList(rob_ready_to_writeback_list, "ready-to-write", ROB_STATE_READY);
  rob_cache_miss_list("cache-miss", rob_states, 0);
  rob_ready_to_commit_queue("ready-to-commit", rob_states, ROB_STATE_READY);
  //
  // Miscellaneous
  //
  branchpred.init();
  fetch_uuid = 0;
  current_basic_block = null;
  current_basic_block_transop_index = 0;
  current_icache_block = 0;
  round_robin_reg_file_offset = 0;
  smc_invalidate_pending = 0;
  caches.reset();
  caches.callback = &cache_callbacks;
  setzero(robs_on_fu);
  prev_interrupts_pending = 0;
  handle_interrupt_at_next_eom = 0;
}

template <typename T> 
static void OutOfOrderModel::print_list_of_state_lists(ostream& os, const ListOfStateLists& lol, const char* title) {
  os << title, ":", endl;
  foreach (i, lol.count) {
    StateList& list = *lol[i];
    if (!list.count) continue;
    os << list.name, " (", list.count, " entries):", endl;
    int n = 0;
    T* obj;
    foreach_list_mutable(list, obj, entry, nextentry) {
      if ((n % 16) == 0) os << " ";
      os << " ", intstring(obj->index(), -3);
      if (((n % 16) == 15) || (n == list.count-1)) os << endl;
      n++;
    }
    os << endl;
    // list.validate();
  }
}

void StateList::checkvalid() {
#if 0
  int realcount = 0;
  selfqueuelink* obj;
  foreach_list_mutable(*this, obj, entry, nextentry) {
    realcount++;
  }
  assert(count == realcount);
#endif
}

void PhysicalRegisterFile::init(const char* name, int coreid, int rfid, int size) {
  assert(rfid < PHYS_REG_FILE_COUNT);
  assert(size <= MAX_PHYS_REG_FILE_SIZE);
  this->size = size;
  this->coreid = coreid;
  this->rfid = rfid;
  this->name = name;
  this->allocations = 0;
  this->frees = 0;

  foreach (i, MAX_PHYSREG_STATE) {
    states[i].init(physreg_state_names[i], getcore().physreg_states);
  }

  foreach (i, size) {
    (*this)[i].init(coreid, rfid, i);
  }
}

PhysicalRegister* PhysicalRegisterFile::alloc(int r) {
  PhysicalRegister* physreg = (PhysicalRegister*)((r >= 0) ? states[PHYSREG_FREE].remove(&(*this)[r]) : states[PHYSREG_FREE].dequeue());
  if unlikely (!physreg) return null;
  physreg->state = PHYSREG_NONE;
  physreg->changestate(PHYSREG_WAITING);
  physreg->flags = FLAG_WAIT;
  allocations++;
  return physreg;
}

ostream& PhysicalRegisterFile::print(ostream& os) const {
  os << "PhysicalRegisterFile<", name, ", rfid ", rfid, ", size ", size, ">:", endl;
  foreach (i, size) {
    os << (*this)[i], endl;
  }
  return os;
}

void PhysicalRegisterFile::reset() {
  foreach (i, MAX_PHYSREG_STATE) {
    states[i].reset();
  }

  foreach (i, size) {
    (*this)[i].reset();
  }
}

StateList& PhysicalRegister::get_state_list(int s) const {
  return getcore().physregfiles[rfid].states[s];
}

namespace OutOfOrderModel {
  ostream& operator <<(ostream& os, const PhysicalRegister& physreg) {
    stringbuf sb;
    print_value_and_flags(sb, physreg.data, physreg.flags);
    
    os << "  r", intstring(physreg.index(), -3), " state ", padstring(physreg.get_state_list().name, -12), " ", sb;
    if (physreg.rob) os << " rob ", physreg.rob->index(), " (uuid ", physreg.rob->uop.uuid, ")";
    os << " refcount ", physreg.refcount;
    
    return os;
  }
};

ostream& RegisterRenameTable::print(ostream& os) const {
  foreach (i, TRANSREG_COUNT) {
    if ((i % 8) == 0) os << " ";
    os << " ", padstring(arch_reg_names[i], -6), " r", intstring((*this)[i]->index(), -3), " | ";
    if (((i % 8) == 7) || (i == TRANSREG_COUNT-1)) os << endl;
  }
  return os;
}

//
// Execute one cycle of the entire core state machine
//
bool OutOfOrderCore::runcycle() {
  bool exiting = 0;

  //
  // Detect edge triggered transition from 0->1 for
  // pending interrupt events, then wait for current
  // x86 insn EOM uop to commit before redirecting
  // to the interrupt handler.
  //
#ifdef PTLSIM_HYPERVISOR
  bool current_interrupts_pending = ctx.check_events();
  bool edge_triggered = ((!prev_interrupts_pending) & current_interrupts_pending);
  handle_interrupt_at_next_eom |= edge_triggered;
  prev_interrupts_pending = current_interrupts_pending;
#endif

  // All FUs are available at top of cycle:
  fu_avail = bitmask(FU_COUNT);
  loads_in_this_cycle = 0;
  caches.clock();

  int commitrc = commit();

  for_each_cluster(i) { writeback(i); }
  for_each_cluster(i) { transfer(i); }
  for_each_cluster(i) { issue(i); complete(i); }

  int dispatchrc = dispatch();

  if likely (dispatchrc >= 0) {
    frontend();
    rename();
    fetch();
  }

  if likely (dispatchrc >= 0) { foreach_issueq(clock()); }

  if unlikely (config.event_log_enabled) {
    if unlikely (config.flush_event_log_every_cycle) {
      eventlog.flush(true);
    }
  }

#ifdef ENABLE_CHECKS
  // This significantly slows down simulation; only enable it if absolutely needed:
  //check_refcounts();
#endif

  if unlikely (commitrc == COMMIT_RESULT_SMC) {
    if (logable(3)) logfile << "Potentially cross-modifying SMC detected: global flush required (cycle ", sim_cycle, ", ", total_user_insns_committed, " commits)", endl, flush;
    flush_pipeline();
    invalidate_smc();
    exiting = 0;
  } else if unlikely (commitrc == COMMIT_RESULT_EXCEPTION) {
    exiting = !handle_exception();
  } else if unlikely (commitrc == COMMIT_RESULT_BARRIER) {
    exiting = !handle_barrier();
  } else if unlikely (commitrc == COMMIT_RESULT_INTERRUPT) {
    handle_interrupt();
  } else if unlikely (commitrc == COMMIT_RESULT_STOP) {
    exiting = 1;
  }

  if unlikely ((sim_cycle - last_commit_at_cycle) > 1024) {
    stringbuf sb;
    sb << "WARNING: At cycle ", sim_cycle, ", ", total_user_insns_committed, 
      " user commits: no instructions have committed for ", (sim_cycle - last_commit_at_cycle),
      " cycles; the pipeline could be deadlocked", endl;
    logfile << sb, flush;
    cerr << sb, flush;
    exiting = 1;
  }

  return exiting;
}

//
// ReorderBufferEntry
//
void ReorderBufferEntry::init(int idx) {
  this->idx = idx;
  entry_valid = 0;
  selfqueuelink::reset();
  current_state_list = null;
  reset();
}

//
// Clean out various fields from the ROB entry that are 
// expected to be zero when allocating a new ROB entry.
//
void ReorderBufferEntry::reset() {
  int latency, operand;
  // Deallocate ROB entry
  entry_valid = false;
  cycles_left = 0;
  physreg = (PhysicalRegister*)null;
  lfrqslot = -1;
  lsq = 0;
  issued = 0;
  load_store_second_phase = 0;
  lock_acquired = 0;
  consumer_count = 0;
  executable_on_cluster_mask = 0;
#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
  dest_renamed_before_writeback = 0;
  no_branches_between_renamings = 0;
#endif
}

bool ReorderBufferEntry::ready_to_issue() const {
  bool raready = operands[0]->ready();
  bool rbready = operands[1]->ready();
  bool rcready = operands[2]->ready();
  bool rsready = operands[3]->ready();
  
  if (isstore(uop.opcode)) {
    return (load_store_second_phase) ? (raready & rbready & rcready & rsready) : (raready & rbready);
  } else if (isload(uop.opcode)) {
    return (load_store_second_phase) ? (raready & rbready & rcready & rsready) : (raready & rbready & rcready);
  } else {
    return (raready & rbready & rcready & rsready);
  }
}

bool ReorderBufferEntry::ready_to_commit() const {
  return (current_state_list == &getcore().rob_ready_to_commit_queue);
}

StateList& ReorderBufferEntry::get_ready_to_issue_list() const {
  OutOfOrderCore& core = getcore();
  return 
    isload(uop.opcode) ? core.rob_ready_to_load_list[cluster] :
    isstore(uop.opcode) ? core.rob_ready_to_store_list[cluster] :
    core.rob_ready_to_issue_list[cluster];
}

//
// Reorder Buffer
//
stringbuf& ReorderBufferEntry::get_operand_info(stringbuf& sb, int operand) const {
  PhysicalRegister& physreg = *operands[operand];
  ReorderBufferEntry& sourcerob = *physreg.rob;

  sb << "r", physreg.index();
  if (PHYS_REG_FILE_COUNT > 1) sb << "@", getcore().physregfiles[physreg.rfid].name;

  switch (physreg.state) {
  case PHYSREG_WRITTEN:
    sb << " (written)"; break;
  case PHYSREG_BYPASS:
    sb << " (ready)"; break;
  case PHYSREG_WAITING:
    sb << " (wait rob ", sourcerob.index(), " uuid ", sourcerob.uop.uuid, ")"; break;
  case PHYSREG_ARCH: break;
    if (physreg.index() == PHYS_REG_NULL)  sb << " (zero)"; else sb << " (arch ", arch_reg_names[physreg.archreg], ")"; break;
  case PHYSREG_PENDINGFREE:
    sb << " (pending free for ", arch_reg_names[physreg.archreg], ")"; break;
  default:
    // Cannot be in free state!
    sb << " (FREE)"; assert(false); break;
  }

  return sb;
}

ostream& ReorderBufferEntry::print_operand_info(ostream& os, int operand) const {
  stringbuf sb;
  get_operand_info(sb, operand);
  os << sb;
  return os;
}

ostream& ReorderBufferEntry::print(ostream& os) const {
  stringbuf name, rainfo, rbinfo, rcinfo;
  nameof(name, uop);
  get_operand_info(rainfo, 0);
  get_operand_info(rbinfo, 1);
  get_operand_info(rcinfo, 2);

  os << "rob ", intstring(index(), -3), " uuid ", intstring(uop.uuid, 16), " ", padstring(current_state_list->name, -24), " @ ", padstring((cluster >= 0) ? clusters[cluster].name : "???", -4), " ", padstring(name, -12), " r", 
    intstring(physreg->index(), -3), " ", padstring(arch_reg_names[uop.rd], -6);
  if (isload(uop.opcode)) 
    os << " ld", intstring(lsq->index(), -3);
  else if (isstore(uop.opcode))
    os << " st", intstring(lsq->index(), -3);
  else os << "      ";

  os << " = ";
  os << padstring(rainfo, -30);
  os << padstring(rbinfo, -30);
  os << padstring(rcinfo, -30);

  return os;
}

void OutOfOrderCore::print_rob(ostream& os) {
  os << "ROB head ", ROB.head, " to tail ", ROB.tail, " (", ROB.count, " entries):", endl;
  foreach_forward(ROB, i) {
    ReorderBufferEntry& rob = ROB[i];
    os << "  ", rob, endl;
  }
}

void OutOfOrderCore::print_lsq(ostream& os) {
  os << "LSQ head ", LSQ.head, " to tail ", LSQ.tail, " (", LSQ.count, " entries):", endl;
  foreach_forward(LSQ, i) {
    LoadStoreQueueEntry& lsq = LSQ[i];
    os << "  ", lsq, endl;
  }
}

void OutOfOrderCore::print_rename_tables(ostream& os) {
  os << "SpecRRT:", endl;
  os << specrrt;
  os << "CommitRRT:", endl;
  os << commitrrt;
}

void OutOfOrderCore::dump_ooo_state(ostream& os) {
  print_rename_tables(os);
  print_rob(os);
  print_list_of_state_lists<PhysicalRegister>(os, physreg_states, "Physical register states");
  print_list_of_state_lists<ReorderBufferEntry>(os, rob_states, "ROB entry states");
  print_lsq(os);
  os << "Issue Queues:", endl;
  foreach_issueq(print(os));
  foreach (i, PHYS_REG_FILE_COUNT) {
    os << physregfiles[i];
  }
  caches.print(os);
  os << flush;
}

//
// Validate the physical register reference counters against what
// is really accessible from the various tables and operand fields.
//
// This is for debugging only.
//
void OutOfOrderCore::check_refcounts() {
  int refcounts[PHYS_REG_FILE_COUNT][MAX_PHYS_REG_FILE_SIZE];
  memset(refcounts, 0, sizeof(refcounts));

  foreach (rfid, PHYS_REG_FILE_COUNT) {
    // Null physreg in each register file is special and can never be freed:
    refcounts[rfid][PHYS_REG_NULL]++;
  }

  foreach_forward(ROB, i) {
    ReorderBufferEntry& rob = ROB[i];
    foreach (j, MAX_OPERANDS) {
      refcounts[rob.operands[j]->rfid][rob.operands[j]->index()]++;
    }
  }

  foreach (i, TRANSREG_COUNT) {
    refcounts[commitrrt[i]->rfid][commitrrt[i]->index()]++;
    refcounts[specrrt[i]->rfid][specrrt[i]->index()]++;
  }

  bool errors = 0;

  foreach (rfid, PHYS_REG_FILE_COUNT) {
    PhysicalRegisterFile& physregs = physregfiles[rfid];
    foreach (i, physregs.size) {
      if unlikely (physregs[i].refcount != refcounts[rfid][i]) {
        logfile << "ERROR: r", i, " refcount is ", physregs[i].refcount, " but should be ", refcounts[rfid][i], endl;
        
        foreach_forward(ROB, r) {
          ReorderBufferEntry& rob = ROB[r];
          foreach (j, MAX_OPERANDS) {
            if ((rob.operands[j]->index() == i) & (rob.operands[j]->rfid == rfid)) logfile << "  ROB ", r, " operand ", j, endl;
          }
        }
        
        foreach (j, TRANSREG_COUNT) {
          if ((commitrrt[j]->index() == i) & (commitrrt[j]->rfid == rfid)) logfile << "  CommitRRT ", arch_reg_names[j], endl;
          if ((specrrt[j]->index() == i) & (specrrt[j]->rfid == rfid)) logfile << "  SpecRRT ", arch_reg_names[j], endl;
        }
        
        errors = 1;
      }
    }
  }

  if (errors) assert(false);
}

void OutOfOrderCore::check_rob() {
  foreach (i, ROB_SIZE) {
    ReorderBufferEntry& rob = ROB[i];
    if (!rob.entry_valid) continue;
    assert(inrange((int)rob.forward_cycle, 0, (MAX_FORWARDING_LATENCY+1)-1));
  }

  foreach (i, rob_states.count) {
    StateList& list = *rob_states[i];
    ReorderBufferEntry* rob;
    foreach_list_mutable(list, rob, entry, nextentry) {
      assert(inrange(rob->index(), 0, ROB_SIZE-1));
      assert(rob->current_state_list == &list);
      if (!((rob->current_state_list != &rob_free_list) ? rob->entry_valid : (!rob->entry_valid))) {
        logfile << "ROB ", rob->index(), " list = ", rob->current_state_list->name, " entry_valid ", rob->entry_valid, endl, flush;
        dump_ooo_state(logfile);
        assert(false);
      }
    }
  }
}

ostream& LoadStoreQueueEntry::print(ostream& os) const {
  os << (store ? "st" : "ld"), intstring(index(), -3), " ";
  os << "uuid ", intstring(rob->uop.uuid, 10), " ";
  os << "rob ", intstring(rob->index(), -3), " ";
  os << "r", intstring(rob->physreg->index(), -3);
  if (PHYS_REG_FILE_COUNT > 1) os << "@", getcore().physregfiles[rob->physreg->rfid].name;
  os << " ";
  if (invalid) {
    os << "< Invalid: fault 0x", hexstring(data, 8), " > ";
  } else {
    if (datavalid)
      os << bytemaskstring((const byte*)&data, bytemask, 8);
    else os << "<    Data Invalid     >";
    os << " @ ";
    if (addrvalid)
      os << "0x", hexstring(physaddr << 3, 48);
    else os << "< Addr Inval >";
  }    
  return os;
}

//
// Barriers must flush the fetchq and stall the frontend until
// after the barrier is consumed. Execution resumes at the address
// in internal register nextrip (rip after the instruction) after
// handling the barrier in microcode.
//
bool OutOfOrderCore::handle_barrier() {
  // Release resources of everything in the pipeline:
  core_to_external_state();
  flush_pipeline();

  int assistid = ctx.commitarf[REG_rip];
  assist_func_t assist = (assist_func_t)(Waddr)assistid_to_func[assistid];
  
  if (logable(4)) {
    logfile << "[vcpu ", ctx.vcpuid, "] Barrier (#", assistid, " -> ", (void*)assist, " ", assist_name(assist), " called from ",
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

  // Flush again, but restart at possibly modified rip
  flush_pipeline();

#ifndef PTLSIM_HYPERVISOR
  if (requested_switch_to_native) {
    logfile << "PTL call requested switch to native mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], endl;
    return false;
  }
#endif
  return true;
}

bool OutOfOrderCore::handle_exception() {
  // Release resources of everything in the pipeline:
  core_to_external_state();
  flush_pipeline();

  if (logable(4)) {
    logfile << "Exception ", exception_name(ctx.exception), " called from rip ", (void*)(Waddr)ctx.commitarf[REG_rip], 
      " at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits", endl, flush;
  }

  //
  // CheckFailed and SkipBlock exceptions are raised by the chk uop.
  // This uop is used at the start of microcoded instructions to assert
  // that certain conditions are true so complex corrective actions can
  // be taken if the check fails.
  //
  // SkipBlock is a special case used for checks at the top of REP loops.
  // Specifically, if the %rcx register is zero on entry to the REP, no
  // action at all is to be taken; the rip should simply advance to
  // whatever is in chk_recovery_rip and execution should resume.
  //
  // CheckFailed exceptions usually indicate the processor needs to take
  // evasive action to avoid a user visible exception. For instance, 
  // CheckFailed is raised when an inlined floating point operand is
  // denormal or otherwise cannot be handled by inlined fastpath uops,
  // or when some unexpected segmentation or page table conditions
  // arise.
  //
  if (ctx.exception == EXCEPTION_SkipBlock) {
    ctx.commitarf[REG_rip] = chk_recovery_rip;
    if (logable(6)) logfile << "SkipBlock pseudo-exception: skipping to ", (void*)(Waddr)ctx.commitarf[REG_rip], endl, flush;
    flush_pipeline();
    return true;
  }

#ifdef PTLSIM_HYPERVISOR
  //
  // Map PTL internal hardware exceptions to their x86 equivalents,
  // depending on the context. The error_code field should already
  // be filled out.
  //
  // Exceptions not listed here are propagated by microcode
  // rather than the processor itself.
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

  // Flush again, but restart at modified rip
  flush_pipeline();

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
  machine.dump_state(logfile);
  logfile << flush;

  logfile << "Aborting...", endl, flush;
  cerr << "Aborting...", endl, flush;

  abort();
  return false;
#endif
}

bool OutOfOrderCore::handle_interrupt() {
#ifdef PTLSIM_HYPERVISOR
  // Release resources of everything in the pipeline:
  core_to_external_state();
  flush_pipeline();

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

  // Flush again, but restart at modified rip
  flush_pipeline();
#endif
  return true;
}

//
// Event Formatting
//
void PhysicalRegister::fill_operand_info(PhysicalRegisterOperandInfo& opinfo) {
  opinfo.physreg = index();
  opinfo.state = state;
  opinfo.rfid = rfid;
  opinfo.archreg = archreg;
  if (rob) {
    opinfo.rob = rob->index();
    opinfo.uuid = rob->uop.uuid;
  }
}

ostream& OutOfOrderModel::operator <<(ostream& os, const PhysicalRegisterOperandInfo& opinfo) {
  os << "[r", opinfo.physreg, " ", short_physreg_state_names[opinfo.state], " ";
  switch (opinfo.state) {
  case PHYSREG_WAITING:
  case PHYSREG_BYPASS:
  case PHYSREG_WRITTEN:
    os << "rob ", opinfo.rob, " uuid ", opinfo.uuid; break;
  case PHYSREG_ARCH:
  case PHYSREG_PENDINGFREE:
    os << arch_reg_names[opinfo.archreg]; break;
  };
  os << "]";
  return os;
}

bool EventLog::init(size_t bufsize) {
  reset();
  size_t bytes = bufsize * sizeof(OutOfOrderCoreEvent);
  start = (OutOfOrderCoreEvent*)ptl_mm_alloc_private_pages(bytes);
  if unlikely (!start) return false;
  end = start + bufsize;
  tail = start;
  
  foreach (i, bufsize) start[i].type = EVENT_INVALID;
  return true;
}

void EventLog::reset() {
  if (!start) return;

  size_t bytes = (end - start) * sizeof(OutOfOrderCoreEvent);
  ptl_mm_free_private_pages(start, bytes);
  start = null;
  end = null;
  tail = null;
}

void EventLog::flush(bool only_to_tail) {
  if likely (!logable(6)) return;
  if unlikely (!logfile) return;
  if unlikely (!logfile->ok()) return;
  print(*logfile, only_to_tail);
  tail = start;
}

ostream& EventLog::print(ostream& os, bool only_to_tail) {
  if (tail >= end) tail = start;
  if (tail < start) tail = end;

  OutOfOrderCoreEvent* p = (only_to_tail) ? start : tail;

  // os << "Ring buffer (tail ", (tail - start), " out of ", (end - start), " entries):", endl;

  W64 cycle = limits<W64>::max;
  size_t bufsize = end - start;
  foreach (i, (only_to_tail ? (tail - start) : bufsize)) {
    if unlikely (p >= end) p = start;
    if unlikely (p < start) p = end-1;
    if unlikely (p->type == EVENT_INVALID) {
      p++;
      continue;
    }

    if unlikely (p->cycle != cycle) {
      cycle = p->cycle;
      os << "Cycle ", cycle, ":", endl;
    }

    p->print(os);
    p++;
  }

  return os;
}

ostream& OutOfOrderCoreEvent::print(ostream& os) const {
  bool ld = isload(uop.opcode);
  bool st = isstore(uop.opcode);
  bool br = isbranch(uop.opcode);
  W32 exception = LO32(commit.state.reg.rddata);
  W32 error_code = HI32(commit.state.reg.rddata);

  os << intstring(uuid, 20), " ";
  switch (type) {
    //
    // Fetch Events
    //
  case EVENT_FETCH_STALLED:
    os << "fetch  frontend stalled"; break;
  case EVENT_FETCH_ICACHE_WAIT:
    os << "fetch  rip ", rip, ": wait for icache fill"; break;
  case EVENT_FETCH_FETCHQ_FULL:
    os << "fetch  rip ", rip, ": fetchq full"; break;
  case EVENT_FETCH_BOGUS_RIP:
    os << "fetch  rip ", rip, ": bogus RIP or decode failed"; break;
  case EVENT_FETCH_ICACHE_MISS:
    os << "fetch  rip ", rip, ": wait for icache fill of phys ", (void*)(Waddr)((rip.mfnlo << 12) + lowbits(rip.rip, 12)), " on missbuf ", fetch.missbuf; break;
  case EVENT_FETCH_SPLIT:
    os << "fetch  rip ", rip, ": split unaligned load or store ", uop; break;
  case EVENT_FETCH_ASSIST:
    os << "fetch  rip ", rip, ": branch into assist microcode: ", uop; break;
  case EVENT_FETCH_TRANSLATE:
    os << "xlate  rip ", rip, ": BB ", fetch.bb, " of ", fetch.bb_uop_count, " uops"; break;
  case EVENT_FETCH_OK: {
    os << "fetch  rip ", rip, ": ", uop, 
      " (BB ", fetch.bb, " uopid ", uop.bbindex;
    if (uop.som) os << "; SOM";
    if (uop.eom) os << "; EOM ", uop.bytes, " bytes";
    os << ")";
    if (uop.eom && fetch.predrip) os << " -> pred ", (void*)fetch.predrip;
    break;
  }
    //
    // Rename Events
    //
  case EVENT_RENAME_FETCHQ_EMPTY:
    os << "rename fetchq empty"; break;
  case EVENT_RENAME_ROB_FULL:
    os << "rename ROB full"; break;
  case EVENT_RENAME_PHYSREGS_FULL:
    os << "rename physical register file full"; break;
  case EVENT_RENAME_LDQ_FULL:
    os << "rename load queue full"; break;
  case EVENT_RENAME_STQ_FULL:
    os << "rename store queue full"; break;
  case EVENT_RENAME_MEMQ_FULL:
    os << "rename memory queue full"; break;
  case EVENT_RENAME_OK: {
    os << "rename rob ", intstring(rob, -3), " r", intstring(physreg, -3), "@", phys_reg_file_names[rfid];
    if (ld|st) os << " lsq", lsq;
    os << " = ";
    foreach (i, MAX_OPERANDS) os << rename.opinfo[i], ((i < MAX_OPERANDS-1) ? " " : "");
    os << "; renamed";
    os << " ", arch_reg_names[uop.rd], " (old r", rename.oldphys, ")";
    if unlikely (!uop.nouserflags) {
      if likely (uop.setflags & SETFLAG_ZF) os << " zf (old r", rename.oldzf, ")";
      if likely (uop.setflags & SETFLAG_CF) os << " cf (old r", rename.oldcf, ")";
      if likely (uop.setflags & SETFLAG_OF) os << " of (old r", rename.oldof, ")";
    }
    break;
  }
  case EVENT_FRONTEND:
    os << "front  rob ", intstring(rob, -3), " frontend stage ", (FRONTEND_STAGES - frontend.cycles_left), " of ", FRONTEND_STAGES;
    break;
  case EVENT_CLUSTER_NO_CLUSTER:
  case EVENT_CLUSTER_OK: {
    os << "clustr rob ", intstring(rob, -3), " allowed FUs = ", 
      bitstring(fuinfo[uop.opcode].fu, FU_COUNT, true), " -> clusters ",
      bitstring(select_cluster.allowed_clusters, MAX_CLUSTERS, true), " avail";
    foreach (i, MAX_CLUSTERS) os << " ", select_cluster.iq_avail[i];
    os << "-> ";
    if (type == EVENT_CLUSTER_OK) os << "cluster ", clusters[cluster].name; else os << "-> none"; break;
    break;
  }
  case EVENT_DISPATCH_NO_CLUSTER:
  case EVENT_DISPATCH_OK: {
    os << "disptc rob ", intstring(rob, -3), " operands ";
    foreach (i, MAX_OPERANDS) os << dispatch.opinfo[i], ((i < MAX_OPERANDS-1) ? " " : "");
    if (type == EVENT_DISPATCH_OK) os << " -> cluster ", clusters[cluster].name; else os << " -> none";
    break;
  }
  case EVENT_ISSUE_NO_FU: {
    os << "issue  rob ", intstring(rob, -3);
    os << "no FUs available in cluster ", clusters[cluster].name, ": ",
      "fu_avail = ", bitstring(issue.fu_avail, FU_COUNT, true), ", ",
      "op_fu = ", bitstring(fuinfo[uop.opcode].fu, FU_COUNT, true), ", "
      "fu_cl_mask = ", bitstring(clusters[cluster].fu_mask, FU_COUNT, true);
    break;
  }
  case EVENT_ISSUE_OK: {
    stringbuf sb;
    sb << "issue  rob ", intstring(rob, -3);
    sb << " on ", padstring(fu_names[fu], -4), " in ", padstring(cluster_names[cluster], -4), ": r", intstring(physreg, -3), "@", phys_reg_file_names[rfid];
    sb << " "; print_value_and_flags(sb, issue.state.reg.rddata, issue.state.reg.rdflags); sb << " =";
    sb << " "; print_value_and_flags(sb, issue.operand_data[RA], issue.operand_flags[RA]); sb << ", ";
    sb << " "; print_value_and_flags(sb, issue.operand_data[RB], issue.operand_flags[RB]); sb << ", ";
    sb << " "; print_value_and_flags(sb, issue.operand_data[RC], issue.operand_flags[RC]);
    sb << " (", issue.cycles_left, " cycles left)";
    if (issue.mispredicted) sb << "; mispredicted (real ", (void*)(Waddr)issue.state.reg.rddata, " vs expected ", (void*)(Waddr)issue.predrip, ")";
    os << sb;
    break;
  }
  case EVENT_REPLAY: {
    os << "replay rob ", intstring(rob, -3), " r", intstring(physreg, -3), "@", phys_reg_file_names[rfid],
      " on cluster ", clusters[cluster].name, ": waiting on";
    foreach (i, MAX_OPERANDS) {
      if (!bit(replay.ready, i)) os << " ", replay.opinfo[i];
    }
    break;
  }
  case EVENT_STORE_WAIT: {
    os << "store", (loadstore.load_store_second_phase ? "2" : " "), " rob ", intstring(rob, -3), " stq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ";
    os << "wait on ";
    if (!loadstore.rcready) os << " rc";
    if (loadstore.inherit_sfr_used) {
      os << ((loadstore.rcready) ? "" : " and "), loadstore.inherit_sfr,
        " (uuid ", loadstore.inherit_sfr_uuid, ", stq ", loadstore.inherit_sfr_lsq,
        ", rob ", loadstore.inherit_sfr_rob, ", r", loadstore.inherit_sfr_physreg, ")";
    }
    break;
  }
  case EVENT_STORE_PARALLEL_FORWARDING_MATCH: {
    os << "store", (loadstore.load_store_second_phase ? "2" : " "), " rob ", intstring(rob, -3), " stq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ";
    os << "ignored parallel forwarding match with ldq ", loadstore.inherit_sfr_lsq,
      " (uuid ", loadstore.inherit_sfr_uuid, " rob", loadstore.inherit_sfr_rob,
      " r", loadstore.inherit_sfr_physreg, ")";
    break;
  }
  case EVENT_STORE_ALIASED_LOAD: {
    os << "store", (loadstore.load_store_second_phase ? "2" : " "), " rob ", intstring(rob, -3), " stq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ";
    os << "aliased with ldbuf ", loadstore.inherit_sfr_lsq, " (uuid ", loadstore.inherit_sfr_uuid,
      " rob", loadstore.inherit_sfr_rob, " r", loadstore.inherit_sfr_physreg, ");",
      " (add colliding load rip ", (void*)(Waddr)loadstore.inherit_sfr_rip, "; replay from rip ", rip, ")";
    break;
  }
  case EVENT_STORE_ISSUED: {
    os << "store", (loadstore.load_store_second_phase ? "2" : " "), " rob ", intstring(rob, -3), " stq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ";
    if (loadstore.inherit_sfr_used) {
      os << "inherit from ", loadstore.inherit_sfr, " (uuid ", loadstore.inherit_sfr_uuid,
        ", rob", loadstore.inherit_sfr_rob, ", lsq ", loadstore.inherit_sfr_lsq,
        ", r", loadstore.inherit_sfr_physreg, ");";
    }
    os << " <= ", hexstring(loadstore.data_to_store, 8*(1<<uop.size)), " = ", loadstore.sfr;
    break;
  }
  case EVENT_STORE_LOCK_RELEASED: {
    os << "lk-rel", " rob ", intstring(rob, -3), " stq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ",
      "lock released (original ld.acq uuid ", loadstore.locking_uuid, " rob ", loadstore.locking_rob, " on vcpu ", loadstore.locking_vcpuid, ")";
    break;
  }
  case EVENT_STORE_LOCK_ANNULLED: {
    os << "lk-anl", " rob ", intstring(rob, -3), " stq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ",
      "lock annulled (original ld.acq uuid ", loadstore.locking_uuid, " rob ", loadstore.locking_rob, " on vcpu ", loadstore.locking_vcpuid, ")";
    break;
  }
  case EVENT_STORE_LOCK_REPLAY: {
    os << "store", (loadstore.load_store_second_phase ? "2" : " "), " rob ", intstring(rob, -3), " stq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ",
      "replay because vcpuid ", loadstore.locking_vcpuid, " uop uuid ", loadstore.locking_uuid, " has lock";
    break;
  }
  case EVENT_LOAD_WAIT: {
    os << (loadstore.load_store_second_phase ? "load2 " : "load  "), " rob ", intstring(rob, -3), " ldq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ";
    os << "wait on sfr ", loadstore.inherit_sfr,
      " (uuid ", loadstore.inherit_sfr_uuid, ", stq ", loadstore.inherit_sfr_lsq,
      ", rob ", loadstore.inherit_sfr_rob, ", r", loadstore.inherit_sfr_physreg, ")";
    if (loadstore.predicted_alias) os << "; stalled by predicted aliasing";
    break;
  }
  case EVENT_LOAD_HIT: 
  case EVENT_LOAD_MISS: {
    if (type == EVENT_LOAD_HIT)
      os << (loadstore.load_store_second_phase ? "load2 " : "load  ");
    else os << (loadstore.load_store_second_phase ? "ldmis2" : "ldmiss");

    os << " rob ", intstring(rob, -3), " ldq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ";
    if (loadstore.inherit_sfr_used) {
      os << "inherit from ", loadstore.inherit_sfr, " (uuid ", loadstore.inherit_sfr_uuid,
        ", rob", loadstore.inherit_sfr_rob, ", lsq ", loadstore.inherit_sfr_lsq,
        ", r", loadstore.inherit_sfr_physreg, "); ";
    }
    if (type == EVENT_LOAD_HIT)
      os << "hit L1: value 0x", hexstring(loadstore.sfr.data, 64);
    else os << "missed L1 (lfrqslot ", lfrqslot, ") [value would be 0x", hexstring(loadstore.sfr.data, 64), "]";
    break;
  }
  case EVENT_LOAD_LOCK_REPLAY: {
    os << (loadstore.load_store_second_phase ? "load2 " : "load  "), " rob ", intstring(rob, -3), " ldq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ",
      "replay because vcpuid ", loadstore.locking_vcpuid, " uop uuid ", loadstore.locking_uuid, " has lock";
    break;
  }
  case EVENT_LOAD_LOCK_OVERFLOW: {
    os << (loadstore.load_store_second_phase ? "load2 " : "load  "), " rob ", intstring(rob, -3), " ldq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ",
      "replay because locking required but no free interlock buffers", endl;
    break;
  }
  case EVENT_LOAD_LOCK_ACQUIRED: {
    os << "lk-acq", " rob ", intstring(rob, -3), " ldq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ",
      "lock acquired";
    break;
  }
  case EVENT_LOAD_LFRQ_FULL:
    os << "load   rob ", intstring(rob, -3), " ldq ", lsq, " r", intstring(physreg, -3), ": LFRQ or miss buffer full; replaying"; break;
  case EVENT_LOAD_HIGH_ANNULLED: {
    os << (loadstore.load_store_second_phase ? "load2 " : "load  "), " rob ", intstring(rob, -3), " ldq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, " (phys ", (void*)(Waddr)(loadstore.sfr.physaddr << 3), "): ";
    os << "load was annulled (high unaligned load)";
    break;
  }
  case EVENT_LOAD_WAKEUP:
    os << "ldwake rob ", intstring(rob, -3), " ldq ", lsq, " r", intstring(physreg, -3), ": wakeup load via lfrq slot ", lfrqslot; break;
  case EVENT_LOAD_EXCEPTION: {
    os << (loadstore.load_store_second_phase ? "load2 " : "load  "), " rob ", intstring(rob, -3), " stq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, ": exception ", exception_name(exception), ", pfec ", PageFaultErrorCode(error_code);
    break;
  }
  case EVENT_STORE_EXCEPTION: {
    os << "store", (loadstore.load_store_second_phase ? "2" : " "), " rob ", intstring(rob, -3), " stq ", lsq,
      " r", intstring(physreg, -3), " on ", padstring(fu_names[fu], -4), " @ ",
      (void*)(Waddr)loadstore.virtaddr, ": exception ", exception_name(exception), ", pfec ", PageFaultErrorCode(error_code);
    break;
  }
  case EVENT_ALIGNMENT_FIXUP:
    os << "algnfx", " rip ", rip, ": set unaligned bit for uop ", uop.bbindex, " and refetch"; break;
  case EVENT_ANNUL_NO_FUTURE_UOPS:
    os << "misspc rob ", intstring(rob, -3), ": SOM rob ", annul.somidx, ", EOM rob ", annul.eomidx, ": no future uops to annul"; break;
  case EVENT_ANNUL_MISSPECULATION: {
    os << "misspc rob ", intstring(rob, -3), ": SOM rob ", annul.somidx, 
      ", EOM rob ", annul.eomidx, ": annul from rob ", annul.startidx, " to rob ", annul.endidx;
    break;
  }
  case EVENT_ANNUL_EACH_ROB: {
    os << "annul  rob ", intstring(rob, -3), ": annul rip ", rip;
    os << (uop.som ? " SOM" : "    "); os << (uop.eom ? " EOM" : "    ");
    os << ": free";
    os << " r", physreg;
    if (ld|st) os << " lsq", lsq;
    if (lfrqslot >= 0) os << " lfrq", lfrqslot;
    if (annul.annulras) os << " ras";
    os << " bb ", annul.bb, " (", annul.bb->refcount, " refs)";
    break;
  }
  case EVENT_ANNUL_PSEUDOCOMMIT: {
    os << "pseucm rob ", intstring(rob, -3), ": r", physreg, " rebuild rrt:";
    os << " arch ", arch_reg_names[uop.rd];
    if likely (!uop.nouserflags) {
      if (uop.setflags & SETFLAG_ZF) os << " zf";
      if (uop.setflags & SETFLAG_CF) os << " cf";
      if (uop.setflags & SETFLAG_OF) os << " of";
    }
    os << " = r", physreg;
    break;
  }
  case EVENT_ANNUL_FETCHQ_RAS:
    os << "anlras rip ", rip, ": annul RAS update still in fetchq"; break;
  case EVENT_ANNUL_FETCHQ:
    os << "anlbbc rip ", rip, ": annul bb ", annul.bb, " (", annul.bb_refcount, " refs)"; break;
  case EVENT_ANNUL_FLUSH:
    os << "flush  rob ", intstring(rob, -3), " rip ", rip, " bb ", annul.bb, " (", annul.bb_refcount, " refs)"; break;
  case EVENT_REDISPATCH_DEPENDENTS:
    os << "redisp rob ", intstring(rob, -3), " find all dependents"; break;
  case EVENT_REDISPATCH_DEPENDENTS_DONE:
    os << "redisp rob ", intstring(rob, -3), " redispatched ", (redispatch.count - 1), " dependent uops"; break;
  case EVENT_REDISPATCH_EACH_ROB: {
    os << "redisp rob ", intstring(rob, -3), " from state ", redispatch.current_state_list->name, ": dep on ";
    if (!redispatch.dependent_operands) {
      os << " [self]";
    } else {
      foreach (i, MAX_OPERANDS) {
        if (bit(redispatch.dependent_operands, i)) os << " ", redispatch.opinfo[i];
      }
    }

    os << "; redispatch ";
    os << " [rob ", rob, "]";
    os << " [physreg ", physreg, "]";
    if (ld|st) os << " [lsq ", lsq, "]";
    if (redispatch.iqslot) os << " [iqslot]";
    if (lfrqslot >= 0) os << " [lfrqslot ", lfrqslot, "]";
    if (redispatch.opinfo[RS].physreg != PHYS_REG_NULL) os << " [inheritsfr ", redispatch.opinfo[RS], "]";

    break;
  }
  case EVENT_COMPLETE:
    os << "complt rob ", intstring(rob, -3), " on ", padstring(fu_names[fu], -4), ": r", intstring(physreg, -3); break;
  case EVENT_FORWARD: {
    os << "forwd", forwarding.forward_cycle, " rob ", intstring(rob, -3), 
      " (", clusters[cluster].name, ") r", intstring(physreg, -3), 
      " => ", "uuid ", forwarding.target_uuid, " rob ", forwarding.target_rob,
      " (", clusters[forwarding.target_cluster].name, ") r", forwarding.target_physreg,
      " operand ", forwarding.operand;
    if (forwarding.target_st) os << " => st", forwarding.target_lsq;
    os << " [still waiting?";
    foreach (i, MAX_OPERANDS) { if (!bit(forwarding.target_operands_ready, i)) os << " r", (char)('a' + i); }
    if (forwarding.target_all_operands_ready) os << " READY";
    os << "]";
    break;
  }
  case EVENT_BROADCAST: {
    os << "brcst", forwarding.forward_cycle, " rob ", intstring(rob, -3), 
      " from cluster ", clusters[cluster].name, " to cluster ", clusters[forwarding.target_cluster].name,
      " on forwarding cycle ", forwarding.forward_cycle;
    break;
  }
  case EVENT_WRITEBACK: {
    os << "write  rob ", intstring(rob, -3), " (cluster ", clusters[cluster].name, ") r", intstring(physreg, -3), "@", phys_reg_file_names[rfid], " = 0x", hexstring(writeback.data, 64), " ", flagstring(writeback.flags);
    if (writeback.transient) os << " (transient)";
    os << " (", writeback.consumer_count, " consumers";
    if (writeback.all_consumers_sourced_from_bypass) os << ", all from bypass";
    if (writeback.no_branches_between_renamings) os << ", no intervening branches";
    if (writeback.dest_renamed_before_writeback) os << ", dest renamed before writeback";
    os << ")";
    break;
  }
  case EVENT_COMMIT_EXCEPTION_DETECTED:
    os << "detect rob ", intstring(rob, -3), " exception ", exception_name(exception), " (", exception, "), error code ", hexstring(error_code, 16), ", origvirt ", (void*)(Waddr)commit.origvirt; break;
  case EVENT_COMMIT_EXCEPTION_ACKNOWLEDGED:
    os << "except rob ", intstring(rob, -3), " exception ", exception_name(exception), " [EOM #", commit.total_user_insns_committed, "]"; break;
  case EVENT_COMMIT_SKIPBLOCK:
    os << "skipbk rob ", intstring(rob, -3), " skip block: advance rip by ", uop.bytes, " to ", (void*)(Waddr)(rip.rip + uop.bytes), " [EOM #", commit.total_user_insns_committed, "]"; break;
  case EVENT_COMMIT_SMC_DETECTED:
    os << "smcdet rob ", intstring(rob, -3), ": self-modifying code at rip ", rip, " detected (mfn was dirty); invalidate and retry [EOM #", commit.total_user_insns_committed, "]"; break;
  case EVENT_COMMIT_OK: {
    os << "commit rob ", intstring(rob, -3);
    if likely (archdest_can_commit[uop.rd])
                os << " [rrt ", arch_reg_names[uop.rd], " = r", physreg, " 0x", hexstring(commit.state.reg.rddata, 64), "]";

    if ((!uop.nouserflags) && uop.setflags) {
      os << " [flags ", ((uop.setflags & SETFLAG_ZF) ? "z" : ""), 
        ((uop.setflags & SETFLAG_CF) ? "c" : ""), ((uop.setflags & SETFLAG_OF) ? "o" : ""),
        " -> ", flagstring(commit.state.reg.rdflags), "]";
    }

    if (uop.eom) os << " [rip = ", (void*)(Waddr)commit.target_rip, "]";

    if unlikely (st && commit.state.st.bytemask)
                  os << " [mem ", (void*)(Waddr)(commit.state.st.physaddr << 3), " = ", bytemaskstring((const byte*)&commit.state.st.data, commit.state.st.bytemask, 8), "]";

    if unlikely (commit.pteupdate.a | commit.pteupdate.d | commit.pteupdate.ptwrite) {
      os << " [pte:";
      if (commit.pteupdate.a) os << " a";
      if (commit.pteupdate.d) os << " d";
      if (commit.pteupdate.ptwrite) os << " w";
      os << "]";
    }
        
    if unlikely (ld|st) {
      os << " [lsq ", lsq, "]";
    }
        
    if likely (commit.oldphysreg > 0) {
      if unlikely (commit.oldphysreg_refcount) {
        os << " [pending free old r", commit.oldphysreg, " ref by";
        os << " refcount ", commit.oldphysreg_refcount;
        os << "]";
      } else {
        os << " [free old r", commit.oldphysreg, "]";
      }
    }

    os << " [commit r", physreg, "]";

    foreach (i, MAX_OPERANDS) {
      if unlikely (commit.operand_physregs[i] != PHYS_REG_NULL) os << " [unref r", commit.operand_physregs[i], "]";
    }

    if unlikely (br) {
      os << " [brupdate", (commit.taken ? " tk" : " nt"), (commit.predtaken ? " pt" : " np"), ((commit.taken == commit.predtaken) ? " ok" : " MP"), "]";
    }
        
    os << " [bb ", commit.bb, ", ", commit.bb_refcount, " refs]";    
    if (uop.eom) os << " [EOM #", commit.total_user_insns_committed, "]";
    break;
  }
  case EVENT_COMMIT_ASSIST: {
    os << "assist rob ", intstring(rob, -3), " calling assist ", (void*)rip.rip, " (#",
      assist_index((assist_func_t)rip.rip), ": ", assist_name((assist_func_t)rip.rip), ")";
    break;
  }
  case EVENT_RECLAIM_PHYSREG:
    os << "free   r", physreg, " no longer referenced; moving to free state"; break;
  default:
    os << "?????? unknown event type ", type;
    break;
  }

  os << endl;
  return os;
}

OutOfOrderMachine::OutOfOrderMachine(const char* name) {
  // Add to the list of available core types
  addmachine(name, this);
}

//
// Construct all the structures necessary to configure
// the cores. This function is only called once, after
// all other PTLsim subsystems are brought up.
//
bool OutOfOrderMachine::init(PTLsimConfig& config) {
  foreach (i, contextcount) {
    cores[i] = new OutOfOrderCore(i, contextof(i), *this);
    cores[i]->init();
    //
    // Note: in a multi-processor model, config may
    // specify various ways of slicing contextcount up
    // into threads, cores and sockets; the appropriate
    // interconnect and cache hierarchy parameters may
    // be specified here.
    //
  }
  
  init_luts();
  return true;
}

//
// Run the processor model, until a stopping point
// is hit (as configured elsewhere in config).
//
int OutOfOrderMachine::run(PTLsimConfig& config) {
  time_this_scope(cttotal);

  logfile << "Starting out-of-order core toplevel loop", endl, flush;

  foreach (i, contextcount) {
    OutOfOrderCore& core =* cores[i];
    Context& ctx = contextof(i);

    if unlikely (config.event_log_enabled && (!core.eventlog.start)) {
      core.eventlog.init(config.event_log_ring_buffer_size);
      core.eventlog.logfile = &logfile;
    }

    core.flush_pipeline();

    if (logable(6)) {
      logfile << "VCPU ", i, " initial state:", endl;
      logfile << ctx;
      logfile << endl;
    }
  }

  bool exiting = false;

  for (;;) {
    if unlikely (iterations >= config.start_log_at_iteration) {
      if unlikely (!logenable) logfile << "Start logging at level ", config.loglevel, " in cycle ", iterations, endl, flush;
      logenable = 1;
    }

    update_progress();
    inject_events();

    foreach (i, contextcount) {
      OutOfOrderCore& core =* cores[i];
      Context& ctx = contextof(i);

#ifdef PTLSIM_HYPERVISOR
      if unlikely (!ctx.running) {
        if (ctx.check_events()) core.handle_interrupt();
        continue;
      }
#endif
      exiting |= core.runcycle();
    }

    exiting |= check_for_async_sim_break();

    stats.summary.cycles++;
    stats.ooocore.cycles++;
    sim_cycle++;
    iterations++;

    if unlikely (exiting) break;
  }

  logfile << "Exiting out of order mode at ", total_user_insns_committed, " commits, ", total_uops_committed, " uops and ", iterations, " iterations (cycles)", endl;

  foreach (i, contextcount) {
    OutOfOrderCore& core =* cores[i];
    Context& ctx = contextof(i);

    core.core_to_external_state();

    if (logable(6) | ((sim_cycle - core.last_commit_at_cycle) > 1024) | config.dump_state_now) {
      logfile << "VCPU ", i, " core state at end:", endl;
      logfile << ctx;
      core.dump_ooo_state(logfile);
      if (config.event_log_enabled) core.eventlog.print(logfile);
    }
  }

  config.dump_state_now = 0;

  // Flush everything to remove any remaining refs to basic blocks
  flush_all_pipelines();

  return exiting;
}

void OutOfOrderMachine::dump_state(ostream& os) {
  foreach (i, contextcount) {
    if (!cores[i]) continue;
    OutOfOrderCore& core =* cores[i];
    Context& ctx = contextof(i);
    os << "Core ", i, ":", endl;
    if unlikely (config.event_log_enabled) core.eventlog.print(logfile);
    core.dump_ooo_state(os);
  }
  os << "Memory interlock buffer:", endl;
  interlocks.print(os);
}

namespace OutOfOrderModel {
  CycleTimer cttotal;
  CycleTimer ctfetch;
  CycleTimer ctdecode;
  CycleTimer ctrename;
  CycleTimer ctfrontend;
  CycleTimer ctdispatch;
  CycleTimer ctissue;
  CycleTimer ctissueload;
  CycleTimer ctissuestore;
  CycleTimer ctcomplete;
  CycleTimer cttransfer;
  CycleTimer ctwriteback;
  CycleTimer ctcommit;
};

void OutOfOrderMachine::update_stats(PTLsimStats& stats) {
  stats.ooocore.issue.uipc = (double)stats.ooocore.issue.uops / (double)stats.ooocore.cycles;
  stats.ooocore.commit.uipc = (double)stats.ooocore.commit.uops / (double)stats.ooocore.cycles;
  stats.ooocore.commit.ipc = (double)stats.ooocore.commit.insns / (double)stats.ooocore.cycles;

  stats.ooocore.simulator.total_time = cttotal.seconds();
  stats.ooocore.simulator.cputime.fetch = ctfetch.seconds();
  stats.ooocore.simulator.cputime.decode = ctdecode.seconds();
  stats.ooocore.simulator.cputime.rename = ctrename.seconds();
  stats.ooocore.simulator.cputime.frontend = ctfrontend.seconds();
  stats.ooocore.simulator.cputime.dispatch = ctdispatch.seconds();
  stats.ooocore.simulator.cputime.issue = ctissue.seconds() - (ctissueload.seconds() + ctissuestore.seconds());
  stats.ooocore.simulator.cputime.issueload = ctissueload.seconds();
  stats.ooocore.simulator.cputime.issuestore = ctissuestore.seconds();
  stats.ooocore.simulator.cputime.complete = ctcomplete.seconds();
  stats.ooocore.simulator.cputime.transfer = cttransfer.seconds();
  stats.ooocore.simulator.cputime.writeback = ctwriteback.seconds();
  stats.ooocore.simulator.cputime.commit = ctcommit.seconds();
}

//
// Flush all pipelines in every core, and process any
// pending BB cache invalidates.
//
// Typically this is in response to some infrequent event
// like cross-modifying SMC or cache coherence deadlocks.
//
void OutOfOrderMachine::flush_all_pipelines() {
  foreach (i, contextcount) {
    if (!cores[i]) continue;
    OutOfOrderCore& core =* cores[i];
    core.flush_pipeline();
  }

  foreach (i, contextcount) {
    if (!cores[i]) continue;
    OutOfOrderCore& core =* cores[i];
    core.invalidate_smc();
  }
}

OutOfOrderMachine ooomodel("ooo");

OutOfOrderCore& OutOfOrderModel::coreof(int coreid) {
  return *ooomodel.cores[coreid];
}
