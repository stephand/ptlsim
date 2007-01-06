// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Out-of-Order Core Simulator Configuration
//
// Copyright 2003-2006 Matt T. Yourst <yourst@yourst.com>
//

// With these disabled, simulation is faster
//#define ENABLE_CHECKS
#define ENABLE_LOGGING

#ifndef _OOOCORE_H_
#define _OOOCORE_H_

//#define ENABLE_SIM_TIMING
#ifdef ENABLE_SIM_TIMING
#define time_this_scope(ct) CycleTimerScope ctscope(ct)
#define start_timer(ct) ct.start()
#define stop_timer(ct) ct.stop()
#else
#define time_this_scope(ct) (0)
#define start_timer(ct) (0)
#define stop_timer(ct) (0)
#endif

namespace OutOfOrderModel {
  //
  // Operand formats
  //
  static const int MAX_OPERANDS = 4;
  static const int RA = 0;
  static const int RB = 1;
  static const int RC = 2;
  static const int RS = 3;

  //
  // Uop to functional unit mappings
  //
  static const int FU_COUNT = 8;
  static const int LOADLAT = 2;

  enum {
    FU_LDU0       = (1 << 0),
    FU_STU0       = (1 << 1),
    FU_LDU1       = (1 << 2),
    FU_STU1       = (1 << 3),
    FU_ALU0       = (1 << 4),
    FU_FPU0       = (1 << 5),
    FU_ALU1       = (1 << 6),
    FU_FPU1       = (1 << 7),
  };

  static const int LOAD_FU_COUNT = 2;

  const char* fu_names[FU_COUNT] = {
    "ldu0",
    "stu0",
    "ldu1",
    "stu1",
    "alu0",
    "fpu0",
    "alu1",
    "fpu1",
  };

  //
  // Opcodes and properties
  //
#define ALU0 FU_ALU0
#define ALU1 FU_ALU1
#define STU0 FU_STU0
#define STU1 FU_STU1
#define LDU0 FU_LDU0
#define LDU1 FU_LDU1
#define FPU0 FU_FPU0
#define FPU1 FU_FPU1
#define A 1 // ALU latency, assuming fast bypass
#define L LOADLAT

#define ANYALU ALU0|ALU1
#define ANYLDU LDU0|LDU1
#define ANYSTU STU0|STU1
#define ANYFPU FPU0|FPU1
#define ANYINT ANYALU|ANYSTU|ANYLDU

  struct FunctionalUnitInfo {
    byte opcode;   // Must match definition in ptlhwdef.h and ptlhwdef.cpp! 
    byte latency;  // Latency in cycles, assuming ideal bypass
    W16  fu;       // Map of functional units on which this uop can issue
  };

  //
  // WARNING: This table MUST be kept in sync with the table
  // in ptlhwdef.cpp and the uop enum in ptlhwdef.h!
  //
  const FunctionalUnitInfo fuinfo[OP_MAX_OPCODE] = {
    // name, latency, fumask
    {OP_nop,            A, ANYINT|ANYFPU},
    {OP_mov,            A, ANYINT|ANYFPU},
    // Logical
    {OP_and,            A, ANYINT|ANYFPU},
    {OP_andnot,         A, ANYINT|ANYFPU},
    {OP_xor,            A, ANYINT|ANYFPU},
    {OP_or,             A, ANYINT|ANYFPU},
    {OP_nand,           A, ANYINT|ANYFPU},
    {OP_ornot,          A, ANYINT|ANYFPU},
    {OP_eqv,            A, ANYINT|ANYFPU},
    {OP_nor,            A, ANYINT|ANYFPU},
    // Mask, insert or extract bytes
    {OP_maskb,          A, ANYINT},
    // Add and subtract
    {OP_add,            A, ANYINT},
    {OP_sub,            A, ANYINT},
    {OP_adda,           A, ANYINT},
    {OP_suba,           A, ANYINT},
    {OP_addm,           A, ANYINT},
    {OP_subm,           A, ANYINT},
    // Condition code logical ops
    {OP_andcc,          A, ANYINT},
    {OP_orcc,           A, ANYINT},
    {OP_xorcc,          A, ANYINT},
    {OP_ornotcc,        A, ANYINT},
    // Condition code movement and merging
    {OP_movccr,         A, ANYINT},
    {OP_movrcc,         A, ANYINT},
    {OP_collcc,         A, ANYINT},
    // Simple shifting (restricted to small immediate 1..8)
    {OP_shls,           A, ANYINT},
    {OP_shrs,           A, ANYINT},
    {OP_bswap,          A, ANYINT},
    {OP_sars,           A, ANYINT},
    // Bit testing
    {OP_bt,             A, ANYALU},
    {OP_bts,            A, ANYALU},
    {OP_btr,            A, ANYALU},
    {OP_btc,            A, ANYALU},
    // Set and select
    {OP_set,            A, ANYINT},
    {OP_set_sub,        A, ANYINT},
    {OP_set_and,        A, ANYINT},
    {OP_sel,            A, ANYINT},
    // Branches
    {OP_br,             A, ANYINT},
    {OP_br_sub,         A, ANYINT},
    {OP_br_and,         A, ANYINT},
    {OP_jmp,            A, ANYINT},
    {OP_bru,            A, ANYINT},
    {OP_jmpp,           A, ANYALU|ANYLDU},
    {OP_brp,            A, ANYALU|ANYLDU},
    // Checks
    {OP_chk,            A, ANYINT},
    {OP_chk_sub,        A, ANYINT},
    {OP_chk_and,        A, ANYINT},
    // Loads and stores
    {OP_ld,             L, ANYLDU},
    {OP_ldx,            L, ANYLDU},
    {OP_ld_pre,         1, ANYLDU},
    {OP_st,             1, ANYSTU},
    {OP_mf,             1, STU0  },
    // Shifts, rotates and complex masking
    {OP_shl,            A, ANYALU},
    {OP_shr,            A, ANYALU},
    {OP_mask,           A, ANYALU},
    {OP_sar,            A, ANYALU},
    {OP_rotl,           A, ANYALU},  
    {OP_rotr,           A, ANYALU},   
    {OP_rotcl,          A, ANYALU},
    {OP_rotcr,          A, ANYALU},  
    // Multiplication
    {OP_mull,           4, ANYFPU},
    {OP_mulh,           4, ANYFPU},
    {OP_mulhu,          4, ANYFPU},
    // Bit scans
    {OP_ctz,            3, ANYFPU},
    {OP_clz,            3, ANYFPU},
    {OP_ctpop,          3, ANYFPU},  
    {OP_permb,          4, ANYFPU},
    // Floating point
    // uop.size bits have following meaning:
    // 00 = single precision, scalar (preserve high 32 bits of ra)
    // 01 = single precision, packed (two 32-bit floats)
    // 1x = double precision, scalar or packed (use two uops to process 128-bit xmm)
    {OP_addf,           6, ANYFPU},
    {OP_subf,           6, ANYFPU},
    {OP_mulf,           6, ANYFPU},
    {OP_maddf,          6, ANYFPU},
    {OP_msubf,          6, ANYFPU},
    {OP_divf,           6, ANYFPU},
    {OP_sqrtf,          6, ANYFPU},
    {OP_rcpf,           6, ANYFPU},
    {OP_rsqrtf,         6, ANYFPU},
    {OP_minf,           4, ANYFPU},
    {OP_maxf,           4, ANYFPU},
    {OP_cmpf,           4, ANYFPU},
    // For fcmpcc, uop.size bits have following meaning:
    // 00 = single precision ordered compare
    // 01 = single precision unordered compare
    // 10 = double precision ordered compare
    // 11 = double precision unordered compare
    {OP_cmpccf,         4, ANYFPU},
    // and/andn/or/xor are done using integer uops
    {OP_permf,          3, ANYFPU}, // shuffles
    // For these conversions, uop.size bits select truncation mode:
    // x0 = normal IEEE-style rounding
    // x1 = truncate to zero
    {OP_cvtf_i2s_ins,   6, ANYFPU},
    {OP_cvtf_i2s_p,     6, ANYFPU},
    {OP_cvtf_i2d_lo,    6, ANYFPU},
    {OP_cvtf_i2d_hi,    6, ANYFPU},
    {OP_cvtf_q2s_ins,   6, ANYFPU},
    {OP_cvtf_q2d,       6, ANYFPU},
    {OP_cvtf_s2i,       6, ANYFPU},
    {OP_cvtf_s2q,       6, ANYFPU},
    {OP_cvtf_s2i_p,     6, ANYFPU},
    {OP_cvtf_d2i,       6, ANYFPU},
    {OP_cvtf_d2q,       6, ANYFPU},
    {OP_cvtf_d2i_p,     6, ANYFPU},
    {OP_cvtf_d2s_ins,   6, ANYFPU},
    {OP_cvtf_d2s_p,     6, ANYFPU},
    {OP_cvtf_s2d_lo,    6, ANYFPU},
    {OP_cvtf_s2d_hi,    6, ANYFPU},
  };

#undef A
#undef L
#undef F

#undef ALU0
#undef ALU1
#undef STU0
#undef STU1
#undef LDU0
#undef LDU1
#undef FPU0
#undef FPU1
#undef L

#undef ANYALU
#undef ANYLDU
#undef ANYSTU
#undef ANYFPU
#undef ANYINT
  
  //
  // Global limits
  //
  
  const int MAX_ISSUE_WIDTH = 8;
  
  // Largest size of any physical register file or the store queue:
  const int MAX_PHYS_REG_FILE_SIZE = 128;
  const int PHYS_REG_NULL = 0;
  
  //
  // IMPORTANT! If you change this to be greater than 256, you MUST
  // #define BIG_ROB below to use the correct associative search logic
  // (16-bit tags vs 8-bit tags).
  //
  //#define BIG_ROB
  
  const int ROB_SIZE = 128;
  
  // Maximum number of branches in the pipeline at any given time
  const int MAX_BRANCHES_IN_FLIGHT = 32;

  // Set this to combine the integer and FP phys reg files:
  // #define UNIFIED_INT_FP_PHYS_REG_FILE
  
#ifdef UNIFIED_INT_FP_PHYS_REG_FILE
  // unified, br, st
  const int PHYS_REG_FILE_COUNT = 3;
#else
  // int, fp, br, st
  const int PHYS_REG_FILE_COUNT = 4;
#endif
  
  //
  // Load and Store Queues
  //
  const int LDQ_SIZE = 48;
  const int STQ_SIZE = 32;

  //
  // Fetch
  //
  const int FETCH_QUEUE_SIZE = 32;
  const int FETCH_WIDTH = 4;

  //
  // Frontend (Rename and Decode)
  //
  const int FRONTEND_WIDTH = 4;
  const int FRONTEND_STAGES = 5;

  //
  // Dispatch
  //
  const int DISPATCH_WIDTH = 4;

  //
  // Writeback
  //
  const int WRITEBACK_WIDTH = 4;

  //
  // Commit
  //
  const int COMMIT_WIDTH = 4;

  //
  // Clustering, Issue Queues and Bypass Network
  //
  const int MAX_FORWARDING_LATENCY = 2;
  const int MAX_CLUSTERS = 4;

  enum { PHYSREG_NONE, PHYSREG_FREE, PHYSREG_WAITING, PHYSREG_BYPASS, PHYSREG_WRITTEN, PHYSREG_ARCH, PHYSREG_PENDINGFREE, MAX_PHYSREG_STATE };
  static const char* physreg_state_names[MAX_PHYSREG_STATE] = {"none", "free", "waiting", "bypass", "written", "arch", "pendingfree"};
  static const char* short_physreg_state_names[MAX_PHYSREG_STATE] = {"-", "free", "wait", "byps", "wrtn", "arch", "pend"};

#ifdef INSIDE_OOOCORE

  struct OutOfOrderCore;
  OutOfOrderCore& coreof(int coreid);

  struct ReorderBufferEntry;

  //
  // Issue queue based scheduler with broadcast
  //
#ifdef BIG_ROB
  typedef W16 issueq_tag_t;
#else
  typedef byte issueq_tag_t;
#endif

  template <int size, int operandcount = MAX_OPERANDS>
  struct IssueQueue {
#ifdef BIG_ROB
    typedef FullyAssociativeTags16bit<size, size> assoc_t;
    typedef vec8w vec_t;
#else
    typedef FullyAssociativeTags8bit<size, size> assoc_t;
    typedef vec16b vec_t;
#endif

    typedef issueq_tag_t tag_t;

    static const int SIZE = size;

    assoc_t uopids;
    assoc_t tags[operandcount];

    // States:
    //             V I
    // free        0 0
    // dispatched  1 0
    // issued      1 1
    // complete    0 1

    bitvec<size> valid;
    bitvec<size> issued;
    bitvec<size> allready;
    int count;
    byte coreid;

    bool remaining() const { return (size - count); }
    bool empty() const { return (!count); }
    bool full() const { return (!remaining()); }

    int uopof(int slot) const {
      return uopids[slot];
    }

    int slotof(int uopid) const {
      return uopids.search(uopid);
    }

    void reset(int coreid);
    void clock();
    bool insert(tag_t uopid, const tag_t* operands, const tag_t* preready);
    bool broadcast(tag_t uopid);
    int issue();
    bool replay(int slot, const tag_t* operands, const tag_t* preready);
    bool remove(int slot);
    ostream& print(ostream& os) const;
    void tally_broadcast_matches(tag_t sourceid, const bitvec<size>& mask, int operand) const;

    //
    // Replay a uop that has already issued once.
    // The caller may add or reset dependencies here as needed.
    //
    bool replay(int slot) {
      issued[slot] = 0;
      return true;
    }

    //
    // Remove an entry from the issue queue after it has completed,
    // or in the process of annulment.
    //
    bool release(int slot) {
      remove(slot);
      return true;
    }

    bool annul(int slot) {
      remove(slot);
      return true;
    }

    bool annuluop(int uopid) {
      int slot = slotof(uopid);
      if (slot < 0) return false;
      remove(slot);
      return true;
    }

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  template <int size, int operandcount>
  static inline ostream& operator <<(ostream& os, const IssueQueue<size, operandcount>& issueq) {
    return issueq.print(os);
  }

  //
  // Iterate through a linked list of objects where each object directly inherits
  // only from the selfqueuelink class or otherwise has a selfqueuelink object
  // as the first member.
  //
  // This iterator supports mutable lists, meaning the current entry (obj) may
  // be safely removed from the list and/or moved to some other list without
  // affecting the next object processed.
  //
  // This does NOT mean you can remove any object from the list other than the
  // current object obj - to do this, copy the list of pointers to an array and
  // then process that instead.
  //
#define foreach_list_mutable_linktype(L, obj, entry, nextentry, linktype) \
  linktype* entry; \
  linktype* nextentry; \
  for (entry = (L).next, nextentry = entry->next, prefetch(entry->next), obj = (typeof(obj))entry; \
    entry != &(L); entry = nextentry, nextentry = entry->next, prefetch(nextentry), obj = (typeof(obj))entry)

#define foreach_list_mutable(L, obj, entry, nextentry) foreach_list_mutable_linktype(L, obj, entry, nextentry, selfqueuelink)

  struct StateList;

  struct ListOfStateLists: public array<StateList*, 64> {
    int count;

    ListOfStateLists() { count = 0; }

    int add(StateList* list);
    void reset();
  };

  struct StateList: public selfqueuelink {
    const char* name;
    int count;
    int listid;
    W64 dispatch_source_counter;
    W64 issue_source_counter;
    W32 flags;

    StateList() { count = 0; listid = 0; }

    void init(const char* name, ListOfStateLists& lol, W32 flags = 0) {
      reset();
      this->name = name;
      this->flags = flags;
      count = 0;
      listid = lol.add(this);
      dispatch_source_counter = 0;
      issue_source_counter = 0;
    }

    StateList(const char* name, ListOfStateLists& lol, W32 flags = 0) {
      init(name, lol, flags);
    }

    // simulated asymmetric c++ array constructor:
    StateList& operator ()(const char* name, ListOfStateLists& lol, W32 flags = 0) {
      init(name, lol, flags);
      return *this;
    }

    void reset() {
      selfqueuelink::reset();
      count = 0;
    }

    selfqueuelink* dequeue() {
      if (empty())
        return null;
      count--;
      selfqueuelink* obj = removehead();
      return obj;
    }

    selfqueuelink* enqueue(selfqueuelink* entry) {
      entry->addtail(this);
      count++;
      return entry;
    }

    selfqueuelink* enqueue_after(selfqueuelink* entry, selfqueuelink* preventry) {
      if (preventry) entry->addhead(preventry); else entry->addhead(this);
      count++;
      return entry;
    }

    selfqueuelink* remove(selfqueuelink* entry) {
      assert(entry->linked());
      entry->unlink();
      count--;
      return entry;
    }

    selfqueuelink* peek() {
      return (empty()) ? null : head();
    }

    void checkvalid();
  };

  int ListOfStateLists::add(StateList* list) {
    assert(count < lengthof(data));
    data[count] = list;
    return count++;
  }

  void ListOfStateLists::reset() {
    foreach (i, count) {
      data[i]->reset();
    }
  }

  template <typename T> 
  static void print_list_of_state_lists(ostream& os, const ListOfStateLists& lol, const char* title);

  //
  // Fetch Buffers
  //
  struct BranchPredictorUpdateInfo: public PredictorUpdate {
    int stack_recover_idx;
    int bptype;
    W64 ripafter;
  };

  struct FetchBufferEntry: public TransOp {
    RIPVirtPhys rip;
    W64 uuid;
    uopimpl_func_t synthop;
    BranchPredictorUpdateInfo predinfo;
    BasicBlock* bb;
    W16 index;

    int init(int index) { this->index = index; return 0; }
    void validate() { }

    FetchBufferEntry() { }
    
    FetchBufferEntry(const TransOp& transop) {
      *((TransOp*)this) = transop;
    }
  };

  //
  // ReorderBufferEntry
  //

  struct OutOfOrderCore;
  struct PhysicalRegister;
  struct LoadStoreQueueEntry;
  struct OutOfOrderCoreEvent;

  //
  // Reorder Buffer (ROB) structure, used for tracking all uops in flight.
  // This same structure is used to represent both dispatched but not yet issued 
  // uops as well as issued uops.
  //
  struct ReorderBufferEntry: public selfqueuelink {
    FetchBufferEntry uop;
    struct StateList* current_state_list;
    PhysicalRegister* physreg;
    PhysicalRegister* operands[MAX_OPERANDS];
    LoadStoreQueueEntry* lsq;
    W16s idx;
    W16s cycles_left; // execution latency counter, decremented every cycle when executing
    W16s forward_cycle; // forwarding cycle after completion
    W16s lfrqslot;
    W16s iqslot;
    W16  executable_on_cluster_mask;
    W8s  cluster;
    W8   coreid;
    byte fu;
    byte consumer_count;
    PTEUpdate pteupdate;
    Waddr origvirt;
    byte entry_valid:1, issued:1, load_store_second_phase:1, all_consumers_off_bypass:1, dest_renamed_before_writeback:1, no_branches_between_renamings:1, transient:1, lock_acquired:1;

    int index() const { return idx; }
    void validate() { entry_valid = true; }

    void changestate(StateList& newqueue, bool place_at_head = false, ReorderBufferEntry* prevrob = null) {
      if (current_state_list)
        current_state_list->remove(this);
      current_state_list = &newqueue;
      if (place_at_head) newqueue.enqueue_after(this, prevrob); else newqueue.enqueue(this);
    }

    void init(int idx);
    void reset();
    bool ready_to_issue() const;
    bool ready_to_commit() const;
    StateList& get_ready_to_issue_list() const;
    bool find_sources();
    int forward();
    int select_cluster();
    int issue();
    void* addrgen(LoadStoreQueueEntry& state, Waddr& origaddr, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate, Waddr& addr, int& exception, PageFaultErrorCode& pfec, bool& annul);
    bool handle_common_load_store_exceptions(LoadStoreQueueEntry& state, Waddr& origaddr, Waddr& addr, int& exception, PageFaultErrorCode& pfec);
    int issuestore(LoadStoreQueueEntry& state, Waddr& origvirt, W64 ra, W64 rb, W64 rc, bool rcready, PTEUpdate& pteupdate);
    int issueload(LoadStoreQueueEntry& state, Waddr& origvirt, W64 ra, W64 rb, W64 rc, PTEUpdate& pteupdate);
    void release();
    W64 annul(bool keep_misspec_uop, bool return_first_annulled_rip = false);
    W64 annul_after() { return annul(true); }
    W64 annul_after_and_including() { return annul(false); }
    int commit();
    void replay();
    int pseudocommit();
    void redispatch(const bitvec<MAX_OPERANDS>& dependent_operands, ReorderBufferEntry* prevrob);
    void redispatch_dependents(bool inclusive = true);
    void loadwakeup();
    bool release_mem_lock(bool forced = false);
    ostream& print(ostream& os) const;
    stringbuf& get_operand_info(stringbuf& sb, int operand) const;
    ostream& print_operand_info(ostream& os, int operand) const;

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  static inline ostream& operator <<(ostream& os, const ReorderBufferEntry& rob) {
    return rob.print(os);
  }

  //
  // Load/Store Queue
  //
#define LSQ_SIZE (LDQ_SIZE + STQ_SIZE)

  struct LoadStoreQueueEntry: public SFR {
    ReorderBufferEntry* rob;
    W16 idx;
    byte coreid;
    W8s mbtag;
    W8 store:1, entry_valid:1;
    W32 padding;

    LoadStoreQueueEntry() { }

    int index() const { return idx; }

    void reset() {
      int oldidx = idx;
      setzero(*this);
      idx = oldidx;
      mbtag = -1;
    }

    void init(int idx) {
      this->idx = idx;
      reset();
    }

    void validate() { entry_valid = 1; }
  
    ostream& print(ostream& os) const;

    LoadStoreQueueEntry& operator =(const SFR& sfr) {
      *((SFR*)this) = sfr;
      return *this;
    }

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  static inline ostream& operator <<(ostream& os, const LoadStoreQueueEntry& lsq) {
    return lsq.print(os);
  }

  struct PhysicalRegisterOperandInfo {
    W32 uuid;
    W16 physreg;
    W16 rob;
    byte state;
    byte rfid;
    byte archreg;
    byte pad1;
  };

  ostream& operator <<(ostream& os, const PhysicalRegisterOperandInfo& opinfo);

  //
  // Physical Register File
  //
  struct PhysicalRegister: public selfqueuelink {
    ReorderBufferEntry* rob;
    W64 data;
    W16 flags;
    W16 idx;
    W8  coreid;
    W8  rfid;
    W8  state;
    W8  archreg;
    W8  all_consumers_sourced_from_bypass:1;
    W16s refcount;

    StateList& get_state_list(int state) const;
    StateList& get_state_list() const { return get_state_list(this->state); }

    void changestate(int newstate) {
      if likely (state != PHYSREG_NONE) get_state_list(state).remove(this);
      state = newstate;
      get_state_list(state).enqueue(this);
    }

    void init(int coreid, int rfid, int idx) {
      this->coreid = coreid;
      this->rfid = rfid;
      this->idx = idx;
      reset();
    }

    void addref() { refcount++; }
    void unref() { refcount--; assert(refcount >= 0); }
    void addref(const ReorderBufferEntry& rob) { addref(); }
    void unref(const ReorderBufferEntry& rob) { unref(); }
    void addspecref(int archreg) { addref(); }
    void unspecref(int archreg) { unref(); }
    void addcommitref(int archreg) { addref(); }
    void uncommitref(int archreg) { unref(); }
    bool referenced() const { return (refcount > 0); }
    bool nonnull() const { return (index() != PHYS_REG_NULL); }
    bool allocated() const { return (state != PHYSREG_FREE); }
    void commit() { changestate(PHYSREG_ARCH); }
    void complete() { changestate(PHYSREG_BYPASS); }
    void writeback() { changestate(PHYSREG_WRITTEN); }

    void free() {
      changestate(PHYSREG_FREE);
      rob = 0;
      refcount = 0;
      all_consumers_sourced_from_bypass = 1;
    }

    void reset() {
      selfqueuelink::reset();
      state = PHYSREG_NONE;
      free();
    }

    int index() const { return idx; }
    bool valid() const { return ((flags & FLAG_INV) == 0); }
    bool ready() const { return ((flags & FLAG_WAIT) == 0); }

    void fill_operand_info(PhysicalRegisterOperandInfo& opinfo);

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  ostream& operator <<(ostream& os, const PhysicalRegister& physreg);

  struct PhysicalRegisterFile: public array<PhysicalRegister, MAX_PHYS_REG_FILE_SIZE> {
    byte coreid;
    byte rfid;
    W16 size;
    const char* name;
    StateList states[MAX_PHYSREG_STATE];
    W64 allocations;
    W64 frees;

    PhysicalRegisterFile() { }

    PhysicalRegisterFile(const char* name, int coreid, int rfid, int size) {
      init(name, coreid, rfid, size); reset();
    }

    PhysicalRegisterFile& operator ()(const char* name, int coreid, int rfid, int size) {
      init(name, coreid, rfid, size); reset(); return *this;
    }

    void init(const char* name, int coreid, int rfid, int size);
    bool remaining() const { return (!states[PHYSREG_FREE].empty()); }
    PhysicalRegister* alloc(int r = -1);
    void reset();
    ostream& print(ostream& os) const;

    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  static inline ostream& operator <<(ostream& os, const PhysicalRegisterFile& physregs) {
    return physregs.print(os);
  }

  //
  // Register Rename Table
  //
  struct RegisterRenameTable: public array<PhysicalRegister*, TRANSREG_COUNT> {
#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
    bitvec<TRANSREG_COUNT> renamed_in_this_basic_block;
#endif
    ostream& print(ostream& os) const;
  };

  static inline ostream& operator <<(ostream& os, const RegisterRenameTable& rrt) {
    return rrt.print(os);
  }

  enum {
    ISSUE_COMPLETED = 1,      // issued correctly
    ISSUE_NEEDS_REPLAY = 0,   // fast scheduling replay
    ISSUE_MISSPECULATED = -1, // mis-speculation: redispatch dependent slice
    ISSUE_NEEDS_REFETCH = -2, // refetch from RIP of bad insn
  };

  enum {
    COMMIT_RESULT_NONE = 0,   // no instructions committed: some uops not ready
    COMMIT_RESULT_OK = 1,     // committed
    COMMIT_RESULT_EXCEPTION = 2, // exception
    COMMIT_RESULT_BARRIER = 3,// barrier; branch to microcode (brp uop)
    COMMIT_RESULT_SMC = 4,    // self modifying code detected
    COMMIT_RESULT_INTERRUPT = 5, // interrupt pending
    COMMIT_RESULT_STOP = 6    // stop processor model (shutdown)
  };

  // Branch predictor outcomes:
  enum { MISPRED = 0, CORRECT = 1 };

  //
  // Lookup tables (LUTs):
  //
  struct Cluster {
    char* name;
    W16 issue_width;
    W32 fu_mask;
  };

  extern const Cluster clusters[MAX_CLUSTERS];
  extern byte uop_executable_on_cluster[OP_MAX_OPCODE];
  extern W32 forward_at_cycle_lut[MAX_CLUSTERS][MAX_FORWARDING_LATENCY+1];
  extern const byte archdest_can_commit[TRANSREG_COUNT];
  extern const byte archdest_is_visible[TRANSREG_COUNT];

  struct OutOfOrderMachine;

  struct OutOfOrderCoreCacheCallbacks: public CacheSubsystem::PerCoreCacheCallbacks {
    OutOfOrderCore& core;
    OutOfOrderCoreCacheCallbacks(OutOfOrderCore& core_): core(core_) { }
    virtual void dcache_wakeup(LoadStoreInfo lsi, W64 physaddr);
    virtual void icache_wakeup(LoadStoreInfo lsi, W64 physaddr);
  };

  struct MemoryInterlockEntry {
    W64 uuid;
    W16 rob;
    byte vcpuid;
    void reset() { uuid = 0; rob = 0; vcpuid = 0; }

    ostream& print(ostream& os, W64 physaddr) const {
      os << "phys ", (void*)physaddr, ": vcpu ", vcpuid, ", uuid ", uuid, ", rob ", rob;
      return os;
    }
  };

  struct MemoryInterlockBuffer: public LockableAssociativeArray<W64, MemoryInterlockEntry, 16, 4, 8> { };

  extern MemoryInterlockBuffer interlocks;

  //
  // Event Tracing
  //
  enum {
    EVENT_INVALID = 0,
    EVENT_FETCH_STALLED,
    EVENT_FETCH_ICACHE_WAIT,
    EVENT_FETCH_FETCHQ_FULL,
    EVENT_FETCH_BOGUS_RIP,
    EVENT_FETCH_ICACHE_MISS,
    EVENT_FETCH_SPLIT,
    EVENT_FETCH_ASSIST,
    EVENT_FETCH_TRANSLATE,
    EVENT_FETCH_OK,
    EVENT_RENAME_FETCHQ_EMPTY,
    EVENT_RENAME_ROB_FULL,
    EVENT_RENAME_PHYSREGS_FULL,
    EVENT_RENAME_LDQ_FULL,
    EVENT_RENAME_STQ_FULL,
    EVENT_RENAME_MEMQ_FULL,
    EVENT_RENAME_OK,
    EVENT_FRONTEND,
    EVENT_CLUSTER_NO_CLUSTER,
    EVENT_CLUSTER_OK,
    EVENT_DISPATCH_NO_CLUSTER,
    EVENT_DISPATCH_DEADLOCK,
    EVENT_DISPATCH_OK,
    EVENT_ISSUE_NO_FU,
    EVENT_ISSUE_OK,
    EVENT_REPLAY,
    EVENT_STORE_EXCEPTION,
    EVENT_STORE_WAIT,
    EVENT_STORE_PARALLEL_FORWARDING_MATCH,
    EVENT_STORE_ALIASED_LOAD,
    EVENT_STORE_ISSUED,
    EVENT_STORE_LOCK_RELEASED,
    EVENT_STORE_LOCK_ANNULLED,
    EVENT_STORE_LOCK_REPLAY,
    EVENT_LOAD_EXCEPTION,
    EVENT_LOAD_WAIT,
    EVENT_LOAD_HIGH_ANNULLED,
    EVENT_LOAD_HIT,
    EVENT_LOAD_MISS,
    EVENT_LOAD_LOCK_REPLAY,
    EVENT_LOAD_LOCK_OVERFLOW,
    EVENT_LOAD_LOCK_ACQUIRED,
    EVENT_LOAD_LFRQ_FULL,
    EVENT_LOAD_WAKEUP,
    EVENT_ALIGNMENT_FIXUP,
    EVENT_ANNUL_NO_FUTURE_UOPS,
    EVENT_ANNUL_MISSPECULATION,
    EVENT_ANNUL_EACH_ROB,
    EVENT_ANNUL_PSEUDOCOMMIT,
    EVENT_ANNUL_FETCHQ_RAS,
    EVENT_ANNUL_FETCHQ,
    EVENT_ANNUL_FLUSH,
    EVENT_REDISPATCH_DEPENDENTS,
    EVENT_REDISPATCH_DEPENDENTS_DONE,
    EVENT_REDISPATCH_EACH_ROB,
    EVENT_COMPLETE,
    EVENT_BROADCAST,
    EVENT_FORWARD,
    EVENT_WRITEBACK,
    EVENT_COMMIT_EXCEPTION_DETECTED,
    EVENT_COMMIT_EXCEPTION_ACKNOWLEDGED,
    EVENT_COMMIT_SKIPBLOCK,
    EVENT_COMMIT_SMC_DETECTED,
    EVENT_COMMIT_ASSIST,
    EVENT_COMMIT_OK,
    EVENT_RECLAIM_PHYSREG,
  };

  //
  // Event that gets written to the trace buffer
  //
  // In the interest of minimizing space, the cycle counters
  // and uuids are only 32-bits; in practice wraparound is
  // not likely to be a problem.
  //
  struct OutOfOrderCoreEvent {
    W32 cycle;
    W32 uuid;
    RIPVirtPhysBase rip;
    TransOpBase uop;
    W16 rob;
    W16 physreg;
    W16 lsq;
    W16 type;
    W16s lfrqslot;
    byte rfid;
    byte cluster;
    byte fu;

    OutOfOrderCoreEvent* fill(int type) {
      this->type = type;
      cycle = sim_cycle;
      uuid = 0;
      return this;
    }

    OutOfOrderCoreEvent* fill(int type, const FetchBufferEntry& uop) {
      fill(type);
      uuid = uop.uuid;
      rip = uop.rip;
      this->uop = uop;
      return this;
    }

    OutOfOrderCoreEvent* fill(int type, const RIPVirtPhys& rvp) {
      fill(type);
      rip = rvp;
      return this;
    }

    OutOfOrderCoreEvent* fill(int type, const ReorderBufferEntry* rob) {
      fill(type, rob->uop);
      this->rob = rob->index();
      physreg = rob->physreg->index();
      lsq = (rob->lsq) ? rob->lsq->index() : 0;
      rfid = rob->physreg->rfid;
      cluster = rob->cluster;
      fu = rob->fu;
      lfrqslot = rob->lfrqslot;
      return this;
    }

    OutOfOrderCoreEvent* fill_commit(int type, const ReorderBufferEntry* rob) {
      fill(type, rob);
      if unlikely (isstore(rob->uop.opcode)) {
        commit.state.st = *rob->lsq;
      } else {
        commit.state.reg.rddata = rob->physreg->data;
        commit.state.reg.rdflags = rob->physreg->flags;
      }
      // taken, predtaken only for branches
      commit.pteupdate = rob->pteupdate;
      // oldphysreg filled in later
      // oldphysreg_refcount filled in later
      commit.bb_refcount = rob->uop.bb->refcount;
      commit.bb = rob->uop.bb;
      commit.origvirt = rob->origvirt;
      commit.total_user_insns_committed = total_user_insns_committed;
      // target_rip filled in later
      foreach (i, MAX_OPERANDS) commit.operand_physregs[i] = rob->operands[i]->index();
      return this;
    }

    OutOfOrderCoreEvent* fill_load_store(int type, const ReorderBufferEntry* rob, LoadStoreQueueEntry* inherit_sfr, Waddr virtaddr) {
      fill(type, rob);
      loadstore.sfr = *rob->lsq;
      loadstore.virtaddr = virtaddr;
      loadstore.load_store_second_phase = rob->load_store_second_phase;
      loadstore.inherit_sfr_used = (inherit_sfr != null);
      if unlikely (inherit_sfr) {
        loadstore.inherit_sfr = *inherit_sfr;
        loadstore.inherit_sfr_lsq = inherit_sfr->rob->lsq->index();
        loadstore.inherit_sfr_uuid = inherit_sfr->rob->uop.uuid;
        loadstore.inherit_sfr_rob = inherit_sfr->rob->index();
        loadstore.inherit_sfr_physreg = inherit_sfr->rob->physreg->index();
        loadstore.inherit_sfr_rip = inherit_sfr->rob->uop.rip;
      }
      return this;
    }

    union {
      struct {
        W16s missbuf;
        BasicBlock* bb;
        W64 predrip;
        W16 bb_uop_count;
      } fetch;
      struct {
        W16  oldphys;
        W16  oldzf;
        W16  oldcf;
        W16  oldof;
        PhysicalRegisterOperandInfo opinfo[MAX_OPERANDS];
      } rename;
      struct {
        W16 cycles_left;
      } frontend;
      struct {
        W16 allowed_clusters;
        W16 iq_avail[MAX_CLUSTERS];
      } select_cluster;
      struct {
        PhysicalRegisterOperandInfo opinfo[MAX_OPERANDS];
      } dispatch;
      struct {
        byte mispredicted:1;
        IssueState state;
        W16 cycles_left;
        W64 operand_data[MAX_OPERANDS];
        W16 operand_flags[MAX_OPERANDS];
        W64 predrip;
        W32 fu_avail;
      } issue;
      struct {
        PhysicalRegisterOperandInfo opinfo[MAX_OPERANDS];
        byte ready;
      } replay;
      struct {
        W64 virtaddr;
        W64 data_to_store;
        SFR sfr;
        SFR inherit_sfr;
        W64 inherit_sfr_uuid;
        W64 inherit_sfr_rip;
        W16 inherit_sfr_lsq;
        W16 inherit_sfr_rob;
        W16 inherit_sfr_physreg;
        W16 cycles_left;
        W64 locking_uuid;
        byte inherit_sfr_used:1, rcready:1, load_store_second_phase:1, predicted_alias:1;
        byte locking_vcpuid;
        W16 locking_rob;
      } loadstore;
      struct {
        W16 somidx;
        W16 eomidx;
        W16 startidx;
        W16 endidx;
        W16 bb_refcount;
        byte annulras;
        BasicBlock* bb;
      } annul;
      struct {
        StateList* current_state_list;
        W16 iqslot;
        W16 count;
        byte dependent_operands;
        PhysicalRegisterOperandInfo opinfo[MAX_OPERANDS];
      } redispatch;
      struct {
        W8  forward_cycle;
        W8  operand;
        W8  target_operands_ready;
        W8  target_all_operands_ready;
        W16 target_rob;
        W16 target_physreg;
        W8  target_rfid;
        W8  target_cluster;
        W64 target_uuid;
        W16 target_lsq;
        W8  target_st;
      } forwarding;
      struct {
        W16 consumer_count;
        W16 flags;
        W64 data;
        byte transient:1, all_consumers_sourced_from_bypass:1, no_branches_between_renamings:1, dest_renamed_before_writeback:1;
      } writeback;
      struct {
        IssueState state;
        byte taken:1, predtaken:1;
        PTEUpdateBase pteupdate;
        W16s oldphysreg;
        W16 oldphysreg_refcount;
        W16 bb_refcount;
        BasicBlock* bb;
        W64 origvirt;
        W64 total_user_insns_committed;
        W64 target_rip;
        W16 operand_physregs[MAX_OPERANDS];
      } commit;
    };

    ostream& print(ostream& os) const;
  };

  struct EventLog {
    OutOfOrderCoreEvent* start;
    OutOfOrderCoreEvent* end;
    OutOfOrderCoreEvent* tail;
    ostream* logfile;

    EventLog() { start = null; end = null; tail = null; logfile = null; }

    bool init(size_t bufsize);
    void reset();

    OutOfOrderCoreEvent* add() {
      if unlikely (tail >= end) {
        tail = start;
        flush();
      }
      OutOfOrderCoreEvent* event = tail;
      tail++;
      return event;
    }

    void flush(bool only_to_tail = false);

    OutOfOrderCoreEvent* add(int type) {
      return add()->fill(type);
    }

    OutOfOrderCoreEvent* add(int type, const RIPVirtPhys& rvp) {
      return add()->fill(type, rvp);
    }

    OutOfOrderCoreEvent* add(int type, const FetchBufferEntry& uop) {
      return add()->fill(type, uop);
    }

    OutOfOrderCoreEvent* add(int type, const ReorderBufferEntry* rob) {
      return add()->fill(type, rob);
    }

    OutOfOrderCoreEvent* add_commit(int type, const ReorderBufferEntry* rob) {
      return add()->fill_commit(type, rob);
    }

    OutOfOrderCoreEvent* add_load_store(int type, const ReorderBufferEntry* rob, LoadStoreQueueEntry* inherit_sfr = null, Waddr addr = 0) {
      return add()->fill_load_store(type, rob, inherit_sfr, addr);
    }

    ostream& print(ostream& os, bool only_to_tail = false);
  };

  //
  // Out-of-order core
  //
  struct OutOfOrderCore {
    int coreid;
    OutOfOrderMachine& machine;
    Context& ctx;
    EventLog eventlog;
    BranchPredictorInterface branchpred;
    ListOfStateLists rob_states;
    ListOfStateLists physreg_states;
    ListOfStateLists lsq_states;

    //
    // Issue Queues (one per cluster)
    //
    IssueQueue<16> issueq_int0;
    IssueQueue<16> issueq_int1;
    IssueQueue<16> issueq_ld;
    IssueQueue<16> issueq_fp;

    // Instantiate any issueq sizes used above:
#define declare_issueq_templates template struct IssueQueue<16>

#define foreach_issueq(expr) { issueq_int0.expr; issueq_int1.expr; issueq_ld.expr; issueq_fp.expr; }
  
    void sched_get_all_issueq_free_slots(int* a) {
      a[0] = issueq_int0.remaining();
      a[1] = issueq_int1.remaining();
      a[2] = issueq_ld.remaining();
      a[3] = issueq_fp.remaining();
    }

#define issueq_operation_on_cluster_with_result(core, cluster, rc, expr) \
  switch (cluster) { \
  case 0: rc = core.issueq_int0.expr; break; \
  case 1: rc = core.issueq_int1.expr; break; \
  case 2: rc = core.issueq_ld.expr; break; \
  case 3: rc = core.issueq_fp.expr; break; \
  }

#define per_cluster_stats_update(prefix, cluster, expr) \
  switch (cluster) { \
  case 0: prefix.int0 expr; break; \
  case 1: prefix.int1 expr; break; \
  case 2: prefix.ld expr; break; \
  case 3: prefix.fp expr; break; \
  }

#define per_physregfile_stats_update(prefix, rfid, expr) \
  switch (rfid) { \
  case 0: prefix.integer expr; break; \
  case 1: prefix.fp expr; break; \
  case 2: prefix.st expr; break; \
  case 3: prefix.br expr; break; \
  }

#define issueq_operation_on_cluster(core, cluster, expr) { int dummyrc; issueq_operation_on_cluster_with_result(core, cluster, dummyrc, expr); }

#define for_each_cluster(iter) foreach (iter, MAX_CLUSTERS)
#define for_each_operand(iter) foreach (iter, MAX_OPERANDS)

    //
    // Each ROB's state can be linked into at most one of the
    // following rob_xxx_list lists at any given time; the ROB's
    // current_state_list points back to the list it belongs to.
    //
    StateList rob_free_list;                             // Free ROB entyry
    StateList rob_frontend_list;                         // Frontend in progress (artificial delay)
    StateList rob_ready_to_dispatch_list;                // Ready to dispatch
    StateList rob_dispatched_list[MAX_CLUSTERS];         // Dispatched but waiting for operands
    StateList rob_ready_to_issue_list[MAX_CLUSTERS];     // Ready to issue (all operands ready)
    StateList rob_ready_to_store_list[MAX_CLUSTERS];     // Ready to store (all operands except possibly rc are ready)
    StateList rob_ready_to_load_list[MAX_CLUSTERS];      // Ready to load (all operands ready)
    StateList rob_issued_list[MAX_CLUSTERS];             // Issued and in progress (or for loads, returned here after address is generated)
    StateList rob_completed_list[MAX_CLUSTERS];          // Completed and result in transit for local and global forwarding
    StateList rob_ready_to_writeback_list[MAX_CLUSTERS]; // Completed; result ready to writeback in parallel across all cluster register files
    StateList rob_cache_miss_list;                       // Loads only: wait for cache miss to be serviced
    StateList rob_ready_to_commit_queue;                 // Ready to commit

    enum {
      ROB_STATE_READY = (1 << 0),
      ROB_STATE_IN_ISSUE_QUEUE = (1 << 1),
      ROB_STATE_PRE_READY_TO_DISPATCH = (1 << 2)
    };

#define InitClusteredROBList(name, description, flags) \
  name[0](description "-int0", rob_states, flags); \
  name[1](description "-int1", rob_states, flags); \
  name[2](description "-ld", rob_states, flags); \
  name[3](description "-fp", rob_states, flags)

    // Default constructor to bind a core to a specific hardware context
    OutOfOrderCore(int coreid_, Context& ctx_, OutOfOrderMachine& machine_): coreid(coreid_), ctx(ctx_), machine(machine_), cache_callbacks(*this) { }

    //
    // Initialize structures independent of the core parameters
    //
    void init_generic();

    //
    // Initialize all structures for the first time
    //
    void init() {
      init_generic();

      //
      // Physical register files
      //
      physregfiles[0]("int", coreid, 0, 128);
      physregfiles[1]("fp", coreid, 1, 128);
      physregfiles[2]("st", coreid, 2, STQ_SIZE);
      physregfiles[3]("br", coreid, 3, MAX_BRANCHES_IN_FLIGHT);
    }

    //
    // Physical Registers
    //

    enum { PHYS_REG_FILE_INT, PHYS_REG_FILE_FP, PHYS_REG_FILE_ST, PHYS_REG_FILE_BR };

    enum {  
      PHYS_REG_FILE_MASK_INT = (1 << 0),
      PHYS_REG_FILE_MASK_FP  = (1 << 1),
      PHYS_REG_FILE_MASK_ST  = (1 << 2),
      PHYS_REG_FILE_MASK_BR  = (1 << 3)
    };

    // Major core structures
    PhysicalRegisterFile physregfiles[PHYS_REG_FILE_COUNT];
    Queue<ReorderBufferEntry, ROB_SIZE> ROB;
    Queue<LoadStoreQueueEntry, LSQ_SIZE> LSQ;
    RegisterRenameTable specrrt;
    RegisterRenameTable commitrrt;

    // Fetch-related structures
    Queue<FetchBufferEntry, FETCH_QUEUE_SIZE> fetchq;
    RIPVirtPhys fetchrip;
    BasicBlock* current_basic_block;
    TransOpBuffer unaligned_ldst_buf;
    int current_basic_block_transop_index;
    bool stall_frontend;
    bool waiting_for_icache_fill;
    // How many bytes of x86 code to fetch into decode buffer at once
    static const int ICACHE_FETCH_GRANULARITY = 16;
    // Last block in icache we fetched into our buffer
    W64 current_icache_block;
    W64 fetch_uuid;
    int loads_in_flight;
    int stores_in_flight;
    bool prev_interrupts_pending;
    bool handle_interrupt_at_next_eom;

    // Dispatch
    int round_robin_reg_file_offset;
    static const int DISPATCH_DEADLOCK_COUNTDOWN_CYCLES = 64;
    int dispatch_deadlock_countdown;

    // Issue
    W32 fu_avail;
    ReorderBufferEntry* robs_on_fu[FU_COUNT];
    struct LoadStoreAliasPredictor: public FullyAssociativeTags<W64, 8> { };
    LoadStoreAliasPredictor lsap;
    int loads_in_this_cycle;
    W32 load_to_store_parallel_forwarding_buffer[LOAD_FU_COUNT];

    // Commit
    W64 chk_recovery_rip;
    W64 last_commit_at_cycle;
    bool smc_invalidate_pending;
    RIPVirtPhys smc_invalidate_rvp;

    CacheSubsystem::CacheHierarchy caches;
    OutOfOrderCoreCacheCallbacks cache_callbacks;

    // Pipeline Stages
    bool runcycle();
    bool fetch();
    void rename();
    void frontend();
    int dispatch();
    int issue(int cluster);
    int complete(int cluster);
    int transfer(int cluster);
    int writeback(int cluster);
    int commit();

    // Pipeline Flush Handling
    bool handle_barrier();
    bool handle_exception();
    bool handle_interrupt();

    // Pipeline Control and Fetching
    void reset_fetch_unit(W64 realrip);
    void flush_pipeline();
    void invalidate_smc();
    void external_to_core_state();
    void core_to_external_state() { }
    void annul_fetchq();
    BasicBlock* fetch_or_translate_basic_block(Context& ctx, const RIPVirtPhys& rvp);
    void redispatch_deadlock_recovery();

    // Debugging
    void dump_ooo_state(ostream& os);
    void print_rob(ostream& os);
    void print_lsq(ostream& os);
    void check_refcounts();
    void check_rob();
    void print_rename_tables(ostream& os);
    OutOfOrderCore& getcore() const { return coreof(coreid); }
  };

  struct OutOfOrderMachine: public PTLsimMachine {
    OutOfOrderCore* cores[MAX_CONTEXTS];

    OutOfOrderMachine(const char* name);
    virtual bool init(PTLsimConfig& config);
    virtual int run(PTLsimConfig& config);
    virtual void dump_state(ostream& os);
    virtual void update_stats(PTLsimStats& stats);
    void flush_all_pipelines();
  };

  extern CycleTimer cttotal;
  extern CycleTimer ctfetch;
  extern CycleTimer ctdecode;
  extern CycleTimer ctrename;
  extern CycleTimer ctfrontend;
  extern CycleTimer ctdispatch;
  extern CycleTimer ctissue;
  extern CycleTimer ctissueload;
  extern CycleTimer ctissuestore;
  extern CycleTimer ctcomplete;
  extern CycleTimer cttransfer;
  extern CycleTimer ctwriteback;
  extern CycleTimer ctcommit;

#ifdef DECLARE_STRUCTURES
  //
  // The following configuration has two integer/store clusters with a single cycle
  // latency between them, but both clusters can access the load pseudo-cluster with
  // no extra cycle. The floating point cluster is two cycles from everything else.
  //

  const Cluster clusters[MAX_CLUSTERS] = {
    {"int0",  2, (FU_ALU0|FU_STU0)},
    {"int1",  2, (FU_ALU1|FU_STU1)},
    {"ld",    2, (FU_LDU0|FU_LDU1)},
    {"fp",    2, (FU_FPU0|FU_FPU1)},
  };

  const byte intercluster_latency_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
    // I0 I1 LD FP <-to
    {0, 1, 0, 2}, // from I0
    {1, 0, 0, 2}, // from I1
    {0, 0, 0, 2}, // from LD
    {2, 2, 2, 0}, // from FP
  };

  const byte intercluster_bandwidth_map[MAX_CLUSTERS][MAX_CLUSTERS] = {
    // I0 I1 LD FP <-to
    {2, 2, 1, 1}, // from I0
    {2, 2, 1, 1}, // from I1
    {1, 1, 2, 2}, // from LD
    {1, 1, 1, 2}, // from FP
  };
#endif // DECLARE_STRUCTURES

#endif // INSIDE_OOOCORE

  //
  // This part is used when parsing stats.h to build the
  // data store template; these must be in sync with the
  // corresponding definitions elsewhere.
  //
  static const char* cluster_names[MAX_CLUSTERS] = {"int0", "int1", "ld", "fp"};
  static const char* phys_reg_file_names[PHYS_REG_FILE_COUNT] = {"int", "fp", "st", "br"};
};

//
// Out of Order Core
//
struct OutOfOrderCoreStats { // rootnode:
  W64 cycles;
  struct fetch {
    struct stop { // node: summable
      W64 stalled;
      W64 icache_miss;
      W64 fetchq_full;
      W64 bogus_rip;
      W64 microcode_assist;
      W64 branch_taken;
      W64 full_width;
    } stop;

    W64 opclass[OPCLASS_COUNT]; // label: opclass_names
    W64 width[OutOfOrderModel::FETCH_WIDTH+1]; // histo: 0, OutOfOrderModel::FETCH_WIDTH, 1

    W64 blocks;
    W64 uops;
    W64 user_insns;
  } fetch;
  struct frontend {
    struct status { // node: summable
      W64 complete;
      W64 fetchq_empty;
      W64 rob_full;
      W64 physregs_full;
      W64 ldq_full;
      W64 stq_full;
    } status;

    W64 width[OutOfOrderModel::FRONTEND_WIDTH+1]; // histo: 0, OutOfOrderModel::FRONTEND_WIDTH, 1

    struct renamed {
      W64 none;
      W64 reg;
      W64 flags;
      W64 reg_and_flags;
    } renamed;

    struct alloc {
      W64 reg;
      W64 ldreg;
      W64 sfr;
      W64 br;
    } alloc;

    // NOTE: This is capped at 255 consumers to keep the size reasonable:
    W64 consumer_count[256]; // histo: 0, 255, 1
  } frontend;
  struct dispatch {
    W64 width[OutOfOrderModel::DISPATCH_WIDTH+1]; // histo: 0, OutOfOrderModel::DISPATCH_WIDTH, 1

    struct source { // node: summable
      W64 integer[OutOfOrderModel::MAX_PHYSREG_STATE]; // label: OutOfOrderModel::physreg_state_names
      W64 fp[OutOfOrderModel::MAX_PHYSREG_STATE]; // label: OutOfOrderModel::physreg_state_names
      W64 st[OutOfOrderModel::MAX_PHYSREG_STATE]; // label: OutOfOrderModel::physreg_state_names
      W64 br[OutOfOrderModel::MAX_PHYSREG_STATE]; // label: OutOfOrderModel::physreg_state_names
    } source;

    W64 cluster[OutOfOrderModel::MAX_CLUSTERS]; // label: OutOfOrderModel::cluster_names

    struct redispatch {
      W64 trigger_uops;
      W64 deadlock_flushes;
      W64 deadlock_uops_flushed;
      W64 dependent_uops[OutOfOrderModel::ROB_SIZE+1]; // histo: 0, OutOfOrderModel::ROB_SIZE, 1
    } redispatch;

  } dispatch;
  struct issue {
    W64 uops;
    double uipc;
    struct result { // node: summable
      W64 no_fu;
      W64 replay;
      W64 misspeculated;
      W64 refetch;
      W64 branch_mispredict;
      W64 exception;
      W64 complete;
    } result;
    struct width {
      W64 int0[OutOfOrderModel::MAX_ISSUE_WIDTH+1]; // histo: 0, OutOfOrderModel::MAX_ISSUE_WIDTH, 1
      W64 int1[OutOfOrderModel::MAX_ISSUE_WIDTH+1]; // histo: 0, OutOfOrderModel::MAX_ISSUE_WIDTH, 1
      W64 ld[OutOfOrderModel::MAX_ISSUE_WIDTH+1]; // histo: 0, OutOfOrderModel::MAX_ISSUE_WIDTH, 1
      W64 fp[OutOfOrderModel::MAX_ISSUE_WIDTH+1]; // histo: 0, OutOfOrderModel::MAX_ISSUE_WIDTH, 1
    } width;
    struct source { // node: summable
      W64 integer[OutOfOrderModel::MAX_PHYSREG_STATE]; // label: OutOfOrderModel::physreg_state_names
      W64 fp[OutOfOrderModel::MAX_PHYSREG_STATE]; // label: OutOfOrderModel::physreg_state_names
      W64 st[OutOfOrderModel::MAX_PHYSREG_STATE]; // label: OutOfOrderModel::physreg_state_names
      W64 br[OutOfOrderModel::MAX_PHYSREG_STATE]; // label: OutOfOrderModel::physreg_state_names
    } source;
    W64 opclass[OPCLASS_COUNT]; // label: opclass_names
  } issue;
  struct writeback {
    W64 writebacks[OutOfOrderModel::PHYS_REG_FILE_COUNT]; // label: OutOfOrderModel::phys_reg_file_names
    struct width {
      W64 int0[OutOfOrderModel::MAX_ISSUE_WIDTH+1]; // histo: 0, OutOfOrderModel::MAX_ISSUE_WIDTH, 1
      W64 int1[OutOfOrderModel::MAX_ISSUE_WIDTH+1]; // histo: 0, OutOfOrderModel::MAX_ISSUE_WIDTH, 1
      W64 ld[OutOfOrderModel::MAX_ISSUE_WIDTH+1]; // histo: 0, OutOfOrderModel::MAX_ISSUE_WIDTH, 1
      W64 fp[OutOfOrderModel::MAX_ISSUE_WIDTH+1]; // histo: 0, OutOfOrderModel::MAX_ISSUE_WIDTH, 1
    } width;
  } writeback;

  struct commit {
    W64 uops;
    W64 insns;
    double uipc;
    double ipc;
    struct freereg { // node: summable
      W64 pending;
      W64 free;
    } freereg;

    W64 free_regs_recycled;

    struct result { // node: summable
      W64 none;
      W64 ok;
      W64 exception;
      W64 skipblock;
      W64 barrier;
      W64 smc;
      W64 memlocked;
      W64 stop;
    } result;

    struct setflags { // node: summable
      W64 yes;
      W64 no;
    } setflags;

    W64 width[OutOfOrderModel::COMMIT_WIDTH+1]; // histo: 0, OutOfOrderModel::COMMIT_WIDTH, 1
    W64 opclass[OPCLASS_COUNT]; // label: opclass_names
  } commit;

  struct branchpred {
    W64 predictions;
    W64 updates;

    // These counters are [0] = mispred, [1] = correct
    W64 cond[2]; // label: branchpred_outcome_names
    W64 indir[2]; // label: branchpred_outcome_names
    W64 ret[2]; // label: branchpred_outcome_names
    W64 summary[2]; // label: branchpred_outcome_names
    struct ras { // node: summable
      W64 pushes;
      W64 overflows;
      W64 pops;
      W64 underflows;
      W64 annuls;
    } ras;
  } branchpred;

  struct dcache {
    struct load {
      struct issue { // node: summable
        W64 complete;
        W64 miss;
        W64 exception;
        W64 ordering;
        W64 unaligned;
        struct replay { // node: summable
          W64 sfr_addr_and_data_not_ready;
          W64 sfr_addr_not_ready;
          W64 sfr_data_not_ready;
          W64 missbuf_full;
          W64 interlocked;
          W64 interlock_overflow;
          W64 fence;
        } replay;
      } issue;
        
      struct forward { // node: summable
        W64 cache;
        W64 sfr;
        W64 sfr_and_cache;
      } forward;
        
      struct dependency { // node: summable
        W64 independent;
        W64 predicted_alias_unresolved;
        W64 stq_address_match;
        W64 stq_address_not_ready;
      } dependency;
        
      struct type { // node: summable
        W64 aligned;
        W64 unaligned;
        W64 internal;
      } type;
        
      W64 size[4]; // label: sizeshift_names

      W64 datatype[DATATYPE_COUNT]; // label: datatype_names
    } load;

    struct store {
      struct issue { // node: summable
        W64 complete;
        W64 exception;
        W64 ordering;
        W64 unaligned;
        struct replay { // node: summable
          W64 sfr_addr_and_data_not_ready;
          W64 sfr_addr_not_ready;
          W64 sfr_data_not_ready;
          W64 sfr_addr_and_data_and_data_to_store_not_ready;
          W64 sfr_addr_and_data_to_store_not_ready;
          W64 sfr_data_and_data_to_store_not_ready;
          W64 interlocked;
          W64 fence;
        } replay;
      } issue;

      struct forward { // node: summable
        W64 zero;
        W64 sfr;
      } forward;
        
      struct type { // node: summable
        W64 aligned;
        W64 unaligned;
        W64 internal;
      } type;
        
      W64 size[4]; // label: sizeshift_names

      W64 datatype[DATATYPE_COUNT]; // label: datatype_names

      W64 parallel_aliasing;
    } store;
  } dcache;

  struct simulator {
    double total_time;
    struct cputime { // node: summable
      double fetch;
      double decode;
      double rename;
      double frontend;
      double dispatch;
      double issue;
      double issueload;
      double issuestore;
      double complete;
      double transfer;
      double writeback;
      double commit;
    } cputime;
  } simulator;
};

#endif // _OOOCORE_H_
