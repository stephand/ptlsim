//
// Branch Prediction
//
// Copyright 2002-2005 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#include <branchpred.h>

template <int SIZE>
struct BimodalPredictor {
  array<byte, SIZE> table;

  void reset() {
    int flipflop = 1;
    foreach (i, SIZE) {
      table[i] = flipflop;
      flipflop = 3 - flipflop;
    }
  }

  inline int hash(W64 branchaddr) {
    branchaddr >>= log2(sizeof(W32));
    return lowbits((branchaddr >> 16) ^ branchaddr, log2(SIZE));
  }

  byte* predict(W64 branchaddr) {
    return &table[hash(branchaddr)];
  }
};

template <int L1SIZE, int L2SIZE, int SHIFTWIDTH, bool HISTORYXOR>
struct TwoLevelPredictor {
  array<int, L1SIZE> shiftregs; // L1 history table
  array<byte, L2SIZE> l2table;  // L2 prediction state table

  void reset() {
    // initialize counters to weakly this-or-that
    int flipflop = 1;
    foreach (i, L2SIZE) {
      l2table[i] = flipflop;
      flipflop = 3 - flipflop;
    }
  }

  byte* predict(W64 branchaddr) {
    // Assume instruction address is 32 bit aligned, so >> 2 to remove redundant information:
    branchaddr >>= log2(sizeof(W32));

    // traverse 2-level tables
    int l1index = lowbits(branchaddr, log2(L1SIZE));
    int l2index = shiftregs[l1index];

    if (HISTORYXOR) {
      l2index ^= branchaddr;
    } else {
      l2index |= branchaddr << SHIFTWIDTH;
	  }

    l2index = lowbits(l2index, log2(L2SIZE));

    return &l2table[l2index];
  }
};

struct BTBEntry {
  W64 target;		// last destination of branch when taken

  void reset() {
    target = 0;
  }
};

template <int SETCOUNT, int WAYCOUNT>
struct BranchTargetBuffer: public AssociativeArray<W64, BTBEntry, SETCOUNT, WAYCOUNT, 1> { };

W64 branchpred_ras_pushes;
W64 branchpred_ras_overflows;
W64 branchpred_ras_pops;
W64 branchpred_ras_underflows;
W64 branchpred_ras_annuls;

template <int SIZE> struct ReturnAddressStack;

template <int SIZE>
ostream& operator <<(ostream& os, ReturnAddressStack<SIZE>& ras);

template <int SIZE>
struct ReturnAddressStack: public array<W64, SIZE> {
  typedef array<W64, SIZE> base_t;
  int top;

  void reset() {
    top = 0;
  }

  ReturnAddressStack() {
    reset();
  }

  W64 peek() {
    return (*this)[add_index_modulo(top, -1, SIZE)];
  }

  void push(W64 branchaddr, int& ras_old_top, W64& ras_old_data) {
    ras_old_top = top;
    ras_old_data = (*this)[top];

    (*this)[top] = branchaddr;
    top = add_index_modulo(top, +1, SIZE);

    branchpred_ras_pushes++;

    if (logable(1)) logfile << *this;
  }

  W64 pop(int& ras_old_top, W64& ras_old_data) {
    ras_old_top = top;
    ras_old_data = 0;

    top = add_index_modulo(top, -1, SIZE);
    W64 target = (*this)[top];

    branchpred_ras_pops++;
    return target;
  }

  void annul(bool push, int ras_old_top, W64 ras_old_data) {
    top = ras_old_top;
    assert(inrange(top, 0, SIZE-1));
    if (push) (*this)[top] = ras_old_data;

    branchpred_ras_annuls++;
  }
};

template <int SIZE>
ostream& operator <<(ostream& os, ReturnAddressStack<SIZE>& ras) {
  os << "ReturnAddressStack<", SIZE, ">: top ", ras.top, ":", endl;
  foreach (i, ras.top+8) {
    if (i == ras.top) os << "   ---- top ----", endl;
    os << "  ", intstring(i, 3), ": ", (void*)ras[i], endl;
  }

  return os;
}

template <int METASIZE, int BIMODSIZE, int L1SIZE, int L2SIZE, int SHIFTWIDTH, bool HISTORYXOR, int BTBSETS, int BTBWAYS, int RASSIZE>
struct CombinedPredictor {
  TwoLevelPredictor<L1SIZE, L2SIZE, SHIFTWIDTH, HISTORYXOR> twolevel;
  BimodalPredictor<BIMODSIZE> bimodal;
  BimodalPredictor<METASIZE> meta;

  BranchTargetBuffer<BTBSETS, BTBWAYS> btb;
  ReturnAddressStack<RASSIZE> ras;

  void reset() {
    twolevel.reset();
    bimodal.reset();
    meta.reset();
    btb.reset();
    ras.reset();
  }

  W64 lookups;
  W64 used_2lev;
  W64 used_bimod;
  W64 jmp_seen;
  W64 jmp_hits;
  W64 ras_pops;
  W64 ras_pushes;
  W64 addr_hits;
  W64 dir_hits;
  W64 misses;

  void updateras(PredictorUpdate& predinfo, W64 branchaddr) {
    if (predinfo.flags & BRANCH_HINT_RET) {
      predinfo.ras_push = 0;
      ras.pop(predinfo.ras_old_top, predinfo.ras_old_data);
    } else if (predinfo.flags & BRANCH_HINT_CALL) {
      predinfo.ras_push = 1;
      ras.push(branchaddr, predinfo.ras_old_top, predinfo.ras_old_data);
    }
  }

  //
  // NOTE: branchaddr should point to first byte *after* branching insn,
  // since x86 has variable length instructions.
  //
  W64 predict(PredictorUpdate& update, int type, W64 branchaddr, W64 target) {
    lookups++;

    update.pdir1 = null;
    update.pdir2 = null;
    update.pmeta = null;
    update.flags = type;

    if (type & BRANCH_HINT_COND) {
      byte& bimodalctr = *bimodal.predict(branchaddr);
      byte& twolevelctr = *twolevel.predict(branchaddr);
      byte& metactr = *meta.predict(branchaddr);
      update.pmeta = &metactr;
      update.meta  = (metactr >= 2);
      update.bimod = (bimodalctr >= 2);
      update.twolev  = (twolevelctr >= 2);
      if (metactr >= 2) {
        update.pdir1 = &twolevelctr;
	      update.pdir2 = &bimodalctr;
	    } else {
	      update.pdir1 = &bimodalctr;
	      update.pdir2 = &twolevelctr;
	    }
    }

    //
    // If this is a return, find next entry that would be popped
    // Caller is responsible for using updateras() to update the
    // RAS once annulable resources have been allocated for this
    // return insn.
    //
    if (type & BRANCH_HINT_RET) {
      return ras.peek();
    }

    BTBEntry* pbtb = btb.probe(branchaddr);

    // if this is a jump, ignore predicted direction; we know it's taken.
    if (!(type & BRANCH_HINT_COND)) {
      return (pbtb ? pbtb->target : target);
    }

    //
    // Predict conditional branch:
    //
    return (*(update.pdir1) >= 2) ? target : branchaddr;
  }

  void update(PredictorUpdate& update, W64 branchaddr, W64 target, bool taken, bool pred_taken, bool correct) {
    int type = update.flags;

    if (correct)
      addr_hits++;

    if (pred_taken == taken)
      dir_hits++;
    else
      misses++;

    if (update.meta)
      used_2lev++;
    else
      used_bimod++;

    //
    // keep stats about JMPs; also, but don't change any pred state for JMPs
    // which are returns.
    //
    if (type & BRANCH_HINT_INDIRECT) {
      jmp_seen++;
      if (correct) jmp_hits++;

      if (type & BRANCH_HINT_RET) return; // return that used the ret-addr stack; no further work to do */
    }

    //
    // L1 table is updated unconditionally for combining predictor too:
    //
    if (type & BRANCH_HINT_COND) {
      int l1index = lowbits(branchaddr, log2(L1SIZE));
      twolevel.shiftregs[l1index] = lowbits((twolevel.shiftregs[l1index] << 1) | taken, SHIFTWIDTH);
    }

    //
    // Find BTB entry if it's a taken branch (don't allocate for non-taken)
    //
    BTBEntry* pbtb = (taken) ? btb.select(branchaddr) : null;

    //
    // Now p is a possibly null pointer into the direction prediction table, 
    // and pbtb is a possibly null pointer into the BTB (either to a 
    // matched-on entry or a victim which was LRU in its set)
    //

    //
    // update state (but not for jumps)
    //
    if (update.pdir1) {
      byte& counter = *update.pdir1;
      counter = clipto(counter + (taken ? +1 : -1), 0, 3);
    }

    //
    // combining predictor also updates second predictor and meta predictor
    // second direction predictor
    //
    if (update.pdir2) {
      byte& counter = *update.pdir2;
      counter = clipto(counter + (taken ? +1 : -1), 0, 3);
    }

    //
    // Update meta predictor
    //
    if (update.pmeta) {
      if (update.bimod != update.twolev) {
        //
        // We only update meta predictor if directions were different.
        // We increment the counter if the twolevel predictor was correct; 
        // if the bimodal predictor was correct, we decrement it.
        //
        byte& counter = *update.pmeta;
        bool twolevel_or_bimodal = (update.twolev == taken);
        counter = clipto(counter + (twolevel_or_bimodal ? +1 : -1), 0, 3);
      }
    }

    //
    // update BTB (but only for taken branches)
    //
    if (pbtb) {
      // Update either the entry selected above, or if not found, use the LRU entry:
      pbtb->target = target;
    }
  }

  //
  // Speculative execution can corrupt the RAS, since entries will be pushed
  // as call insns are fetched. If those call insns were along an incorrect
  // branch path, they must be annulled.
  //
  void annulras(const PredictorUpdate& predinfo) {
    ras.annul(predinfo.ras_push, predinfo.ras_old_top, predinfo.ras_old_data);
  }
};

// template <int METASIZE, int BIMODSIZE, int L1SIZE, int L2SIZE, int SHIFTWIDTH, bool HISTORYXOR, int BTBSETS, int BTBWAYS, int RASSIZE>
//CombinedPredictor<16384, 16384, 16384, 16384, 16, 0, 1024, 4, 16> combpred;
CombinedPredictor<65536, 65536, 65536, 65536, 16, 1, 1024, 4, 512> combpred;

void BranchPredictorInterface::reset() {
  combpred.reset();
}

W64 BranchPredictorInterface::predict(PredictorUpdate& update, int type, W64 branchaddr, W64 target) {
  return combpred.predict(update, type, branchaddr, target);
}

void BranchPredictorInterface::update(PredictorUpdate& update, W64 branchaddr, W64 target, bool taken, bool pred_taken, bool correct) {
  combpred.update(update, branchaddr, target, taken, pred_taken, correct);
}

void BranchPredictorInterface::updateras(PredictorUpdate& predinfo, W64 branchaddr) {
  combpred.updateras(predinfo, branchaddr);
};

void BranchPredictorInterface::annulras(const PredictorUpdate& predinfo) {
  combpred.annulras(predinfo);
};

void BranchPredictorInterface::flush() { }

ostream& operator <<(ostream& os, const BranchPredictorInterface& branchpred) {
  os << combpred.ras;
  return os;
}

BranchPredictorInterface branchpred;

