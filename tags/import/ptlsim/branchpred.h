// -*- c++ -*-
//
// Branch Prediction
//
// Copyright 2002-2005 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#ifndef _BRANCHPRED_H_
#define _BRANCHPRED_H_

#include <ptlsim.h>

#define BRANCH_HINT_UNCOND      0
#define BRANCH_HINT_COND        (1 << 0)
#define BRANCH_HINT_INDIRECT    (1 << 1)
#define BRANCH_HINT_CALL        (1 << 2)
#define BRANCH_HINT_RET         (1 << 3)

struct PredictorUpdate {
  byte* pdir1; // direction-1 predictor counter
  byte* pdir2; // direction-2 predictor counter
  byte* pmeta; // meta predictor counter
  // predicted directions:
  W32 bimod:1, twolev:1, meta:1, ras_push:1, flags:8;
  int ras_old_top;
  W64 ras_old_data;
};

extern W64 branchpred_ras_pushes;
extern W64 branchpred_ras_overflows;
extern W64 branchpred_ras_pops;
extern W64 branchpred_ras_underflows;
extern W64 branchpred_ras_annuls;

struct BranchPredictorInterface {
  BranchPredictorInterface() { reset(); }
  void reset();
  W64 predict(PredictorUpdate& update, int type, W64 branchaddr, W64 target);
  void update(PredictorUpdate& update, W64 branchaddr, W64 target, bool taken, bool pred_taken, bool correct);
  void updateras(PredictorUpdate& predinfo, W64 branchaddr);
  void annulras(const PredictorUpdate& predinfo);
  void flush();
};

ostream& operator <<(ostream& os, const BranchPredictorInterface& branchpred);

extern BranchPredictorInterface branchpred;

#endif // _BRANCHPRED_H_
