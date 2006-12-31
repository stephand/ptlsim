// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Sequential Core Simulator Configuration
//
// Copyright 1999-2006 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _SEQCORE_H_
#define _SEQCORE_H_

#include <ptlsim.h>

//
// Free-standing sequential execution of one basic block
//
int execute_sequential(Context& ctx);

enum {
  SEQEXEC_OK = 0,
  SEQEXEC_EARLY_EXIT,
  SEQEXEC_SMC,
  SEQEXEC_CHECK,
  SEQEXEC_UNALIGNED,
  SEQEXEC_EXCEPTION,
  SEQEXEC_INVALIDRIP,
  SEQEXEC_SKIPBLOCK,
  SEQEXEC_BARRIER,
  SEQEXEC_INTERRUPT,
  SEQEXEC_RESULT_COUNT,
};

extern const char* seqexec_result_names[SEQEXEC_RESULT_COUNT];

#endif // _SEQCORE_H_
