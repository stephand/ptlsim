// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// PTLsim loader structures
//
// Copyright 2004-2008 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _LOADER_H_
#define _LOADER_H_

#include <globals.h>

#define LOADER_THUNK_SIZE 4096

#define W32string(c0, c1, c2, c3) \
   (((W64)c3 << (3*8)) + ((W64)c2 << (2*8)) + ((W64)c1 << (1*8)) + ((W64)c0 << (0*8)))

#define W64string(c0, c1, c2, c3, c4, c5, c6, c7) \
  (((W64)c7 << (7*8)) + ((W64)c6 << (6*8)) + ((W64)c5 << (5*8)) + ((W64)c4 << (4*8)) + \
   ((W64)c3 << (3*8)) + ((W64)c2 << (2*8)) + ((W64)c1 << (1*8)) + ((W64)c0 << (0*8)))

#define LOADER_MAGIC W64string('P', 'T', 'L', 's', 'i', 'm', 'L', 'd')

struct LoaderInfo {
  W64 initialize;
  W64 origrip;
  W64 origrsp;
  char ptlsim_filename[1024];
  byte saved_thunk[LOADER_THUNK_SIZE];
};

// Special magic number for ehdr->e_type to signal
// PTLsim is running within target address space:
#define ET_PTLSIM 0x5054

#endif // _LOADER_H_
