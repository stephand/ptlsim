//
// PTLsim: Cycle Accurate x86-64 Simulator
// Trigger functions 
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#ifndef __PTLCALLS_H__
#define __PTLCALLS_H__

#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>

typedef unsigned char byte;
typedef unsigned short W16;
typedef unsigned int W32;
typedef unsigned long long W64;

// Put at start of address space where nothing normally goes
#define PTLSIM_THUNK_PAGE 0x1000

#define PTLSIM_THUNK_MAGIC 0x34366d69734c5450ULL

static int running_under_ptlsim = -1;

typedef W64 (*ptlcall_func_t)(W64 callid, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5);

struct PTLsimThunkPage {
  W64 magic; // "PTLsim64" = 0x34366d69734c5450
  W64 simulated;
  W64 call_code_addr; // thunk function to call
};

static inline W64 ptlcall(W64 callid, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5) {
  struct PTLsimThunkPage* thunk = (struct PTLsimThunkPage*)PTLSIM_THUNK_PAGE;
  ptlcall_func_t func;

  if (running_under_ptlsim < 0) {
    /*
     * Quick and dirty trick to find out if a given page is mapped:
     * If the page is valid, munmap() is basically a nop, but if
     * it isn't, it returns -ENOMEM.
     */

    int rc = munlock(thunk, 4096);
    running_under_ptlsim = (rc == 0);

    if (running_under_ptlsim && (thunk->magic != PTLSIM_THUNK_MAGIC))
      running_under_ptlsim = 0;
  }

  if (!running_under_ptlsim) return 0;
#ifdef __x86_64__
  func = (ptlcall_func_t)thunk->call_code_addr;
#else
  func = (ptlcall_func_t)(W32)thunk->call_code_addr;
#endif

  return func(callid, arg1, arg2, arg3, arg4, arg5);
}

enum {
  PTLCALL_NOP,
  PTLCALL_MARKER,
  PTLCALL_SWITCH_TO_SIM,
  PTLCALL_SWITCH_TO_NATIVE,
  PTLCALL_CAPTURE_STATS,
  PTLCALL_COUNT,
};

// Valid in any mode
static inline W64 ptlcall_nop() { return ptlcall(PTLCALL_MARKER, 0, 0, 0, 0, 0); }
static inline W64 ptlcall_marker(W64 marker) { return ptlcall(PTLCALL_MARKER, marker, 0, 0, 0, 0); }
static inline W64 ptlcall_capture_stats(const char* name) { return ptlcall(PTLCALL_CAPTURE_STATS, (W64)name, 0, 0, 0, 0); }

// Valid in native mode only:
static inline W64 ptlcall_switch_to_sim() { return ptlcall(PTLCALL_SWITCH_TO_SIM, 0, 0, 0, 0, 0); }

// Valid in simulator mode only:
static inline W64 ptlcall_switch_to_native() { return ptlcall(PTLCALL_SWITCH_TO_NATIVE, 0, 0, 0, 0, 0); }

#endif // __PTLCALLS_H__
