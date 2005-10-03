//
// PTLsim: Cycle Accurate x86-64 Simulator
// Trigger functions for Fortran code
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <ptlcalls.h>

W64 ptlcall_nop__() { return ptlcall_nop(); }
W64 ptlcall_marker__(W64 marker) { return ptlcall_marker(marker); }
W64 ptlcall_switch_to_sim__() { return ptlcall_switch_to_sim(); }
W64 ptlcall_switch_to_native__() { return ptlcall_switch_to_native(); }
W64 ptlcall_capture_stats__() { return ptlcall_capture_stats(); }
