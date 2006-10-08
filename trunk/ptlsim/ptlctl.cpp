//
// PTLsim: Cycle Accurate x86-64 Simulator
// Control program used inside target virtual machine
//
// Copyright 2000-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <config.h>
#include <logic.h>
#include <signal.h>
#include <errno.h>

#include <ptlcalls.h>

//
// Expand one command list, 
//

int main(int argc, char* argv[]) {
  argc--; argv++;

  bool flushing = 0;
  foreach (i, argc) { flushing |= strequal(argv[i], "-flush"); }
  // Default behavior: always flush when we run this interactively:
  flushing = 1;

  dynarray<char*> list;
  expand_command_list(list, argc, argv);

  cout << "Sending ", (flushing ? "flush and" : ""), " command list to PTLsim hypervisor:", endl, flush;

  foreach (i, list.length) {
    cout << "  ", list[i], endl, flush;
  }

  int rc = ptlcall_multi(list, list.length, flushing);
  if (rc == -ENOSYS) {
    cerr << "ptlctl: Not running under PTLsim", endl, endl, flush;
  } else {
    cerr << "PTLsim returned rc ", rc, endl, endl, flush;
  }

  return 0;
}

