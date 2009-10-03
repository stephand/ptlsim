//
// PTLsim: Cycle Accurate x86-64 Simulator
// Control program used inside target virtual machine
//
// Copyright 2006-2008 Matt T. Yourst <yourst@yourst.com>
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

  if (!argc) {
    // Just get the PTLsim hypervisor version
    if (check_ptlcall_insn()) {
      if (check_running_under_ptlsim())
        cout << "Currently running on PTLsim virtual CPU", endl;
      else cout << "Currently running in native mode", endl;
    } else {
      cout << "Not running under PTLsim hypervisor", endl;
    }
    return 0;
  }

  if (strequal(argv[0], "-marker")) {
    W64 marker = (argc > 1) ? atoll(argv[1]) : 0;
    cout << "Making PTLsim marker '", marker, "'...", flush;
    int rc = ptlcall_marker(marker);
    cout << "rc = ", rc, endl;
    return 0;
  }

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

