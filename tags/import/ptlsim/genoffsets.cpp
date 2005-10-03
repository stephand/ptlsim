//
// PTLsim: Cycle Accurate x86-64 Simulator
// Offset header file generator for use in assembly code
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim.h>

int main(int argc, char* argv[]) {
  CoreState ctx;
#define ctxoffset(member) (LO32((W64)(((byte*)&ctx.member) - ((byte*)&ctx))))
#define printoffset(member) cout << "#define offsetof_"#member, " ", ctxoffset(member), endl
#define printoffset_named(name, member) cout << "#define offsetof_"#name, " ", ctxoffset(member), endl

  printoffset(commitarf);
  printoffset(specarf);
  printoffset(exception);
  printoffset_named(specarf_rip, specarf[REG_rip]);
  printoffset_named(specarf_flags, specarf[REG_flags]);
}
