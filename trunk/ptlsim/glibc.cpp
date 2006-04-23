//
// Standard library functions only used in normal (non-embedded) programs
//
// Copyright 2006 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#include <globals.h>

//
// Full featured float format function:
//
int format_float(char* buf, int bufsize, double v, int precision, int pad) {
  char format[32];
  snprintf(format, sizeof(format), "%%.%df", precision);
  snprintf(buf, bufsize, format, v);
  return strlen(buf);
}

