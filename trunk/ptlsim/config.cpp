//
// PTLsim: Cycle Accurate x86-64 Simulator
// Configuration Management
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <ptlsim.h>
#include <datastore.h>

ostream& ConfigurationParser::printusage(ostream& os) const {
  os << "Options are:", endl;
  foreach (i, optioncount) {
    if (options[i].type == OPTION_TYPE_SECTION) {
      os << options[i].description, ":", endl;
      continue;
    }
    os << "  -", padstring(options[i].option, -16), " ", options[i].description, " ";
    if (!options[i].variable) {
      os << endl;
      continue;
    }
    os << "[";
    switch (options[i].type) {
    case OPTION_TYPE_NONE:
      break;
    case OPTION_TYPE_W64: {
      W64 v = *((W64*)(options[i].variable));
      if (v == infinity) os << "inf"; else os << v;
      break;
    }
    case OPTION_TYPE_FLOAT:
      os << *((double*)(options[i].variable));
      break;
    case OPTION_TYPE_STRING:
      os << ((*((void**)options[i].variable)) ? *((char**)(options[i].variable)) : "(null)");
      break;
    case OPTION_TYPE_BOOL:
      os << ((*((W64**)(options[i].variable))) ? "enabled" : "disabled");
      break;
    default:
      assert(false);
    }
    os << "]", endl;
  }
  os << endl;

  return os;
}

int ConfigurationParser::parse(int argc, char* argv[]) {
  int i = 0;

  while (i < argc) {
    if ((argv[i][0] == '-') && strlen(argv[i]) > 1) {
      char* option = &argv[i][1];
      i++;
      bool found = false;
      for (int j = 0; j < optioncount; j++) {
        if (options[j].type == OPTION_TYPE_SECTION) continue;
        if (strequal(option, options[j].option)) {
          found = true;
          void* variable = options[j].variable;
          if ((options[j].type != OPTION_TYPE_NONE) && (options[j].type != OPTION_TYPE_BOOL) && (i == (argc+1))) {
            cerr << "Warning: missing value for option '", argv[i-1], "'", endl;
            break;
          }
          switch (options[j].type) {
          case OPTION_TYPE_NONE:
            break;
          case OPTION_TYPE_W64: {
            char* p = argv[i];
            int len = strlen(p);
            W64 multiplier = 1;
            char* endp = p;
            if (!len) {
              cerr << "Warning: option ", argv[i-1], " had no argument; ignoring", endl;
              break;
            }
            bool isinf = (strncmp(p, "inf", 3) == 0);
            if (len > 1) {
              char& c = p[len-1];
              switch (c) {
              case 'k': case 'K':
                multiplier = 1000LL; c = 0; break;
              case 'm': case 'M':
                multiplier = 1000000LL; c = 0; break;
              case 'g': case 'G':
                multiplier = 1000000000LL; c = 0; break;
              case 't': case 'T':
                multiplier = 1000000000000LL; c = 0; break;
              }
            }
            W64 v = (isinf) ? infinity : strtoull(p, &endp, 0);
            if ((!isinf) && (endp[0] != 0)) {
              cerr << "Warning: invalid value '", p, "' for option ", argv[i-1], "; ignoring", endl;
            }
            v *= multiplier;
            *((W64*)variable) = v;
            i++;
            break;
          }
          case OPTION_TYPE_FLOAT:
            *((double*)variable) = atof(argv[i++]);
            break;
          case OPTION_TYPE_STRING:
            *((char**)variable) = argv[i++];
            break;
          case OPTION_TYPE_BOOL:
            *((W64*)variable) = (!(*((W64*)variable)));
            break;
          default:
            assert(false);
          }
          break;
        }
      }
      if (!found) {
        cerr << "Warning: invalid option '", argv[i++], "'", endl;
      }
    } else {
      return i; // trailing arguments, if any
    }
  }

  // no trailing arguments
  return -1;
}

ostream& ConfigurationParser::print(ostream& os) const {
  os << "Active parameters:", endl;

  foreach (i, optioncount) {
    if (!options[i].variable)
      continue;
    os << "  -", padstring(options[i].option, -12), " ";
    switch (options[i].type) {
    case OPTION_TYPE_NONE:
      break;
    case OPTION_TYPE_W64: {
      W64 v = *((W64*)(options[i].variable));
      if (v == 0) {
        os << 0;
      } else if (v == infinity) {
        os << "infinity";
      } else if ((v % 1000000000LL) == 0) {
        os << (v / 1000000000LL), " G";
      } else if ((v % 1000000LL) == 0) {
        os << (v / 1000000LL), " M";
      } else {
        os << v;
      }
      break;
    } case OPTION_TYPE_FLOAT:
      os << *((double*)(options[i].variable));
      break;
    case OPTION_TYPE_STRING:
      os << ((*((void**)options[i].variable)) ? *((char**)(options[i].variable)) : "(null)");
      break;
    case OPTION_TYPE_BOOL:
      os << (*((W64*)(options[i].variable)) ? "enabled" : "disabled");
      break;
    default:
      assert(false);
    }
    os << endl;
  }

  return os;
}

ostream& operator <<(ostream& os, const ConfigurationParser& clp) {
  return clp.print(os);
}

