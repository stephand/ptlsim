//
// Data Store
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <datastore.h>

using namespace superstl;

DataStoreNode::DataStoreNode() {
  init(null, DS_NODE_TYPE_NULL, 0);
}

DataStoreNode::DataStoreNode(const char* name) {
  init(name, DS_NODE_TYPE_NULL, 1);
}

DataStoreNode::DataStoreNode(const char* name, NodeType type, int count) {
  init(name, type, count);
}

void DataStoreNode::init(const char* name, int type, int count) {
  this->type = type;
  this->name = (name) ? strdup(name) : null;
  this->count = count;
  value.w = 0;
  subnodes = null;
  parent = null;
  summable = 0;
  histogramarray = 0;
  labeled_histogram = 0;
  identical_subtrees = 0;
  histomin = 0;
  histomax = 0;
  histostride = 0;
  dynamic = 0;
  sum_of_subtrees_cache = null;
  average_of_subtrees_cache = null;
  labels = null;
  total_sum_cache = -1;
}

void DataStoreNode::rename(const char* newname) {
  DataStoreNode* oldparent = parent;

  if (oldparent)
    assert(oldparent->remove(name));

  delete name;
  name = strdup(newname);

  if (oldparent) oldparent->add(this);
}

void DataStoreNode::invalidate_caches() {
  if (sum_of_subtrees_cache) delete sum_of_subtrees_cache;
  sum_of_subtrees_cache = null;
  if (average_of_subtrees_cache) delete average_of_subtrees_cache;
  average_of_subtrees_cache = null;
  total_sum_cache = -1;
  if (parent) parent->invalidate_caches();
}

void DataStoreNode::cleanup() {
  invalidate_caches();
  if (type == DS_NODE_TYPE_STRING) {
    if (count > 1) {
      foreach (i, count) {
        delete this->values[i].s;
      }
      delete[] values;
    } else {
      delete this->value.s;
    }
  } else {
    if (count > 1)
      delete[] values;
  }
  if (labels) {
    foreach (i, count) {
      delete labels[i];
    }
    delete[] labels;
  }
}

DataStoreNode::~DataStoreNode() {
  if (parent)
    assert(parent->remove(name));
  cleanup();
  removeall();
  if (subnodes)
    delete subnodes;
  delete name;
  subnodes = null;
  parent = null;
  name = null;
  type = DS_NODE_TYPE_NULL;
  count = 0;
}

DataStoreNode& DataStoreNode::add(DataStoreNode* node) {
  if (!subnodes) subnodes = new hash_t();
  node->parent = this;

  DataStoreNode** oldnode = subnodes->get(node->name);
  if (oldnode) {
    delete *oldnode;
  }

  subnodes->add(node->name, node);

  return *node;
}

bool DataStoreNode::remove(const char* key) {
  if (!subnodes)
    return false;
  return subnodes->remove(key);
}

void DataStoreNode::removeall() {
  DataStoreNodeDirectory& a = getentries();

  foreach (i, a.length) {
    delete a[i].value;
  }

  if (subnodes) assert(subnodes->count == 0);

  delete &a;
}

DataStoreNode::DataType DataStoreNode::getdata() const {
  if (!count) {
    DataType dummy;
    dummy.w = 0;
    return dummy;
  }

  return (count == 1) ? value : values[0];
}

DataStoreNode* DataStoreNode::search(const char* key) const {
  if (!subnodes)
    return null;

  if (strequal(key, "[total]")) {
    return sum_of_subtrees();
  }

  if (strequal(key, "[average]")) {
    return average_of_subtrees();
  }

  DataStoreNode** nodeptr = (*subnodes)(key);
  return (nodeptr) ? *nodeptr : null;
}

DataStoreNode* DataStoreNode::searchpath(const char* path) const {
  dynarray<char*> tokens;

  if (path[0] == '/') path++;

  char* pbase = tokens.tokenize(strdup(path), "/");

  const DataStoreNode* ds = this;

  foreach (i, tokens.count()) {
    char* p = tokens[i];
    DataStoreNode* dsn = ds->search(p);

    if (!dsn) {
      delete pbase;
      return null;
    }
    ds = dsn;
  }

  delete pbase;

  return (DataStoreNode*)ds;
}

DataStoreNode& DataStoreNode::get(const char* key) {
  DataStoreNode* node = search(key);
  if (node)
    return *node;

  node = new DataStoreNode(key, DS_NODE_TYPE_NULL);
  add(node);
  return *node;
}

//
// Type: null
//

//
// Type: W64s (int)
//

DataStoreNode::DataStoreNode(const char* name, W64s value) {
  init(name, DS_NODE_TYPE_INT, 1);
  this->value.w = value;
}

DataStoreNode::DataStoreNode(const char* name, const W64s* values, int count, bool histogram) {
  init(name, DS_NODE_TYPE_INT, count);
  this->values = (count) ? (new DataType[count]) : null;
  if (this->values) arraycopy(this->values, (DataType*)values, count);
}

DataStoreNode& DataStoreNode::histogram(const char* key, const W64* value, int count, W64s histomin, W64s histomax, W64s histostride) {
  DataStoreNode& ds = add(key, (W64s*)value, count);
  ds.histogramarray = 1;
  ds.histomin = histomin;
  ds.histomax = histomax;
  ds.histostride = histostride;

  return ds;
}

DataStoreNode& DataStoreNode::operator =(W64s data) {
  cleanup();
  this->type = DS_NODE_TYPE_INT;
  this->value.w = data;
  return *this;
}

DataStoreNode::operator W64s() const {
  switch (type) {
  case DS_NODE_TYPE_INT:
    return getdata().w; break;
  case DS_NODE_TYPE_FLOAT:
    return (W64s)getdata().f; break;
  case DS_NODE_TYPE_STRING:
    return strtoll(getdata().s, (char**)null, 10); break;
  case DS_NODE_TYPE_NULL:
    return 0;
  }
  return 0;
}

DataStoreNode::operator W64s*() const {
  assert(type == DS_NODE_TYPE_INT);
  return (!count) ? null : (count == 1) ? (W64s*)&value : (W64s*)values;
}

DataStoreNode::operator W64*() const {
  return (W64*)(W64s*)(*this);
}

//
// Type: double (float)
//

DataStoreNode::DataStoreNode(const char* name, double data) {
  init(name, DS_NODE_TYPE_FLOAT, 1);
  this->value.f = data;
}

DataStoreNode::DataStoreNode(const char* name, const double* values, int count) {
  init(name, DS_NODE_TYPE_FLOAT, count);
  this->values = (count) ? (new DataType[count]) : null;
  if (this->values) arraycopy(this->values, (DataType*)values, count);
}

DataStoreNode& DataStoreNode::operator =(double data) {
  cleanup();
  this->type = DS_NODE_TYPE_FLOAT;
  this->value.f = data;
  return *this;
}

DataStoreNode::operator double() const {
  switch (type) {
  case DS_NODE_TYPE_INT:
    return (W64s)getdata().w; break;
  case DS_NODE_TYPE_FLOAT:
    return getdata().f; break;
  case DS_NODE_TYPE_STRING:
    return atof(getdata().s); break;
  case DS_NODE_TYPE_NULL:
    return 0;
  }
  return 0;
}

DataStoreNode::operator double*() const {
  assert(type == DS_NODE_TYPE_FLOAT);
  return (!count) ? null : (count == 1) ? (double*)&value : (double*)values;
}

DataStoreNode::operator float() const {
  return (double)(*this);
}

//
// Type: const char* (string)
//

DataStoreNode::DataStoreNode(const char* name, const char* value) {
  init(name, DS_NODE_TYPE_STRING, 1);
  this->value.s = strdup(value);
}

DataStoreNode::DataStoreNode(const char* name, const char** values, int count) {
  init(name, DS_NODE_TYPE_FLOAT, count);
  this->values = (count) ? (new DataType[count]) : null;
  if (this->values) {
    foreach (i, count) {
      this->values[i].s = strdup(values[i]);
    }
  }
}

DataStoreNode& DataStoreNode::operator =(const char* data) {
  cleanup();
  this->type = DS_NODE_TYPE_FLOAT;
  this->value.s = strdup(data);
  return *this;
}

const char* DataStoreNode::string() const {
  assert(type == DS_NODE_TYPE_STRING);
  return getdata().s;
}

DataStoreNode::operator const char**() const {
  assert(type == DS_NODE_TYPE_STRING);
  return (!count) ? null : (count == 1) ? (const char**)&value : (const char**)values;
}

DataStoreNodeDirectory& DataStoreNode::getentries() const {
  return (subnodes) ? subnodes->getentries() : *(new DataStoreNodeDirectory());
}

double DataStoreNode::total() const {
  if (total_sum_cache > 0) return total_sum_cache;

  double result = (double)(*this);

  DataStoreNodeDirectory& list = getentries();
  foreach (i, list.length) {
    result += list[i].value->total();
  }

  delete &list;

  ((DataStoreNode*)this)->total_sum_cache = result;

  return result;
}

double DataStoreNode::percent_of_parent() const {
  if (!parent) return 0;
  if (parent->subnodes->count == 1) return 1.0;
  return total() / parent->total();
}

double DataStoreNode::percent_of_toplevel() const {
  if (!parent) return 0;

  // Find the toplevel summable node:
  const DataStoreNode* p = this;
  while (p) {
    if (p->parent && p->parent->summable) p = p->parent; else break;
  }

  return total() / p->total();
}

DataStoreNode& DataStoreNode::histogram(const char* key, const char** names, const W64* values, int count) {
  DataStoreNode& ds = histogram(key, values, count, 0, count-1, 1);
  ds.labeled_histogram = 1;
  ds.labels = new char* [count];
  foreach (i, count) {
    ds.labels[i] = strdup(names[i]);
  }
  return ds;
}

static inline int digits(W64 v) {
  stringbuf sb;
  sb << v;
  return strlen(sb);
}

DataStoreNode* DataStoreNode::sum_of_subtrees() const {
  // We can safely override const modifier for caches:
  DataStoreNode* thisdyn = (DataStoreNode*)this;

  if (!sum_of_subtrees_cache) {
    DataStoreNodeDirectory& a = getentries();

    // Only works with this type of node
    if (!identical_subtrees) {
      thisdyn->sum_of_subtrees_cache = new DataStoreNode("invalid");
      sum_of_subtrees_cache->dynamic = 1;
    } else {
      thisdyn->sum_of_subtrees_cache = a[0].value->clone();
      sum_of_subtrees_cache->dynamic = 1;
      sum_of_subtrees_cache->rename("[total]");

      for (int i = 1; i < a.length; i++) {
        (*sum_of_subtrees_cache) += *(a[i].value);
      }
    }
  }

  return sum_of_subtrees_cache;
}


DataStoreNode* DataStoreNode::average_of_subtrees() const {
  // We can safely override const modifier for caches:
  DataStoreNode* thisdyn = (DataStoreNode*)this;

  if (!average_of_subtrees_cache) {
    DataStoreNodeDirectory& a = getentries();

    // Only works with this type of node
    if (!identical_subtrees) {
      thisdyn->average_of_subtrees_cache = new DataStoreNode("invalid");
      average_of_subtrees_cache->dynamic = 1;
    } else {
      double coeff = 1. / a.size();
      thisdyn->average_of_subtrees_cache = a[0].value->map(ScaleOperator(coeff));
      average_of_subtrees_cache->dynamic = 1;
      average_of_subtrees_cache->rename("[average]");

      for (int i = 1; i < a.length; i++) average_of_subtrees_cache->addscaled(*a[i].value, coeff);
    }
  }

  return average_of_subtrees_cache;
}

ostream& DataStoreNode::print(ostream& os, const DataStoreNodePrintSettings& printinfo, int depth, double supersum) const {
  stringbuf padding;
  foreach (i, depth) { padding << "  "; }
  os << padding;

  double selfsum = total();

  if (parent && parent->summable) {
    double p = ((printinfo.percent_of_toplevel) ? percent_of_toplevel() : percent_of_parent()) * 100.0;
    if (p >= 99.999)
      os << "[ ", padstring("100%", 4 + printinfo.percent_digits), " ] ";
    else os << "[ ", floatstring(p, 3 + printinfo.percent_digits, printinfo.percent_digits), "% ] ";
  }

  switch (type) {
  case DS_NODE_TYPE_NULL: {
    os << name;
    break;
  }
  case DS_NODE_TYPE_INT: {
    os << name;
    if (count == 1) {
      os << " = ", value.w, ";";
    } else {
      os << "[", count, "] = {";

      if (histogramarray) {
        os << endl;

        W64 total = 0;
        W64 maxvalue = 0;
        W64 minvalue = -1ULL;
        foreach (i, count) {
          total += values[i].w;
          minvalue = min((W64)values[i].w, minvalue);
          maxvalue = max((W64)values[i].w, maxvalue);
        }

        W64 thresh = max((W64)math::ceil((double)total * printinfo.histogram_thresh), (W64)1);
        W64 base = histomin;
        int width = digits(max(histomin, histomax));
        int valuewidth = digits(maxvalue);
        int w = max(width, valuewidth);

        if (!labeled_histogram) {
          os << padding, "  ", "Range:   ", intstring(histomin, w), " ", intstring(histomax, w), endl;
          os << padding, "  ", "Stride:  ", intstring(histostride, w), endl;
        }

        os << padding, "  ", "ValRange:", intstring(minvalue, w), " ", intstring(maxvalue, w), endl;
        os << padding, "  ", "Total:   ", intstring(total, w), endl;
        os << padding, "  ", "Thresh:  ", intstring(thresh, w), endl;

        W64 accum = 0;

        foreach (i, count) {
          W64 value = (W64)values[i].w;
          accum += value;

          if (value >= thresh) {
            double percent = ((double)value / (double)total) * 100.0;
            double cumulative_percent = ((double)accum / (double)total) * 100.0;
            os << padding, "  [ ", floatstring(percent, 3 + printinfo.percent_digits, printinfo.percent_digits), "% ] ";

            if (labeled_histogram) {
              os << intstring(base, w), " ", intstring(value, w), " ", labels[i], endl;
            } else {
              if (cumulative_percent >= 99.9)
                os << "[ ", padstring("100", 3 + printinfo.percent_digits), "% ] ";
              else os << "[ ", floatstring(cumulative_percent, 3 + printinfo.percent_digits, printinfo.percent_digits), "% ] ";
              
              os << intstring(base, w), " ", 
                intstring(base + (histostride-1), w), " ",
                intstring(value, w), endl;
            }
          }

          base += histostride;
        }

        os << padding;
      } else {
        foreach (i, count) {
          os << values[i].w;
          if (i != (count-1)) os << ", ";
        }
      }
      os << "};";
    }
    break;
  }
  case DS_NODE_TYPE_FLOAT: {
    os << name;
    if (count == 1) {
      os << " = ", value.f, ";";
    } else {
      os << "[", count, "] = {";
      foreach (i, count) {
        os << values[i].f;
        if (i != (count-1)) os << ", ";
      }
      os << "};";
    }
    break;
  }
  case DS_NODE_TYPE_STRING: {
    os << name;
    if (count == 1) {
      os << " = \"", value.s, "\"", ";";
    } else {
      os << "[", count, "] = {";
      foreach (i, count) {
        os << "\"", values[i].f, "\"";
        if (i != (count-1)) os << ", ";
      }
      os << "};";
    }
    break;
  }
  default:
    assert(false);
  }

  if (depth == printinfo.maxdepth) {
    os << " { ... }", endl;
    return os;
  }

  if (subnodes) {
    bool isint = ((selfsum - math::floor(selfsum)) < 0.0001);
    if (summable) {
      os << " (total ";
      if (isint) os << (W64s)selfsum; else os << (double)selfsum; os << ")";
    }
    os << " {", endl;

    DataStoreNodeDirectory& a = getentries();

    if (identical_subtrees) {
      sum_of_subtrees()->print(os, printinfo, depth + 1, 0);

      if (!printinfo.force_sum_of_subtrees_only) {
        foreach (i, a.length) {
          a[i].value->print(os, printinfo, depth + 1, 0);
        }
      }
    } else {
      foreach (i, a.length) {
        a[i].value->print(os, printinfo, depth + 1, (summable) ? selfsum : 0);
      }
    }
    foreach (i, depth) { os << "  "; }
    os << "}";
    delete &a;
  }
  os << endl;
  return os;
}

struct DataStoreNodeArrayHeader {
  W32 count;
  W32 padding;
  W64 histomin;
  W64 histomax;
  W64 histostride;
};

struct DataStoreNodeHeader {
  W32 magic;
  byte type;
  byte namelength;
  W16 isarray:1, summable:1, histogramarray:1, identical_subtrees:1, labeled_histogram:1;
  W32 subcount;
  // (optional DataStoreNodeArrayInfo iff (isarray == 1)
  // (null-terminated name)
  // (count * sizeof(type) bytes)
  // (all subnodes)
};

DataStoreNode::DataStoreNode(idstream& is) {
  if (!read(is)) {
    init("INVALID", DS_NODE_TYPE_NULL, 0);
  }
}

#define DSN_MAGIC_VER_3 0x334c5450 // 'PTL3'

bool DataStoreNode::read(idstream& is) {
  DataStoreNodeHeader h;
  is >> h;

  // Multiple versions can be supported with different readers

  assert(is);

  if (h.magic != DSN_MAGIC_VER_3) {
    cerr << "DataStoreNode::read(): ERROR: stream does not have proper DSN version 2 header (0x", 
      hexstring(h.magic, 32), ") at offset ", is.where(), endl, flush;
    return false;
  }

  DataStoreNodeArrayHeader ah;

  if (h.isarray) {
    is >> ah;
    count = ah.count;
    histomin = ah.histomin;
    histomax = ah.histomax;
    histostride = ah.histostride;
  }

  name = new char[h.namelength+1];
  is.read((char*)name, h.namelength+1);
  type = h.type;
  summable = h.summable;
  identical_subtrees = h.identical_subtrees;
  histogramarray = h.histogramarray;
  labeled_histogram = h.labeled_histogram;

  count = (h.isarray) ? ah.count : 1;
  subnodes = null;
  parent = null;

  if (h.isarray & h.histogramarray & h.labeled_histogram) {
    // Read the <count> histogram slot labels
    labels = new char* [count];
    foreach (i, count) {
      W16 ll;
      is >> ll;
      labels[i] = new char[ll + 1];
      is.read(labels[i], ll);
      labels[i][ll] = 0;
    }
  }

  switch (type) {
  case DS_NODE_TYPE_NULL: {
    break;
  }
  case DS_NODE_TYPE_INT: {
    if (count == 1) {
      is >> value.w;
    } else {
      values = new DataType[count];
      is.read(values, count * sizeof(DataType));
    }
    break;
  }
  case DS_NODE_TYPE_FLOAT: {
    if (count == 1) {
      is >> value.f;
    } else {
      values = new DataType[count];
      is.read(values, count * sizeof(DataType));
    }
    break;
  }
  case DS_NODE_TYPE_STRING: {
    if (count == 1) {
      W16 len;
      is >> len;
      value.s = new char[len+1];
      is.read((char*)value.s, len+1);
    } else {
      values = new DataType[count];
      foreach (i, count) {
        W16 len;
        is >> len;
        values[i].s = new char[len+1];
        is.read((char*)values[i].s, len+1);
      }
    }
    break;
  }
  default:
    assert(false);
  }

  foreach (i, h.subcount) {
    add(new DataStoreNode(is));
  }
  return is;
}

odstream& DataStoreNode::write(odstream& os) const {
  DataStoreNodeHeader h;
  DataStoreNodeArrayHeader ah;

  int namelen = strlen(name);
  assert(namelen < 256);

  h.magic = DSN_MAGIC_VER_3;
  h.type = type;
  h.namelength = (byte)namelen;
  h.histogramarray = histogramarray;
  h.summable = summable;
  h.identical_subtrees = identical_subtrees;
  h.labeled_histogram = labeled_histogram;

  h.isarray = (count > 1);
  if (count > 1) {
    ah.count = count;
    ah.histomin = histomin;
    ah.histomax = histomax;
    ah.histostride = histostride;
  }

  h.subcount = (subnodes) ? subnodes->count : 0;

  os << h;
  if (h.isarray) os << ah;

  os.write(name, h.namelength + 1);

  if (h.isarray & h.histogramarray & h.labeled_histogram) {
    // Write the <count> histogram slot labels
    foreach (i, count) {
      W16 ll = strlen(labels[i]);
      os << ll;
      os.write(labels[i], ll);
    }
  }

  switch (type) {
  case DS_NODE_TYPE_NULL: {
    break;
  }
  case DS_NODE_TYPE_INT: {
    if (count == 1) {
      os << value.w;
    } else {
      os.write(values, count * sizeof(DataType));
    }
    break;
  }
  case DS_NODE_TYPE_FLOAT: {
    if (count == 1) {
      os << value.f;
    } else {
      os.write(values, count * sizeof(DataType));
    }
    break;
  }
  case DS_NODE_TYPE_STRING: {
    if (count == 1) {
      int len = strlen(value.s);
      assert(len < 65536);     
      os << (W16)len;
      os.write(value.s, len+1);
    } else {
      foreach (i, count) {
        int len = strlen(values[i].s);
        assert(len < 65536);
        os << (W16)len;
        os.write(values[i].s, len+1);
      }
    }
    break;
  }
  default:
    assert(false);
  }

  if (subnodes) {
    DataStoreNodeDirectory& a = getentries();
    foreach (i, a.length) {
      a[i].value->write(os);
    }
    delete &a;
  }
  return os;
}

DataStoreNodeTemplate::DataStoreNodeTemplate(const char* name, int type, int count, const char** labels) {
  magic = DataStoreNodeTemplateBase::MAGIC;
  length = sizeof(DataStoreNodeTemplateBase);
  this->name = strdup(name);
  this->type = type;
  this->count = count;

  parent = null;

  subcount = 0;
  summable = 0;
  histogramarray = 0;
  identical_subtrees = 0;
  labeled_histogram = 0;
  labels = null;

  histomin = 0;
  histomax = 0;
  histostride = 0;
  limit = 0;

  if (labels) {
    labeled_histogram = 1;
    this->labels = new char*[count];
    foreach (i, count) {
      this->labels[i] = strdup(labels[i]);
    }
  }
}

DataStoreNodeTemplate::~DataStoreNodeTemplate() {
  foreach (i, subnodes.length) {
    // delete subnodes[i];
  }
  subnodes.clear();
  subcount = 0;
  // if (labels) delete labels;
  if (name) delete name;
}

//
// Generate a C struct definition for the tree
//
ostream& DataStoreNodeTemplate::generate_struct_def(ostream& os, int depth) const {
  foreach (i, depth) os << "  ";

  if (labeled_histogram) {
    assert(subnodes);
    os << "W64 ", name, "[", subnodes.length, "];", endl;
  } else {
    switch (type) {
    case DS_NODE_TYPE_NULL: {
      os << "struct ", name, " {";
      if (summable | identical_subtrees) os << " // node:";
      if (summable) os << " summable";
      if (identical_subtrees) os << " identical";
      os << endl;
      break;
    }
    case DS_NODE_TYPE_INT: {
      os << "W64 ", name;
      if (count > 1) os << "[", count, "]";
      os << ";";
      if (histogramarray) os << "// histo: ", histomin, " ", histomax, " ", histostride, endl;
      if (labeled_histogram) {
        os << "// label:";
        foreach (i, count) { os << " ", labels[i]; }
      }
      os << endl;
      break;
    }
    case DS_NODE_TYPE_FLOAT: {
      os << "double ", name;
      if (count > 1) os << "[", count, "]";
      os << ";", endl;
      break;
    }
    case DS_NODE_TYPE_STRING: {
      os << "char ", name;
      if (count > 1) os << "[", count, "]";
      os << "[", limit, "]";
      os << ";", endl;
      break;
    }
    default:
      assert(false);
    }

    //os << "// subnodes = ", subnodes, endl;
    foreach (i, subnodes.length) {
      subnodes[i]->generate_struct_def(os, depth + 1);
    }

    if (type == DS_NODE_TYPE_NULL) {
      foreach (i, depth) os << "  ";
      if (depth) {
        os << "} ", (name ?: "UNKNOWN"), ";", endl;
      } else {
        os << "};", endl;
      }
    }
  }

  return os;
}

//
// Write structural definition in binary format for use by ptlstats:
//
odstream& DataStoreNodeTemplate::write(odstream& os) const {
  W16 n;

  os.write((DataStoreNodeTemplateBase*)this, sizeof(DataStoreNodeTemplateBase));

  n = strlen(name); os << n; os.write(name, n);

  if (labeled_histogram) {
    foreach (i, count) {
      n = strlen(labels[i]); os << n; os.write(labels[i], n);
    }
  }

  assert(subcount == subnodes.length);

  foreach (i, subcount) {
    subnodes[i]->write(os);
  }

  return os;
}

//
// Read structural definition in binary format for use by ptlstats:
//
DataStoreNodeTemplate::DataStoreNodeTemplate(idstream& is) {
  // Fill in all static fields:
  is.read(this, sizeof(DataStoreNodeTemplateBase));
  assert(magic == DataStoreNodeTemplateBase::MAGIC);
  assert(length == sizeof(DataStoreNodeTemplateBase));

  parent = null;

  W16 n;
  is >> n; name = new char[n+1]; is.read(name, n); name[n] = 0;

  if (labeled_histogram) {
    labels = new char*[count];
    foreach (i, count) {
      is >> n; labels[i] = new char[n+1]; is.read(labels[i], n); labels[i][n] = 0;
    }
  }

  subnodes.resize(subcount);

  foreach (i, subcount) {
    subnodes[i] = new DataStoreNodeTemplate(is);
  }
}

//
// Reconstruct a stats tree from its template and an array of words
// representing the tree in depth first traversal order, in a format
// identical to the C struct generated by generate_struct_def()
//
DataStoreNode* DataStoreNodeTemplate::reconstruct(const W64*& p) {
  DataStoreNode* ds;

  switch (type) {
  case DS_NODE_TYPE_NULL: {
    ds = new DataStoreNode(name);
    foreach (i, subnodes.length) {
      ds->add(subnodes[i]->reconstruct(p));
    }
    break;
  }
  case DS_NODE_TYPE_INT: {
    if (count > 1) {
      ds = new DataStoreNode(name, (W64s*)p, count);
      ds->histogramarray = histogramarray;
      ds->histomin = histomin;
      ds->histomax = histomax;
      ds->histostride = histostride;
      ds->labeled_histogram = labeled_histogram;
        
      if (labeled_histogram) {
        ds->labels = new char* [count];
        foreach (i, count) {
          ds->labels[i] = strdup(labels[i]);
        }
      }
        
      p += count;
    } else {
      ds = new DataStoreNode(name, *(W64s*)p);
      p++;
    }
    break;
  }
  case DS_NODE_TYPE_FLOAT: {
    if (count > 1) {
      ds = new DataStoreNode(name, (double*)p, count);
      p += count;
    } else {
      ds = new DataStoreNode(name, *(double*)p);
      p++;
    }
    break;
  }
  case DS_NODE_TYPE_STRING: {
    if (count > 1) {
      abort(); // not supported
      const char** strings = new const char* [count];
      foreach (i, count) {
        strings[i] = (const char*)p;
        p += limit / 8;
      }        
      ds = new DataStoreNode(name, strings, count);
    } else {
      ds = new DataStoreNode(name, (const char*)p);
      p = (W64*)(((Waddr)p) + limit);
    }

    break;
  }
  default:
    assert(false);
  }

  return ds;
}

//
// Stats index file header
//
struct StatsIndexHeader {
  W32 magic;
  W32 version;
  W32 record_size;
  W32 template_size;

  static const W32 MAGIC = 0x734c5450; // 'PTLs'
  static const W32 VERSION = 1;
};

//
// Stats index file record, pointing to
// snapshots in data portion of file.
// These structures come immediately
// after the index header and template
// descriptor.
//
struct StatsIndexRecord {
  W64 uuid;
  W64 offset;
  W16 namelen;
};

//
// StatsFileWriter
//
void StatsFileWriter::open(const char* filename, const void* dst, size_t dstsize, int record_size) {
  close();
  indexfile.open(filename);

  stringbuf sb; sb << filename, ".data";
  datafile.open(sb);

  StatsIndexHeader h;
  h.magic = StatsIndexHeader::MAGIC;
  h.version = StatsIndexHeader::VERSION;
  h.record_size = record_size;
  h.template_size = dstsize;
  this->record_size = record_size;

  indexfile << h;
  indexfile.write(dst, dstsize);
  indexfile.flush();
}

void StatsFileWriter::write(const void* record, W64 uuid, const char* name) {
  StatsIndexRecord idx;
  idx.uuid = uuid;
  idx.offset = datafile.where();
  idx.namelen = (name) ? (strlen(name) + 1) : 0;
  indexfile << idx;
  if (idx.namelen) {
    indexfile.write(name, idx.namelen);
  }

  datafile.write(record, record_size);
}

void StatsFileWriter::flush() {
  if (indexfile) indexfile.flush();
  if (datafile) datafile.flush();
}

//
// StatsFileReader
//

bool StatsFileReader::open(const char* filename) {
  close();

  indexfile.open(filename);

  if (!indexfile) {
    cerr << "StatsFileReader: cannot open ", filename, endl;
    return false;
  }

  stringbuf sb; sb << filename, ".data";
  datafile.open(sb);

  if (!datafile) {
    cerr << "StatsFileReader: cannot open ", sb, endl;
    close();
    return false;
  }

  StatsIndexHeader h;
  indexfile >> h;

  if (!indexfile) {
    cerr << "StatsFileReader: error reading index header", endl;
    close();
    return false;
  }

  if ((h.magic != StatsIndexHeader::MAGIC) | (h.version != StatsIndexHeader::VERSION)) {
    cerr << "StatsFileReader: index header magic or version mismatch", endl;
    close();
    return false;
  }

  record_size = h.record_size;
  buf = new byte[record_size];

  dst = new DataStoreNodeTemplate(indexfile);

  if ((!indexfile) | (!dst)) {
    cerr << "StatsFileReader: error while reading and parsing template", endl;
    close();
    return false;
  }

  //
  // Read in the records
  //

  int i = 0;
  while (indexfile) {
    StatsIndexRecord rec;
    indexfile >> rec;
    if (!indexfile) {
      // Last record
      return true;
    }

    //cerr << "  uuid ", intstring(rec.uuid, 12), " @ ", intstring(rec.offset, 12), endl;

    if (rec.namelen) {
      char* name = new char[rec.namelen];
      // Already null-terminated in the file:
      indexfile.read(name, rec.namelen);
      name_to_uuid.add(name, rec.uuid);
      //cerr << "    Name (", rec.namelen, ") = ", name, endl;
      delete name;
    }

    if (i == 0) { base_uuid = rec.uuid; }
    uuid_to_offset.push(rec.offset);
    i++;
  }

  return true;
}

DataStoreNode* StatsFileReader::get(W64 uuid) {
  //cerr << "seek to reconstruct uuid ", uuid, " (base ", base_uuid, ", offset ", offset, endl;

  if unlikely (uuid < base_uuid) return null;
  if unlikely ((uuid - base_uuid) >= uuid_to_offset.length) return null;

  W64 offset = uuid_to_offset[uuid - base_uuid];

  //cerr << "seek to reconstruct uuid ", uuid, ", offset ", offset, endl;

  datafile.seek(offset, SEEK_SET);
  if unlikely (datafile.read(buf, record_size) != record_size) return null;

  const W64* p = (const W64*)buf;
  DataStoreNode* dsn = dst->reconstruct(p);

  //cerr << "dsn ", dsn, " reconstructed from uuid ", uuid, ", offset ", offset, endl;

  return dsn;
}

DataStoreNode* StatsFileReader::get(const char* name) {
  bool all_nums = 1;
  foreach (i, strlen(name)) {
    all_nums &= inrange(name[i], '0', '9');
  }

  if unlikely (all_nums) {
    return get(atoi(name));
  }

  W64* uuidp = name_to_uuid(name);
  if unlikely (!uuidp) return null;

  W64 uuid = *uuidp;

  //cerr << "found uuid ", uuid, " for name ", name, endl;
  return get(uuid);
}

void StatsFileReader::close() {
  if (dst) delete dst;
  if (buf) delete buf;

  name_to_uuid.clear();
  uuid_to_offset.clear();

  if (indexfile) indexfile.close();
  if (datafile) datafile.close();
}
