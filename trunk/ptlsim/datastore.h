// -*- c++ -*-
//
// Data Store
//
// Copyright 2000-2005 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>

#ifndef _DATASTORE_H_
#define _DATASTORE_H_

struct DataStoreNode;

typedef dynarray< KeyValuePair<const char*, DataStoreNode*> > DataStoreNodeDirectory;

struct DataStoreNode;

struct DataStoreNodePrintSettings {
  int maxdepth;
  int percent_digits;
  int force_sum_of_subtrees_only:1, percent_of_toplevel:1;

  DataStoreNodePrintSettings() {
    force_sum_of_subtrees_only = 0;
    maxdepth = limits<int>::max;
    percent_digits = 0;
    percent_of_toplevel = 0;
  }
};

#define DeclareOperator(name, expr) \
  struct name { \
    W64s operator ()(W64s a, W64s b) const { return (expr); } \
    double operator ()(double a, double b) const { return (expr); } \
  }

DeclareOperator(AddOperator, (a + b));
DeclareOperator(SubtractOperator, (a - b));

struct AddScaleOperator {
  typedef double context_t;
  context_t coeff;
  AddScaleOperator(double coeff_): coeff(coeff_) { }; 
  W64s operator ()(W64s a, W64s b) const { return (W64s)math::round((double)a + ((double)b * coeff)); }
  double operator ()(double a, double b) const { return a + b*coeff; }
};

#undef DeclareOperator

//
// Unary operations
//
#define DeclareOperator(name, expr) \
  struct name { \
    W64s operator ()(W64s a) const { return (expr); } \
    double operator ()(double a) const { return (expr); } \
  }

DeclareOperator(IdentityOperator, (a));
DeclareOperator(ZeroOperator, (0));

struct ScaleOperator {
  double coeff;
  ScaleOperator(double coeff_): coeff(coeff_) { }; 
  W64s operator ()(W64s a) const { return (W64s)math::round(((double)a) * coeff); }
  double operator ()(double a) const { return a * coeff; }
};

#undef DeclareOperator

struct DataStoreNode {
  typedef Hashtable<const char*, DataStoreNode*> hash_t;
  hash_t* subnodes;
  const char* name;
  DataStoreNode* sum_of_subtrees_cache;
  DataStoreNode* average_of_subtrees_cache;
  double total_sum_cache;

  W16 type;
  W16 summable:1, histogramarray:1, identical_subtrees:1, dynamic:1;
  W32 count;

  // For nodes with an array style histogram:
  W64 histomin;       // minslot
  W64 histomax;       // maxslot
  W64 histostride;    // real units per histogram slot

  DataStoreNode* parent;

  enum NodeType { DS_NODE_TYPE_NULL, DS_NODE_TYPE_INT, DS_NODE_TYPE_FLOAT, DS_NODE_TYPE_NODE, DS_NODE_TYPE_STRING };

  union DataType {
    W64s w;
    double f;
    const char* s;
    DataStoreNode* n;
  };

  union {
    DataType* values;
    DataType value;
  };

  DataStoreNode();
  DataStoreNode(const char* name);
  DataStoreNode(const char* name, NodeType type, int count = 0);

  void init(const char* name, int type, int count = 0);
  void rename(const char* newname);

  ~DataStoreNode();
  void cleanup();

  DataStoreNode& add(DataStoreNode* node);
  DataStoreNode& add(DataStoreNode& node) { return add(&node); }

  bool remove(const char* key);

  void removeall();

  DataType getdata() const;

  void invalidate_caches();

  DataStoreNode* search(const char* key) const;

  DataStoreNode* searchpath(const char* path) const;

  DataStoreNode& get(const char* key);

  DataStoreNode& operator ()(const char* key) { return get(key); }

  DataStoreNode& operator [](const char* key) { return get(key); }

  //
  // Type: null
  //

  DataStoreNode& add(const char* key) { return add(new DataStoreNode(key)); }

  //
  // Type: W64s (int)
  //

  DataStoreNode(const char* name, W64s value);
  DataStoreNode(const char* name, const W64s* values, int count, bool histogram = false);

  DataStoreNode& add(const char* key, W64s value) { return add(new DataStoreNode(key, (W64s)value)); }
  DataStoreNode& add(const char* key, W64s* value, int count) { return add(new DataStoreNode(key, (W64s*)value, count)); }
  DataStoreNode& add(const char* key, W64s* value, int count, W64s histomin, W64s histomax, W64s histostride);

  operator W64s() const;

  operator W64() const { return (W64s)(*this); }
  operator W32s() const { return (W64s)(*this); }
  operator W32() const { return (W64s)(*this); }
  operator W16s() const { return (W64s)(*this); }
  operator W16() const { return (W64s)(*this); }
  operator byte() const { return (W64s)(*this); }
  operator W8s() const { return (W64s)(*this); }

  operator W64s*() const;
  operator W64*() const;

  DataStoreNode& operator =(W64s data);

  //
  // Type: double (float)
  //

  DataStoreNode(const char* name, double value);
  DataStoreNode(const char* name, const double* values, int count);

  DataStoreNode& addfloat(const char* key, double value) { return add(new DataStoreNode(key, (double)value)); }
  DataStoreNode& addfloat(const char* key, double* value, int count) { return add(new DataStoreNode(key, (double*)value, count)); }

  operator double() const;
  operator double*() const;
  operator float() const;

  DataStoreNode& operator =(double data);

  //
  // Type: const char* (string)
  //

  DataStoreNode(const char* name, const char* value);
  DataStoreNode(const char* name, const char** values, int count);

  DataStoreNode& add(const char* key, const char* value) { return add(new DataStoreNode(key, (const char*)value)); }
  DataStoreNode& add(const char* key, const char** value, int count) { return add(new DataStoreNode(key, (const char**)value, count)); }

  DataStoreNode& operator =(const char* data);

  const char* string() const;

  operator const char**() const;

  DataStoreNodeDirectory& getentries() const;

  double total() const;
  double percent_of_parent() const;
  double percent_of_toplevel() const;

  DataStoreNode& histogram(const W64* values, int count);
  DataStoreNode& histogram(const char** names, const W64* values, int count);

  ostream& print(ostream& os, const DataStoreNodePrintSettings& printinfo = DataStoreNodePrintSettings(), int depth = 0, double supersum = 0) const;

  DataStoreNode(idstream& is);

  bool read(idstream& is);

  odstream& write(odstream& os) const;

  template <class F>
  DataStoreNode* map(const F& func) const {
    DataStoreNode* newnode = null;

    switch (type) {
    case DataStoreNode::DS_NODE_TYPE_NULL: {
      newnode = new DataStoreNode(name);
      break;
    }
    case DataStoreNode::DS_NODE_TYPE_INT: {
      if (count == 1) {
        newnode = new DataStoreNode(name, func(value.w));
      } else {
        W64s* destdata = new W64s[count];
        foreach (i, count) destdata[i] = func(values[i].w);
        newnode = new DataStoreNode(name, destdata, count);
      }
      break;
    }
    case DataStoreNode::DS_NODE_TYPE_FLOAT: {
      if (count == 1) {
        newnode = new DataStoreNode(name, func(value.f));
      } else {
        double* destdata = new double[count];
        foreach (i, count) destdata[i] = func(values[i].f);
        newnode = new DataStoreNode(name, destdata, count);
      }
      break;
    }
    case DataStoreNode::DS_NODE_TYPE_STRING: {
      if (count == 1) {
        newnode = new DataStoreNode(name, string());
      } else {
        newnode = new DataStoreNode(name, (const char**)(*this), count);
      }
      break;
    }
    default:
      assert(false);
    }

    newnode->summable = summable;
    newnode->histogramarray = histogramarray;
    newnode->identical_subtrees = identical_subtrees;

    newnode->histomin = histomin;
    newnode->histomax = histomax;
    newnode->histostride = histostride;

    DataStoreNodeDirectory& list = getentries();
    
    foreach (i, list.length) {
      newnode->add(list[i].value->map(func));
    }
    
    delete &list;

    return newnode;
  }

  DataStoreNode* clone() const { return map(IdentityOperator()); }
  DataStoreNode* zero() const { return map(ZeroOperator()); }

  // NOTE: These results cannot be freed: dynamic cached subtree only
  DataStoreNode* sum_of_subtrees() const;
  DataStoreNode* average_of_subtrees() const;

  template <class F>
  static DataStoreNode* apply(const F& func, const DataStoreNode& a, const DataStoreNode& b) {
    DataStoreNode* newnode = null;

    if (!((a.type == b.type) & (a.count == b.count))) {
      cerr << "DataStoreNode::apply(", a.name, ", ", b.name, "): mismatch types (", a.type, " vs ", b.type, "), count (", a.count, " vs ", b.count, ")", endl, flush;
      assert(false);
    }

    switch (a.type) {
    case DataStoreNode::DS_NODE_TYPE_NULL: {
      newnode = new DataStoreNode(a.name);
      break;
    }
    case DataStoreNode::DS_NODE_TYPE_INT: {
      if (a.count == 1) {
        newnode = new DataStoreNode(a.name, func(a.value.w, b.value.w));
      } else {
        W64s* destdata = new W64s[a.count];
        W64s* adata = a;
        W64s* bdata = b;
        foreach (i, a.count) destdata[i] = func(adata[i], bdata[i]);
        newnode = new DataStoreNode(a.name, destdata, a.count);
      }
      break;
    }
    case DataStoreNode::DS_NODE_TYPE_FLOAT: {
      if (a.count == 1) {
        newnode = new DataStoreNode(a.name, func(a.value.f, b.value.f));
      } else {
        double* destdata = new double[a.count];
        double* adata = a;
        double* bdata = b;
        foreach (i, a.count) destdata[i] = func(adata[i], bdata[i]);
        newnode = new DataStoreNode(a.name, destdata, a.count);
      }
      break;
    }
    case DataStoreNode::DS_NODE_TYPE_STRING: {
      if (a.count == 1) {
        newnode = new DataStoreNode(a.name, b.string());
      } else {
        newnode = new DataStoreNode(a.name, (const char**)b, b.count);
      }
      break;
    }
    default:
      assert(false);
    }

    newnode->summable = a.summable;
    newnode->histogramarray = a.histogramarray;
    newnode->identical_subtrees = a.identical_subtrees;

    newnode->histomin = a.histomin;
    newnode->histomax = a.histomax;
    newnode->histostride = a.histostride;

    DataStoreNodeDirectory& alist = a.getentries();
    DataStoreNodeDirectory& blist = b.getentries();

    if (alist.length != blist.length) {
      cerr << "DataStoreNode::apply(", a.name, ", ", b.name, "): mismatch in subnode list length (", alist.length, " vs ", blist.length, ")", endl, flush;
      assert(alist.length == blist.length);
    }

    foreach (i, alist.length) {
      DataStoreNode& anode = *a.search(alist[i].key);
      DataStoreNode& bnode = *b.search(blist[i].key);
      assert(&anode); assert(&bnode);
      newnode->add(apply(func, anode, bnode));
    }

    delete &alist;
    delete &blist;

    return newnode;
  }

  template <class F>
  DataStoreNode& apply(const F& func, const DataStoreNode& b) {
    if (!((type == b.type) & (count == b.count))) {
      cerr << "DataStoreNode::apply(", name, ", ", b.name, "): mismatch types (", type, " vs ", b.type, "), count (", count, " vs ", b.count, ")", endl, flush;
      assert(false);
    }

    switch (type) {
    case DataStoreNode::DS_NODE_TYPE_NULL: {
      // No action
      break;
    }
    case DataStoreNode::DS_NODE_TYPE_INT: {
      if (count == 1) {
        value.w = func(value.w, b.value.w);
      } else {
        foreach (i, count) values[i].w = func(values[i].w, b.values[i].w);
      }
      break;
    }
    case DataStoreNode::DS_NODE_TYPE_FLOAT: {
      if (count == 1) {
        value.f = func(value.f, b.value.f);
      } else {
        foreach (i, count) values[i].f = func(values[i].f, b.values[i].f);
      }
      break;
    }
    case DataStoreNode::DS_NODE_TYPE_STRING: {
      // Leave strings alone
      break;
    }
    default:
      assert(false);
    }

    DataStoreNodeDirectory& alist = getentries();
    DataStoreNodeDirectory& blist = b.getentries();

    if (alist.length != blist.length) {
      cerr << "DataStoreNode::apply(", name, ", ", b.name, "): mismatch in subnode list length (", alist.length, " vs ", blist.length, ")", endl, flush;
      assert(alist.length == blist.length);
    }

    foreach (i, alist.length) {
      DataStoreNode& anode = *search(alist[i].key);
      DataStoreNode& bnode = *b.search(blist[i].key);
      assert(&anode); assert(&bnode);
      anode.apply(func, bnode);
    }

    delete &alist;
    delete &blist;

    return *this;
  }

  DataStoreNode* operator +(const DataStoreNode& b) const {
    return apply(AddOperator(), *this, b);
  }

  DataStoreNode* operator -(const DataStoreNode& b) const {
    return apply(SubtractOperator(), *this, b);
  }

  DataStoreNode& operator +=(const DataStoreNode& b) {
    return apply(AddOperator(), b);
  }

  DataStoreNode& addscaled(const DataStoreNode& b, double scale) {
    return apply(AddScaleOperator(scale), b);
  }

  DataStoreNode& operator -=(const DataStoreNode& b) {
    return apply(SubtractOperator(), b);
  }
};

inline odstream& operator <<(odstream& os, const DataStoreNode& node) {
  return node.write(os);
}

#endif // _DATASTORE_H_
