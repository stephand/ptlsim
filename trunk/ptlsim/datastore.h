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

struct DataStoreNode {
  typedef Hashtable<const char*, DataStoreNode*> hash_t;
  hash_t* subnodes;
  const char* name;
  W16 type;
  W16 summable:1;
  W32 count;
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

  ~DataStoreNode();
  void cleanup();

  DataStoreNode& add(DataStoreNode* node);

  bool remove(const char* key);

  void removeall();

  DataType getdata() const;

  DataStoreNode* search(const char* key) const;

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
  DataStoreNode(const char* name, const W64s* values, int count);

  DataStoreNode& add(const char* key, W64s value) { return add(new DataStoreNode(key, (W64s)value)); }
  DataStoreNode& add(const char* key, W64s* value, int count) { return add(new DataStoreNode(key, (W64s*)value, count)); }

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

  DataStoreNode* subtract(DataStoreNode& prev);

  double sum() const;

  ostream& print(ostream& os, bool percents = false, int depth = 0, double supersum = 0) const;

  DataStoreNode(idstream& is);

  bool read(idstream& is);

  odstream& write(odstream& os) const;

};

inline odstream& operator <<(odstream& os, const DataStoreNode& node) {
  return node.write(os);
}

#endif // _DATASTORE_H_
