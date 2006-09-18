// -*- c++ -*-
//
// Super Standard Template Library
//
// Faster and more optimized than stock STL implementation,
// plus includes various customized features
//
// Copyright 1997-2005 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#ifndef _SUPERSTL_H_
#define _SUPERSTL_H_

//
// Formatting
//
#define FMT_ZEROPAD 1 /* pad with zero */
#define FMT_SIGN    2 /* unsigned/signed long */
#define FMT_PLUS    4 /* show plus */
#define FMT_SPACE   8 /* space if plus */
#define FMT_LEFT	  16 /* left justified */
#define FMT_SPECIAL	32 /* 0x */
#define FMT_LARGE	  64 /* use 'ABCDEF' instead of 'abcdef' */

namespace superstl {
  //
  // String buffer
  //

#define stringbuf_smallbufsize 256
  class stringbuf;

  stringbuf& operator <<(stringbuf& os, const char* v);
  stringbuf& operator <<(stringbuf& os, const char v);

  class stringbuf {
  public:
    stringbuf() { buf = null; reset(); }
    stringbuf(int length) {
      buf = null;
      reset(length);
    }

    void reset(int length = stringbuf_smallbufsize);

    ~stringbuf();

    int remaining() const {
      return (buf + length) - p;
    }

    operator char*() const {
      return buf;
    }

    void resize(int newlength);

    void expand() {
      resize(length*2);
    }

    void reserve(int extra);

    int size() const { return p - buf; }
    bool empty() const { return (size() == 0); }
    bool set() const { return !empty(); }

    stringbuf& operator =(const char* str) {
      if unlikely (!str) {
        reset();
        return *this;
      }
      reset(strlen(str)+1);
      *this << str;
      return *this;
    }

    bool operator ==(const stringbuf& s) {
      return (strcmp(*this, s) == 0);
    }

    bool operator !=(const stringbuf& s) {
      return (strcmp(*this, s) != 0);
    }

  public:
    char smallbuf[stringbuf_smallbufsize];
    char* buf;
    char* p;
    int length;
  };

  //
  // Inserters
  //

#define DefineIntegerInserter(T, signedtype) \
  static inline stringbuf& operator <<(stringbuf& os, const T v) { \
    char buf[128]; \
    format_integer(buf, sizeof(buf), ((signedtype) ? (W64s)v : (W64)v)); \
    return os << buf; \
  }

  DefineIntegerInserter(signed short, 1);
  DefineIntegerInserter(signed int, 0);
  DefineIntegerInserter(signed long, 0);
  DefineIntegerInserter(signed long long, 0);
  DefineIntegerInserter(unsigned short, 0);
  DefineIntegerInserter(unsigned int, 0);
  DefineIntegerInserter(unsigned long, 0);
  DefineIntegerInserter(unsigned long long, 0);

#define DefineFloatInserter(T, digits) \
  static inline stringbuf& operator <<(stringbuf& os, const T v) { \
    char buf[128]; \
    format_float(buf, sizeof(buf), v, digits); \
    return os << buf; \
  }

  DefineFloatInserter(float, 6);
  DefineFloatInserter(double, 16);

  static inline stringbuf& operator <<(stringbuf& os, const bool v) {
    return os << (int)v;
  }

#undef DefineInserter

  static inline stringbuf& operator <<(stringbuf& os, const stringbuf& sb) {
    os << ((char*)sb);
    return os;
  }

  template <class T>
  static inline stringbuf& operator <<(stringbuf& os, const T* v) {
    char buf[128];
    format_integer(buf, sizeof(buf), (W64)(Waddr)v, 0, FMT_SPECIAL, 16);
    return os << buf;
  }

  //
  // A much more intuitive syntax than STL provides:
  //
  template <class T>
  static inline stringbuf& operator ,(stringbuf& os, const T& v) {
    return os << v;
  }

  //
  // ostream class
  //
  static const char endl[] = "\n";
  static class iosflush { } flush;

#define OSTREAM_BUF_SIZE 256

  class odstream {
  protected:
    int fd;
    byte* buf;
    int bufsize;
    int tail;
    odstream* chain;
    W64 offset;
    bool ringbuf_mode;
    byte* ringbuf;
    int ringbuf_tail;
  public:
    bool close_on_destroy;

    odstream();

    bool open(const char* filename, bool append = false, int bufsize = 65536);

    bool open(int fd, int bufsize = 65536);

    void close();

    int setbuf(int bufsize);

    void setchain(odstream* chain);

    void set_ringbuf_mode(bool new_ringbuf_mode);

    ~odstream();

    odstream(int fd) {
      this->fd = -1;
      open(fd);
    }

    odstream(const char* filename, bool append = false, int bufsize = 65536) {
      this->fd = -1;
      open(filename, append, bufsize);
    }

    int write(const void* buf, int count);

    operator bool() const {
      return ok();
    }

    bool ok() const {
      return (fd >= 0);
    }

    int filehandle() const {
      return fd;
    }

    W64 seek(W64 pos, int whence = SEEK_SET);

    W64 where() const;

    void flush();
  };
  
  //
  // Manipulators
  //      
  static inline odstream& operator <<(odstream& os, const iosflush& v) {
    os.flush();
    return os;
  }

  template <typename T>
  static inline odstream& operator <<(odstream& os, const T& v) {
    os.write(&v, sizeof(T));
    return os;
  }

  template <typename T>
  static inline odstream& operator ,(odstream& os, const T& v) {
    return os << v;
  }

  class ostream: public odstream {
  public:
    ostream(): odstream() { }

    ostream(int fd): odstream(fd) { }

    ostream(const char* filename, bool append = false): odstream(filename, append) { }
  };
  
  //
  // Inserters
  //

  template <typename T>
  static inline ostream& operator <<(ostream& os, const T& v) {
    stringbuf sb;
    sb << v;
    os.write((char*)sb, sb.size());
    return os;
  }

  template <>
  static inline ostream& operator <<(ostream& os, const iosflush& v) {
    os.flush();
    return os;
  }

  template <>
  static inline ostream& operator <<(ostream& os, const char& v) {
    os.write(&v, sizeof(char));
    return os;
  }

  static inline ostream& operator <<(ostream& os, const char* v) {
    os.write(v, strlen(v));
    return os;
  }

  template <>
  static inline ostream& operator <<(ostream& os, const stringbuf& v) { stringbuf sb; sb << (char*)v; os.write((char*)sb, sb.size()); return os; }

  template <class T>
  static inline ostream& operator ,(ostream& os, const T& v) {
    return os << v;
  }

#define DeclareStringBufToStream(T) inline ostream& operator <<(ostream& os, const T& arg) { stringbuf sb; sb << arg; os << sb; return os; }

  // Print bits as a string:
  struct bitstring {
    W64 bits;
    int n;
    bool reverse;
    
    bitstring() { }
    
    bitstring(const W64 bits, const int n, bool reverse = false) {
      assert(n <= 64);
      this->bits = bits;
      this->n = n;
      this->reverse = reverse;
    }
  };

  stringbuf& operator <<(stringbuf& os, const bitstring& bs);

  DeclareStringBufToStream(bitstring);

  struct bitmaskstring {
    W64 bits;
    W64 mask;
    int n;
    bool reverse;
    
    bitmaskstring() { }
    
    bitmaskstring(const W64 bits, W64 mask, const int n, bool reverse = false) {
      assert(n <= 64);
      this->bits = bits;
      this->mask = mask;
      this->n = n;
      this->reverse = reverse;
    }
  };
  
  stringbuf& operator <<(stringbuf& os, const bitmaskstring& bs);

  DeclareStringBufToStream(bitmaskstring);

  struct hexstring {
    W64 value;
    int n;
    
    hexstring() { }
    
    hexstring(const W64 value, const int n) {
      this->value = value;
      this->n = n;
    }
  };
  
  stringbuf& operator <<(stringbuf& os, const hexstring& hs);

  DeclareStringBufToStream(hexstring);

  struct bytemaskstring {
    const byte* bytes;
    W64 mask;
    int n;
    int splitat;

    bytemaskstring() { }

    bytemaskstring(const byte* bytes, W64 mask, int n, int splitat = 16) {
      assert(n <= 64);
      this->bytes = bytes;
      this->mask = mask;
      this->n = n;
      this->splitat = splitat;
    }
  };
  
  stringbuf& operator <<(stringbuf& os, const bytemaskstring& bs);

  DeclareStringBufToStream(bytemaskstring);

  struct intstring {
    W64s value;
    int width;

    intstring() { }

    intstring(W64s value, int width) {
      this->value = value;
      this->width = width;
    }
  };

  stringbuf& operator <<(stringbuf& os, const intstring& is);

  DeclareStringBufToStream(intstring);

  struct floatstring {
    double value;
    int width;
    int precision;
    
    floatstring() { }

    floatstring(double value, int width = 0, int precision = 6) {
      this->value = value;
      this->width = width;
      this->precision = precision;
    }
  };
  
  stringbuf& operator <<(stringbuf& os, const floatstring& fs);

  DeclareStringBufToStream(floatstring);

  struct padstring {
    const char* value;
    int width;

    padstring() { }

    padstring(const char* value, int width) {
      this->value = value;
      this->width = width;
    }
  };

  stringbuf& operator <<(stringbuf& os, const padstring& s);

  DeclareStringBufToStream(padstring);

  struct substring {
    const char* str;
    int length;

    substring() { }

    substring(const char* str, int start, int length) {
      int r = strlen(str);
      this->length = min(length, r - start);
      this->str = str + min(start, r);
    }
  };

  stringbuf& operator <<(stringbuf& os, const substring& s);

  DeclareStringBufToStream(substring);

  //
  // String tools
  //
  int stringsubst(stringbuf& sb, const char* pattern, const char* find, const char* replace);
  int stringsubst(stringbuf& sb, const char* pattern, const char* find[], const char* replace[], int substcount);

  class readline;

  //
  // istream class
  //
  class idstream {
  protected:
    int fd;
    int error;
    int eos;
    int head;
    int tail;
    int bufsize;
    int bufused;
    W32 bufmask;
    W64 offset;
    byte* buf;

    int fillbuf();
    int readbuf(byte* dest, int bytes);
    int unread(int bytes);

    inline int addmod(int a, int b) { return ((a + b) & bufmask); }

    inline void reset() { fd = -1; error = 0; eos = 0; head = 0; tail = 0; buf = null; bufused = 0; bufsize = 0; bufmask = 0; offset = 0; close_on_destroy = 1; }

  public:
    bool close_on_destroy;

    idstream() { reset(); }

    bool open(const char* filename, int bufsize = 65536);

    bool open(int fd, int bufsize = 65536);

    int setbuf(int bufsize);

    idstream(const char* filename) {
      reset();
      open(filename);
    }

    idstream(int fd) {
      reset();
      open(fd);
    }
    
    void close();

    ~idstream() {
      if likely (close_on_destroy) close();
    }

    bool ok() const { return (!error); }
    operator bool() { return ok(); }

    int read(void* data, int count);

    int filehandle() const { return fd; }

    int readline(char* v, int len);
    int readline(stringbuf& sb);

    bool getc(char& c);

    W64 seek(W64 pos, int whence = SEEK_SET);
    W64 where() const;
    W64 size() const;

    void* mmap(long long size);
  };

  template <typename T>
  inline idstream& operator >>(idstream& is, T& v) { 
    is.read(&v, sizeof(T)); 
    return is; 
  }

  template <typename T>
  inline idstream& operator ,(idstream& is, T& v) {
    return is >> v;
  }

  class istream: public idstream {
  public:
    istream(): idstream() { }
    istream(const char* filename): idstream(filename) { }
    istream(int fd): idstream(fd) { }
  };

  class readline { 
  public:
    readline(char* p, size_t l): buf(p), len(l) { }
    char* buf;
    size_t len;
  };

  //inline istream& operator ,(istream& is, const readline& v) { return is >> v; }

  static inline istream& operator >>(istream& is, const readline& v) {
    is.readline(v.buf, v.len);
    return is;
  }

  static inline istream& operator >>(istream& is, stringbuf& sb) {
    is.readline(sb);
    return is;
  }

  //
  // Global streams:
  //
  extern istream cin;
  extern ostream cout;
  extern ostream cerr;

  template <typename T>
  static inline T* renew(T* p, size_t oldcount, size_t newcount) {
    if unlikely (newcount <= oldcount) return p;

    T* pp = new T[newcount];

    if unlikely (!p) assert(oldcount == 0);

    if likely (p) {
      memcpy(pp, p, oldcount * sizeof(T));
      delete[] p;
    }

    return pp;
  }


  /*
   * Simple array class with optional bounds checking
   */  
  template <typename T, int size>
  struct array {
  public:
    array() { }
    static const int length = size;

    T data[size];
    const T& operator [](int i) const { 
#ifdef CHECK_BOUNDS
      assert((i >= 0) && (i < size));
#endif
      return data[i]; 
    }

    T& operator [](int i) { 
#ifdef CHECK_BOUNDS
      assert((i >= 0) && (i < size));
#endif
      return data[i]; 
    }

    void clear() {
      foreach(i, size) data[i] = T();
    }

    void fill(const T& v) {
      foreach(i, size) data[i] = v;
    }
  };

  template <typename T, int size>
  struct stack {
  public:
    int sp;
    static const int length = size;
    T data[size];

    void reset() { sp = 0; }

    stack() { reset(); }

    const T& operator [](int i) const { 
#ifdef CHECK_BOUNDS
      assert(((sp-1) - i) >= 0);
#endif
      return data[(sp-1) - i]; 
    }

    T& operator [](int i) { 
#ifdef CHECK_BOUNDS
      assert(((sp-1) - i) >= 0);
#endif
      return data[(sp-1) - i]; 
    }

    T& push() {
#ifdef CHECK_BOUNDS
      assert(sp < size);
#endif
      T& v = data[sp++];
      return v;
    }

    T& push(const T& v) {
      T& r = push();
      r = v;
      return r;
    }

    T& pop() {
#ifdef CHECK_BOUNDS
      assert(sp > 0);
#endif
      T& v = data[--sp];
      return v;
    } 

    int count() const { return sp; }
    bool empty() const { return (count() == 0); }
    bool full() const { return (count() == size); }
  };

  template <typename T, int size>
  static inline ostream& operator <<(ostream& os, const stack<T, size>& st) {
    foreach (i, st.count()) { os << ((i) ? " " : ""), st[i]; }
    return os;
  }

  template <typename T, int size>
  static inline ostream& operator <<(ostream& os, const array<T, size>& v) {
    os << "Array of ", size, " elements:", endl;
    for (int i = 0; i < size; i++) {
      os << "  [", i, "]: ", v[i], endl;
    }
    return os;
  }

  /*
   * Simple STL-like dynamic array class.
   */
  template <class T>
  class dynarray {
  protected:
  public:
    T* data;
    int length;
    int reserved;
    int granularity;
    
  public:
    inline T& operator [](int i) { return data[i]; }
    inline T operator [](int i) const { return data[i]; }

    operator T*() const { return data; }

    // NOTE: g *must* be a power of two!
    dynarray() {
      length = reserved = 0;
      granularity = 16;
      data = null;
    }
    
    dynarray(int initcap, int g = 16) {
      length = 0;
      reserved = 0;
      granularity = g;
      data = null;
      reserve(initcap);
    }
    
    ~dynarray() {
      delete data;
      data = null;
      length = 0;
      reserved = 0;
    }
    
    inline int capacity() const { return reserved; }
    inline bool empty() const { return (length == 0); }
    inline void clear() { resize(0); }
    inline int size() const { return length; }
    inline int count() const { return length; }
    
    void push(const T& obj) {
      T& pushed = push();
      pushed = obj;
    }
    
    T& push() {
      reserve(length + 1);
      length++;
      return data[length-1];
    }

    T& pop() {
      length--;
      return data[length];
    }   

    void resize(int newsize) {
      if likely (newsize > length) reserve(newsize);
      length = newsize;
    }

    void resize(int newsize, const T& emptyvalue) {
      int oldlength = length;
      resize(newsize);
      if unlikely (newsize <= oldlength) return;
      for (int i = oldlength; i < reserved; i++) { data[i] = emptyvalue; }
    }
    
    void reserve(int newsize) {
      if unlikely (newsize <= reserved) return;
      newsize = (newsize + (granularity-1)) & ~(granularity-1);
      data = renew(data, length, newsize);
      reserved = newsize;
    }

    void fill(const T& value) {
      foreach (i, length) {
        data[i] = value;
      }
    }

    void trim() {
      //++MTY FIXME realloc is not always available!
      //reserved = count;
      //data = (T*)realloc(data, count * sizeof(T));
      //data = renew(data, count, newsize);
    }

    // Only works with specialization for character arrays:
    char* tokenize(char* string, const char* seplist) { abort(); }
  };

  template <>
  char* dynarray<char*>::tokenize(char* string, const char* seplist);

  template <class T>
  static inline ostream& operator <<(ostream& os, const dynarray<T>& v) {
    os << "Array of ", v.size(), " elements (", v.capacity(), " reserved): ", endl;
    for (int i = 0; i < v.size(); i++) {
      os << "  [", i, "]: ", v[i], endl;
    }
    return os;
  }

  /*
   * Simple type-safe temporary buffer with overflow protection.
   */
  template <class T>
  class tempbuf {
  protected:
  public:
    T* data;
    T* endp;
    T* base;

  public:
    inline T& operator [](int i) { return base[i]; }
    inline T operator [](int i) const { return base[i]; }
    inline operator T*() { return data; }
    T& operator ->() { return *data; }

    inline operator const T&() { return *data; }

    inline const T& operator =(const T& v) { *data = v; return *this; }
    //inline const T& operator +=(const T& v) { *data++ = v; return v; }
    inline T* operator +=(int n) { return (data += n); }
    inline T* operator -=(int n) { return (data -= n); }

    inline T* operator ++() { return ++data; }
    inline T* operator ++(int postfix) { return data++; }

    inline T* operator --() { return --data; }
    inline T* operator --(int postfix) { return data--; }

    tempbuf() {
      data = endp = base = NULL;
    }

    void free() {
      if unlikely (!base)
        return;
      assert(data <= endp);
      munmap(base, ((char*)endp - (char*)base) + PAGE_SIZE);
      base = endp = data = NULL;
    }

    ~tempbuf() {
      free();
    }

    void resize(int size) {
      free();

      int realsize = ceil(size * sizeof(T), PAGE_SIZE);
      
      base = (T*)sys_mmap(NULL, realsize + 2*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 0, 0);
      assert(base != MAP_FAILED);

      base = (T*)((char*)base + PAGE_SIZE);
      endp = (T*)((char*)base + realsize);

      assert(sys_mprotect(((char*)base) - PAGE_SIZE, PAGE_SIZE, PROT_NONE) == 0);
      assert(sys_mprotect((char*)endp, PAGE_SIZE, PROT_NONE) == 0);
      data = base;
    }

    tempbuf(int size) {
      resize(size);
    }

    inline bool empty() const { return (data == base); }
    inline void clear() { data = base; }
    inline int capacity() const { return (endp - base); }
    inline int setcount(int newcount) {
      data = base + newcount; 
      return newcount;
    }
    inline int size() const { return (data - base); }
    inline int count() const { return (data - base); }
    inline operator bool() const { return empty(); }

    inline T* start() const { return base; }
    inline T* end() const { return data; }
    inline T* dup() const {
      T* t = new T[count()];
      memcpy(t, base, sizeof(T) * count());
      return t;
    }

    T* reserve(int n = 1) {
      T* p = data;
      data = data + n;
      if likely (data <= end)
        return p;

      data = p;
      return NULL;
    }

    const T& push(const T& obj) {
      *data++ = obj;
      return obj;
    }

    T& push() {
      return *data++;
    }

    T& pop() {
      return *data--;
    }
  };

  template <class T> static inline const T& operator <<(tempbuf<T>& buf, const T& v) { return buf.push(v); }
  template <class T> static inline const T& operator >>(tempbuf<T>& buf, T& v) { return (v = buf.pop()); }

  /*
   * CRC32
   */
  struct CRC32 {
    static const W32 crctable[256];
    W32 crc;
    
    inline W32 update(byte value) {
      crc = crctable[(crc ^ value) & 0xff] ^ (crc >> 8);
      return crc;
    }

    inline W32 update(byte* data, int count) {
      foreach (i, count) {
        update(data[i]);
      }
      return crc;
    }

    CRC32() {
      reset();
    }
    
    CRC32(W32 newcrc) {
      reset(newcrc);
    }
    
    inline void reset(W32 newcrc = 0xffffffff) {
      crc = newcrc;
    }

    operator W32() const {
      return crc;
    }
  };

  template <typename T>
  static inline CRC32& operator <<(CRC32& crc, const T& t) {
    crc.update((byte*)&t, sizeof(T));
    return crc;
  }

  template <class T>
  static inline CRC32& operator ,(CRC32& crc, const T& v) {
    return crc << v;
  }

  //
  // selflistlink class
  // Double linked list without pointer: useful as root
  // of inheritance hierarchy for another class to save
  // space, since object pointed to is implied
  //
  class selflistlink {
  public:
    selflistlink* next;
    selflistlink* prev;
  public:
    void reset() { next = null; prev = null; }
    selflistlink() { reset(); }

    selflistlink* unlink() {
      if likely (prev) prev->next = next;
      if likely (next) next->prev = prev;
      prev = null;
      next = null;  
      return this;
    }

    selflistlink* replacewith(selflistlink* newlink) {
      if likely (prev) prev->next = newlink;
      if likely (next) next->prev = newlink;
      newlink->prev = prev;
      newlink->next = next;
      return newlink;
    }

    void addto(selflistlink*& root) {
      // THIS <-> root <-> a <-> b <-> c
      this->prev = (selflistlink*)&root;
      this->next = root;
      if likely (root) root->prev = this;
      // Do not touch root->next since it might not even exist
      root = this;
    }

    bool linked() const {
      return (next || prev);
    }

    bool unlinked() const {
      return !linked();
    }
  };

  static inline ostream& operator <<(ostream& os, const selflistlink& link) {
    return os << "[prev ", link.prev, ", next ", link.next, "]";
  }

  class selfqueuelink {
  public:
    selfqueuelink* next;
    selfqueuelink* prev;
  public:
    void reset() { next = this; prev = this; }
    selfqueuelink() { }

    selfqueuelink& unlink() {
      // No effect if next = prev = this (i.e., unlinked)
      next->prev = prev;
      prev->next = next;
      prev = this;
      next = this;
      return *this;
    }

    void addhead(selfqueuelink& root) {
      addlink(&root, root.next);
    }

    void addhead(selfqueuelink* root) {
      addhead(*root);
    }

    void addto(selfqueuelink& root) {
      addhead(root);
    }

    void addto(selfqueuelink* root) {
      addto(*root);
    }

    void addtail(selfqueuelink& root) {
      addlink(root.prev, &root);
    }

    void addtail(selfqueuelink* root) {
      addtail(*root);
    }

    selfqueuelink* removehead() {
      if unlikely (empty()) return null;
      selfqueuelink* link = next;
      link->unlink();
      return link;
    }

    selfqueuelink* removetail() {
      if unlikely (empty()) return null;
      selfqueuelink* link = prev;
      link->unlink();
      return link;
    }

    selfqueuelink* head() const {
      return next;
    }

    selfqueuelink* tail() const {
      return prev;
    }

    bool empty() const {
      return (next == this);
    }

    bool unlinked() const {
      return ((!prev && !next) || ((prev == this) && (next == this)));
    }

    bool linked() const {
      return !unlinked();
    }

    operator bool() const { return (!empty()); }

  protected:
    void addlink(selfqueuelink* prev, selfqueuelink* next) {
      next->prev = this;
      this->next = next;
      this->prev = prev;
      prev->next = this;      
    }
  };

  //
  // Default link manager for objects in which the
  // very first member (or superclass) is selflistlink.
  //
  template <typename T>
  struct ObjectLinkManager {
    static inline T* objof(selflistlink* link) { return (T*)link; }
    static inline selflistlink* linkof(T* obj) { return (selflistlink*)obj; }
    //
    // Example:
    //
    // T* objof(selflistlink* link) {
    //   return baseof(T, hashlink, link); // a.k.a. (T*)((byte*)link) - offsetof(T, hashlink);
    // }
    //
    // selflistlink* linkof(T* obj) {
    //   return &obj->link;
    // }
    //
  };

  template <class T>
  class queuelink {
  public:
    queuelink<T>* next;
    queuelink<T>* prev;
    T* data;
  public:
    void reset() { next = this; prev = this; data = null; }
    queuelink() { reset(); }
    queuelink(const T& t) { reset(); data = &t; }
    queuelink(const T* t) { reset(); data = t; }
    queuelink<T>& operator ()(T* t) { reset(); data = t; return *this; }

    T& unlink() {
      // No effect if next = prev = this (i.e., unlinked)
      next->prev = prev;
      prev->next = next;
      prev = this;
      next = this;
      return *data;
    }

    void add_to_head(queuelink<T>& root) {
      addlink(&root, root.next);
    }

    void addto(queuelink<T>& root) {
      addhead(root);
    }

    void add_to_tail(queuelink<T>& root) {
      addlink(root.prev, &root);
    }

    queuelink<T>* remove_head() {
      queuelink<T>* link = next;
      link->unlink();
      return link;
    }

    queuelink<T>* remove_tail() {
      queuelink<T>* link = prev;
      link->unlink();
      return link;
    }

    queuelink<T>* head() const {
      return next;
    }

    queuelink<T>* tail() const {
      return prev;
    }

    bool empty() const {
      return (next == this);
    }

    bool unlinked() const {
      return ((!prev && !next) || ((prev == this) && (next == this)));
    }

    bool linked() const {
      return !unlinked();
    }

    operator bool() const { return (!empty()); }

    T* operator->() const { return data; }
    operator T*() const { return data; }
    operator T&() const { return *data; }

  protected:
    void addlink(queuelink<T>* prev, queuelink<T>* next) {
      next->prev = this;
      this->next = next;
      this->prev = prev;
      prev->next = this;      
    }
  };

  //
  // Index References (indexrefs) work exactly like pointers but always
  // index into a specific structure. This saves considerable space and
  // can allow aliasing optimizations not possible with pointers.
  //

  template <typename T, typename P = W32, Waddr base = 0, int granularity = 1>
  struct shortptr {
    P p;

    shortptr() { }

    shortptr(const T& obj) {
      *this = obj;
    }

    shortptr(const T* obj) {
      *this = obj;
    }

    shortptr<T, P, base, granularity>& operator =(const T& obj) { 
      index = obj.index();
      return *this;
    }

    shortptr<T, P, base, granularity>& operator =(const T* obj) {
      p = (P)((((Waddr)obj) - base) / granularity);
      return *this;
    }

    T* get() const {
      return (T*)((p * granularity) + base);
    }

    T* operator ->() const {
      return get();
    }
  
    T& operator *() const {
      return *get();
    }

    operator T*() const { return get(); }
  };

  template <typename T, typename P, Waddr base, int granularity>
  static inline stringbuf& operator <<(stringbuf& os, const shortptr<T, P, base, granularity>& sp) {
    return os << (T*)sp;
  }
  
  // null allowed:
  template <typename T>
  struct indexrefnull {
    W16s index;

    indexrefnull() { }

    indexrefnull<T>& operator =(const T& obj) { 
      index = (&obj) ? obj.index() : -1;
      return *this;
    }

    indexrefnull<T>& operator =(const T* obj) {
      index = (obj) ? obj->index() : -1;
      return *this;
    }

    indexrefnull<T>& operator =(int i) {
      index = i;
      return *this;
    }

    T* operator ->() const {
      return (index >= 0) ? &(get(index)) : null;
    }

    T& operator *() const {
      return (index >= 0) ? get(index) : *(T*)null;
    }

    operator T*() const { return &(get(index)); }

    T& get(int index) const;
  };

  template <typename T>
  struct indexref {
    W16s index;

    indexref() { }

    indexref<T>& operator =(const T& obj) { 
      index = obj.index();
      return *this;
    }

    indexref<T>& operator =(const T* obj) {
      index = obj->index();
      return *this;
    }

    indexref<T>& operator =(int i) {
      index = i;
      return *this;
    }

    T* operator ->() const {
      return &(get(index));
    }

    T& operator *() const {
      return get(index);
    }

    operator T*() const { return &(get(index)); }

    T& get(int index) const;
  };

#define BITS_PER_WORD ((sizeof(unsigned long) == 8) ? 64 : 32)
#define BITVEC_WORDS(n) ((n) < 1 ? 0 : ((n) + BITS_PER_WORD - 1)/BITS_PER_WORD)

#ifdef __x86_64__
#define __builtin_ctzl(t) lsbindex64(t)
#define __builtin_clzl(t) msbindex64(t)
#else
#define __builtin_ctzl(t) lsbindex32(t)
#define __builtin_clzl(t) msbindex32(t)
#endif

  template<size_t N>
  struct bitvecbase {
    typedef unsigned long T;

    T w[N];

    bitvecbase() { resetop(); }

    bitvecbase(const bitvecbase<N>& vec) { foreach (i, N) w[i] = vec.w[i]; }

    bitvecbase(unsigned long long val) {
      resetop();
      w[0] = val;
    }

    static size_t wordof(size_t index) { return index / BITS_PER_WORD; }
    static size_t byteof(size_t index) { return (index % BITS_PER_WORD) / __CHAR_BIT__; }
    static size_t bitof(size_t index) { return index % BITS_PER_WORD; }
    static T maskof(size_t index) { return (static_cast<T>(1)) << bitof(index); }

    T& getword(size_t index) { return w[wordof(index)]; }
    T getword(size_t index) const { return w[wordof(index)]; }
    T& hiword() { return w[N - 1]; }
    T hiword() const { return w[N - 1]; }

    void andop(const bitvecbase<N>& x) {
      for (size_t i = 0; i < N; i++) w[i] &= x.w[i];
    }

    void orop(const bitvecbase<N>& x) {
      foreach (i, N) w[i] |= x.w[i];
    }

    void xorop(const bitvecbase<N>& x) {
      foreach (i, N) w[i] ^= x.w[i];
    }

    void shiftleftop(size_t shift) {
      if likely (shift) {
        const size_t wshift = shift / BITS_PER_WORD;
        const size_t offset = shift % BITS_PER_WORD;
    
        if unlikely (offset == 0) {
          for (size_t i = N - 1; i >= wshift; --i) { w[i] = w[i - wshift]; }
        } else {
          const size_t suboffset = BITS_PER_WORD - offset;
          for (size_t i = N - 1; i > wshift; --i) { w[i] = (w[i - wshift] << offset) | (w[i - wshift - 1] >> suboffset); }
          w[wshift] = w[0] << offset;
        }

        // memset(w, static_cast<T>(0), wshift);
        foreach (i, wshift) { w[i] = 0; }
      }
    }

    void shiftrightop(size_t shift) {
      if likely (shift) {
        const size_t wshift = shift / BITS_PER_WORD;
        const size_t offset = shift % BITS_PER_WORD;
        const size_t limit = N - wshift - 1;
      
        if unlikely (offset == 0) {
          for (size_t i = 0; i <= limit; ++i) { w[i] = w[i + wshift]; }
        } else {
          const size_t suboffset = BITS_PER_WORD - offset;
          for (size_t i = 0; i < limit; ++i) { w[i] = (w[i + wshift] >> offset) | (w[i + wshift + 1] << suboffset); }
          w[limit] = w[N-1] >> offset;
        }

        //memset(w + limit + 1, static_cast<T>(0), N - (limit + 1));
        foreach (i, N - (limit + 1)) { w[limit + 1 + i] = 0; }
      }
    }

    void maskop(size_t count) {
      w[wordof(count)] &= bitmask(bitof(count));

      for (size_t i = wordof(count)+1; i < N; i++) {
        w[i] = 0;
      }
    }

    void invertop() {
      foreach (i, N) w[i] = ~w[i];
    }

    void setallop() {
      foreach (i, N) w[i] = ~static_cast<T>(0);
    }

    void resetop() { memset(w, 0, N * sizeof(T)); }

    bool equalop(const bitvecbase<N>& x) const {
      T t = 0;
      foreach (i, N) { t |= (w[i] ^ x.w[i]); }
      return (t == 0);
    }

    bool nonzeroop() const {
      T t = 0;
      foreach (i, N) { t |= w[i]; }
      return (t != 0);
    }

    size_t popcountop() const {
      size_t result = 0;

      foreach (i, N)
        result += popcount64(w[i]);

      return result;
    }

    unsigned long integerop() const { return w[0]; }

    void insertop(size_t i, size_t n, T v) {
      T& lw = w[wordof(i)];
      T lm = (bitmask(n) << bitof(i));
      lw = (lw & ~lm) | ((v << i) & lm);

      if unlikely ((bitof(i) + n) > BITS_PER_WORD) {
        T& hw = w[wordof(i+1)];
        T hm = (bitmask(n) >> (BITS_PER_WORD - bitof(i)));
        hw = (hw & ~hm) | ((v >> (BITS_PER_WORD - bitof(i))) & hm);
      }
    }

    void accumop(size_t i, size_t n, T v) {
      w[wordof(i)] |= (v << i);

      if unlikely ((bitof(i) + n) > BITS_PER_WORD)
        w[wordof(i+1)] |= (v >> (BITS_PER_WORD - bitof(i)));
    }

    // find index of first "1" bit starting from low end
    size_t lsbop(size_t notfound) const {
      foreach (i, N) {
        T t = w[i];
        if likely (t) return (i * BITS_PER_WORD) + __builtin_ctzl(t);
      }
      return notfound;
    }

    // find index of last "1" bit starting from high end
    size_t msbop(size_t notfound) const {
      for (int i = N-1; i >= 0; i--) {
        T t = w[i];
        if likely (t) return (i * BITS_PER_WORD) + __builtin_clzl(t);
      }
      return notfound;
    }

    // assume value is nonzero
    size_t lsbop() const {
      return lsbop(0);
    }

    // assume value is nonzero
    size_t msbop() const {
      return msbop(0);
    }

    // find the next "on" bit that follows "prev"

    size_t nextlsbop(size_t prev, size_t notfound) const {
      // make bound inclusive
      ++prev;

      // check out of bounds
      if unlikely (prev >= N * BITS_PER_WORD)
        return notfound;

      // search first word
      size_t i = wordof(prev);
      T t = w[i];

      // mask off bits below bound
      t &= (~static_cast<T>(0)) << bitof(prev);

      if likely (t != static_cast<T>(0))
        return (i * BITS_PER_WORD) + __builtin_ctzl(t);

      // check subsequent words
      i++;
      for ( ; i < N; i++ ) {
        t = w[i];
        if likely (t != static_cast<T>(0))
          return (i * BITS_PER_WORD) + __builtin_ctzl(t);
      }
      // not found, so return an indication of failure.
      return notfound;
    }
  };

  template <>
  struct bitvecbase<1> {
    typedef unsigned long T;
    T w;

    bitvecbase(void): w(0) {}
    bitvecbase(unsigned long long val): w(val) {}

    static size_t wordof(size_t index) { return index / BITS_PER_WORD; }
    static size_t byteof(size_t index) { return (index % BITS_PER_WORD) / __CHAR_BIT__; }
    static size_t bitof(size_t index) { return index % BITS_PER_WORD; }
    static T maskof(size_t index) { return (static_cast<T>(1)) << bitof(index); }

    T& getword(size_t) { return w; }
    T getword(size_t) const { return w; }
    T& hiword() { return w; }
    T hiword() const { return w; }
    void andop(const bitvecbase<1>& x) { w &= x.w; }
    void orop(const bitvecbase<1>& x)  { w |= x.w; }
    void xorop(const bitvecbase<1>& x) { w ^= x.w; }
    void shiftleftop(size_t __shift) { w <<= __shift; }
    void shiftrightop(size_t __shift) { w >>= __shift; }
    void invertop() { w = ~w; }
    void setallop() { w = ~static_cast<T>(0); }
    void resetop() { w = 0; }
    bool equalop(const bitvecbase<1>& x) const { return w == x.w; }
    bool nonzeroop() const { return (!!w); }
    size_t popcountop() const { return popcount64(w); }
    unsigned long integerop() const { return w; }
    size_t lsbop() const { return __builtin_ctzl(w); }
    size_t msbop() const { return __builtin_clzl(w); }
    size_t lsbop(size_t notfound) const { return (w) ? __builtin_ctzl(w) : notfound; }
    size_t msbop(size_t notfound) const { return (w) ? __builtin_clzl(w) : notfound; }
    void maskop(size_t count) { w &= bitmask(bitof(count)); }

    void insertop(size_t i, size_t n, T v) {
      T m = (bitmask(n) << bitof(i));
      w = (w & ~m) | ((v << i) & m);
    }

    void accumop(size_t i, size_t n, T v) {
      w |= (v << i);
    }

    // find the next "on" bit that follows "prev"
    size_t nextlsbop(size_t __prev, size_t notfound) const {
      ++__prev;
      if unlikely (__prev >= ((size_t) BITS_PER_WORD))
        return notfound;

      T x = w >> __prev;
      if likely (x != 0)
        return __builtin_ctzl(x) + __prev;
      else
        return notfound;
    }
  };

  template <>
  struct bitvecbase<0> {
    typedef unsigned long T;

    bitvecbase() { }
    bitvecbase(unsigned long long) { }

    static size_t wordof(size_t index) { return index / BITS_PER_WORD; }
    static size_t byteof(size_t index) { return (index % BITS_PER_WORD) / __CHAR_BIT__; }
    static size_t bitof(size_t index) { return index % BITS_PER_WORD; }
    static T maskof(size_t index) { return (static_cast<T>(1)) << bitof(index); }

    T& getword(size_t) const { return *new T;  }
    T hiword() const { return 0; }
    void andop(const bitvecbase<0>&) { }
    void orop(const bitvecbase<0>&)  { }
    void xorop(const bitvecbase<0>&) { }
    void shiftleftop(size_t) { }
    void shiftrightop(size_t) { }
    void invertop() { }
    void setallop() { }
    void resetop() { }
    bool equalop(const bitvecbase<0>&) const { return true; }
    bool nonzeroop() const { return false; }
    size_t popcountop() const { return 0; }
    void maskop(size_t count) { }
    void accumop(int i, int n, T v) { }
    void insertop(int i, int n, T v) { }
    unsigned long integerop() const { return 0; }
    size_t lsbop() const { return 0; }
    size_t msbop() const { return 0; }
    size_t lsbop(size_t notfound) const { return notfound; }
    size_t msbop(size_t notfound) const { return notfound; }
    size_t nextlsbop(size_t, size_t) const { return 0; }
  };

  // Helper class to zero out the unused high-order bits in the highest word.
  template <size_t extrabits>
  struct bitvec_sanitizer {
    static void sanitize(unsigned long& val) { 
      val &= ~((~static_cast<unsigned long>(0)) << extrabits); 
    }
  };

  template <>
  struct bitvec_sanitizer<0> { 
    static void sanitize(unsigned long) { }
  };

  template<size_t N>
  class bitvec: private bitvecbase<BITVEC_WORDS(N)> {
  private:
    typedef bitvecbase<BITVEC_WORDS(N)> base_t;
    typedef unsigned long T;

    bitvec<N>& sanitize() {
      bitvec_sanitizer<N % BITS_PER_WORD>::sanitize(this->hiword());
      return *this;
    }

  public:
    class reference {
      friend class bitvec;

      T *wp;
      T bpos;

      // left undefined
      reference();

    public:
      inline reference(bitvec& __b, size_t index) {
        wp = &__b.getword(index);
        bpos = base_t::bitof(index);
      }

      ~reference() { }

      // For b[i] = x;
      inline reference& operator =(bool x) {
        // Optimized, x86-specific way:
        if (isconst(x) & isconst(bpos)) {
          // Most efficient to just AND/OR with a constant mask: 
          *wp = ((x) ? (*wp | base_t::maskof(bpos)) : (*wp & (~base_t::maskof(bpos))));
        } else {
          // Use bit set or bit reset x86 insns:
          T b1 = x86_bts(*wp, bpos);
          T b0 = x86_btr(*wp, bpos);
          *wp = (x) ? b1 : b0;
        }
        /*
        // Optimized, branch free generic way:
        *wp = (__builtin_constant_p(x)) ? 
          ((x) ? (*wp | base_t::maskof(bpos)) : (*wp & (~base_t::maskof(bpos)))) :
          (((*wp) & (~base_t::maskof(bpos))) | ((static_cast<T>((x != 0))) << base_t::bitof(bpos)));
        */
        return *this;
      }

      // For b[i] = b[j];
      inline reference& operator =(const reference& j) {
        // Optimized, x86-specific way:
        // Use bit set or bit reset x86 insns:
        T b1 = x86_bts(*wp, bpos);
        T b0 = x86_btr(*wp, bpos);
        *wp = (x86_bt(*j.wp, j.bpos)) ? b1 : b0;
        /*
        // Optimized, branch free generic way:
        *wp = (__builtin_constant_p(x)) ? 
          (((*(j.wp) & base_t::maskof(j.bpos))) ? (*wp | base_t::maskof(bpos)) : (*wp & (~base_t::maskof(bpos)))) :
          (((*wp) & (~base_t::maskof(bpos))) | ((static_cast<T>((((*(j.wp) & base_t::maskof(j.bpos))) != 0))) << base_t::bitof(bpos)));
        */
        return *this;
      }

      // For b[i] = 1;
      inline reference& operator++(int postfixdummy) {
        if (isconst(bpos))
          *wp |= base_t::maskof(bpos);
        else *wp = x86_bts(*wp, bpos);
        return *this;
      }

      // For b[i] = 0;
      inline reference& operator--(int postfixdummy) {
        if (isconst(bpos))
          *wp &= ~base_t::maskof(bpos);
        else *wp = x86_btr(*wp, bpos);
        return *this;
      }

      // Flips the bit
      bool operator~() const {
        //return (*(wp) & base_t::maskof(bpos)) == 0;
        return x86_btn(*wp, bpos);
      }

      // For x = b[i];
      inline operator bool() const {
        return x86_bt(*wp, bpos);
      }

      // For b[i].invert();
      inline reference& invert() {
        *wp = x86_btc(*wp, bpos);
        return *this;
      }

      bool testset() { return x86_test_bts(*wp, bpos); }
      bool testclear() { return x86_test_btr(*wp, bpos); }
      bool testinv() { return x86_test_btc(*wp, bpos); }

      bool atomicset() { return x86_locked_bts(*wp, bpos); }
      bool atomicclear() { return x86_locked_btr(*wp, bpos); }
      bool atomicinv() { return x86_locked_btc(*wp, bpos); }
    };

    friend class reference;

    bitvec() { }

    bitvec(const bitvec<N>& vec): base_t(vec) { }

    bitvec(unsigned long long val): base_t(val) { sanitize(); }

    bitvec<N>& operator&=(const bitvec<N>& rhs) {
      this->andop(rhs);
      return *this;
    }

    bitvec<N>& operator|=(const bitvec<N>& rhs) {
      this->orop(rhs);
      return *this;
    }

    bitvec<N>& operator^=(const bitvec<N>& rhs) {
      this->xorop(rhs);
      return *this;
    }

    bitvec<N>& operator <<=(int index) {
      if likely (index < N) {
        this->shiftleftop(index);
        this->sanitize();
      } else this->resetop();
      return *this;
    }

    bitvec<N>& operator>>=(int index) {
      if likely (index < N) {
        this->shiftrightop(index);
        this->sanitize();
      } else this->resetop();
      return *this;
    }

    bitvec<N>& set(size_t index) {
      this->getword(index) |= base_t::maskof(index);
      return *this;
    }

    bitvec<N>& reset(size_t index) {
      this->getword(index) &= ~base_t::maskof(index);
      return *this;
    }

    bitvec<N>& assign(size_t index, int val) {
      if (val)
        this->getword(index) |= base_t::maskof(index);
      else
        this->getword(index) &= ~base_t::maskof(index);
      return *this;
    }

    bitvec<N>& invert(size_t index) {
      this->getword(index) ^= base_t::maskof(index);
      return *this;
    }

    bool test(size_t index) const {
      return (this->getword(index) & base_t::maskof(index)) != static_cast<T>(0);
    }

    bitvec<N>& setall() {
      this->setallop();
      this->sanitize();
      return *this;
    }

    bitvec<N>& reset() {
      this->resetop();
      return *this;
    }

    bitvec<N>& operator++(int postfixdummy) { return setall(); }
    bitvec<N>& operator--(int postfixdummy) { return reset(); }

    bitvec<N>& invert() {
      this->invertop();
      this->sanitize();
      return *this;
    }

    bitvec<N> operator ~() const { return bitvec<N>(*this).invert(); }

    reference operator [](size_t index) { return reference(*this, index); }

    bool operator [](size_t index) const { return test(index); }

    bool operator *() const { return nonzero(); }
    bool operator !() const { return iszero(); }

    unsigned long integer() const { return this->integerop(); }

    // Returns the number of bits which are set.
    size_t popcount() const { return this->popcountop(); }

    // Returns the total number of bits.
    size_t size() const { return N; }

    bool operator ==(const bitvec<N>& rhs) const { return this->equalop(rhs); }
    bool operator !=(const bitvec<N>& rhs) const { return !this->equalop(rhs); }
    bool nonzero() const { return this->nonzeroop(); }
    bool iszero() const { return !this->nonzeroop(); }
    bool allset() const { return (~(*this)).iszero(); }
    bool all() const { return allset(N); }

    bitvec<N> operator <<(size_t shift) const { return bitvec<N>(*this) <<= shift; }

    bitvec<N> operator >>(size_t shift) const { return bitvec<N>(*this) >>= shift; }

    size_t lsb() const { return this->lsbop(); }
    size_t msb() const { return this->msbop(); }
    size_t lsb(int notfound) const { return this->lsbop(notfound); }
    size_t msb(int notfound) const { return this->msbop(notfound); }
    size_t nextlsb(size_t prev, int notfound = -1) const { return this->nextlsbop(prev, notfound); }

    bitvec<N> insert(int i, int n, T v) const {
      bitvec<N> b(*this);
      b.insertop(i, n, v);
      b.sanitize();
      return b;
    }

    bitvec<N> accum(size_t i, size_t n, T v) const {
      bitvec<N> b(*this);
      b.accumop(i, n, v);
      return b;
    }

    bitvec<N> mask(size_t count) const { 
      bitvec<N> b(*this);
      b.maskop(count);
      return b;
    }

    bitvec<N> operator %(size_t b) const {
      return mask(b);
    }
 
    bitvec<N> extract(size_t index, size_t count) const {
      return (bitvec<N>(*this) >> index) % count;
    }

    bitvec<N> operator ()(size_t index, size_t count) const {
      return extract(index, count);
    }

    bitvec<N> operator &(const bitvec<N>& y) const {
      return bitvec<N>(*this) &= y;
    }

    bitvec<N> operator |(const bitvec<N>& y) const {
      return bitvec<N>(*this) |= y;
    }

    bitvec<N> operator ^(const bitvec<N>& y) const {
      return bitvec<N>(*this) ^= y;
    }

    bitvec<N> remove(size_t index, size_t count = 1) {
      return (((*this) >> (index + count)) << index) | ((*this) % index);
    }

    template <int S> bitvec<S> subset(int i) const {
      return bitvec<S>((*this) >> i);
    }

    // This introduces ambiguity:
    // explicit operator unsigned long long() const { return integer(); }

    ostream& print(ostream& os) const {
      foreach (i, N) {
        os << (((*this)[i]) ? '1' : '0');
      }
      return os;
    }

    stringbuf& print(stringbuf& sb) const {
      foreach (i, N) {
        sb << (((*this)[i]) ? '1' : '0');
      }
      return sb;
    }

    ostream& printhl(ostream& os) const {
      for (int i = N-1; i >= 0; i--) {
        os << (((*this)[i]) ? '1' : '0');
      }
      return os;
    }

    stringbuf& printhl(stringbuf& sb) const {
      for (int i = N-1; i >= 0; i--) {
        sb << (((*this)[i]) ? '1' : '0');
      }
      return sb;
    }
  };

  //
  // Print hi-to-lo:
  //
  template <int N>
  struct hilo {
    const bitvec<N>& b;
    int bitcount;

    hilo() { }

    hilo(const bitvec<N>& b_, int bitcount_ = N): b(b_), bitcount(bitcount_) { }
  };

  template <int N>
  static inline stringbuf& operator <<(stringbuf& os, const hilo<N>& hl) {
    return hl.b.printhl(os);
  }

  template <int N>
  DeclareStringBufToStream(hilo<N>);

  template <size_t N>
  static inline ostream& operator <<(ostream& os, const bitvec<N>& v) {
    return v.print(os);
  }

  template <size_t N>
  static inline stringbuf& operator <<(stringbuf& sb, const bitvec<N>& v) {
    return v.print(sb);
  }

  template <int size, typename T>
  static inline T vec_min_index(T* list, const bitvec<size>& include) {
    int minv = limits<T>::max;
    int mini = 0;
    foreach (i, size) {
      T v = list[i];
      bool ok = (v < minv) & include[i];
      minv = (ok) ? v : minv;
      mini = (ok) ? i : mini;
    }
    return mini;
  }

  template <int size, typename T, typename I>
  static inline void vec_make_sorting_permute_map(I* permute, T* list) {
    bitvec<size> include;
    include++;

    int n = 0;
    while (*include) {
      int mini = vec_min_index<size>(list, include);
      include[mini] = 0;
      assert(n < size);
      permute[n++] = mini;
    }
  }

#undef BITVEC_WORDS
#undef BITS_PER_WORD
#undef __builtin_ctzl
#undef __builtin_clzl

  //
  // Convenient list iterator
  //
#define foreachlink(list, type, iter) \
  for (type* iter = (type*)((list)->first); (iter != NULL); prefetch(iter->next), iter = (type*)(iter->next)) \

  template <typename K, typename T>
  struct KeyValuePair {
    T value;
    K key;
  };

  template <typename K, int setcount>
  struct HashtableKeyManager {
    static inline int hash(const K& key);
    static inline bool equal(const K& a, const K& b);
    static inline K dup(const K& key);
    static inline void free(K& key);
  };

  template <int setcount>
  struct HashtableKeyManager<W64, setcount> {
    static inline int hash(W64 key) {
      W64 slot = 0;

      foreach (i, ((setcount == 1) ? 0 : (64 / log2(setcount)))+1) {
        slot ^= key;
        key >>= log2(setcount);
      }

      return slot;
    }

    static inline bool equal(W64 a, W64 b) { return (a == b); }
    static inline W64 dup(W64 key) { return key; }
    static inline void free(W64 key) { }
  };

  template <int setcount>
  struct HashtableKeyManager<const char*, setcount> {
    static inline int hash(const char* key) {
      int len = strlen(key);
      CRC32 h;
      foreach (i, len) { h << key[i]; }
      return h;
    }

    static inline bool equal(const char* a, const char* b) {
      return (strcmp(a, b) == 0);
    }

    static inline const char* dup(const char* key) {
      return strdup(key);
    }

    static inline void free(const char* key) {
      ::free((void*)key);
    }
  };

  template <typename T, typename K>
  struct HashtableLinkManager {
    static inline T* objof(selflistlink* link);
    static inline K& keyof(T* obj);
    static inline selflistlink* linkof(T* obj);
    //
    // Example:
    //
    // T* objof(selflistlink* link) {
    //   return baseof(T, hashlink, link); // a.k.a. *(T*)((byte*)link) - offsetof(T, hashlink);
    // }
    //
  };

  template <typename K, typename T, int setcount = 64, typename LM = ObjectLinkManager<T>, typename KM = HashtableKeyManager<K, setcount> >
  struct SelfHashtable {
  protected:
    selflistlink* sets[setcount];
  public:
    int count;

    T* get(const K& key) {
      selflistlink* tlink = sets[lowbits(KM::hash(key), log2(setcount))];
      while (tlink) {
        T* obj = LM::objof(tlink);
        if likely (KM::equal(LM::keyof(obj), key)) return obj;
        tlink = tlink->next;
      }

      return null;
    }

    struct Iterator {
      SelfHashtable<K, T, setcount, LM, KM>* ht;
      selflistlink* link;
      int slot;

      Iterator() { }

      Iterator(SelfHashtable<K, T, setcount, LM, KM>* ht) {
        reset(ht);
      }

      void reset(SelfHashtable<K, T, setcount, LM, KM>* ht) {
        this->ht = ht;
        slot = 0;
        link = ht->sets[slot];
      }

      T* next() {
        for (;;) {
          if unlikely (slot >= setcount) return null;

          if unlikely (!link) {
            // End of chain: advance to next chain
            slot++;
            if unlikely (slot >= setcount) return null;
            link = ht->sets[slot];
            continue;
          }

          T* obj = LM::objof(link);
          link = link->next;
          prefetch(link);
          return obj;
        }
      }
    };

    dynarray<T*>& getentries(dynarray<T*>& a) {
      a.resize(count);
      int n = 0;
      Iterator iter(this);
      T* t;
      while (t = iter.next()) {
        assert(n < count);
        a[n++] = t;
      }
      return a;
    }

    SelfHashtable() {
      count = 0;
      foreach (i, setcount) { sets[i] = null; }
    }

    void clear() {
      foreach (i, setcount) {
        selflistlink* tlink = sets[i];
        while (tlink) {
          selflistlink* tnext = tlink->next;
          tlink->unlink();
          tlink = tnext;
        }
        sets[i] = null;
      }
      count = 0;
    }

    T* operator ()(const K& key) {
      return get(key);
    }

    T* add(T* obj) {
      T* oldobj = get(LM::keyof(obj));
      if unlikely (oldobj) {
        remove(oldobj);
      }

      if (LM::linkof(obj)->linked()) return obj;

      LM::linkof(obj)->addto(sets[lowbits(KM::hash(LM::keyof(obj)), log2(setcount))]);
      count++;
      return obj;
    }

    T& add(T& obj) {
      return *add(&obj);
    }

    T* remove(T* obj) {
      selflistlink* link = LM::linkof(obj);
      if (!link->linked()) return obj;
      link->unlink();
      count--;
      return obj;
    }

    T& remove(T& obj) {
      return *remove(&obj);
    }

    ostream& print(ostream& os) const {
      os << "Hashtable of ", setcount, " sets containing ", count, " entries:", endl;
      foreach (i, setcount) {
        selflistlink* tlink = sets[i];
        if (!tlink)
          continue;
        os << "  Set ", i, ":", endl;
        int n = 0;
        while likely (tlink) {
          T* obj = LM::objof(tlink);
          os << "    ", LM::keyof(obj), " -> ", *obj, endl;
          tlink = tlink->next;
          n++;
        }
      }
      return os;
    }
  };

  template <typename K, typename T, typename LM, int setcount, typename KM>
  static inline ostream& operator <<(ostream& os, const SelfHashtable<K, T, setcount, LM, KM>& ht) {
    return ht.print(os);
  }

  template <typename K, typename T, typename KM>
  struct ObjectHashtableEntry: public KeyValuePair<K, T> {
    typedef KeyValuePair<K, T> base_t;
    selflistlink hashlink;

    ObjectHashtableEntry() { }

    ObjectHashtableEntry(const K& key, const T& value) {
      this->value = value;
      this->key = KM::dup(key);
    }

    ~ObjectHashtableEntry() {
      hashlink.unlink();
      KM::free(this->key);
    }
  };

  template <typename K, typename T, typename KM>
  struct ObjectHashtableLinkManager {
    typedef ObjectHashtableEntry<K, T, KM> entry_t;

    static inline entry_t* objof(selflistlink* link) {
      return baseof(entry_t, hashlink, link);
    }

    static inline K& keyof(entry_t* obj) {
      return obj->key;
    }

    static inline selflistlink* linkof(entry_t* obj) {
      return &obj->hashlink;
    }
  };

  template <typename K, typename T, int setcount = 64, typename KM = HashtableKeyManager<K, setcount> >
  struct Hashtable: public SelfHashtable<K, ObjectHashtableEntry<K, T, KM>, setcount, ObjectHashtableLinkManager<K, T, KM> > {
    typedef ObjectHashtableEntry<K, T, KM> entry_t;
    typedef SelfHashtable<K, entry_t, setcount, ObjectHashtableLinkManager<K, T, KM> > base_t;

    struct Iterator: public base_t::Iterator {
      Iterator() { }

      Iterator(Hashtable<K, T, setcount, KM>* ht) {
        reset(ht);
      }

      void reset(Hashtable<K, T, setcount, KM>* ht) {
        base_t::Iterator::reset(ht);
      }

      KeyValuePair<K, T>* next() {
        return base_t::Iterator::next();
      }
    };

    dynarray< KeyValuePair<K, T> >& getentries(dynarray< KeyValuePair<K, T> >& a) {
      a.resize(base_t::count);
      int n = 0;
      Iterator iter(this);
      KeyValuePair<K, T>* kvp;
      while (kvp = iter.next()) {
        assert(n < base_t::count);
        a[n++] = *kvp;
      }
      return a;
    }

    T* get(const K& key) {
      entry_t* entry = base_t::get(key);
      return &entry->value;
    }

    T* operator ()(const K key) {
      return get(key);
    }

    T* add(const K& key, const T& value) { 
      entry_t* entry = base_t::get(key);
      if unlikely (entry) {
        entry->value = value;
        return &entry->value;
      }

      entry = new entry_t(key, value);
      base_t::add(entry);
      return &entry->value;
    }

    bool remove(const K& key, T& value) {
      entry_t* entry = base_t::get(key);
      if unlikely (!entry) return false;

      value = entry->value;
      base_t::remove(entry);
      delete entry;
      return true;
    }

    bool remove(const K key) {
      T dummy;
      return remove(key, dummy);
    }

    ostream& print(ostream& os) {
      os << "Hashtable of ", setcount, " sets containing ", base_t::count, " entries:", endl;
      Iterator iter;
      iter.reset(this);
      KeyValuePair<K, T>* kvp;
      while (kvp = iter.next()) {
        os << "  ", kvp->key, " -> ", kvp->value, endl;
      }
      return os;
    }
  };

  template <typename K, typename T, int setcount, typename KM>
  static inline ostream& operator <<(ostream& os, const Hashtable<K, T, setcount, KM>& ht) {
    return ((Hashtable<K, T, setcount, KM>&)ht).print(os);
  }

  template <typename T, int N>
  struct ChunkList {
    struct Chunk;

    struct Chunk {
      selflistlink link;
      bitvec<N> freemap;

      // Formula: (CHUNK_SIZE - sizeof(ChunkHeader<T>)) / sizeof(T);
      T data[N];

      Chunk() { link.reset(); freemap++; }

      bool full() const { return (!freemap); }
      bool empty() const { return freemap.allset(); }

      int add(const T& entry) {
        if unlikely (full()) return -1;
        int idx = freemap.lsb();
        freemap[idx] = 0;
        data[idx] = entry;
        return idx;
      }

      bool contains(T* entry) const {
        int idx = entry - data;
        return ((idx >= 0) & (idx < lengthof(data)));
      }

      bool remove(int idx) {
        data[idx] = 0;
        freemap[idx] = 1;

        return empty();
      }

      struct Iterator {
        Chunk* chunk;
        size_t i;

        Iterator() { }

        Iterator(Chunk* chunk_) {
          reset(chunk_);
        }

        void reset(Chunk* chunk_) {
          this->chunk = chunk_;
          i = 0;
        }

        T* next() {
          for (;;) {
            if unlikely (i >= lengthof(chunk.data)) return null;
            if unlikely (chunk->freemap[i]) { i++; continue; }
            return &chunk->data[i++];
          }
        }
      };

      int getentries(T* a, int limit) {
        Iterator iter(this);
        T* entry;
        int n = 0;
        while (entry = iter.next()) {
          if unlikely (n >= limit) return n;
          a[n++] = *entry;
        }

        return n;
      }
    };

    struct Locator {
      Chunk* chunk;
      int index;

      void reset() { chunk = null; index = 0; }
    };

    selflistlink* head;
    int elemcount;

    ChunkList() { head = null; elemcount = 0; }

    bool add(const T& entry, Locator& hint) {
      Chunk* chunk = (Chunk*)head;

      while (chunk) {
        prefetch(chunk->link.next);
        int index = chunk->add(entry);
        if likely (index >= 0) {
          hint.chunk = chunk;
          hint.index = index;
          elemcount++;
          return true;
        }
        chunk = (Chunk*)chunk->link.next;
      }

      Chunk* newchunk = new Chunk();
      newchunk->link.addto(head);

      int index = newchunk->add(entry);
      assert(index >= 0);

      hint.chunk = newchunk;
      hint.index = index;
      elemcount++;

      return true;
    }

    bool remove(const Locator& locator) {
      locator.chunk->remove(locator.index);
      elemcount--;

      if (locator.chunk->empty()) {
        locator.chunk->link.unlink();
        delete locator.chunk;
      }

      return empty();
    }

    void clear() {
      Chunk* chunk = (Chunk*)head;

      while (chunk) {
        Chunk* next = (Chunk*)chunk->link.next;
        prefetch(next);
        delete chunk;
        chunk = next;
      }

      elemcount = 0;
      head = null;
    }

    int count() { return elemcount; }

    bool empty() { return (elemcount == 0); }

    ~ChunkList() {
      clear();
    }

    struct Iterator {
      Chunk* chunk;
      Chunk* nextchunk;
      int i;

      Iterator() { }
      
      Iterator(ChunkList<T, N>* chunklist) {
        reset(chunklist);
      }

      void reset(ChunkList<T, N>* chunklist) {
        chunk = (Chunk*)chunklist->head;
        nextchunk = (chunk) ? (Chunk*)chunk->link.next : null;
        i = 0;
      }

      T* next() {
        for (;;) {
          if unlikely (!chunk) return null;

          if unlikely (i >= lengthof(chunk->data)) {
            chunk = nextchunk;
            if unlikely (!chunk) return null;
            nextchunk = (Chunk*)chunk->link.next;
            prefetch(nextchunk);
            i = 0;
          }
          
          if unlikely (chunk->freemap[i]) { i++; continue; }

          return &chunk->data[i++];
        }
      }
    };

    int getentries(T* a, int limit) {
      Iterator iter(this);
      T* entry;
      int n;
      while (entry = iter.next()) {
        if unlikely (n >= limit) return n;
        a[n++] = *entry;
      }

      return n;
    }
  };

  static inline W64s expandword(const byte*& p, int type) {
    W64s v;

    switch (type) {
    case 0: 
      return 0;
    case 1:
      v = *((W8s*)p);
      p += 1;
      return v;
    case 2:
      v = *((W16s*)p);
      p += 2;
      return v;
    case 3:
      v = *((W32s*)p);
      p += 4;
      return v;
    case 4: // signed or unsigned W64
      v = *((W64s*)p);
      p += 8;
      return v;
    case 5: // unsigned byte
      v = *((byte*)p);
      p += 1;
      return v;
    case 6: // unsigned W16
      v = *((W16*)p);
      p += 2;
      return v;
    case 7: // unsigned W32
      v = *((W32*)p);
      p += 4;
      return v;
    }

    return v;
  }

  static inline int compressword(byte*& p, W64s v) {
    int f;

    if likely (!v) {
      f = 0;
    } else if (v >= 0) {
      if (inrange(v, 0LL, 255LL)) {
        *((byte*)p) = bits(v, 0, 8);
        p += 1;
        f = 5;
      } else if (inrange(v, 0LL, 65535LL)) {
        *((W16*)p) = bits(v, 0, 16);
        p += 2;
        f = 6;
      } else if (inrange(v, 0LL, 4294967295LL)) {
        *((W32*)p) = bits(v, 0, 32);
        p += 4;
        f = 7;
      } else {
        // default to W64:
        *((W64*)p) = v;
        p += 8;
        f = 4;
      }
    } else {
      if (inrange(v, -128LL, 127LL)) {
        *((byte*)p) = bits(v, 0, 8);
        p += 1;
        f = 1;
      } else if (inrange(v, -32768LL, 32767LL)) {
        *((W16*)p) = bits(v, 0, 16);
        p += 2;
        f = 2;
      } else if (inrange(v, -2147483648LL, -2147483647LL)) {
        *((W32*)p) = bits(v, 0, 32);
        p += 4;
        f = 3;
      } else {
        // default to W64:
        *((W64*)p) = v;
        p += 8;
        f = 4;
      }
    }

    return f;
  }

  class CycleTimer {
  public:
    CycleTimer() { total = 0; tstart = 0; iterations = 0; title = "(generic)"; running = 0; }
    CycleTimer(const char* title) { total = 0; tstart = 0; iterations = 1; this->title = title; running = 0; }

    inline void start() { W64 t = rdtsc(); if (running) return; iterations++; tstart = t; running = 1; }
    inline W64 stop() {
      W64 t = rdtsc() - tstart;

      if unlikely (!running) return total;

      tstart = 0;
      total += t;
      running = 0;
      return t;
    }

    inline W64 cycles() const {
      return total;
    }

    inline double seconds() const {
      return (double)total / hz;
    }

    inline void reset() {
      stop();
      tstart = 0;
      total = 0;
    }

  public:
    W64 total;
    W64 tstart;
    int iterations;
    const char* title;
    bool running;

    static double gethz();

  protected:
    static double hz;
  };

  ostream& operator <<(ostream& os, const CycleTimer& ct);

  //
  // Automatically start cycle timer at top of block and
  // stop it when this struct leaves the scope
  // 
  struct CycleTimerScope {
    CycleTimer& ct;
    CycleTimerScope(CycleTimer& ct_): ct(ct_) { ct.start(); }
    ~CycleTimerScope() { ct.stop(); }
  };

} // namespace superstl

#endif // _SUPERSTL_H_
