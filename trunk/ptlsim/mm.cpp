//
// PTLsim: Cycle Accurate x86-64 Simulator
// Memory Management
//
// Copyright 2000-2006 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <kernel.h>
#include <mm.h>
#include <datastore.h>

//
// Which pages are mapped to slab cache pages?
//
// We need to know this to correctly free objects
// allocated at arbitrary addresses.
//
// The full 4 GB address space is covered by 1048576
// bits, or 131072 bytes in the bitmap
//
bitvec<PTL_PAGE_POOL_SIZE> page_is_slab_bitmap;

struct AddressSizeSpan {
  void* address;
  Waddr size;
  
  AddressSizeSpan() { }
  
  AddressSizeSpan(void* address, Waddr size) {
    this->address = address;
    this->size = size;
  }
};

//
// Extent Allocator, suitable for use as a memory allocator
// at both the page level and sub-block level.
//
// This allocator requires no overhead on allocated blocks,
// however, when freeing blocks, the number of bytes to free
// must be explicitly specified.
//
// Blocks can be freed from the middle of an allocated
// region if desired, but the range of the free must not
// overlap an area that is already free.
//
// The parameters CHUNKSIZE, SIZESLOTS and HASHSLOTS must
// be a power of two. 
//
// Allocations smaller than one chunk are rounded up to a
// chunk, i.e. CHUNKSIZE is the minimum granularity. The
// chunk size must be at least 32 bytes on 32-bit platforms
// and 64 bytes on 64-bit platforms, to fit the tracking
// structures in the smallest empty block size.
//
// To initialize the allocator, use free() to add a large
// initial pool of storage to it.
//
template <int CHUNKSIZE, int SIZESLOTS, int HASHSLOTS>
struct ExtentAllocator {
  struct FreeExtentBase {
    selflistlink sizelink;
    selflistlink startaddrlink;
    selflistlink endaddrlink;
  };

  struct FreeExtent: public FreeExtentBase {
    Waddr size;
    byte padding[CHUNKSIZE - (sizeof(FreeExtentBase) + sizeof(Waddr))];
    static FreeExtent* sizelink_to_self(selflistlink* link) { return (link) ? (FreeExtent*)(link - 0) : null; } 
    static FreeExtent* startaddrlink_to_self(selflistlink* link) { return (link) ? (FreeExtent*)(link - 1) : null; }
    static FreeExtent* endaddrlink_to_self(selflistlink* link) { return (link) ? (FreeExtent*)(link - 2) : null; }

    ostream& print(ostream& os) {
      return os << this, ": size ", intstring(size, 7), " = ", intstring(size * CHUNKSIZE, 10), 
        " bytes (range ", (void*)this, " to ", (void*)(this + size), "); sizelink ", FreeExtentBase::sizelink, ", startaddrlink ", FreeExtentBase::startaddrlink, 
        ", endaddrlink ", FreeExtentBase::endaddrlink;
    }
  };

  int extent_size_to_slot(size_t size) const {
    return min(size-1, (size_t)(SIZESLOTS-1));
  }

  int addr_to_hash_slot(void* size) const {
    W64 key = ((Waddr)size >> log2(CHUNKSIZE));
    W64 slot = 0;
    foreach (i, (64 / log2(HASHSLOTS))+1) {
      slot ^= key;
      key >>= log2(HASHSLOTS);
    }

    return lowbits(slot, log2(HASHSLOTS));
  }

  selflistlink* free_extents_by_size[SIZESLOTS];
  selflistlink* free_extents_by_startaddr_hash[HASHSLOTS];
  selflistlink* free_extents_by_endaddr_hash[HASHSLOTS];
  int extent_count;

  W64 current_bytes_allocated;
  W64 peak_bytes_allocated;
  W64 allocs;
  W64 frees;
  W64 extents_reclaimed;
  W64 extent_reclaim_reqs;
  W64 chunks_allocated;

  void reset() {
    extent_count = 0;

    foreach (i, SIZESLOTS) {
      free_extents_by_size[i] = null;
    }

    foreach (i, HASHSLOTS) {
      free_extents_by_startaddr_hash[i] = null;
    }

    foreach (i, HASHSLOTS) {
      free_extents_by_endaddr_hash[i] = null;
    }

    current_bytes_allocated = 0;
    peak_bytes_allocated = 0;
    allocs = 0;
    frees = 0;
    extents_reclaimed = 0;
    extent_reclaim_reqs = 0;
    chunks_allocated = 0;
  }

  FreeExtent* find_extent_by_startaddr(void* addr) const {
    int slot = addr_to_hash_slot(addr);
    FreeExtent* r = FreeExtent::startaddrlink_to_self(free_extents_by_startaddr_hash[slot]);

    while (r) {
      if (r == (FreeExtent*)addr) return r;
      r = FreeExtent::startaddrlink_to_self(r->startaddrlink.next);
    }

    return null;
  }

  FreeExtent* find_extent_by_endaddr(void* addr) const {
    int slot = addr_to_hash_slot(addr);
    FreeExtent* r = FreeExtent::endaddrlink_to_self(free_extents_by_endaddr_hash[slot]);

    while (r) {
      if ((r + r->size) == (FreeExtent*)addr) return r;
      r = FreeExtent::endaddrlink_to_self(r->endaddrlink.next);
    }

    return null;
  }

  void alloc_extent(FreeExtent* r) {
    r->sizelink.unlink();
    r->startaddrlink.unlink();
    r->endaddrlink.unlink();
    extent_count--;
    assert(extent_count >= 0);
  }

  FreeExtent* find_extent_in_size_slot(size_t size, int sizeslot) {
    static const bool DEBUG = 0;

    FreeExtent* r = FreeExtent::sizelink_to_self(free_extents_by_size[sizeslot]);

    if (DEBUG) cout << "find_extent_in_size_slot(size ", size, ", slot ", sizeslot, "): r = ", r, endl;

    while (r) {
      if (r->size < size) {
        if (DEBUG) cout << "  ", r, " too small: only ", r->size, " chunks", endl;
        r = FreeExtent::sizelink_to_self(r->sizelink.next);
        continue;
      }

      alloc_extent(r);

      if (size == r->size) {
        if (DEBUG) cout << "  Exact match: ", r, endl;
        return r;
      }
      
      int remaining_size = r->size - size;
      FreeExtent* rsplit = r + size;
      if (DEBUG) cout << "rsplit = ", rsplit, ", size ", size, ", r->size = ", r->size, ", remaining_size = ", remaining_size, endl, flush;

      free_extent(rsplit, remaining_size);
      
      return r;
    }

    return null;
  }

  FreeExtent* find_free_extent_of_size(size_t size) {
    if (!size) return null;

    for (int i = extent_size_to_slot(size); i < SIZESLOTS; i++) {
      FreeExtent* r = find_extent_in_size_slot(size, i);
      if (r) return r;
    }

    return null;
  }

  void free_extent(FreeExtent* r, size_t size) {
    static const bool DEBUG = 0;

    if ((!r) | (!size)) return;
    //
    // <F1> AAA [now-F] AA <F2>
    //
    // Need to quickly find F1 and F2
    //
    if (DEBUG) {
      cout << "free_extent(", r, ", ", size, "): from ", r, " to ", (r + size), endl, flush;
      cout << "  Add to size slot ", extent_size_to_slot(size), " @ ", &free_extents_by_size[extent_size_to_slot(size)], endl, flush;
      cout << "  Add to startaddr slot ", addr_to_hash_slot(r), " @ ", &free_extents_by_startaddr_hash[addr_to_hash_slot(r)], endl, flush;
      cout << "  Add to endaddr slot ", addr_to_hash_slot(r + r->size), " @ ", &free_extents_by_endaddr_hash[addr_to_hash_slot(r + r->size)], endl, flush;
    }

    r->sizelink.reset();
    r->startaddrlink.reset();
    r->size = 0;

    FreeExtent* right = find_extent_by_startaddr(r + size);

    //
    // Try to merge with right extent if possible
    //

    if (right) {
      right->sizelink.unlink();
      right->startaddrlink.unlink();
      right->endaddrlink.unlink();
      size = size + right->size;
      if (DEBUG) cout << "  Merge with right extent ", right, " of size ", right->size, " to form new extent of total size ", size, endl;
      extent_count--;
      assert(extent_count >= 0);
    }

    FreeExtent* left = find_extent_by_endaddr(r);

    if (left) {
      left->sizelink.unlink();
      left->startaddrlink.unlink();
      left->endaddrlink.unlink();
      size = size + left->size;
      r -= left->size;
      if (DEBUG) cout << "  Merge with left extent ", left, " of size ", left->size, " to form new extent of total size ", size, endl;
      extent_count--;
      assert(extent_count >= 0);
    }

    r->size = size;
    r->sizelink.addto(free_extents_by_size[extent_size_to_slot(size)]);
    r->startaddrlink.addto(free_extents_by_startaddr_hash[addr_to_hash_slot(r)]);
    r->endaddrlink.addto(free_extents_by_endaddr_hash[addr_to_hash_slot(r + r->size)]);

    extent_count++;
    assert(extent_count > 0);
  }

  void* alloc(size_t size) {
    size = ceil(size, CHUNKSIZE) >> log2(CHUNKSIZE);
    void* addr = (void*)find_free_extent_of_size(size);
    if (!addr) return null;
    allocs++;
    current_bytes_allocated += (size * CHUNKSIZE);
    peak_bytes_allocated = max(peak_bytes_allocated, current_bytes_allocated);
    return addr;
  }

  void free(void* p, size_t size) {
    size = ceil(size, CHUNKSIZE) >> log2(CHUNKSIZE);
    free_extent((FreeExtent*)p, size);
    frees++;
    current_bytes_allocated = min(current_bytes_allocated - (size * CHUNKSIZE), 0ULL);
  }

  void add_to_free_pool(void* p, size_t size) {
    chunks_allocated++;
    size = ceil(size, CHUNKSIZE) >> log2(CHUNKSIZE);
    free_extent((FreeExtent*)p, size);
  }

  int reclaim_unused_extents(AddressSizeSpan* ass, int asscount, int sizealign) {
    static const int DEBUG = 0;

    int minchunks = ceil(sizealign, CHUNKSIZE) >> log2(CHUNKSIZE);

    int n = 0;

    extent_reclaim_reqs++;

    for (int i = extent_size_to_slot(minchunks); i < SIZESLOTS; i++) {
      FreeExtent* r = FreeExtent::sizelink_to_self(free_extents_by_size[i]);

      while (r) {
        //
        // Example:
        //
        // ..ffffff ffffffff fff.....
        //   aaaaaa aaaaaaaa aaa.....
        //   ffffff          fff
        //          -return-
        //

        Waddr rstart = (Waddr)r;
        Waddr rend = rstart + (r->size * CHUNKSIZE);

        Waddr first_full_page = ceil(rstart, sizealign);
        Waddr last_full_page = floor(rend, sizealign);
        Waddr bytes_in_middle = last_full_page - first_full_page;

        if (DEBUG) {
          cout << "  Trying to reclaim extent "; r->print(cout); cout << " (", bytes_in_middle, " bytes in middle)", endl;
        }

        if (!bytes_in_middle) {
          r = FreeExtent::sizelink_to_self(r->sizelink.next);          
          continue;
        }

        // These are full pages that we can return to the system
        if (n == asscount) return n;

        Waddr full_page_bytes = last_full_page - first_full_page;
        if (DEBUG) cout << "    Adding reclaimed full page extent at ", (void*)first_full_page, " of ", full_page_bytes, " bytes (", full_page_bytes / sizealign, " pages)", endl;
        ass[n++] = AddressSizeSpan((void*)first_full_page, full_page_bytes);

        Waddr bytes_at_end_of_first_page = ceil(rstart, sizealign) - rstart; 
        Waddr bytes_at_start_of_last_page = rend - floor(rend, sizealign);

        alloc_extent(r);
        extents_reclaimed++;

        if (bytes_at_end_of_first_page) {
          if (DEBUG) cout << "    Adding ", bytes_at_end_of_first_page, " bytes at end of first page @ ", r, " back to free pool", endl;
          free(r, bytes_at_end_of_first_page);
        }

        if (bytes_at_start_of_last_page) {
          void* p = (void*)(rend - bytes_at_start_of_last_page);
          if (DEBUG) cout << "    Adding ", bytes_at_start_of_last_page, " bytes at start of last page @ ", p, " back to free pool", endl;
          free(p, bytes_at_start_of_last_page);
        }

        //
        // Start again since we may have invalidated the next entry,
        // or moved some big entries in the current list back into
        // one of the smaller lists (smaller than the page size)
        //
        r = FreeExtent::sizelink_to_self(free_extents_by_size[i]);
      }
    }

    return n;
  }

  bool validate() {
    // Collect all regions
    FreeExtent** extarray = new FreeExtent*[extent_count];

    int n = 0;

    foreach (i, SIZESLOTS) {
      FreeExtent* r = FreeExtent::sizelink_to_self(free_extents_by_size[i]);
      if (!r) continue;
      while (r) {
        if (n >= extent_count) {
          cerr << "ERROR (chunksize ", CHUNKSIZE, "): ", n, " exceeds extent count ", extent_count, endl, flush;
          cerr << *this;
          return false;
        }
        extarray[n++] = r;
        r = FreeExtent::sizelink_to_self(r->sizelink.next);
      }
    }

    foreach (i, extent_count) {
      FreeExtent* r = extarray[i];
      Waddr start = (Waddr)r;
      Waddr end = start + (r->size * CHUNKSIZE);
      foreach (j, extent_count) {
        if (j == i) continue;
        FreeExtent* rr = extarray[j];
        Waddr rrstart = (Waddr)rr;
        Waddr rrend = rrstart + (rr->size * CHUNKSIZE);

        // ........rrrrrrrrrrr............
        // .....ssssssss..................

        if (inrange(start, rrstart, rrend-1) | inrange(end, rrstart, rrend-1)) {
          cerr << "ERROR (chunksize ", CHUNKSIZE, "): overlap between extent ", r, " (", (r->size * CHUNKSIZE), " bytes; ",  (void*)start, " to ", (void*)end, ") "
            "and extent ", rr, " (", (rr->size * CHUNKSIZE), " bytes; ", (void*)rrstart, " to ", (void*)rrend, ")", endl, flush;
          cerr << *this;
          return false;
        }
      }
    }

    delete[] extarray;

    return true;
  }

  ostream& print(ostream& os) const {
    os << "ExtentAllocator<", CHUNKSIZE, ", ", SIZESLOTS, ", ", HASHSLOTS, ">: ", extent_count, " extents:", endl;

    os << "Extents by size:", endl, flush;
    foreach (i, SIZESLOTS) {
      FreeExtent* r = FreeExtent::sizelink_to_self(free_extents_by_size[i]);
      if (!r) continue;
      os << "  Size slot ", intstring(i, 7), " = ", intstring((i+1) * CHUNKSIZE, 10), " bytes (root @ ", &free_extents_by_size[i], "):", endl, flush;
      while (r) {
        os << "    ";
        os << r->print(os);
        os << endl;
        r = FreeExtent::sizelink_to_self(r->sizelink.next);
      }
    }
    os << endl, flush;

    os << "Extents by startaddr hash:", endl, flush;
    foreach (i, HASHSLOTS) {
      FreeExtent* r = FreeExtent::startaddrlink_to_self(free_extents_by_startaddr_hash[i]);
      if (!r) continue;
      os << "  Hash slot ", intstring(i, 7), ":", endl, flush;
      while (r) {
        os << "    ";
        os << r->print(os);
        os << endl;
        r = FreeExtent::startaddrlink_to_self(r->startaddrlink.next);
      }
    }
    os << endl, flush;

    os << "Extents by endaddr hash:", endl, flush;
    foreach (i, HASHSLOTS) {
      FreeExtent* r = FreeExtent::endaddrlink_to_self(free_extents_by_endaddr_hash[i]);
      if (!r) continue;
      os << "  Hash slot ", intstring(i, 7), ":", endl, flush;
      while (r) {
        os << "    ";
        os << r->print(os);
        os << endl;
        r = FreeExtent::endaddrlink_to_self(r->endaddrlink.next);
      }
    }
    os << endl, flush;

    return os;
  }

  DataStoreNode& capture_stats(DataStoreNode& root) {
    root.add("current-bytes-allocated", current_bytes_allocated);
    root.add("peak-bytes-allocated", peak_bytes_allocated);
    root.add("allocs", allocs);
    root.add("frees", frees);
    root.add("extents-reclaimed", extents_reclaimed);
    root.add("extent-reclaim-reqs", extent_reclaim_reqs);
    root.add("chunks-allocated", chunks_allocated);
    return root;
  }
};

template <int CHUNKSIZE, int SIZESLOTS, int HASHSLOTS>
ostream& operator <<(ostream& os, const ExtentAllocator<CHUNKSIZE, SIZESLOTS, HASHSLOTS>& alloc) {
  return alloc.print(os);
}

//
// Slab cache allocator
//
// Minimum object size is 16 bytes (for 256 objects per page)
//

struct SlabAllocator;
ostream& operator <<(ostream& os, const SlabAllocator& slaballoc);

//
// In PTLxen, the hypervisor is running on the bare hardware
// and must handle all page allocation itself.
//
// In userspace PTLsim, we use pagealloc only for its
// statistics counters.
//
ExtentAllocator<4096, 512, 512> pagealloc;

struct SlabAllocator {
  struct FreeObjectHeader: public selflistlink { };

  static const int GRANULARITY = sizeof(FreeObjectHeader);

  struct PageHeader: public selflistlink {
    FreeObjectHeader* freelist;
    SlabAllocator* allocator;
    W64s freecount;
    FreeObjectHeader objs[];
  };

  W64 current_objs_allocated;
  W64 peak_objs_allocated;

  W64 current_bytes_allocated;
  W64 peak_bytes_allocated;

  W64 current_pages_allocated;
  W64 peak_pages_allocated;

  W64 allocs;
  W64 frees;
  W64 page_allocs;
  W64 page_frees;
  W64 reclaim_reqs;

  PageHeader* free_pages;
  PageHeader* partial_pages;
  PageHeader* full_pages;
  W16s free_page_count;
  W16 objsize;
  W16 max_objects_per_page;
  W16 padding;
  
  static const int FREE_PAGE_HI_THRESH = 4;
  static const int FREE_PAGE_LO_THRESH = 1;

  SlabAllocator() { }
  
  SlabAllocator(int objsize) {
    reset(objsize);
  }

  void reset(int objsize) {
    free_pages = null;
    partial_pages = null;
    full_pages = null;
    free_page_count = 0;
    this->objsize = objsize;
    max_objects_per_page = ((PAGE_SIZE - sizeof(PageHeader)) / objsize);

    current_objs_allocated = 0;
    peak_objs_allocated = 0;
    current_bytes_allocated = 0;
    peak_bytes_allocated = 0;
    current_pages_allocated = 0;
    peak_pages_allocated = 0;
    allocs = 0;
    frees = 0;
    page_allocs = 0;
    page_frees = 0;
    reclaim_reqs = 0;
  }

  static SlabAllocator* pointer_to_slaballoc(void* p) {
    Waddr pfn = (((Waddr)p) - PTL_PAGE_POOL_BASE) >> 12;
    if (pfn >= PTL_PAGE_POOL_SIZE) return null; // must be some other kind of page

    if (!page_is_slab_bitmap[pfn]) return null;

    PageHeader* page = (PageHeader*)floor((Waddr)p, PAGE_SIZE);
    return page->allocator;
  }

  FreeObjectHeader* alloc_from_page(PageHeader* page) {  
    FreeObjectHeader* obj = page->freelist;
    if (!obj) return obj;

    obj->unlink();
    assert(page->freecount > 0);
    page->freecount--;
    
    if (!page->freelist) {
      assert(page->freecount == 0);
      page->unlink();
      page->addto((selflistlink*&)full_pages);
    }

    allocs++;

    current_objs_allocated++;
    peak_objs_allocated = max(current_objs_allocated, peak_objs_allocated);

    current_bytes_allocated += objsize;
    peak_bytes_allocated = max(current_bytes_allocated, peak_bytes_allocated);

    return obj;
  }

  PageHeader* alloc_new_page() {
    //
    // We need the pages in the low 2 GB of the address space so we can use
    // page_is_slab_bitmap to find out if it's a slab or genalloc page:
    //
    PageHeader* page = (PageHeader*)ptl_alloc_private_32bit_page();
    if (!page) return null;

    page_allocs++;
    current_pages_allocated++;
    peak_pages_allocated = max(current_pages_allocated, peak_pages_allocated);

    page->reset();
    page->freelist = null;
    page->freecount = 0;
    page->allocator = this;

    Waddr pfn = (((Waddr)page) - PTL_PAGE_POOL_BASE) >> 12;
    assert(pfn < PTL_PAGE_POOL_SIZE);
    page_is_slab_bitmap[pfn] = 1;

    FreeObjectHeader* obj = page->objs;
    FreeObjectHeader* prevobj = (FreeObjectHeader*)&page->freelist;

    foreach (i, max_objects_per_page) {
      prevobj->next = obj;
      obj->prev = prevobj;
      obj->next = null;
      prevobj = obj;
      obj = (FreeObjectHeader*)(((byte*)obj) + objsize);
    }

    page->freecount = max_objects_per_page;

    return page;
  }

  void* alloc() {
    PageHeader* page = partial_pages;

    if (!page) page = free_pages;

    if (!page) {
      page = alloc_new_page();
      assert(page);
      page->addto((selflistlink*&)partial_pages);
    }

    if (page == free_pages) {
      page->unlink();
      page->addto((selflistlink*&)partial_pages);
      free_page_count--;
      assert(free_page_count >= 0);
    }

    FreeObjectHeader* obj = alloc_from_page(page);
    assert(obj);

    return (void*)obj;
  }

  void free(void* p) {
    frees++;
    if (current_objs_allocated > 0) current_objs_allocated--;
    current_bytes_allocated -= min((W64)objsize, current_bytes_allocated);

    FreeObjectHeader* obj = (FreeObjectHeader*)p;
    PageHeader* page = (PageHeader*)floor((Waddr)p, PAGE_SIZE);
    obj->reset();
    obj->addto((selflistlink*&)page->freelist);

    assert(page->freecount <= max_objects_per_page);
    page->freecount++;

    if (page->freecount == max_objects_per_page) {
      assert(page->freelist); // all free?
      page->unlink();
      page->addto((selflistlink*&)free_pages);
      free_page_count++;
    }

    if (free_page_count >= FREE_PAGE_HI_THRESH) {
      reclaim(FREE_PAGE_LO_THRESH);
    }
  }

  int reclaim(int limit = 0) {
    // Return some of the pages to the main allocator all at once
    int n = 0;
    reclaim_reqs++;
    while (free_page_count > limit) {
      PageHeader* page = free_pages;
      if (!page) break;
      assert(page->freecount == max_objects_per_page);
      page->unlink();
      
      Waddr pfn = (((Waddr)page) - PTL_PAGE_POOL_BASE) >> 12;
      assert(pfn < PTL_PAGE_POOL_SIZE);
      page_is_slab_bitmap[pfn] = 0;

      ptl_free_private_page(page);
      page_frees++;
      if (current_pages_allocated > 0) current_pages_allocated--;
      n++;
      free_page_count--;
    }
    return n;
  }

  ostream& print_page_chain(ostream& os, PageHeader* page) const {
    while (page) {
      os << "  Page ", page, ": free list size ", page->freecount, ", prev ", page->prev, ", next ", page->next, ":", endl;
      FreeObjectHeader* obj = page->freelist;
      int c = 0;
      while (obj) {
        os << "    Object #", c, ": ", obj, " (prev ", obj->prev, ", next ", obj->next, ")", endl;
        obj = (FreeObjectHeader*)obj->next;
        c++;
      }
      if (c != page->freecount) {
        os << "    WARNING: c = ", c, " vs page->freecount ", page->freecount, endl, flush;
      }
      page = (PageHeader*)page->next;
    }
    return os;
  }

  ostream& print(ostream& os) const {
    os << "SlabAllocator<", objsize, "-byte objects = ", max_objects_per_page, " objs per page>:", endl;

    os << "Free Pages (", free_page_count, " pages):", endl;
    print_page_chain(os, free_pages);

    os << "Partial Pages:", endl;
    print_page_chain(os, partial_pages);

    os << "Full Pages:", endl;
    print_page_chain(os, full_pages);

    return os;
  }

  DataStoreNode& capture_stats(DataStoreNode& root) {
    root.add("current-objs-allocated", current_objs_allocated);
    root.add("peak-objs-allocated", peak_objs_allocated);

    root.add("current-bytes-allocated", current_bytes_allocated);
    root.add("peak-bytes-allocated", peak_bytes_allocated);

    root.add("current-pages-allocated", current_pages_allocated);
    root.add("peak-pages-allocated", peak_pages_allocated);

    root.add("allocs", allocs);
    root.add("frees", frees);
    root.add("page-allocs", page_allocs);
    root.add("page-frees", page_frees);
    root.add("reclaim-reqs", reclaim_reqs);
    return root;
  }
};

ostream& operator <<(ostream& os, const SlabAllocator& slaballoc) {
  return slaballoc.print(os);
}

//
// Memory Management
//

static const int GEN_ALLOC_GRANULARITY = 64;

ExtentAllocator<GEN_ALLOC_GRANULARITY, 4096, 2048> genalloc;

// Objects larger than this will be allocated from the general purpose allocator
static const int SLAB_ALLOC_LARGE_OBJ_THRESH = 1024;
static const int SLAB_ALLOC_SLOT_COUNT = (SLAB_ALLOC_LARGE_OBJ_THRESH / SlabAllocator::GRANULARITY);

SlabAllocator slaballoc[SLAB_ALLOC_SLOT_COUNT];

#ifdef PTLSIM_HYPERVISOR
//
// Full-system PTLxen running on the bare hardware:
//
void* ptl_alloc_private_pages(Waddr bytecount, int prot, Waddr base) {
  return pagealloc.alloc(bytecount);
}

void* ptl_alloc_private_32bit_pages(Waddr bytecount, int prot, Waddr base) {
  return pagealloc.alloc(bytecount);
}

void ptl_free_private_pages(void* addr, Waddr bytecount) {
  pagealloc.free(floorptr(addr, PAGE_SIZE), ceil(bytecount, PAGE_SIZE));
}

void ptl_zero_private_pages(void* addr, Waddr bytecount) {
  memset(addr, 0, bytecount);
}

#else

void* ptl_alloc_private_pages(Waddr bytecount, int prot, Waddr base) {
  int flags = MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : 0);
  flags |= (inside_ptlsim) ? MAP_SHARED : MAP_PRIVATE;
  if (base == 0) base = PTL_PAGE_POOL_BASE;
  void* addr = sys_mmap((void*)base, ceil(bytecount, PAGE_SIZE), prot, flags, 0, 0);
  if (addr) {
    pagealloc.allocs++;
    pagealloc.current_bytes_allocated += ceil(bytecount, PAGE_SIZE);
    pagealloc.peak_bytes_allocated = max(pagealloc.peak_bytes_allocated, pagealloc.current_bytes_allocated);
  }

  return addr;
}

void* ptl_alloc_private_32bit_pages(Waddr bytecount, int prot, Waddr base) {
#ifdef __x86_64__
  int flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : MAP_32BIT);
#else
  int flags = MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE | (base ? MAP_FIXED : 0);
#endif
  void* addr = sys_mmap((void*)base, ceil(bytecount, PAGE_SIZE), prot, flags, 0, 0);  
  if (addr) {
    pagealloc.allocs++;
    pagealloc.current_bytes_allocated += ceil(bytecount, PAGE_SIZE);
    pagealloc.peak_bytes_allocated = max(pagealloc.peak_bytes_allocated, pagealloc.current_bytes_allocated);
  }

  return addr;
}

void ptl_free_private_pages(void* addr, Waddr bytecount) {
  bytecount = ceil(bytecount, PAGE_SIZE);

  pagealloc.frees++;
  pagealloc.current_bytes_allocated -= min(pagealloc.current_bytes_allocated, (W64)bytecount);

  sys_munmap(addr, bytecount);
}

void ptl_zero_private_pages(void* addr, Waddr bytecount) {
  sys_madvise((void*)floor((Waddr)addr, PAGE_SIZE), bytecount, MADV_DONTNEED);
}

#endif

void* ptl_alloc_private_page() {
  return ptl_alloc_private_pages(PAGE_SIZE);
}

void* ptl_alloc_private_32bit_page() {
  return ptl_alloc_private_32bit_pages(PAGE_SIZE);
}

void ptl_free_private_page(void* addr) {
  ptl_free_private_pages(addr, PAGE_SIZE);
}

void ptl_zero_private_page(void* addr) {
  ptl_zero_private_pages(addr, PAGE_SIZE);
}

void ptl_mm_init() {
  page_is_slab_bitmap--;

#ifdef PTLSIM_HYPERVISOR
  //++MTY TODO
  pagealloc.free(pool, POOLSIZE);
#else
  // No special actions required
#endif
  genalloc.reset();  

  foreach (i, SLAB_ALLOC_SLOT_COUNT) {
    slaballoc[i].reset((i+1) * SlabAllocator::GRANULARITY);
  }
}

static const int GEN_ALLOC_CHUNK_SIZE = 256*1024; // 256 KB (64 pages)

void* ptl_mm_alloc(size_t bytes) {
  // General purpose malloc

  if (!bytes) return null;

  if ((bytes <= SLAB_ALLOC_LARGE_OBJ_THRESH)) {
    //
    // Allocate from slab
    //
    bytes = ceil(bytes, SlabAllocator::GRANULARITY);
    int slot = (bytes >> log2(SlabAllocator::GRANULARITY))-1;
    assert(slot < SLAB_ALLOC_SLOT_COUNT);
    void* p = slaballoc[slot].alloc();
    if (!p) {
      ptl_mm_reclaim();
      p = slaballoc[slot].alloc();
    }
    return p;
  } else {
    //
    // Allocate from general allocation pool
    //
    bytes += sizeof(Waddr);
    Waddr* p = (Waddr*)genalloc.alloc(bytes);
    if (!p) {
      // Add some storage to the pool
      Waddr pagebytes = max((Waddr)ceil(bytes, PAGE_SIZE), (Waddr)GEN_ALLOC_CHUNK_SIZE);
      //
      // We need the pages in the low 2 GB of the address space so we can use
      // page_is_slab_bitmap to find out if it's a slab or genalloc page:
      //
      void* newpool = ptl_alloc_private_32bit_pages(pagebytes);
      if (!newpool) {
        ptl_mm_reclaim();
        pagebytes = ceil(bytes, PAGE_SIZE);
        newpool = ptl_alloc_private_32bit_pages(pagebytes);
      }

      if (!newpool) {
#ifdef PTLSIM_HYPERVISOR
        cerr << pagealloc, flush;
#endif
        cerr << genalloc, flush;
        assert(false);
      }
      genalloc.add_to_free_pool(newpool, pagebytes);

      p = (Waddr*)genalloc.alloc(bytes);
      assert(p);
    }

    *p = bytes;
    p++; // skip over hidden size word
    return p;
  }
}

void ptl_mm_free(void* p) {
  SlabAllocator* sa;

  if (sa = SlabAllocator::pointer_to_slaballoc(p)) {
    //
    // From slab allocation pool: all objects on a given page are the same size
    //
    sa->free(p);
  } else {
    //
    // Pointer is in the general allocation pool.
    // The word prior to the start of the block specifies
    // the block size.
    //
    Waddr* pp = ((Waddr*)p)-1;
    Waddr bytes = *pp;

    genalloc.free(pp, bytes);
  }
}

//
// Return unused sub-allocator resources to the main page allocator
// in case of an out-of-memory condition. This may free up some space
// for other types of big allocations.
//
void ptl_mm_reclaim() {
  foreach (i, SLAB_ALLOC_SLOT_COUNT) {
    slaballoc[i].reclaim();
  }

  AddressSizeSpan ass[1024];

  int n;

  while (n = genalloc.reclaim_unused_extents(ass, lengthof(ass), PAGE_SIZE)) {
    // cout << "Reclaimed ", n, " extents", endl;

    foreach (i, n) {
      ptl_free_private_pages(ass[i].address, ass[i].size);
    }
  }
}

DataStoreNode& ptl_mm_capture_stats(DataStoreNode& root) {
  pagealloc.capture_stats(root("page"));
  genalloc.capture_stats(root("general"));
  DataStoreNode& slab = root("slab"); {
    slab.summable = 1;
    slab.identical_subtrees = 1;
    foreach (i, SLAB_ALLOC_SLOT_COUNT) {
      stringbuf sizestr; sizestr << slaballoc[i].objsize;
      slaballoc[i].capture_stats(slab(sizestr));
    }
  }

  return root;
}

extern "C" void* malloc(size_t size) {
  return ptl_mm_alloc(size);
}

extern "C" void free(void* ptr) {
  ptl_mm_free(ptr);
}

void* operator new(size_t sz) {
  return ptl_mm_alloc(sz);
}

void operator delete(void* m) {
  ptl_mm_free(m);
}

void* operator new[](size_t sz) {
  return ptl_mm_alloc(sz);
}

void operator delete[](void* m) {
  ptl_mm_free(m);
}
