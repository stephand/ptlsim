# -*- makefile -*- 

SUBDIRS = gzip vpr gcc mcf crafty eon bzip2 twolf perlbmk parser gap vortex wupwise swim mgrid applu mesa art equake apsi sixtrack ammp fma3d lucas facerec

all:
	for dir in $(SUBDIRS); do \
	  echo "Making all in $$dir"; \
	  make -j2 -C $$dir; \
	done;

run:
	for dir in $(SUBDIRS); do \
	  echo "Making run in $$dir"; \
	  make -C $$dir run; \
	done;

use32:
	for dir in $(SUBDIRS); do \
	  echo "Making run in $$dir"; \
	  make -C $$dir use32; \
	done;

use64:
	for dir in $(SUBDIRS); do \
	  echo "Making run in $$dir"; \
	  make -C $$dir use64; \
	done;

usenone:
	for dir in $(SUBDIRS); do \
	  echo "Making run in $$dir"; \
	  make -C $$dir usenone; \
	done;

clean:
	for dir in $(SUBDIRS); do \
	  echo "Making clean in $$dir"; \
	  make -C $$dir clean; \
	done;

graphs:
	for dir in $(SUBDIRS); do \
	  echo "Making graphs in $$dir"; \
	  make -C $$dir graphs; \
	done;

distclean:
	 rm -fv `find -name logfile -or -name "ptlsim.stats.*" -or -name run.log` 
