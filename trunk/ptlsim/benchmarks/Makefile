# -*- makefile -*- 

SUBDIRS = gzip gcc

all:
	for dir in $(SUBDIRS); do \
	  echo "Making all in $$dir"; \
		make -j2 -C $$dir & \
	done;

run:
	for dir in $(SUBDIRS); do \
	  echo "Making run in $$dir"; \
		make -C $$dir run; \
	done;

clean:
	for dir in $(SUBDIRS); do \
	  echo "Making clean in $$dir"; \
		make -C $$dir clean; \
	done;
