LIBS=-lpcre -lcurl -lcrypto -lm -lpthread
CFLAGS=-ggdb -O3 -Wall
OBJS=vanitygen.o oclvanitygen.o oclvanityminer.o oclengine.o keyconv.o pattern.o util.o donna.o
PROGS=vanitygen keyconv oclvanitygen oclvanityminer

PLATFORM=$(shell uname -s)
ifeq ($(PLATFORM),Darwin)
OPENCL_LIBS=-framework OpenCL
else
OPENCL_LIBS=-lOpenCL
endif


miner: oclvanitygen.o oclengine.o pattern.o util.o donna.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS)

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
