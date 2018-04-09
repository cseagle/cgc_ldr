#Set this variable to point to your SDK directory
IDA_SDK=../../

SDKVER=$(shell pwd | grep -o -E "idasdk[0-9]{2,3}" | cut -c 7-)
IDAVER=$(shell pwd | grep -o -E "idasdk[0-9]{2,3}" | cut -c 7- | sed 's/\(.\)\(.\)/\1\.\2/')
IDAVER_MAJOR=$(shell pwd | grep -o -E "idasdk[0-9]{2,3}" | cut -c 7)

PLATFORM=$(shell uname | cut -f 1 -d _)

#Set this variable to the desired name of your compiled loader
PROC=cgc

ifeq "$(PLATFORM)" "Linux"
IDA=/opt/ida-$(IDAVER)
HAVE_IDA64=$(shell if [ -f $(IDA)/libida64.so ]; then echo -n yes; fi)
PLATFORM_CFLAGS=-D__LINUX__
PLATFORM_LDFLAGS=-shared -s
IDADIR=-L$(IDA)

ifeq "$(IDAVER_MAJOR)" "6"
LOADER_EXT32=.llx
LOADER_EXT64=.llx64
else
LOADER_EXT32=.so
LOADER_EXT64=64.so
endif

IDALIB32=-lida
IDALIB64=-lida64

else ifeq "$(PLATFORM)" "Darwin"

IDAHOME=/Applications/IDA Pro $(IDAVER)

ifeq "$(IDAVER_MAJOR)" "6"
IDA=$(shell dirname "`find "$(IDAHOME)" -name idaq | tail -n 1`")
LOADER_EXT32=.lmc
LOADER_EXT64=.lmc64
else
IDA=$(shell dirname "`find "$(IDAHOME)" -name ida | tail -n 1`")
LOADER_EXT32=.dylib
LOADER_EXT64=64.dylib
endif

HAVE_IDA64=$(shell find "$(IDA)" -name libida64.dylib -exec echo -n yes \;)
PLATFORM_CFLAGS=-D__MAC__
PLATFORM_LDFLAGS=-dynamiclib
IDADIR=-L"$(IDA)"

IDALIB32=-lida
IDALIB64=-lida64
endif

ifeq "$(IDAVER_MAJOR)" "6"
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS) -m32 -fPIC
LDFLAGS=$(PLATFORM_LDFLAGS) -m32
else
CFLAGS=-Wextra -Os $(PLATFORM_CFLAGS) -D__X64__ -m64  -fPIC
LDFLAGS=$(PLATFORM_LDFLAGS) -m64
endif

#specify any additional libraries that you may need
EXTRALIBS=

# Destination directory for compiled plugins
OUTDIR=./bin/

OBJDIR32=./obj32
OBJDIR64=./obj64

#list out the object files in your project here
OBJS32=	$(OBJDIR32)/cgc.o
OBJS64=	$(OBJDIR64)/cgc.o

SRCS=cgc.cpp

BINARY32=$(OUTDIR)$(PROC)$(LOADER_EXT32)
BINARY64=$(OUTDIR)$(PROC)$(LOADER_EXT64)

ifdef HAVE_IDA64

all: $(OUTDIR) $(BINARY32) $(BINARY64)

clean:
	-@rm $(OBJDIR32)/*.o
	-@rm $(OBJDIR64)/*.o
	-@rm $(BINARY32)
	-@rm $(BINARY64)

$(OBJDIR64):
	-@mkdir -p $(OBJDIR64)

else

all: $(OUTDIR) $(BINARY32)

clean:
	-@rm $(OBJDIR32)/*.o
	-@rm $(BINARY32)

endif

$(OUTDIR):
	-@mkdir -p $(OUTDIR)

$(OBJDIR32):
	-@mkdir -p $(OBJDIR32)

CC=g++
#CC=clang
INC=-I$(IDA_SDK)include/

LD=g++
#LD=clang

%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(OBJDIR32)/%.o: %.cpp
	$(CC) -c $(CFLAGS) $(INC) $< -o $@

$(BINARY32): $(OBJDIR32) $(OBJS32)
	$(LD) $(LDFLAGS) -o $@ $(CFLAGS) $(OBJS32) $(IDADIR) $(IDALIB32) $(EXTRALIBS) 

ifdef HAVE_IDA64

$(OBJDIR64)/%.o: %.cpp
	$(CC) -c $(CFLAGS) -D__EA64__ $(INC) $< -o $@

$(BINARY64): $(OBJDIR64) $(OBJS64)
	$(LD) $(LDFLAGS) -o $@ $(OBJS64) $(IDADIR) $(IDALIB64) $(EXTRALIBS) 

endif

$(OUTDIR):
	-@mkdir -p $(OUTDIR)


#change cgc below to the name of your loader, make sure to add any 
#additional files that your loader is dependent on
$(OBJS32): cgc.cpp
$(OBJS64): cgc.cpp

