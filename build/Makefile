#!/bin/make
EXESUF = .exe
SOSUF = .dll
ASUF = .a
topsrcdir=..

CC = gcc
LD = ld
AR = ar

CFLAGS := $(CFLAGS) -fno-common -Wall -mms-bitfields

ifdef BUILD
CC := $(BUILD)-$(CC)
LD := $(BUILD)-$(LD)
AR := $(BUILD)-$(AR)
BUILD_CFLAGS = -I/mingw/$(BUILD)/include -I/mingw/$(BUILD)/include/tre
else
BUILD_CFLAGS = -I/mingw/include/tre
endif

ifdef DEBUG
DEBUG_CFLAGS = -g -O0
else
DEBUG_CFLAGS = -O3
endif

COMMON_CFLAGS = -I/usr/local/include -I$(topsrcdir)/include -D_WIN32_WINNT=0x0502 $(DEBUG_CFLAGS)
COMMON_LDFLAGS = -L/usr/local/lib -L.
MAGIC_LIBS = -lmagic -ltre
COM_LIBS = -luuid -lole32
MIMERUNREG_LIBS = -lmsvcrt

VERSION_MAJOR = 0

MIMERUNSHOOK_SHARED = libmimerunshook-$(VERSION_MAJOR)$(SOSUF)
MIMERUNSHOOK_IMPLIB = libmimerunshook$(SOSUF)$(ASUF)
CMDRUN_NAME = cmdrun$(EXESUF)
MIMERUNREG_NAME = mimerunreg$(EXESUF)
SONAME = libmimerunshook-$(VERSION_MAJOR)

MIMERUN_HEADERS = \
	$(topsrcdir)/include/mimerun/mimerun.h \
	$(topsrcdir)/include/mimerun/misc.h \
	$(topsrcdir)/include/mimerun/mimerunshook.h \
	$(topsrcdir)/include/mimerun/mimerunguid.h \

MIMERUNREG_FILES = \
	$(topsrcdir)/src/mimerunreg.c \
	$(topsrcdir)/src/misc.c \
	$(topsrcdir)/src/mimerunguid.c \

MIMERUNSHOOK_FILES = \
	$(topsrcdir)/src/mimerunshook.c \
	$(topsrcdir)/src/mimerunguid.c \
	$(topsrcdir)/src/misc.c \
	$(topsrcdir)/src/mimerun.c \
	
CMDRUN_FILES = \
	$(topsrcdir)/src/cmdrun.c \
	$(topsrcdir)/src/misc.c \

MIMERUNREG_OBJFILES = $(patsubst $(topsrcdir)/src/%,./%,$(patsubst %.c,%.o,$(MIMERUNREG_FILES)))
MIMERUNSHOOK_OBJFILES = $(patsubst $(topsrcdir)/src/%,./%,$(patsubst %.c,%.o,$(MIMERUNSHOOK_FILES)))
CMDRUN_OBJFILES = $(patsubst $(topsrcdir)/src/%,./%,$(patsubst %.c,%.o,$(CMDRUN_FILES)))

CD = $(shell cd)

ifeq ($(OS),Windows_NT)
	ifeq ($(MSYSTEM),MINGW32)
		ENV = mingw-msys
	else
		ENV = mingw-cmd
	endif
else
	ENV = gnu
endif

ifndef ABI
	ABI = 32
endif
ifeq ($(ABI),64)
	ARCHDIR = x64
else
  ifeq ($(ABI),32)
	ARCHDIR = x86
  else
	ARCHDIR =
  endif
endif

all: $(MIMERUNSHOOK_SHARED) $(CMDRUN_NAME) $(MIMERUNREG_NAME)

clean:
ifeq ($(ENV),mingw-cmd)
	cmd /c "del /S *.o *.dll *.a *.exe"
else
	find . \( -name "*.o" -o -name "*.dll" -o -name "*.a" -o -name "*.exe" \) -exec rm -rf {} \;
endif

./%.o: $(topsrcdir)/src/%.c
	$(CC) $(BUILD_CFLAGS) $(COMMON_CFLAGS) -o $@ -c $< 

$(MIMERUNSHOOK_SHARED): $(MIMERUNSHOOK_OBJFILES)
	$(CC) -shared $(MIMERUNSHOOK_OBJFILES) $(COMMON_LDFLAGS) $(LDFLAGS) -Wl,--out-implib=$(MIMERUNSHOOK_IMPLIB),--add-stdcall-alias,-soname,$(SONAME) -o $(MIMERUNSHOOK_SHARED) $(MAGIC_LIBS) $(COM_LIBS)

$(CMDRUN_NAME): $(CMDRUN_OBJFILES)
	$(CC) -static -o $(CMDRUN_NAME) $(CMDRUN_OBJFILES) $(COMMON_LDFLAGS) $(LDFLAGS) -mwindows

$(MIMERUNREG_NAME): $(MIMERUNREG_OBJFILES)
	$(CC) -static -o $(MIMERUNREG_NAME) $(MIMERUNREG_OBJFILES) $(COMMON_LDFLAGS) $(LDFLAGS) $(MIMERUNREG_LIBS)

install: $(MIMERUNSHOOK_SHARED) $(CMDRUN_NAME) $(MIMERUNREG_NAME)
ifndef DESTDIR
  ifeq ($(ENV),mingw-cmd)
	@echo Please use DESTDIR=drive:\installation\directory to specify installation path
  else
	@echo Please use DESTDIR=/installation/directory to specify installation path
  endif
endif
ifeq ($(ENV),mingw-cmd)
	@echo Installing into $(DESTDIR)\$(ARCHDIR)
	cmd /C if NOT EXIST $(DESTDIR)\$(ARCHDIR) mkdir /p $(DESTDIR)\$(ARCHDIR)
	cmd /C copy /Y $(CMDRUN_NAME) $(DESTDIR)\$(ARCHDIR)\$(CMDRUN_NAME)
	cmd /C copy /Y $(MIMERUNREG_NAME) $(DESTDIR)\$(ARCHDIR)\$(MIMERUNREG_NAME)
	cmd /C copy /Y $(MIMERUNSHOOK_SHARED) $(DESTDIR)\$(ARCHDIR)\$(MIMERUNSHOOK_SHARED)
else
	@echo Installing into $(DESTDIR)/$(ARCHDIR)
	install -D $(CMDRUN_NAME) $(DESTDIR)/$(ARCHDIR)/$(CMDRUN_NAME)
	install -D $(MIMERUNREG_NAME) $(DESTDIR)/$(ARCHDIR)/$(MIMERUNREG_NAME)
	install -D $(MIMERUNSHOOK_SHARED) $(DESTDIR)/$(ARCHDIR)/$(MIMERUNSHOOK_SHARED)
endif
