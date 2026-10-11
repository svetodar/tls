# Makefile for tls — TLS 1.2/1.3 client and cryptographic primitives
# implemented in pure Free Pascal.
#
# Targets:
#   make            build and run the unit tests (default)
#   make build      build the test runner only
#   make test       run the unit tests
#   make fixtures   (re)generate tests/fixtures with OpenSSL and Python 3
#   make clean      remove build output

FPC      ?= fpc
SRC      := src
TESTS    := tests
BUILD    := build
BIN      := bin
LIB      := $(BUILD)/lib
TESTLIB  := $(BUILD)/testlib

# Executable suffix: .exe on Windows.
ifeq ($(OS),Windows_NT)
EXEEXT := .exe
endif

TESTAPP := $(BIN)/testrunner$(EXEEXT)

# -O2 -gl: optimisation plus debug information; -Fusrc: unit search path.
FPCFLAGS := -O2 -gl -Fusrc

# gmkdir is a cross-platform "mkdir -p" shipped with some FPC builds.
# On Unix fall back to the system mkdir when it is missing.
ifeq ($(OS),Windows_NT)
GMKDIR := gmkdir -p
else
GMKDIR := $(shell command -v gmkdir 2>/dev/null)
ifeq ($(GMKDIR),)
GMKDIR := mkdir -p
endif
endif

SOURCES := $(wildcard $(SRC)/*.pas)
TESTUNITS := $(wildcard $(TESTS)/*.pas)

all: test

build: $(TESTAPP)

test: $(TESTAPP)
	$(TESTAPP) --all --format=plain

$(TESTAPP): $(TESTUNITS) $(TESTS)/testrunner.lpr $(SOURCES)
	@$(GMKDIR) $(TESTLIB) $(BIN)
	$(FPC) $(FPCFLAGS) -Fu$(TESTS) -FU$(TESTLIB) -FE$(BIN) $(TESTS)/testrunner.lpr

# Regenerate certificate and DER fixtures. Requires `openssl` and `python3`.
# The key files produced here are git-ignored: they are test data only.
fixtures:
	./$(TESTS)/fixtures/gen_certs.sh

clean:
	rm -rf $(BUILD) $(BIN)
	rm -f $(SRC)/*.o $(SRC)/*.ppu $(TESTS)/*.o $(TESTS)/*.ppu
	rm -f $(TESTS)/tools/*.o $(TESTS)/tools/*.ppu

.PHONY: all build test fixtures clean
