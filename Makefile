# Makefile for tls — TLS 1.2/1.3 client and cryptographic primitives
# implemented in pure Free Pascal.
#
# Targets:
#   make            build and run the unit tests (default)
#   make build      build the test runner only
#   make test       run the unit tests
#   make leaktest   build the runner with heap tracing and run the leak checks
#   make fixtures   (re)generate tests/fixtures with OpenSSL and Python 3
#   make roots      regenerate src/tlsroots.res from certs/ (FPC fpcres)
#   make check-roots verify that the committed src/tlsroots.res matches certs/
#   make clean      remove build output

FPC      ?= fpc
SRC      := src
TESTS    := tests
BUILD    := build
BIN      := bin
LIB      := $(BUILD)/lib
TESTLIB  := $(BUILD)/testlib
LEAKLIB  := $(BUILD)/leaklib

# Executable suffix: .exe on Windows.
ifeq ($(OS),Windows_NT)
EXEEXT := .exe
endif

TESTAPP := $(BIN)/testrunner$(EXEEXT)
LEAKAPP := $(BIN)/testrunner_leak$(EXEEXT)
EXAMPLEAPP := $(BIN)/https_client$(EXEEXT)

# -O2 -gl: optimisation plus debug information; -Fusrc: unit search path.
FPCFLAGS := -O2 -gl -Fusrc
# Heap tracing is opt-in: heaptrc slows every allocation down (the EC and
# RSA suites take minutes instead of seconds), so the normal test run stays
# fast and only `make leaktest` pays for it. The leak checks in the tests
# are compiled in with -dTLS_HEAPTRACE.
LEAKFLAGS := $(FPCFLAGS) -gh -dTLS_HEAPTRACE

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

# --- Embedded root certificates (task 19) -----------------------------------
#
# `make roots` turns the committed snapshot in certs/ into the DER table and
# the resource script (both under build/roots/), then compiles the script into
# $(ROOTSRES), which src/tls.roots.pas links in with {$R}. The last step runs
# fpcres, the FPC resource compiler: it is the only external program the
# target needs. Point FPCRES at it when it is not on PATH; on a host without
# fpcres the library can still be built with -dTLS_NO_EMBEDDED_ROOTS.
#
# $(ROOTSRES) itself is committed, because {$R} is resolved by the compiler: a
# program that only puts src/ on its unit path — a consumer on another host, a
# checkout built without make — must find the resource next to the unit, just
# as it finds the .pas file. The build rules below therefore never regenerate
# it implicitly: they check that it is present (check-roots-file) and, in
# `make check-roots`, that it still matches certs/. Rebuild it with
# `make roots` and commit it together with the snapshot and the constants
# pinned in tests/test_roots.pas.
FPCRES   ?= fpcres
ROOTSGEN := $(BIN)/rootsgen$(EXEEXT)
ROOTSTMP := $(BUILD)/roots
ROOTSRES := $(SRC)/tlsroots.res

# Look the resource compiler up once, at parse time, so check-fpcres can stop
# the run before anything is compiled. `command -v` accepts a bare command
# name and an absolute path alike; an empty result means "not there".
FPCRES_FOUND := $(shell command -v $(FPCRES) 2>/dev/null)

# What the generator is built from: its own source and the units it links.
# tls.roots is excluded on purpose — it pulls $(ROOTSRES) in, and the table
# producer must not depend on the table it produces.
ROOTSGEN_DEPS := tools/rootsgen/rootsgen.lpr \
  $(filter-out $(SRC)/tls.roots.pas,$(SOURCES))

# Inputs of the table. distrusted.txt may legitimately be absent (no root is
# distrusted then, which the generator accepts), so it joins the list only
# when it exists and a change to it must trigger a regeneration.
ROOTS_INPUTS := certs/roots.pem certs/roots.date \
  $(wildcard certs/distrusted.txt)

all: test

build: $(TESTAPP)

test: $(TESTAPP)
	$(TESTAPP) --all --format=plain

# Build the OpenSSL-free HTTPS client example.
example: $(EXAMPLEAPP)

$(EXAMPLEAPP): $(SOURCES)
	@$(GMKDIR) $(BUILD)/example $(BIN)
	$(FPC) $(FPCFLAGS) -FU$(BUILD)/example -FE$(BIN) examples/https_client.pas

# Fail if any library or example unit pulls in the FPC OpenSSL bindings.
check-no-openssl:
	@for f in $(SOURCES) examples/*.pas; do \
	  awk '/^[ \t]*uses[ \t]/{u=1} u{print FILENAME":"FNR":"$$0} u&&/;/{u=0}' "$$f"; \
	done | grep -iE '\b(openssl|opensslsockets|fpopenssl)\b' \
	  && { echo "ERROR: OpenSSL unit referenced in a uses clause"; exit 1; } \
	  || echo "OK: no OpenSSL unit references"
# The runner links tests/test_roots.pas, which pulls in tls.roots and its
# {$R tlsroots.res}. The resource is committed, so no rule builds it here;
# check-roots-file (order-only, so it never forces a rebuild) only stops the
# run with a clear message when the file is missing, instead of letting fpc
# fail with "Can't open resource file".
$(TESTAPP): $(TESTUNITS) $(TESTS)/testrunner.lpr $(SOURCES) | check-roots-file
	@$(GMKDIR) $(TESTLIB) $(BIN)
	$(FPC) $(FPCFLAGS) -Fu$(TESTS) -FU$(TESTLIB) -FE$(BIN) $(TESTS)/testrunner.lpr

# Same runner built with heap tracing, so the leak checks can read heaptrc.
# Kept apart from `make test`: tracing makes the crypto suites very slow.
$(LEAKAPP): $(TESTUNITS) $(TESTS)/testrunner.lpr $(SOURCES) | check-roots-file
	@$(GMKDIR) $(LEAKLIB) $(BIN)
	$(FPC) $(LEAKFLAGS) -Fu$(TESTS) -FU$(LEAKLIB) -FE$(BIN) \
	  -o$(LEAKAPP) $(TESTS)/testrunner.lpr

leaktest: $(LEAKAPP)
	$(LEAKAPP) --suite=TCertVerifyTests --format=plain

# Regenerate certificate and DER fixtures. Requires `openssl` and `python3`.
# The key files produced here are git-ignored: they are test data only.
fixtures:
	./$(TESTS)/fixtures/gen_certs.sh

# --- Embedded roots: rules (task 19) ----------------------------------------

# Fail with instructions instead of a compiler puzzle when the committed
# resource is missing (a deleted file, a copy of src/ taken without it). Phony,
# so it is evaluated on every build; used order-only, so it never forces a
# rebuild.
check-roots-file:
	@if [ ! -f "$(ROOTSRES)" ]; then \
	  echo "ERROR: $(ROOTSRES) is missing, but src/tls.roots.pas links it with"; \
	  echo "       {\$$R}, which FPC resolves at compile time."; \
	  echo "       It is a committed file; restore it with"; \
	  echo "         git checkout -- $(ROOTSRES)"; \
	  echo "       or rebuild it from certs/ with 'make roots' (needs fpcres),"; \
	  echo "       or compile with -dTLS_NO_EMBEDDED_ROOTS to leave it out."; \
	  exit 1; \
	fi

# Regenerate the embedded trust table and the resource the library links.
# Deterministic: the same committed inputs give byte-identical output. Commit
# the new $(ROOTSRES) together with the snapshot and with the constants pinned
# in tests/test_roots.pas.
roots: $(ROOTSRES)

# Check that the committed resource still is what certs/ produces: regenerate
# into $(ROOTSTMP) and compare byte for byte. Needs fpcres, never writes
# $(ROOTSRES).
check-roots: $(ROOTSGEN) $(ROOTS_INPUTS) | check-fpcres
	@$(GMKDIR) $(ROOTSTMP)
	$(ROOTSGEN) --pem certs/roots.pem --date certs/roots.date \
	  --distrusted certs/distrusted.txt \
	  --out $(ROOTSTMP)/roots.bin --rc $(ROOTSTMP)/tlsroots.check.rc \
	  --res $(ROOTSTMP)/tlsroots.check.res --fpcres "$(FPCRES)"
	@if cmp -s "$(ROOTSRES)" "$(ROOTSTMP)/tlsroots.check.res"; then \
	  echo "OK: $(ROOTSRES) matches certs/"; \
	else \
	  echo "ERROR: $(ROOTSRES) is out of date with certs/."; \
	  echo "       Run 'make roots' and commit the result together with the"; \
	  echo "       constants pinned in tests/test_roots.pas."; \
	  exit 1; \
	fi

# Fail early — before the generator is compiled — with a message that says
# what to do, instead of a puzzle from a program that is not there.
check-fpcres:
	@if [ -z "$(FPCRES_FOUND)" ]; then \
	  echo "ERROR: $(FPCRES) not found: it is FPC's resource compiler and"; \
	  echo "       turns $(ROOTSRES) into a resource the linker accepts."; \
	  echo "       Install FPC (fpcres ships with it), or name the program:"; \
	  echo "         make roots FPCRES=/path/to/fpcres"; \
	  echo "       A host without fpcres can still build the library with"; \
	  echo "         -dTLS_NO_EMBEDDED_ROOTS"; \
	  echo "       the resource tests then report a skip."; \
	  exit 1; \
	fi

# The generator is a standalone program, never linked into the library, so it
# gets its own unit output directory.
$(ROOTSGEN): $(ROOTSGEN_DEPS)
	@$(GMKDIR) $(BUILD)/rootsgen $(BIN)
	$(FPC) $(FPCFLAGS) -FU$(BUILD)/rootsgen -FE$(BIN) tools/rootsgen/rootsgen.lpr

# PEM snapshot -> DER table + .rc -> src/tlsroots.res. check-fpcres is an
# order-only prerequisite: it runs first, but being phony it must not make the
# resource look out of date on every build. The result is a committed file, so
# this rule only runs when someone asks for it or when certs/ was changed by
# hand — and then the new resource belongs in the same commit as the snapshot.
$(ROOTSRES): $(ROOTSGEN) $(ROOTS_INPUTS) | check-fpcres
	@$(GMKDIR) $(ROOTSTMP)
	$(ROOTSGEN) --pem certs/roots.pem --date certs/roots.date \
	  --distrusted certs/distrusted.txt \
	  --out $(ROOTSTMP)/roots.bin --rc $(ROOTSTMP)/tlsroots.rc \
	  --res $(ROOTSRES) --fpcres "$(FPCRES)"

clean:
	rm -rf $(BUILD) $(BIN)
	rm -f $(SRC)/*.o $(SRC)/*.ppu $(TESTS)/*.o $(TESTS)/*.ppu
	rm -f $(TESTS)/tools/*.o $(TESTS)/tools/*.ppu
# $(ROOTSRES) is deliberately left alone: it is a committed source of the unit,
# not build output. Remove it only to force `make roots`.

.PHONY: all build test leaktest fixtures roots check-roots check-roots-file \
	check-fpcres example check-no-openssl clean
