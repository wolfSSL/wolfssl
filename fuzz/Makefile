CC       = ./clang
CFLAGS   = -g -fsanitize=address,array-bounds,null,return,shift -fsanitize-coverage=trace-pc-guard -I.

CXX      = ./clang++
CXXFLAGS = $(CFLAGS) -std=c++11

LDFLAGS  = -L.
LDLIBS   = -lwolfssl -lFuzzer

PYTHON   = python2

libFuzzer  = libFuzzer.a
fuzzer_dir = Fuzzer
fuzzer_src = https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer

new_clang      = new_clang
clang_tool_src = https://chromium.googlesource.com/chromium/src/tools/clang
clang_dir      = $(new_clang)/clang/clang
clang_tool     = $(clang_dir)/scripts/update.py
clang_bin      = $(new_clang)/third_party/llvm-build/Release+Asserts/bin/

src = $(wildcard *.c)
out = $(patsubst %.c,%,$(src))

all: deps $(out)                # make all
deps: $(CC) $(CXX) $(libFuzzer) # dependencies
dependencies: deps              # deps alias
%: %.c                          # cancel the implicit rule
%: %.cc                         # cancel the implicit rule
.PHONY: clean spotless          # .PHONYs



# libFuzzer

$(fuzzer_dir):
	@echo -e "\nRetrieving libFuzzer...\n"
	@git clone $(fuzzer_src) $@ --depth 1

$(libFuzzer): $(fuzzer_dir)
	@bash $</build.sh
	@echo -e "\nlibFuzzer retrieved!\n"



# clang

$(clang_tool):
	@echo -e "\nRetrieving new clang binaries...\n"
	@git clone $(clang_tool_src) $(clang_dir) --depth 1

$(clang_bin): $(clang_tool)
	@$(PYTHON) $<
	@touch $@ #to prevent make from always running this rule
	@echo -e "\nClang retrieved!\n"

$(clang_bin)/$(CC): $(clang_bin)
$(clang_bin)/$(CXX): $(clang_bin)

$(CC): $(clang_bin)/$(CC)
	@ln -s $< $@
$(CXX): $(clang_bin)/$(CXX)
	@ln -s $< $@



# actual source code

%.o: %.c
	@echo "CC	$<	-o $@"
	@$(CC) -c $< $(CFLAGS) -o $@

%: %.o
	@echo "C++	$<	-o $@"
	@$(CXX) $< $(CXXFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

clean:
	@rm -f $(out)
	@echo "Cleaned!"
spotless:
	@rm -rf $(fuzzer_dir) $(libFuzzer) $(new_clang) $(CC) $(CXX) $(out)
	@echo "Cleaned harder!"
