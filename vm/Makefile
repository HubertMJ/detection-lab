# Reproducible build of the lab canary (variant B test program). The copy-1 image (marker all
# zero) must hash the same every build so the known-hash rule can pin it, so the flags are fixed
# and deterministic: static (no dynamic libc path), no PIE, stripped, no unwind tables, and a
# normalised __FILE__ / build epoch. Build it in ONE pinned toolchain (the CI image); a different
# gcc/libc yields a different, equally valid copy-1 hash that must then be re-pinned in the rule.
CC ?= gcc
SOURCE_DATE_EPOCH ?= 0
CFLAGS := -O2 -static -no-pie -s -fno-asynchronous-unwind-tables \
          -ffile-prefix-map=$(CURDIR)=. -Wall -Wextra -Werror
OUT := dist/lab-canary

.PHONY: all clean hash
all: $(OUT)

$(OUT): scenario.c Makefile
	@mkdir -p dist
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(CC) $(CFLAGS) -o $(OUT) scenario.c
	@sha256sum $(OUT) | awk '{print $$1}' > $(OUT).sha256
	@echo "copy-1 sha256: $$(cat $(OUT).sha256)"

hash: $(OUT)
	@cat $(OUT).sha256

clean:
	rm -rf dist
