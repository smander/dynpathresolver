# Master Makefile for all benchmarks

BENCHMARKS = \
	01_simple_dlopen \
	02_environment_path \
	03_xor_encrypted \
	04_computed_path \
	05_multi_stage

.PHONY: all clean $(BENCHMARKS)

all: $(BENCHMARKS)

$(BENCHMARKS):
	@echo "Building $@..."
	@$(MAKE) -C $@ all

clean:
	@for bench in $(BENCHMARKS); do \
		echo "Cleaning $$bench..."; \
		$(MAKE) -C $$bench clean; \
	done

# Build specific benchmark
build-%:
	$(MAKE) -C $* all

# Run specific benchmark
run-%:
	cd $* && ./test_binary
