.PHONY: all
all:
	cargo build
	cargo clippy
	cargo doc

.PHONY: test
test:
	cargo test -- --test-threads=1

.PHONY: testfips
testfips:
	cargo test --lib --bins --tests -- --test-threads=1

.PHONY: clean
clean:
	cargo clean
