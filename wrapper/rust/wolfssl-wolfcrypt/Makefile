FEATURES := rand_core,aead,cipher,digest,signature
CARGO_FEATURE_FLAGS := --features $(FEATURES)

.PHONY: all
all:
	cargo build $(CARGO_FEATURE_FLAGS)
	cargo clippy $(CARGO_FEATURE_FLAGS)
	cargo doc $(CARGO_FEATURE_FLAGS)

.PHONY: test
test:
	cargo test $(CARGO_FEATURE_FLAGS) -- --test-threads=1

.PHONY: testfips
testfips:
	cargo test $(CARGO_FEATURE_FLAGS) --lib --bins --tests -- --test-threads=1

.PHONY: clean
clean:
	cargo clean
