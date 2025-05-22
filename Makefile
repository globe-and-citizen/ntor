lint:
	cargo clippy

run_tests:
	cargo test -- --show-output

fmt:
	cargo fmt --all