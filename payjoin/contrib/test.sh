#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin --verbose --all-features --lib
cargo test --locked --package payjoin --verbose --all-features --test integration
cargo test --locked --package payjoin --verbose --all-features --test bdk_integration_test
