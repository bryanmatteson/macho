#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkasm_repository=${MKASM_REPOSITORY:-"$(dirname -- "$repository")/go-mkasm"}
arm_corpus=${ARM_CORPUS:-"https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-A64-ISA/ISA_A64/ISA_A64_xml_A_profile-2026-06.tar.gz"}

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /path/to/x86_64.json.xz" >&2
    exit 2
fi

x86_corpus=$1
generated=$(mktemp -d /tmp/macho-mkasm.XXXXXX)
trap 'rm -rf -- "$generated"' EXIT HUP INT TERM

(
    cd "$mkasm_repository"
    go run ./cmd/mkasm --codegen rust --output "$generated/aarch64" "$arm_corpus"
    xz -dc "$x86_corpus" |
        go run ./cmd/mkasm --arch x86_64 --codegen rust --output "$generated/x86_64" -
)

cp "$generated/aarch64/src/decoders.rs" "$repository/crates/mkasm-aarch64/src/decoders.rs"
cp "$generated/aarch64/src/encoders.rs" "$repository/crates/mkasm-aarch64/src/encoders.rs"
cp "$generated/aarch64/src/formatters.rs" "$repository/crates/mkasm-aarch64/src/formatters.rs"
cp "$generated/aarch64/LICENSE" "$repository/crates/mkasm-aarch64/LICENSE"
cp "$generated/x86_64/LICENSE" "$repository/crates/mkasm-x86-64/LICENSE"
cp "$generated/x86_64/src/lib.rs" "$repository/crates/mkasm-x86-64/src/generated.rs"
