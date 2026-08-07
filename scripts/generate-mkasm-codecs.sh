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
    cargo fmt --manifest-path "$generated/aarch64/Cargo.toml"
    cargo fmt --manifest-path "$generated/x86_64/Cargo.toml"
)

cp "$generated/aarch64/src/decoders.rs" "$repository/crates/macho/src/insn/codecs/aarch64/decoders.rs"
cp "$generated/aarch64/src/encoders.rs" "$repository/crates/macho/src/insn/codecs/aarch64/encoders.rs"
cp "$generated/aarch64/src/formatters.rs" "$repository/crates/macho/src/insn/codecs/aarch64/formatters.rs"
cp "$generated/aarch64/LICENSE" "$repository/crates/macho/src/insn/codecs/aarch64/LICENSE"
perl -0pi -e 's/use crate::decoders::/use super::decoders::/' \
    "$repository/crates/macho/src/insn/codecs/aarch64/formatters.rs"
cp "$generated/x86_64/LICENSE" "$repository/crates/macho/src/insn/codecs/x86_64/LICENSE"
cp "$generated/x86_64/src/lib.rs" "$repository/crates/macho/src/insn/codecs/x86_64/generated.rs"
