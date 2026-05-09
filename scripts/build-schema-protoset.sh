#!/usr/bin/env bash
#
# build-schema-protoset.sh
#
# Compiles proto/identity/schema/schema.proto into a self-contained
# FileDescriptorSet (.protoset) at gen/schema/identity.protoset.
#
# The output is consumable by the upstream EntDB CLI when its
# data-plane subcommands need a per-request schema descriptor:
#
#     entdb get   --proto-descriptor=gen/schema/identity.protoset ...
#     entdb put   --proto-descriptor=gen/schema/identity.protoset ...
#     entdb query --proto-descriptor=gen/schema/identity.protoset ...
#
# It does NOT register the schema with EntDB (the SDK has no
# RegisterSchema method as of this writing — see internal/app/schema.go
# for the gap doc).
#
# Requirements:
#   - protoc on PATH
#
# Usage:
#   ./scripts/build-schema-protoset.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

OUT_DIR="gen/schema"
mkdir -p "${OUT_DIR}"

protoc \
	--proto_path=proto \
	--include_imports \
	--include_source_info \
	--descriptor_set_out="${OUT_DIR}/identity.protoset" \
	proto/identity/schema/schema.proto

echo "wrote ${OUT_DIR}/identity.protoset"
