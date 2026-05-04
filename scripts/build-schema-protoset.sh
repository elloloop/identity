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
#   - The tenant-shard-db-go checkout under ../opensource/, OR
#     ENTDB_PROTO_PATH set to a directory containing entdb_options.proto.
#
# Usage:
#   ./scripts/build-schema-protoset.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."

# Locate entdb_options.proto. Prefer an explicit override, fall back
# to the conventional sibling checkout, and stage it under entdb/ so
# the import path "entdb/entdb_options.proto" resolves.
if [[ -n "${ENTDB_PROTO_PATH:-}" ]]; then
	ENTDB_OPTIONS_SRC="${ENTDB_PROTO_PATH}/entdb_options.proto"
else
	ENTDB_OPTIONS_SRC="${HOME}/projects/opensource/tenant-shard-db-go/sdk/entdb_sdk/proto/entdb_options.proto"
fi

if [[ ! -f "${ENTDB_OPTIONS_SRC}" ]]; then
	echo "error: entdb_options.proto not found at ${ENTDB_OPTIONS_SRC}" >&2
	echo "       set ENTDB_PROTO_PATH to override" >&2
	exit 1
fi

INC_DIR="$(mktemp -d)"
trap 'rm -rf "${INC_DIR}"' EXIT
mkdir -p "${INC_DIR}/entdb"
cp "${ENTDB_OPTIONS_SRC}" "${INC_DIR}/entdb/entdb_options.proto"

OUT_DIR="gen/schema"
mkdir -p "${OUT_DIR}"

protoc \
	--proto_path=proto \
	--proto_path="${INC_DIR}" \
	--include_imports \
	--include_source_info \
	--descriptor_set_out="${OUT_DIR}/identity.protoset" \
	proto/identity/schema/schema.proto

echo "wrote ${OUT_DIR}/identity.protoset"
