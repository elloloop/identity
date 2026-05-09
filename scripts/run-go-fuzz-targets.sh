#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <fuzztime>" >&2
  exit 2
fi

fuzztime="$1"
report_dir="${GO_FUZZ_REPORT_DIR:-}"
report=""

if [[ -n "$report_dir" ]]; then
  mkdir -p "$report_dir"
  report="$report_dir/fuzz-targets.md"
  {
    echo "### Go fuzz targets"
    echo
    echo "Fuzz time per target: \`$fuzztime\`"
    echo
  } > "$report"
fi

finish_report() {
  if [[ -n "$report" ]]; then
    cat "$report"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
      cat "$report" >> "$GITHUB_STEP_SUMMARY"
    fi
  fi
}

mapfile -t targets < <(
  grep -rEn \
    --include='*_test.go' \
    --exclude-dir=.claude \
    --exclude-dir=.git \
    --exclude-dir=.idea \
    --exclude-dir=.vscode \
    --exclude-dir=node_modules \
    --exclude-dir=vendor \
    '^func (Fuzz[A-Za-z0-9_]+)\(' . \
    | sed -E 's|^(.*)/[^/]+:[0-9]+:func (Fuzz[A-Za-z0-9_]+).*$|\1\t\2|' \
    | sort -u
)

if [[ ${#targets[@]} -eq 0 ]]; then
  echo "no fuzz targets - skipping"
  if [[ -n "$report" ]]; then
    echo "No fuzz targets were discovered." >> "$report"
    finish_report
  fi
  exit 0
fi

for entry in "${targets[@]}"; do
  dir="${entry%$'\t'*}"
  dir="${dir#./}"
  name="${entry##*$'\t'}"
  echo "::group::fuzz $name in $dir"
  set +e
  go test -run='^$' -fuzz="^${name}$" -fuzztime="$fuzztime" "./$dir"
  status=$?
  set -e
  echo "::endgroup::"

  if [[ "$status" -eq 0 ]]; then
    if [[ -n "$report" ]]; then
      echo "- \`./$dir\` \`$name\`: passed" >> "$report"
    fi
    continue
  fi

  if [[ -n "$report" ]]; then
    echo "- \`./$dir\` \`$name\`: failed" >> "$report"
    finish_report
  fi
  exit "$status"
done

finish_report
