#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="$repo_root/documents"

if [[ ! -d "$source_dir" ]]; then
  echo "Missing source documents directory: $source_dir" >&2
  exit 1
fi

targets=("$@")

if [[ ${#targets[@]} -eq 0 ]]; then
  while IFS= read -r -d '' artifact_dir; do
    targets+=("$(dirname "$artifact_dir")")
  done < <(
    find "$repo_root" \
      \( -path "$repo_root/.git" -o -path "$repo_root/reference_git_repos" -o -path "$repo_root/*/.venv" \) -prune -o \
      -type d -path "$repo_root/v*/artifacts" -print0
    find "$repo_root/exploit_from_v6" \
      -mindepth 2 -maxdepth 2 -type d -path "$repo_root/exploit_from_v6/submit_*/artifacts" -print0 2>/dev/null || true
  )
fi

if [[ ${#targets[@]} -eq 0 ]]; then
  echo "No version artifact directories found." >&2
  exit 1
fi

for target in "${targets[@]}"; do
  if [[ "$target" != /* ]]; then
    target="$repo_root/$target"
  fi

  artifact_dir="$target/artifacts"
  destination="$artifact_dir/documents"

  if [[ ! -d "$artifact_dir" ]]; then
    echo "Skipping $(realpath --relative-to="$repo_root" "$target"): missing artifacts/ directory" >&2
    continue
  fi

  rm -rf "$destination"
  mkdir -p "$artifact_dir"

  if command -v rsync >/dev/null 2>&1; then
    rsync -a "$source_dir/" "$destination/"
  else
    mkdir -p "$destination"
    cp -a "$source_dir/." "$destination/"
  fi

  echo "Synced $(realpath --relative-to="$repo_root" "$destination")"
done
