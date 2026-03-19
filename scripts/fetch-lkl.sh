#!/bin/sh
# SPDX-License-Identifier: MIT
# Fetch prebuilt liblkl.a from GitHub Releases or Actions artifacts.
#
# Usage: ./scripts/fetch-lkl.sh [ARCH]
#   ARCH defaults to x86_64.  Override LKL_DIR to change output directory.
#
# Download order:
#   1. GitHub Releases (curl, no auth needed)
#   2. GitHub CLI (gh) Actions artifacts
#   3. Manual instructions

set -eu

ARCH="${1:-x86_64}"
LKL_DIR="${LKL_DIR:-lkl-${ARCH}}"
REPO="${KBOX_REPO:-lkl/linux}"
ASSET="liblkl-${ARCH}.tar.gz"
SHA256_FILE="scripts/lkl-sha256.txt"

die() {
    echo "error: $*" >&2
    exit 1
}

mkdir -p "$LKL_DIR"

# Already present?
if [ -f "${LKL_DIR}/liblkl.a" ]; then
    echo "OK: ${LKL_DIR}/liblkl.a (already exists)"
    exit 0
fi

# --- Method 1: GitHub Releases (curl, no auth) ---
try_release() {
    if ! command -v curl > /dev/null 2>&1; then
        return 1
    fi

    echo "Querying latest lkl-v* release from ${REPO}..."
    TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases" \
        | grep -o '"tag_name": *"lkl-v[^"]*"' \
        | head -1 \
        | sed 's/.*"lkl-v/lkl-v/; s/"//' 2> /dev/null) || return 1

    if [ -z "$TAG" ]; then
        echo "No lkl-v* release tag found."
        return 1
    fi

    URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
    echo "Downloading ${URL}..."
    curl -fSL -o "${LKL_DIR}/${ASSET}" "$URL" || return 1

    # Verify SHA256 if pinfile exists.
    if [ -f "$SHA256_FILE" ]; then
        EXPECTED=$(grep "$ASSET" "$SHA256_FILE" | awk '{print $1}')
        if [ -n "$EXPECTED" ]; then
            ACTUAL=$(sha256sum "${LKL_DIR}/${ASSET}" | awk '{print $1}')
            if [ "$ACTUAL" != "$EXPECTED" ]; then
                rm -f "${LKL_DIR}/${ASSET}"
                die "SHA256 mismatch for ${ASSET}"
            fi
            echo "SHA256 verified."
        fi
    fi

    tar xzf "${LKL_DIR}/${ASSET}" -C "$LKL_DIR"
    rm -f "${LKL_DIR}/${ASSET}"
    return 0
}

# --- Method 2: gh CLI (Actions artifacts) ---
try_gh() {
    if ! command -v gh > /dev/null 2>&1; then
        return 1
    fi

    echo "Fetching liblkl.a (${ARCH}) via gh CLI..."
    ARTIFACT_NAME="lkl-${ARCH}"

    gh run download --repo "$REPO" \
        --name "$ARTIFACT_NAME" \
        --dir "$LKL_DIR" 2> /dev/null && return 0

    echo "Direct download failed. Trying latest workflow run..."
    RUN_ID=$(gh run list --repo "$REPO" \
        --workflow "push.yml" \
        --status completed \
        --limit 1 \
        --json databaseId \
        --jq '.[0].databaseId' 2> /dev/null) || return 1

    gh run download "$RUN_ID" \
        --repo "$REPO" \
        --name "$ARTIFACT_NAME" \
        --dir "$LKL_DIR" || return 1

    return 0
}

# Try methods in order.
if try_release; then
    :
elif try_gh; then
    :
else
    cat >&2 << EOF
Cannot fetch liblkl.a automatically.

Manual download options:
  1. GitHub Releases: check https://github.com/${REPO}/releases
     for lkl-v* tags, download ${ASSET}, extract into ${LKL_DIR}/
  2. GitHub CLI: install gh from https://cli.github.com/
     then re-run this script
  3. Build from source: see https://github.com/${REPO}

EOF
    exit 1
fi

if [ -f "${LKL_DIR}/liblkl.a" ]; then
    echo "OK: ${LKL_DIR}/liblkl.a"
else
    die "Download succeeded but liblkl.a not found in ${LKL_DIR}/"
fi
