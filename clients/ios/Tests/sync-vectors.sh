#!/bin/sh
# Copies the canonical test vectors into the test bundle resources. SwiftPM copies symlinks as
# symlinks (dangling inside the bundle), so the files are duplicated here; run after regenerating
# spec/vectors.
set -e
cd "$(dirname "$0")"
rm -f SecureKeypadTests/vectors/*.json
cp ../../../spec/vectors/*.json SecureKeypadTests/vectors/
echo "synced $(ls SecureKeypadTests/vectors | wc -l | tr -d ' ') vectors"
