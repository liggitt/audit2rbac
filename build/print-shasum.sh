#!/bin/bash

root="$(dirname "${BASH_SOURCE}")/../bin"

echo "filename | sha256 hash"
echo "-------- | -----------"
for file in $(find $root -name *.tar.gz); do
  echo "$(basename $file) | $(shasum -b -a 256 $file | cut -f 1 -d ' ')"
done
