#!/bin/sh
set -eu
[ -s cover.out ] || { echo "coverage gate: cover.out is missing or empty; refusing to pass vacuously" >&2; exit 1; }
go tool cover -func=cover.out | awk '
  /^total/ {
    found = 1
    gsub("%", "", $3)
    if ($3 + 0 < 100.0) {
      printf "coverage %.1f%% < 100%%\n", $3
      bad = 1
    }
  }
  END {
    if (!found) {
      print "coverage gate: no total line in go tool cover output" > "/dev/stderr"
      exit 1
    }
    if (bad) exit 1
    print "coverage 100%"
  }'
