#!/bin/sh
# Host-independent logic tests for the parser, the odometer and ID matching.
# These compile the REAL hwid.c and the REAL id_related() against a small shim,
# so they run anywhere gcc/clang does - no Windows needed.
set -e
cd "$(dirname "$0")"
cp ../src/hwid.c .
CC=${CC:-gcc}
$CC -std=gnu99 -Wall -fsanitize=address,undefined -I. -o logic_tests logic_tests.c hwid.c 2>/dev/null
$CC -std=gnu99 -Wall -fsanitize=address,undefined -I. -o coverage_test coverage_test.c hwid.c 2>/dev/null
$CC -std=gnu99 -Wall -fsanitize=address,undefined -o budget_test budget_test.c 2>/dev/null
$CC -std=gnu99 -Wall -fsanitize=address,undefined -o vidref_check vidref_check.c 2>/dev/null
$CC -std=gnu99 -Wall -fsanitize=address,undefined -o guard_check guard_check.c 2>/dev/null
$CC -std=gnu99 -Wall -fsanitize=address,undefined -o resweep_test resweep_test.c 2>/dev/null
$CC -std=gnu99 -Wall -fsanitize=address,undefined -o trust_test trust_test.c 2>/dev/null
$CC -std=gnu99 -Wall -fsanitize=address,undefined -I. -o pci_test pci_test.c hwid.c 2>/dev/null
$CC -std=gnu99 -Wall -fsanitize=address,undefined -o vendor_test vendor_test.c 2>/dev/null
$CC -std=gnu99 -Wall -fsanitize=address,undefined -I../src -o vendordb_test vendordb_test.c 2>/dev/null
python3 order_check.py
./logic_tests
./coverage_test
./budget_test
./vidref_check
./guard_check
./resweep_test
./trust_test
./pci_test
./vendor_test
./vendordb_test
rm -f hwid.c logic_tests coverage_test budget_test vidref_check guard_check resweep_test trust_test pci_test vendor_test vendordb_test
