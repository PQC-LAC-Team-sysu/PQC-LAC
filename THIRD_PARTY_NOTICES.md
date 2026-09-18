# Third-party source notices

The existing root `LICENSE` is preserved from the CLion project. It does not
replace the licenses attached to third-party or derived files below.

## BCH implementation

`lib/lac/bch.hpp`, `lib/lac/bch.cpp`, and `lib/lac/bch_tables.hpp` are adapted from
the supplied LAC binary BCH library and its parameter tables. The supplied
`bch.h` identifies:

- Copyright (C) 2011 Parrot S.A.
- Author: Ivan Djelic <ivan.djelic@parrot.com>
- GNU General Public License version 2 (GPL-2.0-only).

The original attribution and GPL notice are retained in the rewritten source.
The license text is included as `LICENSES/GPL-2.0.txt`. The C++ changes include
immutable parameter tables, fixed workspaces, explicit endian handling, and a
bounded Berlekamp–Massey/Chien decoder. These files are not relabeled as MIT.

## AES-NI test reference

`tests/legacy/aes256ctr.c` and `.h` are copied from the supplied LAC project.
The source states that it is based heavily on public-domain code by Romain
Dolbeau and carries a Public Domain notice. The reference is linked only when
`LAC_TEST_LEGACY_AES` is enabled; production LAC uses OpenSSL instead.

## Test vectors and algorithm provenance

`tests/data/` contains six unchanged vector files from the supplied LAC project.
Their origins, hashes, test-only secret-key normalization and transcript
differences are recorded in `tests/data/README.md`. No additional ownership or
license grant for the supplied vectors or LAC algorithm source is asserted here.

OpenSSL is an external dependency selected by CMake. Its own notices remain
part of its installation and distribution.
