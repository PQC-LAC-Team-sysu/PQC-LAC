# Legacy vector provenance

These six `.dat` files are byte-for-byte copies of the supplied repository files
under `测试向量/{LAC_LIGHT,LAC192,LAC256}`. Each file contains the 48-byte header
seed followed by ten length-prefixed records. No LAC128 vector file was supplied.

The original vector driver's header seed does **not** reproduce its keypairs:
the DLL generated random bytes through a different random source. Consequently
the tests verify the recorded plaintexts, keys and ciphertexts rather than
claiming reproducible legacy key generation.

The legacy secret-key files contain nonzero, previously uninitialized reserved
bytes. The test adapter zeroes only `[4 * weight, dimension)` before calling the
new API. Production APIs reject noncanonical keys and do not silently migrate
these bytes.

Legacy KEM shared secrets use truncated `SHA256(message)`. V1 intentionally uses
truncated `SHA256(message || ciphertext)`; the tests verify the legacy secret,
byte-for-byte ciphertext re-encryption and the new secret independently.

| File | SHA-256 of original file |
|---|---|
| LAC_LIGHT/PKE_VEC_INFO.dat | f08ad5cfb5e39d0a0cc39cb7af08a0df1dd51b5297650c9dd6c3c32d63d49a4d |
| LAC_LIGHT/KEM_VEC_INFO.dat | 3d6e536a6c04e811b716472fb4737cbedd2d141c94f4326628fa451eacedd531 |
| LAC192/PKE_VEC_INFO.dat | 3f43c7ece9ac6d32200935e6f4bbaa5265d727421ddb2ca1bbe59f557001d941 |
| LAC192/KEM_VEC_INFO.dat | 6beb19347756367a679fb8e2743168bcaa8c056e41dfcff26d5188f3426bb094 |
| LAC256/PKE_VEC_INFO.dat | 7310c0d5b7a49e8fd67bdbc6c0e23ba6c2c2b91e6b7423b47d7b9351d14fcacc |
| LAC256/KEM_VEC_INFO.dat | b26f4be04269f61fa01f0104c6863d2e6bb6f156d8e7de8e729e3e4679559fef |
