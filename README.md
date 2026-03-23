# LMS-CLI

A minimal command-line implementation of the **Leighton-Micali Signature (LMS)** scheme in C, including LM-OTS (one-time signatures) and SHA-256.

This tool allows you to generate keys, sign messages, verify signatures, and inspect key bundles.

---

## Features

* LMS (Merkle tree-based signature scheme)
* LM-OTS (one-time signatures)
* SHA-256 implementation (no external dependencies)
* Secure random generation via `getrandom()`
* File-based key bundle storage
* Protection against OTS key reuse (via `q` counter + file locking)

---

## Project Structure

```
src/
├── c/
│   ├── main.c        # CLI interface
│   ├── sha256.c      # SHA-256 implementation
│   ├── lm_ots.c      # LM-OTS logic
│   ├── lms.c         # LMS tree + signing + verification
│   ├── utils.c       # Utilities (I/O, randomness, conversions)
│   └── bundle.c      # Bundle storage (key file)
├── h/
│   ├── sha256.h
│   ├── lm_ots.h
│   ├── lms.h
│   ├── utils.h
│   └── bundle.h
└── o/                # Object files (generated)
```

---

## Build

Make sure you have `gcc` installed.

```bash
make
```

This produces:

```
lms-cli
```

To clean:

```bash
make clean
```

---

## Usage

### 1. Generate a Key Bundle

```bash
./lms-cli keygen bundle.lms
```

Creates:

* LMS keypair
* Merkle tree (stored for performance)
* Seed for LM-OTS keys

---

### 2. Sign a Message

```bash
./lms-cli sign bundle.lms message.bin signature.bin
```

* Automatically uses the next unused OTS key (`q`)
* Updates the bundle safely (with file locking)
* Prevents key reuse

---

### 3. Verify a Signature

```bash
./lms-cli verify bundle.lms signature.bin message.bin
```

Output:

```
Signature is valid
```

or

```
Signature is INVALID
```

---

### 4. Show Bundle Info

```bash
./lms-cli info bundle.lms
```

Displays:

* Identifier (`I`)
* Next available OTS index (`q`)
* Whether seed is stored
* Whether tree is stored
* Whether a previous signature exists

---

## Bundle Format

The bundle file contains:

* Magic header (`LMSB2026`)
* Version
* Identifier `I`
* Current OTS index (`next_q`)
* Public key
* Optional:

  * Seed (for private key regeneration)
  * Full Merkle tree (performance optimization)
  * Last signature

---

## Security Notes

* **Each OTS key must be used exactly once**
  This is enforced via the `q` counter.

* **Do not reuse a bundle across systems without synchronization**
  Otherwise, OTS key reuse may occur.

* **Seed must remain secret**
  It is used to derive all private keys.

* File locking (`flock`) is used during signing to prevent race conditions.

---

## Parameters

* Hash: SHA-256
* `N = 32` bytes
* `W = 8`
* `P = 34`
* Tree height: `10`
* Leaves: `1024`

---

## Signature Structure

```
LMS Signature =
    LMS type (4 bytes)
    q (4 bytes)
    LM-OTS signature
    authentication path (H * N bytes)
```

---

## Dependencies

* Standard C library
* Linux `getrandom()` syscall

---

## Limitations

* Linux-only (due to `getrandom()` and `flock`)
* No streaming support for large files
* Entire Merkle tree optionally stored (memory-heavy)
* No support for multiple parameter sets

---

## License

This project is licensed under the **GNU General Public License v3.0**.

---

## Notes

This implementation is intended for **educational and experimental use**.

While it follows the LMS/LM-OTS structure, it has **not been audited** and should not be used in production environments without a full security review.
