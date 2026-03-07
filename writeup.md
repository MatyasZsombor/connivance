# Connivance — CTF Challenge Writeup

**Competition:** DACH CTF 2026  
**Category:** Reverse Engineering  
**Flag:** `dach2026{lE3t_R3V3RSe_MAsTER}`

---

## Table of Contents

1. [Challenge Overview](#1-challenge-overview)
2. [Initial Reconnaissance](#2-initial-reconnaissance)
3. [Static Analysis — The Binary](#3-static-analysis--the-binary)
4. [The TFL File Format](#4-the-tfl-file-format)
5. [VM Architecture](#5-vm-architecture)
6. [Reverse Engineering the Bytecode](#6-reverse-engineering-the-bytecode)
7. [Algorithm Discovery via Dynamic Analysis](#7-algorithm-discovery-via-dynamic-analysis)
8. [Designing the Solver](#8-designing-the-solver)
9. [The Layered Binary Search](#9-the-layered-binary-search)
10. [Flag](#10-flag)

---

## 1. Challenge Overview

We are given a Linux x86-64 binary `main` and a file `flag_checker.tfl`. Running it:

```
$ ./main flag_checker.tfl "dach2026{test_input_here}"
Incorrect!
```

The binary takes a TFL bytecode file and a flag candidate as arguments, runs the flag through a custom virtual machine, and prints `Correct!` or `Incorrect!`.

**Files provided:**

| File | Size | Description |
|------|------|-------------|
| `main` | 520 KB | ELF64 stripped binary |
| `flag_checker.tfl` | 1264 B | Encrypted VM bytecode |
| `hello_world.tfl` | 352 B | Example TFL file |
| `romfs/blob` | 1024 B | ROM filesystem blob |
| `romfs/blob.sig` | 257 B | Signature |
| `romfs/connivance.bin` | 2224 B | ROM binary |
| `romfs/damocles.bin` | 512 B | ROM binary |
| `romfs/dragonfly.bin` | 256 B | ROM binary |
| `romfs/map` | 80 B | Filesystem map |

---

## 2. Initial Reconnaissance

```bash
$ file main
main: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

$ checksec --file=main
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

No PIE — all addresses are fixed, which will make ptrace-based analysis easier. The binary is dynamically linked but quite large (520 KB), suggesting it embeds a significant amount of library code (confirmed later: mbedTLS is statically linked in).

The `.tfl` files start with the magic bytes `TINFOIL`:

```
$ xxd flag_checker.tfl | head -2
00000000: 5449 4e46 4f49 4c f0 190e 07 ...   TINFOIL.......
```

The remaining bytes after the 7-byte magic header are encrypted. The binary must decrypt the bytecode at runtime before executing it.

---

## 3. Static Analysis — The Binary

Opening `main` in a disassembler reveals it is structured as:

1. **Startup**: Parse arguments, read files from the `romfs/` directory
2. **Self-integrity check**: Compute a SHA hash over parts of its own code and the ROM files. If anything has been tampered with, it aborts silently. This is a significant anti-debug measure.
3. **TFL decryption + execution**: Decrypt the `.tfl` file and hand it to the VM interpreter
4. **Flag checking**: Run the VM program, which compares the user input against hardcoded expected values

Key addresses (no PIE, base `0x400000`):

| Address | Description |
|---------|-------------|
| `0x405120` | VM dispatch loop |
| `0x427720` | SHA-256 function |
| `0x414300` | `mbedtls_mpi_cmp_mpi` |
| `0x404150` | VM COMPARE opcode handler |
| `0x4067e0` | VM SHA opcode handler |
| `0x402490` | `printf@plt` (safe breakpoint — not covered by integrity check) |

### Anti-Debug

The binary computes a SHA-256 integrity hash over its own `.text` section and the ROM files at startup. Setting software breakpoints (which modify code bytes with `int3`) causes the integrity check to fail and the binary to abort.

**Workaround**: Use hardware breakpoints (`watch` in GDB, or `ptrace`-based `PEEKUSER`/`POKEUSER` with `DR0`/`DR7`) — these leave no code footprint.

---

## 4. The TFL File Format

The `.tfl` files are encrypted VM bytecode. After the `TINFOIL` magic header, the remaining bytes are decrypted by the binary during loading. Analysis of the decryption routine reveals:

- Format: `[magic:7]["TINFOIL"]` + `[encrypted_bytecode:N]`
- The decrypted bytecode is a flat array of **fixed-width 16-byte instructions**
- Each instruction: `[opcode:1][padding:7][operand_bytes:8]`

`flag_checker.tfl` contains **62 instructions** after decryption.

`hello_world.tfl` is a simpler program and useful for understanding the VM before tackling the flag checker.

---

## 5. VM Architecture

The VM is a **stack-based interpreter** with a small register file.

### Context Layout (on C stack)

The VM context (`rbx` = stack pointer in the dispatch loop at `0x405120`) holds:
- A stack of VM objects (heap-allocated, refcounted)
- A register file: an array of object pointers, accessed by index
- Comparison result register (set by COMPARE, read by conditional jumps)

### Object Model

VM values are heap-allocated 40-byte objects (`0x28` bytes):
```
offset +0x00: 8 bytes — flags/type
offset +0x08: 8 bytes — reference count
offset +0x10: 8 bytes — pointer to data buffer
offset +0x18: 8 bytes — data size (bytes)
offset +0x20: 8 bytes — allocated capacity
```

Objects are refcounted. Pushing clones a reference; dropping decrements the count and frees at zero.

### Instruction Set

| Opcode | Handler | Operation |
|--------|---------|-----------|
| `0x01` | `0x404520` | **NOT**: invert every byte of top object in-place |
| `0x0d` | `0x406550` | **SIZE**: pop object, push its size as an integer |
| `0x15` | `0x405f40` | **STORE**: pop top, save to `reg[operand]` |
| `0x17` | `0x404150` | **COMPARE**: `mbedtls_mpi_cmp_mpi(reg[op1], reg[op2])` |
| `0x19` | `0x404460` | **PUSH_LIT**: push literal bytes from bytecode operand field |
| `0x1c` | `0x404820` | **CJMP_EQ**: jump if last compare == 0 |
| `0x1d` | `0x406540` | **PUSH_INT**: push integer from instruction byte |
| `0x1e` | `0x406370` | **CLONE**: push a copy of the top object |
| `0x2f` | `0x4040b0` | **CJMP_NZ**: jump if last compare ≠ 0 |
| `0x39` | `0x404850` | **CONCAT**: pop A; append A's bytes after B (in-place on next stack item) |
| `0x3b` | `0x404920` | **OUTPUT**: print top object |
| `0x40` | `0x403ff0` | **JMP**: unconditional jump |
| `0x42` | `0x4067e0` | **SHA**: pop input object, push 32-byte SHA-256 hash |
| `0x4b` | `0x406660` | **LOAD**: push `reg[operand]` onto stack |
| `0x51` | `0x404590` | **SHR**: shift every byte right by 1 (`>>=1`) in-place |
| `0x5b` | `0x4063f0` | **NEW**: push a new empty object |
| `0x5e` | `0x406c50` | **STR_OPEN**: string construction helper |

---

## 6. Reverse Engineering the Bytecode

Disassembling the 62 decoded instructions from `flag_checker.tfl` reveals the following high-level logic:

```
1.  PUSH_LIT  "dach2026{"         ; push prefix
2.  STR_OPEN  <flag_arg>          ; push the user-supplied flag argument
3.  SIZE                          ; check flag length
4.  COMPARE   size, 29            ; flag must be exactly 29 bytes
5.  CJMP_NZ   → "Incorrect!"      ; fail if wrong length
6.  LOAD      reg[0]              ; load the 256-byte expected constant
7.  NOT                           ; NOT every byte of the flag
8.  STORE     reg[1]              ; save NOT(flag) to reg[1]

    ; --- 8 SHA rounds (k = 7 down to 0) ---
9.  for k in 7..0:
      LOAD    reg[1]              ; load NOT(flag) (not modified between rounds)
      CLONE                       ; make a working copy
      SHR × k                     ; shift each byte right by k (k times)
      SHA                         ; compute SHA-256 → 32 bytes
      CONCAT → accumulator        ; append hash to accumulator

10. COMPARE   accumulator, reg[0] ; compare 256-byte result with expected
11. CJMP_EQ   → "Correct!"
12. OUTPUT    "Incorrect!"
```

**Key observations:**
- The flag is 29 bytes: `dach2026{` (9) + 19 inner characters + `}` (1)
- The VM applies bitwise NOT to the entire flag first
- It then computes 8 SHA-256 hashes, one per shift level k = 7, 6, …, 0
- The hashes are concatenated to form a 256-byte value that must match a hardcoded constant

---

## 7. Algorithm Discovery via Dynamic Analysis

Static analysis of the bytecode left several questions open (CONCAT direction, exact SHA IVs, flag length). We used `ptrace`-based hardware breakpoints to observe the VM in action without triggering the anti-debug self-check.

### Technique: ptrace Hardware Breakpoints

```c
// Set DR0 = target address, DR7 = 1 (enable BP0, execute)
ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[0]), address);
ptrace(PTRACE_POKEUSER, pid, offsetof(struct user, u_debugreg[7]), 1UL);
```

Hardware breakpoints do not modify code bytes, so the SHA integrity check is not triggered.

### Confirming the SHA Variant

By tracing calls to the SHA handler at `0x4067e0`, we captured the input and output for a known test flag `dach2026{aaaaaaaaaaaaaaaaaaa}`. Comparing against `hashlib.sha256` in Python:

```python
import hashlib
test = bytes([0x01] * 29)   # NOT(flag) >> 7 for 'a'-filled flag
got  = sha_vm(test)          # traced from binary
std  = hashlib.sha256(test).digest()
print(got == std)  # True
```

The VM uses **standard SHA-256** — no custom IV or custom compression. The initial code analysis that identified "rotated IVs" was caused by reading two adjacent data arrays at slightly the wrong offset.

### Confirming the Algorithm

Traced SHA calls for `"dach2026{aaaaaaaaaaaaaaaaaaa}"`:

```
SHA call 1 input  (k=0): 9b9e9c97cdcfcdc9849e9e9e...9e82  (= NOT(flag))
SHA call 1 output:        9e3248abd98bd1c3...

SHA call 2 input  (k=1): 4d4f4e4b66676664424f4f4f...4f41  (= NOT(flag)>>1)
SHA call 2 output:        4527dfe43dbfffcd...
...
SHA call 8 input  (k=7): 0101010101010101010101...0101  (= NOT(flag)>>7)
SHA call 8 output:        993c36a18400df7a...
```

The 256-byte comparison value captured at the COMPARE opcode:

```
A (expected constant): 993c36a1 8400df7a ... 561a8569 ... 236b770f ...
B (computed for 'a's): 993c36a1 8400df7a ... 9e3248ab ... (differs from A)
```

This confirmed the exact assembly order:

```
B[0:32]   = sha256(NOT(flag) >> 7)
B[32:64]  = sha256(NOT(flag) >> 6)
B[64:96]  = sha256(NOT(flag) >> 5)
B[96:128] = sha256(NOT(flag) >> 4)
B[128:160]= sha256(NOT(flag) >> 3)
B[160:192]= sha256(NOT(flag) >> 2)
B[192:224]= sha256(NOT(flag) >> 1)
B[224:256]= sha256(NOT(flag) >> 0)
```

B must equal the hardcoded 256-byte constant:

```
99 3c 36 a1 84 00 df 7a  b6 1f e4 71 34 37 cb 9a   [0:16]   ← sha(NOT>>7)
b3 29 47 d6 b4 b9 bc 31  9c f5 80 90 43 bd 7a df   [16:32]
f4 b6 e9 11 2c 04 ed 73  8a 81 81 13 1c 3b 8c 58   [32:48]  ← sha(NOT>>6)
f2 cb d5 fd 5d f4 64 81  e4 b9 ad 0c 68 fd 01 88   [48:64]
54 bc 8a 04 e5 27 72 62  43 01 93 b8 be 73 6c 77   [64:80]  ← sha(NOT>>5)
0a 3b 08 9e 48 63 ac 81  b9 df 6b 87 09 00 fb e4   [80:96]
4e 79 17 20 06 11 eb d0  9a 45 9c b0 d8 98 bf 91   [96:112] ← sha(NOT>>4)
37 7c af 65 a7 bf 0a 68  4a 1a d8 1e d7 17 06 b1   [112:128]
b7 6a f9 c2 08 9c dc af  26 43 2c e7 34 90 5b b4   [128:144]← sha(NOT>>3)
39 29 74 de 7d 89 f9 de  f8 3c aa 5c 0a 7b 19 38   [144:160]
bc 9a c2 ac 2c 4e 4b 2a  05 9e c5 08 4a ed 74 52   [160:176]← sha(NOT>>2)
fd 90 74 c6 2f 54 64 0c  9e 1d 60 31 11 6e 46 6d   [176:192]
31 0b 06 b4 64 40 23 12  93 ae 39 85 66 12 c6 34   [192:208]← sha(NOT>>1)
d3 be 3f 2f 65 13 58 2e  86 fe 4a 42 60 97 38 93   [208:224]
56 1a 85 69 49 62 01 26  62 3b c8 84 47 2a a4 e8   [224:240]← sha(NOT>>0)
23 6b 77 0f af 1c 70 e3  62 bc 8b 8f a8 55 9d 70   [240:256]
```

---

## 8. Designing the Solver

### Why Brute Force Fails

The flag has 19 unknown inner characters. Even with a restricted charset (`[a-zA-Z0-9_]` — 63 characters), the search space is 63^19 ≈ 10^34. This is completely intractable.

### Key Observation: Shift Collapses Entropy

At shift level k, `NOT(c) >> k` maps each byte `c` to a value in the range `[0, 255 >> k]`. For k=6, there are only 4 possible output values (0, 1, 2, 3). This means:

- Each inner character contributes only **1 bit of information** to the k=6 SHA input
- With 19 inner positions, the k=6 SHA input is determined by a **19-bit mask**
- There are only 2^19 = 524,288 possible SHA inputs at k=6

At k=5, there are 8 possible values → still just 3 bits per position, but after fixing the k=6 result, we only need to determine which half of each current group each character belongs to — again a **2^19 enumeration**.

This gives us a clean **layered binary search** strategy.

---

## 9. The Layered Binary Search

### Algorithm

We track, for each of the 19 inner positions, a **character range** `[lo, hi]` (initially `[0x00, 0x7f]` — printable ASCII).

At each level k (from 6 down to 0):

1. **Build 2^19 candidate SHA inputs**: for each of the 2^19 bit patterns, map bit=0 to the *low half* of the current range, bit=1 to the *high half*.
2. **Compute SHA-256** of each 29-byte candidate input (with fixed prefix `NOT("dach2026{")>>k` and suffix `NOT("}")>>k`).
3. **Find the unique match** against the expected target block `EXPECTED[k-block * 32 : (k-block+1) * 32]`.
4. **Narrow the range**: for each position, keep only the half that corresponds to the matched bit.

After 7 levels (k=6 down to k=0), each range has been halved 7 times from 128 → 1, uniquely identifying each inner character.

### Why It Works

Because SHA-256 is a collision-resistant hash function, there is exactly one 19-bit mask that produces each expected 32-byte output. This gives us a unique sequence of binary decisions that narrows each position from 128 possible values down to exactly 1.

### Complexity

```
7 levels × 2^19 SHA computations per level = 7 × 524,288 ≈ 3.7 million SHA-256 calls
```

Each call hashes 29 bytes = exactly one SHA-256 block (after padding to 64 bytes). Total runtime: **≈ 0.6 seconds**.

Compare this to the direct brute force: even with a 63-character charset, 63^19 ≈ 10^34 tries — physically impossible.

### Example Solver Output

```
$ ./solver
Connivance CTF flag solver
==========================

Algorithm: B = sha256(NOT(flag)>>7) || ... || sha256(NOT(flag)>>0)
Flag length: 29 bytes  (19 inner chars)

Level k=6: finding digit/non-digit pattern...
  mask=0x7febb
Level k=5: refining groups...
  mask=0x0894d
Level k=4: refining groups...
  mask=0x597fc
Level k=3: refining groups...
  mask=0x3011
Level k=2: refining groups...
  mask=0x3389b
Level k=1: refining groups...
  mask=0x497f4
Level k=0: finding exact characters...
  mask=0x2fd56

FLAG: dach2026{lE3t_R3V3RSe_MAsTER}
```

### Building and Running the Solver

```bash
gcc -O2 -o solver solver.c
./solver
```

No external dependencies required (SHA-256 is implemented inline in `solver.c`).

---

## 10. Flag

```
dach2026{lE3t_R3V3RSe_MAsTER}
```

Verified:

```bash
$ ./main flag_checker.tfl "dach2026{lE3t_R3V3RSe_MAsTER}"
Correct!
```

---

## Appendix: Lessons Learned

**1. Hardware breakpoints bypass self-integrity checks.**  
Software breakpoints (`int3`) modify code bytes that are covered by the hash check. Hardware breakpoints via `ptrace`/`DR0`/`DR7` leave no memory footprint and bypass the protection entirely.

**2. Dynamic analysis was essential.**  
The SHA initial values appeared rotated in static analysis because two adjacent data arrays were misidentified. Running the binary under ptrace and comparing the observed output against `hashlib.sha256` immediately confirmed standard SHA-256 is used.

**3. Exploit structure, not brute force.**  
The right-shift operation that appears in the algorithm is not just obfuscation — it leaks the structure of the problem. Each shift level acts as a lossy projection that reduces the search space from 128^19 to 2^19 per level.

**4. Read the flag format carefully.**  
Initial analysis assumed the flag was 17 bytes (7 inner chars) based on a misread of the VM constant. Dynamic capture of the COMPARE operands revealed the flag was actually 29 bytes (19 inner chars), which changed the entire approach.
