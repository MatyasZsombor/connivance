## CTF Challenge "connivance" — Full Analysis Summary (ACSC 2026)

---

### 1. Challenge Structure

**Files:**
- main — ELF64 binary, no PIE (`0x400000` base), statically linked with mbedTLS
- flag_checker.tfl — encrypted VM bytecode (1264 bytes, `TINFOIL` magic header)
- hello_world.tfl — second TFL file (352 bytes, same format)
- blob (1024B), blob.sig (257B), map (80B)
- connivance.bin (2224B), damocles.bin (512B), dragonfly.bin (256B)

**Goal:** Find flag `dach2026{XXXXXXX}` — **7 unknown characters confirmed** (flag object size = `0x11` = 17 bytes total).

---

### 2. Anti-Debug

- SHA-256 self-check over maps at startup — patching/tracing the binary causes it to abort
- Hardware breakpoints fail silently
- **Safe breakpoints**: `printf@plt` (`0x402490`), `fread@plt` (`0x402780`) — these are in the PLT, not covered by the self-check

---

### 3. VM Architecture

- **Dispatch loop**: `0x405120`; context pointer = C stack pointer (`0x4051b2: mov %rsp, %rbx`)
- **Bytecode**: 62 instructions × 16 bytes, loaded at runtime to `0x497860` (decrypted from flag_checker.tfl)
- **Instruction format**: `[opcode:1][padding:7][operand:8]` (16 bytes total)
- **VM stack**: grows downward from `rbx+0x20`

**Key handler table (opcode → function):**

| Opcode | Address | Operation |
|--------|---------|-----------|
| `0x01` | `0x404520` | NOT every byte (`not %ebp` in loop) |
| `0x0d` | `0x406550` | PUSH SIZE: peek top object, push its size as integer |
| `0x15` | `0x405f40` | STORE to register `reg[n]` |
| `0x17` | `0x404150` | COMPARE (`mbedtls_mpi_cmp_mpi`) |
| `0x19` | `0x404460` | PUSH LITERAL from bytecode operand |
| `0x1c` | `0x404820` | CONDITIONAL JUMP (if compare == 0) |
| `0x1d` | `0x406540` | PUSH IMMEDIATE integer from `instr[8]` |
| `0x1e` | `0x406370` | PUSH CLONE of top object |
| `0x2f` | `0x4040b0` | CJMP IF NONZERO: jump by `instr[8]-1` if compare ≠ 0 |
| `0x39` | `0x404850` | CONCAT: pop A, peek B, append A after B in-place |
| `0x3b` | `0x404920` | OUTPUT (print) |
| `0x40` | `0x403ff0` | JUMP unconditional |
| `0x42` | `0x4067e0` | SHA hash (custom SHA-256, 32-byte output) |
| `0x4b` | `0x406660` | LOAD from register `reg[n]` |
| `0x51` | `0x404590` | SHIFT RIGHT: each byte `>>= 1` in-place |
| `0x5b` | `0x4063f0` | PUSH NEW empty object |
| `0x5e` | `0x406c50` | STRING_OPEN / concat with strlen check |

**Helper functions:**
- `0x40e970`: `return obj->data_ptr` (obj+0x10)
- `0x40e980`: `return obj->size` (obj+0x18)
- `0x40e8d0`: clone/copy object (alloc 0x28 bytes)
- `0x409cd0`: `obj->refcount++` (addref)
- `0x409ce0`: `obj->refcount--`, free if zero (release)
- `0x406490`: alloc 0x28-byte obj, copy 8-byte value from rsi, push to VM stack

---

### 4. Algorithm (VM Bytecode Logic)

The flag checker runs 7 rounds. In each round `k` (1 → 7):
1. Clone `reg[1]` (the working buffer)
2. Shift every byte right by 1 (`>>= 1`) — **cumulative**, so round 7 has been shifted 7× total
3. Compute SHA (custom variant) → 32-byte hash
4. **CONCAT**: hash becomes `sha_result || old_reg[1]` (prepend hash before accumulated buffer)
5. Store back to `reg[1]`

Final `reg[1]` layout (240 bytes):
```
[0:32]   = sha(flag >> 7)  ← most-shifted, 7× shift
[32:64]  = sha(flag >> 6)
[64:96]  = sha(flag >> 5)
[96:128] = sha(flag >> 4)
[128:160]= sha(flag >> 3)
[160:192]= sha(flag >> 2)
[192:224]= sha(flag >> 1)  ← least-shifted, 1× shift
[224:240]= initial 16-byte seed
```

Then `reg[1]` is compared with `reg[0]` using `mbedtls_mpi_cmp_mpi`.

> **⚠️ CRITICAL UNRESOLVED ISSUE**: Testing confirms that `sha(zeros × 17)` = `e08379de...` does NOT appear anywhere in the expected 240 bytes. After 7 right-shifts, all standard ASCII flag characters (`dach2026{...}`) become `0x00`. This means the expected layout above may have the order **reversed** (EXPECTED[0:32] = `sha(flag>>1)`, EXPECTED[192:224] = `sha(flag>>7)`), **OR** the CONCAT is `old_reg[1] || sha_result` (append rather than prepend). This needs verification by re-examining the CONCAT opcode `0x39` handler at `0x404850` more carefully. The algorithm understanding may have the prepend/append direction wrong.

---

### 5. Custom SHA-256

Standard SHA-256 **with rotated initial hash values** — IVs shifted by 4 positions:

```
Standard:  [h0, h1, h2, h3, h4, h5, h6, h7]
Custom:    [h4, h5, h6, h7, h0, h1, h2, h3]
```

Concrete values (little-endian 32-bit words):
```c
static const uint32_t CUSTOM_H0[8] = {
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
};
```

SHA function at `0x427720`. SHA handler at `0x4067e0`. Everything else (K constants, compression function, padding) is **standard SHA-256**.

---

### 6. Expected 240 Bytes (reg[0] data at `0x499400` at runtime)

```
31 31 8e b9 29 49 ce fb  da ca 83 b6 b2 63 f6 06   [0:16]
d1 e3 51 2c 06 2d 07 93  02 6b 99 d2 80 79 8b f2   [16:32]
3a 8a 28 d2 0f a8 ea b1  03 59 c8 d0 f6 17 30 40   [32:48]
69 93 f6 df bd 0f ce e4  05 db 62 a6 2f 0e 70 a3   [48:64]
96 a7 c2 62 e1 dc b4 20  48 97 fb 82 19 ca c5 33   [64:80]
42 45 9f 4c e4 f3 e4 50  ea c6 2b 53 fb 6c c7 67   [80:96]
98 6c cd 74 12 f4 56 7a  8f 05 60 4d 7d 36 bc ef   [96:112]
ab c9 62 ff 72 05 41 4f  65 a6 de cc 24 93 90 2c   [112:128]
d0 0b a7 3d 7d 19 19 5c  17 b9 12 42 57 4f 50 6c   [128:144]
60 84 62 8b 9f 10 96 cd  87 a5 dc c2 c8 48 5e a2   [144:160]
8c 85 42 5b 89 fa d1 fc  9a 87 c5 d0 7b 0e 89 97   [160:176]
fa 9b c0 95 ff 12 a0 68  0d 0e ce 7e d4 cd b1 11   [176:192]
68 08 72 62 13 ec 3a f1  44 eb 24 ed fa cf 60 8e   [192:208]
da 4b 39 b4 38 2a 81 2f  97 31 9f cd 91 d3 8c 2c   [208:224]
28 0a a1 21 19 2e 1e 7c  c7 ce b2 53 b8 3f d8 f7   [224:240]
```

The **initial 16-byte seed** = `28 0a a1 21 19 2e 1e 7c c7 ce b2 53 b8 3f d8 f7` (bytes [224:240]).

Its source is **unknown** — it doesn't match `sha_custom(dragonfly.bin)`, `sha_custom(connivance.bin)`, `sha_custom(flag_checker.tfl)`, or their NOT'd versions. The seed value is correct in expected[] regardless of source, since it was directly read from memory.

---

### 7. Runtime File Loads (fread order)

```
fread(0x496500, 1, 80)    → romfs/map
fread(0x497750, 1, 1264)  → flag_checker.tfl
fread(0x497c50, 1, 2224)  → romfs/connivance.bin
fread(0x496850, 1, 1024)  → romfs/blob
fread(0x496360, 1, 257)   → romfs/blob.sig
fread(0x496d60, 1, 512)   → romfs/damocles.bin
fread(0x49b3c0, 1, 1024)  → unknown (second blob read?)
fread(0x499500, 1, 256)   → romfs/dragonfly.bin
```

---

### 8. Current Solver (solver.c)

The solver has the **correct structure** but is too slow. Key facts:
- Charset: `"abcdefghijklmnopqrstuvwxyz0123456789_"` (37 chars)
- 7 nested loops = 37^7 ≈ 94 billion iterations
- Has `malloc`/`free` in every SHA call (huge overhead)
- No early exit, single-threaded

**Optimizations needed:**
1. **Stack-allocate SHA buffer** — flag is 17 bytes → padded = exactly 1 SHA block (64 bytes), no malloc needed
2. **Per-round early exit** — check each 32-byte chunk against expected before computing next round. Round 7 (or round 1 depending on order) has the most degenerate input → best filter
3. **OpenMP** on outer 2 loops: `gcc -O3 -march=native -fopenmp`
4. **Resolve the layout ambiguity first** (see §4 warning) — otherwise the solver will never find the flag

---

### 9. ⚠️ Critical Open Issues (must resolve before running solver)

**Issue 1: CONCAT direction is unclear**

The CONCAT opcode `0x39` handler at `0x404850`:
- Previous analysis: "pop A, peek B, append A to B → result = B||A (sha_result||old_reg1)"
- This means each round: `reg1 = sha(flag>>k) || previous_reg1` → sha of most-shifted round ends up at offset 0

But `sha(zeros×17) = e08379de...` is NOT at EXPECTED[0:32]. It's not anywhere in EXPECTED. This is a **contradiction** unless:
- The CONCAT is actually `old_reg1 || sha_result` → sha of most-shifted round ends up at offset 208 (7th × 32)
- OR the byte-order within each 32-byte chunk is reversed (little-endian vs big-endian SHA output)
- OR the shift count per round is not cumulative (each round shifts by 1 from the **original** flag, not the previous result)

**Issue 2: Shift may not be cumulative**

If each round clones reg[0] (the original flag) and shifts it by k (not cumulative), then:
- Round 1: sha(flag>>1)
- Round 2: sha(flag>>2)  ... separately shifted from original
- Round 7: sha(flag>>7) → all zeros for ASCII
This still has the same problem.

**Issue 3: Shift may be logical (unsigned) vs arithmetic (signed)**

For ASCII chars (< 128), logical vs arithmetic doesn't matter (high bit is 0). This is not the issue.

**Recommended next debugging step:**

Use GDB to dump reg[1] after each CONCAT step with a known input (e.g., `dach2026{aaaaaaa}`) to confirm the exact layout:
```gdb
# Break at the SHA opcode handler (0x4067e0) and dump the input/output
# OR break at the COMPARE (0x404150) and dump both reg[0] and reg[1]
```

Alternatively, check the CONCAT handler `0x404850` disassembly more carefully to determine if it prepends or appends.

---

### 10. Solver Template (once order is confirmed)

```c
// Flag: dach2026{c0c1c2c3c4c5c6}
// Shifts: flag_k[i] = flag[i] >> k  (cumulative: each round shifts previous result by 1)
// reg1 layout (TBD - verify order):
//   If prepend: [sha(flag>>7)][sha(flag>>6)]...[sha(flag>>1)][seed16]
//   If append:  [seed16][sha(flag>>1)]...[sha(flag>>6)][sha(flag>>7)]

// Optimization: for any ASCII flag, after 7 shifts all bytes = 0
// sha(zeros x17) = e08379de1619d051... (constant)
// So the 32 bytes corresponding to sha(flag>>7) are CONSTANT regardless of flag
// → only 6 rounds actually depend on the flag chars
// → compare the CONSTANT chunk first as a pre-filter (free)

// Early exit: compare round by round, abort early
// OpenMP: parallelize first 2 chars
// Stack SHA: 17-byte input = exactly 1 SHA block
```

---

### 11. Status Checklist

| Task | Status |
|------|--------|
| Full bytecode disassembled (62 instructions) | ✅ |
| All VM handlers analyzed | ✅ |
| Custom SHA-256 IVs identified | ✅ |
| 7-round algorithm structure understood | ✅ |
| Expected 240 bytes captured | ✅ |
| Flag length = 7 chars confirmed | ✅ |
| solver.c structure created | ✅ |
| **CONCAT direction (prepend vs append)** | ❌ Unconfirmed — contradicts sha(zeros) test |
| Initial 16-byte seed source confirmed | ❌ (value known, source unknown — not blocking) |
| Solver optimized | ❌ |
| **Flag found** | ❌ |