#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Standard SHA-256 initial values (confirmed by tracing vm SHA calls)
static const uint32_t SHA256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x,n) (((x)>>(n)) | ((x)<<(32-(n))))
#define BE32(p) ((uint32_t)(((uint8_t*)(p))[0]<<24 | ((uint8_t*)(p))[1]<<16 | ((uint8_t*)(p))[2]<<8 | ((uint8_t*)(p))[3]))

// Compute SHA-256 of data[0..len-1], output 32 bytes to out
void sha256_custom(const uint8_t *data, size_t len, uint8_t *out) {
    uint32_t h[8];
    memcpy(h, SHA256_H0, sizeof(h));
    
    // Build padded message
    size_t padded_len = len + 1;
    while (padded_len % 64 != 56) padded_len++;
    padded_len += 8;
    
    uint8_t *padded = (uint8_t *)malloc(padded_len);
    memcpy(padded, data, len);
    padded[len] = 0x80;
    memset(padded + len + 1, 0, padded_len - len - 1);
    uint64_t bit_len = (uint64_t)len * 8;
    for (int i = 7; i >= 0; i--) {
        padded[padded_len - 8 + (7-i)] = (bit_len >> (i*8)) & 0xff;
    }
    
    for (size_t blk = 0; blk < padded_len; blk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) w[i] = BE32(padded + blk + i*4);
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROTR(w[i-15],7) ^ ROTR(w[i-15],18) ^ (w[i-15]>>3);
            uint32_t s1 = ROTR(w[i-2],17) ^ ROTR(w[i-2],19) ^ (w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            hh=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    free(padded);
    
    for (int i = 0; i < 8; i++) {
        out[i*4+0] = (h[i]>>24) & 0xff;
        out[i*4+1] = (h[i]>>16) & 0xff;
        out[i*4+2] = (h[i]>>8)  & 0xff;
        out[i*4+3] =  h[i]       & 0xff;
    }
}

// Expected 256-byte target (reg[0] in the VM comparison).
// B must equal TARGET when B = sha(NOT(flag)>>7) || sha(NOT(flag)>>6) || ...
//                                  || sha(NOT(flag)>>1) || sha(NOT(flag)>>0)
static const uint8_t EXPECTED[256] = {
    0x99,0x3c,0x36,0xa1,0x84,0x00,0xdf,0x7a,0xb6,0x1f,0xe4,0x71,0x34,0x37,0xcb,0x9a,
    0xb3,0x29,0x47,0xd6,0xb4,0xb9,0xbc,0x31,0x9c,0xf5,0x80,0x90,0x43,0xbd,0x7a,0xdf,
    0xf4,0xb6,0xe9,0x11,0x2c,0x04,0xed,0x73,0x8a,0x81,0x81,0x13,0x1c,0x3b,0x8c,0x58,
    0xf2,0xcb,0xd5,0xfd,0x5d,0xf4,0x64,0x81,0xe4,0xb9,0xad,0x0c,0x68,0xfd,0x01,0x88,
    0x54,0xbc,0x8a,0x04,0xe5,0x27,0x72,0x62,0x43,0x01,0x93,0xb8,0xbe,0x73,0x6c,0x77,
    0x0a,0x3b,0x08,0x9e,0x48,0x63,0xac,0x81,0xb9,0xdf,0x6b,0x87,0x09,0x00,0xfb,0xe4,
    0x4e,0x79,0x17,0x20,0x06,0x11,0xeb,0xd0,0x9a,0x45,0x9c,0xb0,0xd8,0x98,0xbf,0x91,
    0x37,0x7c,0xaf,0x65,0xa7,0xbf,0x0a,0x68,0x4a,0x1a,0xd8,0x1e,0xd7,0x17,0x06,0xb1,
    0xb7,0x6a,0xf9,0xc2,0x08,0x9c,0xdc,0xaf,0x26,0x43,0x2c,0xe7,0x34,0x90,0x5b,0xb4,
    0x39,0x29,0x74,0xde,0x7d,0x89,0xf9,0xde,0xf8,0x3c,0xaa,0x5c,0x0a,0x7b,0x19,0x38,
    0xbc,0x9a,0xc2,0xac,0x2c,0x4e,0x4b,0x2a,0x05,0x9e,0xc5,0x08,0x4a,0xed,0x74,0x52,
    0xfd,0x90,0x74,0xc6,0x2f,0x54,0x64,0x0c,0x9e,0x1d,0x60,0x31,0x11,0x6e,0x46,0x6d,
    0x31,0x0b,0x06,0xb4,0x64,0x40,0x23,0x12,0x93,0xae,0x39,0x85,0x66,0x12,0xc6,0x34,
    0xd3,0xbe,0x3f,0x2f,0x65,0x13,0x58,0x2e,0x86,0xfe,0x4a,0x42,0x60,0x97,0x38,0x93,
    0x56,0x1a,0x85,0x69,0x49,0x62,0x01,0x26,0x62,0x3b,0xc8,0x84,0x47,0x2a,0xa4,0xe8,
    0x23,0x6b,0x77,0x0f,0xaf,0x1c,0x70,0xe3,0x62,0xbc,0x8b,0x8f,0xa8,0x55,0x9d,0x70
};

// Flag is 29 bytes: "dach2026{" (9 bytes) + 19 inner chars + "}" (1 byte)
#define FLAG_LEN 29
#define INNER_LEN 19
#define INNER_START 9

// Algorithm (discovered by dynamic analysis):
//   NOT each byte of the flag, then right-shift by k bits (k = 0..7)
//   Compute SHA-256 of the 29-byte shifted result for each k
//   Assemble: B = sha(NOT>>7) || sha(NOT>>6) || ... || sha(NOT>>0)  (256 bytes)
//   B must equal EXPECTED

// Compute B for the given flag and compare against EXPECTED
int check_flag(const uint8_t *flag) {
    uint8_t not_flag[FLAG_LEN];
    for (int i = 0; i < FLAG_LEN; i++) not_flag[i] = (uint8_t)flag[i] ^ 0xff;

    uint8_t b[256];
    for (int k = 7; k >= 0; k--) {
        uint8_t shifted[FLAG_LEN];
        for (int i = 0; i < FLAG_LEN; i++) shifted[i] = not_flag[i] >> k;
        sha256_custom(shifted, FLAG_LEN, b + (7 - k) * 32);
    }
    return memcmp(b, EXPECTED, 256) == 0;
}

// Layered solver using the bit-shift structure of the algorithm.
//
// At shift k, NOT(c) >> k collapses c into one of a small number of groups.
// We use each shift level as a filter, progressively narrowing candidates:
//
//   k=7: all printable ASCII give NOT>>7 = 1 (no information)
//   k=6: digit chars (c in [0x00,0x3f]) -> NOT>>6=3; others -> NOT>>6=2
//   k=5: further splits into 3 groups (letter, underscore-class, digit)
//   k=4: further splits into sub-ranges of 16 chars each
//   k=3: further splits into sub-ranges of 8 chars each
//   k=2: sub-ranges of 4 chars
//   k=1: sub-ranges of 2 chars (pairs)
//   k=0: exact char (full resolution)
//
// At each level we enumerate the 2^19 binary choices for the 19 inner positions
// (low half vs high half of each current group), compute SHA-256, and keep only
// the single combination that matches the expected target block.

// For each inner position, track the current group as (lo, hi) inclusive
static int GROUP_LO[INNER_LEN];  // low end of current char range (inclusive)
static int GROUP_HI[INNER_LEN];  // high end (inclusive)

// Compute the representative >>k value for a group [lo, hi] at the given bit choice
// bit=0: use low half [lo, lo+(sz/2)-1]
// bit=1: use high half [lo+sz/2, hi]
static uint8_t group_k_val(int lo, int hi, int shift, int bit) {
    int sz = hi - lo + 1;
    int half = sz / 2;
    int rep = bit ? (lo + half) : lo;  // representative char of this half
    return (uint8_t)(((uint8_t)rep ^ 0xff) >> shift);
}

// Run one level of the layered search.
// Enumerates all 2^INNER_LEN bit patterns for the 19 inner positions,
// builds the SHA input using group representatives, and returns the single
// matching mask (or -1 if not found).
static int find_mask_for_level(int shift, const uint8_t *target_block) {
    static const char *PREFIX = "dach2026{";
    static const char SUFFIX   = '}';

    // Precompute the fixed prefix and suffix contributions at this shift
    uint8_t pfx[9];
    uint8_t sfx;
    for (int i = 0; i < 9; i++) pfx[i] = (uint8_t)((uint8_t)PREFIX[i] ^ 0xff) >> shift;
    sfx = (uint8_t)((uint8_t)SUFFIX ^ 0xff) >> shift;

    for (int mask = 0; mask < (1 << INNER_LEN); mask++) {
        uint8_t inner[INNER_LEN];
        for (int i = 0; i < INNER_LEN; i++) {
            inner[i] = group_k_val(GROUP_LO[i], GROUP_HI[i], shift, (mask >> i) & 1);
        }
        uint8_t full[FLAG_LEN];
        memcpy(full, pfx, 9);
        memcpy(full + 9, inner, INNER_LEN);
        full[FLAG_LEN - 1] = sfx;

        uint8_t hash[32];
        sha256_custom(full, FLAG_LEN, hash);
        if (memcmp(hash, target_block, 32) == 0) return mask;
    }
    return -1;
}

// Refine GROUP_LO/GROUP_HI for each inner position given the bit mask from a level.
static void refine_groups(int mask) {
    for (int i = 0; i < INNER_LEN; i++) {
        int lo = GROUP_LO[i], hi = GROUP_HI[i];
        int sz = hi - lo + 1;
        int half = sz / 2;
        if ((mask >> i) & 1) lo = lo + half;  // high half
        else                  hi = lo + half - 1;  // low half
        GROUP_LO[i] = lo;
        GROUP_HI[i] = hi;
    }
}

int main(void) {
    printf("Connivance CTF flag solver\n");
    printf("==========================\n\n");
    printf("Algorithm: B = sha256(NOT(flag)>>7) || ... || sha256(NOT(flag)>>0)\n");
    printf("Flag length: %d bytes  (19 inner chars)\n\n", FLAG_LEN);

    // Initialize groups: flag chars are printable ASCII, so [0x00, 0x7f].
    // This ensures each level's split produces a unique NOT>>k representative value.
    for (int i = 0; i < INNER_LEN; i++) {
        GROUP_LO[i] = 0x00;
        GROUP_HI[i] = 0x7f;
    }

    // Level k=6: 2 groups per position (gives digit vs letter/other classification)
    printf("Level k=6: finding digit/non-digit pattern...\n");
    int mask6 = find_mask_for_level(6, EXPECTED + 32);
    if (mask6 < 0) { printf("ERROR: no match at k=6\n"); return 1; }
    printf("  mask=0x%05x\n", mask6);
    refine_groups(mask6);

    // Level k=5
    printf("Level k=5: refining groups...\n");
    int mask5 = find_mask_for_level(5, EXPECTED + 64);
    if (mask5 < 0) { printf("ERROR: no match at k=5\n"); return 1; }
    printf("  mask=0x%05x\n", mask5);
    refine_groups(mask5);

    // Level k=4
    printf("Level k=4: refining groups...\n");
    int mask4 = find_mask_for_level(4, EXPECTED + 96);
    if (mask4 < 0) { printf("ERROR: no match at k=4\n"); return 1; }
    printf("  mask=0x%05x\n", mask4);
    refine_groups(mask4);

    // Level k=3
    printf("Level k=3: refining groups...\n");
    int mask3 = find_mask_for_level(3, EXPECTED + 128);
    if (mask3 < 0) { printf("ERROR: no match at k=3\n"); return 1; }
    printf("  mask=0x%04x\n", mask3);
    refine_groups(mask3);

    // Level k=2
    printf("Level k=2: refining groups...\n");
    int mask2 = find_mask_for_level(2, EXPECTED + 160);
    if (mask2 < 0) { printf("ERROR: no match at k=2\n"); return 1; }
    printf("  mask=0x%05x\n", mask2);
    refine_groups(mask2);

    // Level k=1
    printf("Level k=1: refining groups...\n");
    int mask1 = find_mask_for_level(1, EXPECTED + 192);
    if (mask1 < 0) { printf("ERROR: no match at k=1\n"); return 1; }
    printf("  mask=0x%05x\n", mask1);
    refine_groups(mask1);

    // Level k=0: each group now has exactly 2 chars; pick the right one
    printf("Level k=0: finding exact characters...\n");
    int mask0 = find_mask_for_level(0, EXPECTED + 224);
    if (mask0 < 0) { printf("ERROR: no match at k=0\n"); return 1; }
    printf("  mask=0x%05x\n", mask0);
    refine_groups(mask0);

    // Recover flag: after 8 levels each group is a single char
    uint8_t flag[FLAG_LEN + 1];
    memcpy(flag, "dach2026{", 9);
    for (int i = 0; i < INNER_LEN; i++) {
        if (GROUP_LO[i] != GROUP_HI[i]) {
            printf("WARNING: position %d is ambiguous [0x%02x, 0x%02x]\n",
                   i, GROUP_LO[i], GROUP_HI[i]);
        }
        flag[INNER_START + i] = (uint8_t)GROUP_LO[i];
    }
    flag[FLAG_LEN - 1] = '}';
    flag[FLAG_LEN] = '\0';

    // Final verification
    if (check_flag(flag)) {
        printf("\nFLAG: %s\n", flag);
    } else {
        printf("\nERROR: final flag check failed: %s\n", flag);
        return 1;
    }

    return 0;
}
