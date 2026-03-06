#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Custom SHA-256 with rotated IVs (SHA-256 words h4,h5,h6,h7,h0,h1,h2,h3)
static const uint32_t CUSTOM_H0[8] = {
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
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

// Compute custom SHA-256 of data[0..len-1], output 32 bytes to out
void sha256_custom(const uint8_t *data, size_t len, uint8_t *out) {
    uint32_t h[8];
    memcpy(h, CUSTOM_H0, sizeof(h));
    
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

// Expected 240-byte output (reg[0])
static const uint8_t EXPECTED[240] = {
    0x31, 0x31, 0x8e, 0xb9, 0x29, 0x49, 0xce, 0xfb, 0xda, 0xca, 0x83, 0xb6, 0xb2, 0x63, 0xf6, 0x06,
    0xd1, 0xe3, 0x51, 0x2c, 0x06, 0x2d, 0x07, 0x93, 0x02, 0x6b, 0x99, 0xd2, 0x80, 0x79, 0x8b, 0xf2,
    0x3a, 0x8a, 0x28, 0xd2, 0x0f, 0xa8, 0xea, 0xb1, 0x03, 0x59, 0xc8, 0xd0, 0xf6, 0x17, 0x30, 0x40,
    0x69, 0x93, 0xf6, 0xdf, 0xbd, 0x0f, 0xce, 0xe4, 0x05, 0xdb, 0x62, 0xa6, 0x2f, 0x0e, 0x70, 0xa3,
    0x96, 0xa7, 0xc2, 0x62, 0xe1, 0xdc, 0xb4, 0x20, 0x48, 0x97, 0xfb, 0x82, 0x19, 0xca, 0xc5, 0x33,
    0x42, 0x45, 0x9f, 0x4c, 0xe4, 0xf3, 0xe4, 0x50, 0xea, 0xc6, 0x2b, 0x53, 0xfb, 0x6c, 0xc7, 0x67,
    0x98, 0x6c, 0xcd, 0x74, 0x12, 0xf4, 0x56, 0x7a, 0x8f, 0x05, 0x60, 0x4d, 0x7d, 0x36, 0xbc, 0xef,
    0xab, 0xc9, 0x62, 0xff, 0x72, 0x05, 0x41, 0x4f, 0x65, 0xa6, 0xde, 0xcc, 0x24, 0x93, 0x90, 0x2c,
    0xd0, 0x0b, 0xa7, 0x3d, 0x7d, 0x19, 0x19, 0x5c, 0x17, 0xb9, 0x12, 0x42, 0x57, 0x4f, 0x50, 0x6c,
    0x60, 0x84, 0x62, 0x8b, 0x9f, 0x10, 0x96, 0xcd, 0x87, 0xa5, 0xdc, 0xc2, 0xc8, 0x48, 0x5e, 0xa2,
    0x8c, 0x85, 0x42, 0x5b, 0x89, 0xfa, 0xd1, 0xfc, 0x9a, 0x87, 0xc5, 0xd0, 0x7b, 0x0e, 0x89, 0x97,
    0xfa, 0x9b, 0xc0, 0x95, 0xff, 0x12, 0xa0, 0x68, 0x0d, 0x0e, 0xce, 0x7e, 0xd4, 0xcd, 0xb1, 0x11,
    0x68, 0x08, 0x72, 0x62, 0x13, 0xec, 0x3a, 0xf1, 0x44, 0xeb, 0x24, 0xed, 0xfa, 0xcf, 0x60, 0x8e,
    0xda, 0x4b, 0x39, 0xb4, 0x38, 0x2a, 0x81, 0x2f, 0x97, 0x31, 0x9f, 0xcd, 0x91, 0xd3, 0x8c, 0x2c,
    0x28, 0x0a, 0xa1, 0x21, 0x19, 0x2e, 0x1e, 0x7c, 0xc7, 0xce, 0xb2, 0x53, 0xb8, 0x3f, 0xd8, 0xf7
};

// Flag template: "dach2026{XXXXXXX}" = 17 bytes
// We need to find 7 chars at positions 9..15

// Compute the expected reg[1] for a given flag
void compute_reg1(const uint8_t *flag, int flag_len, uint8_t *reg1_out) {
    // reg1 starts as initial_seed = EXPECTED[224..239] (16 bytes)
    // After 7 rounds: reg1 = sha7 || sha6 || ... || sha1 || initial_seed
    // Round i: shift flag by i bits per byte, hash, prepend to reg1
    // So final reg1[0..31] = sha(flag>>7), reg1[32..63] = sha(flag>>6), ...
    //                         reg1[192..223] = sha(flag>>1), reg1[224..239] = initial_seed
    
    // Just compute all 7 hashes and assemble
    uint8_t shifted[17];
    memcpy(shifted, flag, flag_len);
    
    for (int round = 1; round <= 7; round++) {
        // Shift each byte right by 1 (cumulative)
        for (int i = 0; i < flag_len; i++) shifted[i] >>= 1;
        
        // Hash
        uint8_t hash[32];
        sha256_custom(shifted, flag_len, hash);
        
        // reg1 at round r is at position (7-round)*32
        memcpy(reg1_out + (7 - round) * 32, hash, 32);
    }
    // Append initial seed
    memcpy(reg1_out + 224, EXPECTED + 224, 16);
}

// Check if a flag candidate matches
int check_flag(const uint8_t *flag, int flag_len) {
    uint8_t reg1[240];
    compute_reg1(flag, flag_len, reg1);
    return memcmp(reg1, EXPECTED, 240) == 0;
}

// Character set for brute force
static const char CHARSET[] = "abcdefghijklmnopqrstuvwxyz0123456789_";
static const int CHARSET_LEN = 37;

int main(int argc, char *argv[]) {
    uint8_t flag[17];
    memcpy(flag, "dach2026{", 9);
    flag[16] = '}';
    
    // Quick verification: compute reg1 for known-bad flag and check first bytes
    memset(flag + 9, 'A', 7);
    uint8_t reg1[240];
    compute_reg1(flag, 17, reg1);
    printf("Test flag 'dach2026{AAAAAAA}':\n");
    printf("reg1[0..31]: ");
    for (int i = 0; i < 32; i++) printf("%02x", reg1[i]);
    printf("\n");
    printf("expected[0..31]: ");
    for (int i = 0; i < 32; i++) printf("%02x", EXPECTED[i]);
    printf("\n");
    printf("Match: %s\n\n", check_flag(flag, 17) ? "YES!" : "no");
    
    // Brute force 7 characters
    printf("Starting brute force with charset: %s\n", CHARSET);
    printf("Charset size: %d, total candidates: ~%.0e\n\n", CHARSET_LEN, 
           (double)CHARSET_LEN * CHARSET_LEN * CHARSET_LEN * CHARSET_LEN *
           CHARSET_LEN * CHARSET_LEN * CHARSET_LEN);
    
    // 7-nested loop
    long long count = 0;
    for (int i0 = 0; i0 < CHARSET_LEN; i0++) {
        flag[9] = CHARSET[i0];
        for (int i1 = 0; i1 < CHARSET_LEN; i1++) {
            flag[10] = CHARSET[i1];
            for (int i2 = 0; i2 < CHARSET_LEN; i2++) {
                flag[11] = CHARSET[i2];
                for (int i3 = 0; i3 < CHARSET_LEN; i3++) {
                    flag[12] = CHARSET[i3];
                    for (int i4 = 0; i4 < CHARSET_LEN; i4++) {
                        flag[13] = CHARSET[i4];
                        for (int i5 = 0; i5 < CHARSET_LEN; i5++) {
                            flag[14] = CHARSET[i5];
                            for (int i6 = 0; i6 < CHARSET_LEN; i6++) {
                                flag[15] = CHARSET[i6];
                                count++;
                                if (check_flag(flag, 17)) {
                                    printf("FOUND FLAG: dach2026{%c%c%c%c%c%c%c}\n",
                                           flag[9], flag[10], flag[11], flag[12],
                                           flag[13], flag[14], flag[15]);
                                    return 0;
                                }
                            }
                        }
                        if (count % 10000000 == 0) {
                            printf("Progress: %lld million (%c%c%c%c%c...)\n",
                                   count/1000000, flag[9], flag[10], flag[11], flag[12], flag[13]);
                            fflush(stdout);
                        }
                    }
                }
            }
        }
    }
    
    printf("Not found in charset. Tried %lld combinations.\n", count);
    return 1;
}
