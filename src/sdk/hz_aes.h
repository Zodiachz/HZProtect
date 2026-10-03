// hz_aes.h - header-only AES-256 in CTR mode. Software reference implementation
// (no AES-NI dependency), constant-time-ish table-free SubBytes. For encrypting
// embedded blobs (config, resources, larger secrets) that are decrypted at
// runtime. Symmetric: the same call encrypts and decrypts in CTR mode.
#pragma once
#include <cstdint>
#include <cstring>

namespace hz {
namespace aes_detail {

inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }
inline uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) { if (b & 1) p ^= a; uint8_t hi = a & 0x80; a <<= 1; if (hi) a ^= 0x1b; b >>= 1; }
    return p;
}

// S-box computed once at first use (affine transform of the GF(2^8) inverse),
// so no 256-byte table literal sits in the binary.
struct Sbox {
    uint8_t s[256], inv[256];
    Sbox() {
        uint8_t p = 1, q = 1;
        uint8_t table[256]; table[0] = 0;
        do {
            p = (uint8_t)(p ^ (p << 1) ^ ((p & 0x80) ? 0x1b : 0));
            q ^= q << 1; q ^= q << 2; q ^= q << 4; if (q & 0x80) q ^= 0x09;
            uint8_t x = (uint8_t)(q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4)) ^ 0x63);
            table[p] = x;
        } while (p != 1);
        for (int i = 0; i < 256; ++i) { s[i] = table[i]; inv[s[i]] = (uint8_t)i; }
        s[0] = 0x63; inv[0x63] = 0;
    }
};
inline const Sbox& sbox() { static Sbox b; return b; }

} // namespace aes_detail

struct Aes256 {
    uint8_t rk[240]; // 15 round keys

    void key_expand(const uint8_t key[32]) {
        const auto& S = aes_detail::sbox().s;
        memcpy(rk, key, 32);
        static const uint8_t rcon[11] = {0,1,2,4,8,16,32,64,128,27,54};
        int i = 32, r = 1;
        uint8_t t[4];
        while (i < 240) {
            memcpy(t, rk + i - 4, 4);
            if (i % 32 == 0) {
                uint8_t tmp = t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=tmp;
                for (int j = 0; j < 4; ++j) t[j] = S[t[j]];
                t[0] ^= rcon[r++];
            } else if (i % 32 == 16) {
                for (int j = 0; j < 4; ++j) t[j] = S[t[j]];
            }
            for (int j = 0; j < 4; ++j) rk[i+j] = rk[i-32+j] ^ t[j];
            i += 4;
        }
    }

    void encrypt_block(uint8_t b[16]) const {
        const auto& S = aes_detail::sbox().s;
        auto addrk = [&](int round) { for (int i = 0; i < 16; ++i) b[i] ^= rk[round*16+i]; };
        addrk(0);
        for (int round = 1; round <= 14; ++round) {
            for (int i = 0; i < 16; ++i) b[i] = S[b[i]];                 // SubBytes
            uint8_t t;                                                   // ShiftRows
            t=b[1]; b[1]=b[5]; b[5]=b[9]; b[9]=b[13]; b[13]=t;
            t=b[2]; b[2]=b[10]; b[10]=t; t=b[6]; b[6]=b[14]; b[14]=t;
            t=b[15]; b[15]=b[11]; b[11]=b[7]; b[7]=b[3]; b[3]=t;
            if (round != 14) {                                           // MixColumns
                for (int c = 0; c < 4; ++c) {
                    uint8_t* col = b + c*4;
                    uint8_t a0=col[0],a1=col[1],a2=col[2],a3=col[3];
                    col[0] = (uint8_t)(aes_detail::mul(a0,2) ^ aes_detail::mul(a1,3) ^ a2 ^ a3);
                    col[1] = (uint8_t)(a0 ^ aes_detail::mul(a1,2) ^ aes_detail::mul(a2,3) ^ a3);
                    col[2] = (uint8_t)(a0 ^ a1 ^ aes_detail::mul(a2,2) ^ aes_detail::mul(a3,3));
                    col[3] = (uint8_t)(aes_detail::mul(a0,3) ^ a1 ^ a2 ^ aes_detail::mul(a3,2));
                }
            }
            addrk(round);
        }
    }

    // CTR mode: keystream block i = E(nonce with a big-endian counter added into
    // its low 8 bytes). Symmetric (XOR), so encrypt == decrypt.
    void ctr_xor(uint8_t* data, size_t len, const uint8_t nonce[16]) const {
        uint8_t ks[16];
        size_t off = 0;
        for (uint64_t block = 0; off < len; ++block) {
            memcpy(ks, nonce, 16);
            uint64_t carry = block;
            for (int i = 15; i >= 8 && carry; --i) { // add counter, big-endian, low 8 bytes
                unsigned v = ks[i] + (unsigned)(carry & 0xff);
                ks[i] = (uint8_t)v;
                carry = (carry >> 8) + (v >> 8);
            }
            encrypt_block(ks);
            size_t take = len - off; if (take > 16) take = 16;
            for (size_t i = 0; i < take; ++i) data[off+i] ^= ks[i];
            off += take;
        }
    }
};

inline void aes256_ctr(const uint8_t key[32], const uint8_t nonce[16], uint8_t* data, size_t len) {
    Aes256 a; a.key_expand(key); a.ctr_xor(data, len, nonce);
}

} // namespace hz
