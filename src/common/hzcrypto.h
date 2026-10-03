// hzcrypto.h - tiny header-only primitives shared by builder and loader.
// Stage 1: keyed XOR stream + CRC32. No CRT, no allocations -> safe to call
// from the freestanding loader stub as well as the builder.
#pragma once
#include <cstdint>
#include <cstddef>

namespace hz {

// CRC32 (IEEE 802.3, reflected) computed without a 256-entry table so the
// loader stays small and table-free.
inline uint32_t crc32(const void* data, size_t len, uint32_t crc = 0) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    crc = ~crc;
    for (size_t i = 0; i < len; ++i) {
        crc ^= p[i];
        for (int k = 0; k < 8; ++k)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return ~crc;
}

// SplitMix64: expands the (key,nonce,counter) tuple into a keystream. Not a
// real cipher -> replaced by AES-CTR in stage 2, but keyed and position
// dependent so a flat strings/hexdump reveals nothing.
inline uint64_t splitmix64(uint64_t x) {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

// Symmetric: same call encrypts and decrypts (XOR stream).
inline void xor_stream(uint8_t* buf, size_t len, const uint8_t key[32], const uint8_t nonce[16]) {
    uint64_t k0 = 0, k1 = 0, n0 = 0;
    for (int i = 0; i < 8; ++i) { k0 = (k0 << 8) | key[i]; k1 = (k1 << 8) | key[i + 8]; }
    for (int i = 0; i < 8; ++i) n0 = (n0 << 8) | nonce[i];
    uint64_t block = 0;
    int avail = 0;
    uint64_t counter = 0;
    for (size_t i = 0; i < len; ++i) {
        if (avail == 0) {
            block = splitmix64(k0 ^ (counter * 0x100000001B3ull)) ^ splitmix64(k1 + n0 + counter);
            counter++;
            avail = 8;
        }
        buf[i] ^= (uint8_t)(block & 0xFF);
        block >>= 8;
        avail--;
    }
}

} // namespace hz
