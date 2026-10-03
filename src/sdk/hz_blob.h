// hz_blob.h - embed an AES-256-CTR encrypted asset (config, resource, large
// secret) in your binary and decrypt it ONLY in memory at runtime. The
// plaintext is never written to disk and the holder zeroes it on destruction,
// so a dump taken before or after use finds nothing. The on-disk file stays
// constant (integrity-stamp friendly).
//
// Produce the encrypted header with:  hzblob <asset> <out.h> <name> <key.bin>
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "hz_aes.h"

namespace hz {

// RAII plaintext holder: wiped and freed on scope exit. Allocates len+1 and
// nul-terminates so text assets can be used as C strings.
struct ScopedBytes {
    uint8_t* data;
    size_t   len;
    explicit ScopedBytes(size_t n) : data(new uint8_t[n + 1]()), len(n) {}
    ~ScopedBytes() { if (data) { volatile uint8_t* z = data; for (size_t i = 0; i <= len; ++i) z[i] = 0; delete[] data; } }
    ScopedBytes(ScopedBytes&& o) noexcept : data(o.data), len(o.len) { o.data = nullptr; o.len = 0; }
    ScopedBytes(const ScopedBytes&) = delete;
    ScopedBytes& operator=(const ScopedBytes&) = delete;
    const char* c_str() const { return reinterpret_cast<const char*>(data); }
};

// A reference to an embedded encrypted asset. The cipher bytes and nonce are
// baked in by hzblob; the key is the per-build HZ_BUILD_MASTER_KEY.
struct EncryptedBlob {
    const uint8_t* cipher;
    size_t         len;
    const uint8_t* nonce;   // 16 bytes
    const uint8_t* key;     // 32 bytes

    ScopedBytes decrypt() const {
        ScopedBytes out(len);
        memcpy(out.data, cipher, len);
        aes256_ctr(key, nonce, out.data, len);
        return out;
    }
};

} // namespace hz

// Declare an EncryptedBlob from the arrays hzblob emitted (name_cipher /
// name_nonce / name_len) using the per-build master key.
#define HZ_BLOB(name) \
    ::hz::EncryptedBlob{ name##_cipher, name##_len, name##_nonce, HZ_BUILD_MASTER_KEY }
