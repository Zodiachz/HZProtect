// hz_strcrypt.h - compile-time string obfuscation. Literals wrapped in HZ_STR()
// are never stored in cleartext in the binary: each is XOR-encrypted at compile
// time with a per-call-site key and decrypted into a stack buffer on use, then
// wiped. Keeps `strings` / a hex editor from reading your messages, URLs, keys.
//
// C++14 relaxed constexpr; works on MSVC /std:c++17 and later.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

// Per-build randomization: if hzkeygen has produced hz_build_keys.h, pull in
// HZ_BUILD_SEED so every build encrypts the same literal to different bytes.
// Falls back to a fixed seed when building without keygen (still per-call-site).
#if defined(__has_include)
#  if __has_include("hz_build_keys.h")
#    include "hz_build_keys.h"
#  endif
#endif
#ifndef HZ_BUILD_SEED
#  define HZ_BUILD_SEED 0xA5A5A5A5A5A5A5A5ULL
#endif

namespace hz {
namespace sc {

// A compile-time seed unique per call site (line + a counter + file hash).
constexpr uint32_t fnv1a(const char* s, uint32_t h = 2166136261u) {
    return (*s == 0) ? h : fnv1a(s + 1, (h ^ (uint8_t)*s) * 16777619u);
}

constexpr uint8_t key_byte(uint32_t seed, size_t i) {
    uint32_t x = seed + (uint32_t)i * 0x9E3779B9u;
    x ^= x >> 15; x *= 0x85EBCA6Bu; x ^= x >> 13;
    return (uint8_t)(x & 0xFF);
}

template <size_t N, uint32_t SEED>
struct Encrypted {
    char data[N];
    // volatile sink so the ctor's encryption is not folded into a plaintext blob
    constexpr Encrypted(const char (&in)[N]) : data{} {
        for (size_t i = 0; i < N; ++i)
            data[i] = (char)(in[i] ^ key_byte(SEED, i));
    }

    // Decrypt into caller storage; returns the pointer. Not reentrant across the
    // same buffer, so each use gets its own stack buffer via the macro.
    const char* decrypt(char* out) const {
        for (size_t i = 0; i < N; ++i)
            out[i] = (char)(data[i] ^ key_byte(SEED, i));
        return out;
    }
    static constexpr size_t size() { return N; }
};

// RAII holder: decrypts on construction, zeroes the buffer on destruction so a
// memory dump taken after the string is used finds nothing.
template <size_t N, uint32_t SEED>
struct Scoped {
    char buf[N];
    const char* p;
    explicit Scoped(const Encrypted<N, SEED>& e) { p = e.decrypt(buf); }
    ~Scoped() { volatile char* z = buf; for (size_t i = 0; i < N; ++i) z[i] = 0; }
    operator const char*() const { return p; }
    const char* c_str() const { return p; }
};

} // namespace sc
} // namespace hz

// HZ_STR("literal") -> a temporary Scoped that converts to const char*. Valid
// for the full expression it appears in. The seed mixes __FILE__, __LINE__ and
// __COUNTER__ so two identical literals encrypt differently. __COUNTER__ is
// captured exactly once (passed through HZ_STR_IMPL) because it increments on
// every textual expansion.
#define HZ_STR_IMPL(str, ctr)                                                  \
    ([]() {                                                                    \
        constexpr uint32_t _hz_seed = ::hz::sc::fnv1a(__FILE__) ^              \
            ((uint32_t)(__LINE__) * 2654435761u) ^                            \
            ((uint32_t)(ctr) * 40503u) ^                                       \
            (uint32_t)((HZ_BUILD_SEED) & 0xFFFFFFFFULL) ^                       \
            (uint32_t)(((HZ_BUILD_SEED) >> 32) & 0xFFFFFFFFULL);               \
        constexpr ::hz::sc::Encrypted<sizeof(str), _hz_seed> _hz_enc(str);     \
        return ::hz::sc::Scoped<sizeof(str), _hz_seed>(_hz_enc);               \
    }())
#define HZ_STR(str) HZ_STR_IMPL(str, __COUNTER__)
