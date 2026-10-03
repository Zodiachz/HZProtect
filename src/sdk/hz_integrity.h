// hz_integrity.h - runtime self-integrity check for the developer's own binary.
// Detects on-disk patching (the usual way a crack is distributed) by hashing
// the raw bytes of a chosen PE section from the module's own file on disk and
// comparing against a value baked in at build time.
//
// Why disk and not memory: on x64 with ASLR the in-memory image has base
// relocations applied, so an in-memory .text hash is not stable across runs.
// The on-disk raw section bytes are fixed and are exactly what a patcher edits.
#pragma once
#ifndef _WIN32
#error "hz_integrity.h is Windows-only"
#endif

#include <windows.h>
#include <cstdint>
#include "../common/hzcrypto.h"
#include "hz_sha256.h"

namespace hz {

struct SectionHash {
    bool ok;           // header parsed and section found
    uint32_t crc;      // CRC32 of the raw section bytes on disk
    uint8_t  sha[32];  // SHA-256 of the raw section bytes on disk
    char name[9];      // section name (nul-terminated)
};

// --- stamp: a slot the post-build tool (hzstamp) fills with the digest -------
// The 16-byte magic lets hzstamp locate the slot by scanning the file. The
// slot lives in a writable data section, so it is NOT part of .text and does
// not perturb the .text hash (no chicken-and-egg).
static const uint8_t HZ_STAMP_MAGIC[16] = {
    0x48,0x5A,0x53,0x54,0x41,0x4D,0x50,0x76,0x31,0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C};

#pragma pack(push, 1)
struct HzStamp {
    uint8_t  magic[16];  // == HZ_STAMP_MAGIC
    uint8_t  digest[32]; // SHA-256 of the .text raw bytes, written by hzstamp
    uint32_t filled;     // 0 = not yet stamped, 1 = stamped
    uint32_t reserved;
};
#pragma pack(pop)

enum class Integrity { Ok, Tampered, Unstamped, Unreadable };

// Hash the raw on-disk bytes of the named section of THIS module. section=nullptr
// hashes the first executable section. Returns ok=false if anything is off.
inline SectionHash self_section_crc(const char* section = ".text") {
    SectionHash out{false, 0, {0}};

    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return out;

    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return out;

    HANDLE map = CreateFileMappingW(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map) { CloseHandle(h); return out; }
    const uint8_t* base = static_cast<const uint8_t*>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));
    if (!base) { CloseHandle(map); CloseHandle(h); return out; }

    LARGE_INTEGER fsz; fsz.QuadPart = 0;
    GetFileSizeEx(h, &fsz);
    const uint64_t filesize = (uint64_t)fsz.QuadPart;

    auto bounded = [&](const void* p, size_t len) -> bool {
        const uint8_t* q = static_cast<const uint8_t*>(p);
        return q >= base && (q + len) <= (base + filesize);
    };

    do {
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (!bounded(dos, sizeof(*dos)) || dos->e_magic != IMAGE_DOS_SIGNATURE) break;
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (!bounded(nt, sizeof(*nt)) || nt->Signature != IMAGE_NT_SIGNATURE) break;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        const WORD count = nt->FileHeader.NumberOfSections;
        if (!bounded(sec, sizeof(IMAGE_SECTION_HEADER) * count)) break;

        for (WORD i = 0; i < count; ++i) {
            char nm[9] = {0};
            memcpy(nm, sec[i].Name, 8);
            bool match = section
                ? (memcmp(sec[i].Name, section, (strlen(section) < 8 ? strlen(section) + 1 : 8)) == 0)
                : (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            if (!match) continue;

            const uint32_t raw = sec[i].PointerToRawData;
            const uint32_t rawsz = sec[i].SizeOfRawData;
            if (raw == 0 || rawsz == 0) break;
            if (!bounded(base + raw, rawsz)) break;

            out.crc = hz::crc32(base + raw, rawsz);
            hz::sha256(base + raw, rawsz, out.sha);
            out.ok = true;
            memcpy(out.name, nm, 9);
            break;
        }
    } while (false);

    UnmapViewOfFile(base);
    CloseHandle(map);
    CloseHandle(h);
    return out;
}

// True when the current on-disk section CRC does NOT match the expected value
// baked in at build time (i.e. the binary was patched). Fails closed: if the
// hash cannot be read, treats it as tampered. (Lightweight CRC variant.)
inline bool self_tampered(uint32_t expectedCrc, const char* section = ".text") {
    SectionHash s = self_section_crc(section);
    return !s.ok || s.crc != expectedCrc;
}

// SHA-256 variant driven by a stamp slot that hzstamp filled post-build.
// Compares the live on-disk .text digest against the stamped one. Accepts the
// volatile slot (HZ_DEFINE_STAMP declares it volatile) and snapshots it.
inline Integrity verify_stamp(const volatile HzStamp& slot, const char* section = ".text") {
    HzStamp stamp;
    memcpy(&stamp, const_cast<const HzStamp*>(&slot), sizeof(HzStamp));
    if (memcmp(stamp.magic, HZ_STAMP_MAGIC, 16) != 0) return Integrity::Unstamped;
    if (!stamp.filled) return Integrity::Unstamped;
    SectionHash s = self_section_crc(section);
    if (!s.ok) return Integrity::Unreadable;
    return memcmp(s.sha, stamp.digest, 32) == 0 ? Integrity::Ok : Integrity::Tampered;
}

} // namespace hz

// Define exactly one integrity stamp slot in your program (at file scope), then
// run hzstamp on the built binary. The slot is volatile + referenced so the
// linker keeps it, and lives in .data so it is excluded from the .text hash.
#define HZ_DEFINE_STAMP(name)                                                  \
    volatile ::hz::HzStamp name = {                                            \
        {0x48,0x5A,0x53,0x54,0x41,0x4D,0x50,0x76,0x31,0x9E,0x37,0x79,0xB9,0x7F,0x4A,0x7C}, \
        {0}, 0, 0}
