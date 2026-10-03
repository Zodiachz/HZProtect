// hzstamp.cpp - post-build tool. Computes the SHA-256 of a PE's .text section
// and writes it into the HzStamp slot that the program defined with
// HZ_DEFINE_STAMP, so the running program can verify it has not been patched.
//
//   hzstamp <path-to-exe-or-dll> [--section .text]
//
// Idempotent: re-stamping recomputes and overwrites. The stamp slot lives in a
// data section, so writing it does not change the .text hash.
#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <windows.h>
#include "../sdk/hz_sha256.h"
#include "../sdk/hz_integrity.h"

static bool readFile(const char* path, std::vector<uint8_t>& out) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return false; }
    out.resize((size_t)n);
    bool ok = fread(out.data(), 1, (size_t)n, f) == (size_t)n;
    fclose(f);
    return ok;
}

static bool writeFile(const char* path, const std::vector<uint8_t>& buf) {
    FILE* f = fopen(path, "r+b");
    if (!f) return false;
    bool ok = fwrite(buf.data(), 1, buf.size(), f) == buf.size();
    fclose(f);
    return ok;
}

int main(int argc, char** argv) {
    const char* path = nullptr;
    const char* section = ".text";
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--section") == 0 && i + 1 < argc) section = argv[++i];
        else if (argv[i][0] != '-') path = argv[i];
    }
    if (!path) { fprintf(stderr, "usage: hzstamp <exe|dll> [--section .text]\n"); return 2; }

    std::vector<uint8_t> buf;
    if (!readFile(path, buf)) { fprintf(stderr, "hzstamp: cannot read %s\n", path); return 1; }
    const uint8_t* base = buf.data();
    const size_t size = buf.size();

    auto bounded = [&](const void* p, size_t len) {
        const uint8_t* q = (const uint8_t*)p;
        return q >= base && q + len <= base + size;
    };

    auto* dos = (const IMAGE_DOS_HEADER*)base;
    if (!bounded(dos, sizeof(*dos)) || dos->e_magic != IMAGE_DOS_SIGNATURE) { fprintf(stderr, "hzstamp: not a PE\n"); return 1; }
    auto* nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (!bounded(nt, sizeof(*nt)) || nt->Signature != IMAGE_NT_SIGNATURE) { fprintf(stderr, "hzstamp: bad NT header\n"); return 1; }

    // 1) hash the chosen section's raw bytes
    auto* sec = IMAGE_FIRST_SECTION(nt);
    const WORD count = nt->FileHeader.NumberOfSections;
    uint8_t digest[32]; bool hashed = false;
    for (WORD i = 0; i < count; ++i) {
        char nm[9] = {0}; memcpy(nm, sec[i].Name, 8);
        if (strncmp(nm, section, 8) != 0) continue;
        uint32_t raw = sec[i].PointerToRawData, rsz = sec[i].SizeOfRawData;
        if (!raw || !rsz || !bounded(base + raw, rsz)) { fprintf(stderr, "hzstamp: section %s has no raw data\n", section); return 1; }
        hz::sha256(base + raw, rsz, digest);
        hashed = true;
        printf("hzstamp: %s raw=%u size=%u\n", nm, raw, rsz);
        break;
    }
    if (!hashed) { fprintf(stderr, "hzstamp: section %s not found\n", section); return 1; }

    // Map a file offset to the section that contains it, so we can require the
    // stamp slot live in a writable data section (the HZ_STAMP_MAGIC *constant*
    // also sits in read-only .rdata and must not be mistaken for the slot).
    auto writable_section = [&](size_t off) -> bool {
        for (WORD i = 0; i < count; ++i) {
            uint32_t raw = sec[i].PointerToRawData, rsz = sec[i].SizeOfRawData;
            if (off >= raw && off < (size_t)raw + rsz) {
                DWORD c = sec[i].Characteristics;
                return (c & IMAGE_SCN_MEM_WRITE) && !(c & IMAGE_SCN_MEM_EXECUTE);
            }
        }
        return false;
    };

    // 2) find the stamp slot: a magic occurrence inside a writable section.
    size_t slot = SIZE_MAX;
    for (size_t i = 0; i + sizeof(hz::HzStamp) <= size; ++i) {
        if (buf[i] == hz::HZ_STAMP_MAGIC[0] && memcmp(base + i, hz::HZ_STAMP_MAGIC, 16) == 0 && writable_section(i)) {
            slot = i; break;
        }
    }
    if (slot == SIZE_MAX) { fprintf(stderr, "hzstamp: stamp slot not found (did you HZ_DEFINE_STAMP in a data section?)\n"); return 1; }
    if (slot + sizeof(hz::HzStamp) > size) { fprintf(stderr, "hzstamp: stamp slot truncated\n"); return 1; }

    // 3) write digest + filled flag into the slot
    auto* st = (hz::HzStamp*)(buf.data() + slot);
    memcpy(st->digest, digest, 32);
    st->filled = 1;
    st->reserved = 0;

    if (!writeFile(path, buf)) { fprintf(stderr, "hzstamp: cannot write %s\n", path); return 1; }

    printf("hzstamp: stamped at file offset %zu  sha256=", slot);
    for (int i = 0; i < 32; ++i) printf("%02x", digest[i]);
    printf("\n");
    return 0;
}
