// hz_hooks.h - detect inline (trampoline) hooks on critical WinAPI functions.
// A hook overwrites a function's prologue with a jump to someone else's code
// (cheats, injected DLLs, API monitors do this). We compare the first bytes of
// each function in memory against the clean copy of the same bytes read from
// the module's file on disk, and classify anything that looks like a jump.
//
// Note: for ntdll Nt* stubs the prologue has no base relocations, so a byte
// mismatch there is a strong signal. For other modules a mismatch that is not a
// recognizable jump pattern is reported with lower confidence (maybe_modified).
#pragma once
#ifndef _WIN32
#error "hz_hooks.h is Windows-only"
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace hz {

enum class HookKind { None, JmpRel32, JmpIndirect, PushRet, MovRaxJmp, Int3, Modified };

struct HookResult {
    const char* module;
    const char* func;
    bool found;        // function resolved and compared
    bool hooked;       // in-memory prologue differs from the on-disk clean copy
    HookKind kind;
    uint8_t live[8];   // first 8 bytes in memory
    uint8_t disk[8];   // first 8 bytes on disk
};

namespace detail {

// Map an RVA to a file offset using the section table of a flat-mapped PE.
inline uint32_t rva_to_off(const uint8_t* base, size_t size, uint32_t rva) {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (size < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if ((size_t)dos->e_lfanew + sizeof(*nt) > size || nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint32_t va = sec[i].VirtualAddress;
        uint32_t vs = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (rva >= va && rva < va + vs)
            return sec[i].PointerToRawData + (rva - va);
    }
    return 0;
}

inline HookKind classify(const uint8_t* b) {
    if (b[0] == 0xE9) return HookKind::JmpRel32;                       // jmp rel32
    if (b[0] == 0xFF && b[1] == 0x25) return HookKind::JmpIndirect;    // jmp qword [rip+..]
    if (b[0] == 0x68) return HookKind::PushRet;                        // push imm32 ; ret
    if (b[0] == 0x48 && b[1] == 0xB8) return HookKind::MovRaxJmp;      // mov rax,imm64 ; jmp rax
    if (b[0] == 0xCC) return HookKind::Int3;
    return HookKind::Modified;
}

} // namespace detail

// Check one function. Resolves it in memory, finds its containing module, maps
// that module's file from disk and compares the first 8 bytes.
inline HookResult check_hook(const char* module, const char* func) {
    HookResult r{module, func, false, false, HookKind::None, {0}, {0}};

    HMODULE mod = GetModuleHandleA(module);
    if (!mod) return r;
    FARPROC fn = GetProcAddress(mod, func);
    if (!fn) return r;
    const uint8_t* live = reinterpret_cast<const uint8_t*>(fn);

    // Find the module actually containing the (possibly forwarded) function.
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(live, &mbi, sizeof(mbi))) return r;
    HMODULE owner = reinterpret_cast<HMODULE>(mbi.AllocationBase);

    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(owner, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return r;
    uint32_t rva = (uint32_t)(live - reinterpret_cast<const uint8_t*>(owner));

    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return r;
    HANDLE map = CreateFileMappingW(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map) { CloseHandle(h); return r; }
    LARGE_INTEGER fsz{}; GetFileSizeEx(h, &fsz);
    const uint8_t* disk = static_cast<const uint8_t*>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));
    if (disk) {
        uint32_t off = detail::rva_to_off(disk, (size_t)fsz.QuadPart, rva);
        if (off && off + 8 <= (uint64_t)fsz.QuadPart) {
            memcpy(r.live, live, 8);
            memcpy(r.disk, disk + off, 8);
            r.found = true;
            if (memcmp(r.live, r.disk, 8) != 0) {
                r.hooked = true;
                r.kind = detail::classify(r.live);
            }
        }
        UnmapViewOfFile(disk);
    }
    CloseHandle(map);
    CloseHandle(h);
    return r;
}

// A sensible default watch list: memory + process + module APIs that cheats and
// injectors hook. ntdll stubs first (cleanest signal).
struct HookTarget { const char* module; const char* func; };
inline const HookTarget* default_targets(size_t& count) {
    static const HookTarget t[] = {
        {"ntdll.dll", "NtProtectVirtualMemory"},
        {"ntdll.dll", "NtReadVirtualMemory"},
        {"ntdll.dll", "NtWriteVirtualMemory"},
        {"ntdll.dll", "NtQueryInformationProcess"},
        {"ntdll.dll", "NtCreateThreadEx"},
        {"ntdll.dll", "NtOpenProcess"},
        {"ntdll.dll", "LdrLoadDll"},
        {"kernel32.dll", "VirtualProtect"},
        {"kernel32.dll", "LoadLibraryA"},
        {"kernel32.dll", "GetProcAddress"},
    };
    count = sizeof(t) / sizeof(t[0]);
    return t;
}

// Scans the default list into caller storage; returns the number of hooks found.
inline int scan_hooks(HookResult* out, int cap, int* scanned = nullptr) {
    size_t n = 0; const HookTarget* t = default_targets(n);
    int hooks = 0, did = 0;
    for (size_t i = 0; i < n && did < cap; ++i) {
        HookResult r = check_hook(t[i].module, t[i].func);
        out[did++] = r;
        if (r.hooked) ++hooks;
    }
    if (scanned) *scanned = did;
    return hooks;
}

inline bool hooks_present() {
    HookResult tmp[16];
    return scan_hooks(tmp, 16) > 0;
}

} // namespace hz
