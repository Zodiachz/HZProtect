// hooktest.cpp - verifies inline-hook DETECTION (read-only / defensive):
//   1) scan the default WinAPI watch list on a clean process -> expect 0 hooks
//      (this exercises the whole path: resolve, find owning module, map the
//       module file from disk, RVA->offset, compare prologues)
//   2) unit-test the classifier on synthetic prologue bytes, so we prove it
//      recognizes trampoline shapes without modifying any live function.
#include <cstdio>
#include <cstring>
#include "../src/sdk/hz_hooks.h"

static const char* kindName(hz::HookKind k) {
    switch (k) {
        case hz::HookKind::JmpRel32: return "jmp rel32";
        case hz::HookKind::JmpIndirect: return "jmp [rip]";
        case hz::HookKind::PushRet: return "push/ret";
        case hz::HookKind::MovRaxJmp: return "mov rax;jmp";
        case hz::HookKind::Int3: return "int3";
        case hz::HookKind::Modified: return "modified";
        default: return "none";
    }
}

static void dump(const hz::HookResult& r) {
    printf("  %-13s %-26s found=%d hooked=%d %-11s live=", r.module, r.func, r.found, r.hooked, kindName(r.kind));
    for (int i = 0; i < 8; ++i) printf("%02x", r.live[i]);
    printf("\n");
}

int main() {
    bool pass = true;

    printf("== clean scan (expect 0 hooks) ==\n");
    hz::HookResult res[16];
    int scanned = 0;
    int hooks = hz::scan_hooks(res, 16, &scanned);
    for (int i = 0; i < scanned; ++i) dump(res[i]);
    printf("result: %d hook(s) across %d functions\n", hooks, scanned);
    if (hooks != 0) { printf("  [FAIL] unexpected hook on a clean process\n"); pass = false; }
    else            { printf("  [PASS] no hooks, all prologues match disk\n"); }

    // The scan must actually have compared functions (map-from-disk worked).
    int compared = 0; for (int i = 0; i < scanned; ++i) if (res[i].found) ++compared;
    printf("  functions compared against disk: %d/%d\n", compared, scanned);
    if (compared == 0) { printf("  [FAIL] nothing was comparable\n"); pass = false; }

    printf("\n== classifier unit test (synthetic prologues) ==\n");
    struct Case { const char* name; unsigned char b[8]; hz::HookKind want; };
    const Case cases[] = {
        {"jmp rel32",   {0xE9,0x11,0x22,0x33,0x44,0,0,0},         hz::HookKind::JmpRel32},
        {"jmp [rip]",   {0xFF,0x25,0,0,0,0,0,0},                  hz::HookKind::JmpIndirect},
        {"push/ret",    {0x68,0x11,0x22,0x33,0x44,0xC3,0,0},      hz::HookKind::PushRet},
        {"mov rax;jmp", {0x48,0xB8,0,0,0,0,0,0},                  hz::HookKind::MovRaxJmp},
        {"int3",        {0xCC,0,0,0,0,0,0,0},                     hz::HookKind::Int3},
        {"other bytes", {0x48,0x89,0x5C,0x24,0x08,0,0,0},         hz::HookKind::Modified},
    };
    for (const auto& c : cases) {
        hz::HookKind got = hz::detail::classify(c.b);
        bool ok = got == c.want;
        printf("  %-12s -> %-11s %s\n", c.name, kindName(got), ok ? "[PASS]" : "[FAIL]");
        if (!ok) pass = false;
    }

    printf("\n%s\n", pass ? "ALL PASS" : "FAILURE");
    return pass ? 0 : 1;
}
