// hz_antidebug.h - header-only debugger-presence checks a developer links into
// their OWN application. Each check is independent and returns true when a
// debugger / analysis environment is detected. Combine via hz::debugger_present().
//
// These are standard, documented Win32/NT checks (the same ones DRM and
// commercial protectors use). They are heuristics: no single one is decisive,
// so the aggregate is scored rather than trusted individually.
#pragma once
#ifndef _WIN32
#error "hz_antidebug.h is Windows-only"
#endif

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cstdint>
#include <intrin.h>

namespace hz {
namespace detail {

// PEB via GS on x64 / FS on x86, without importing anything.
inline PEB* peb() {
#if defined(_M_X64) || defined(_M_AMD64)
    return reinterpret_cast<PEB*>(__readgsqword(0x60));
#elif defined(_M_IX86)
    return reinterpret_cast<PEB*>(__readfsdword(0x30));
#else
#error "unsupported architecture"
#endif
}

// NtGlobalFlag lives at a fixed PEB offset (0xBC x86, 0x1C8... use documented
// winternl where possible; the raw offset is used because the field is not in
// the public PEB struct). FLG_HEAP_* bits get set when a process is spawned
// under a debugger.
inline ULONG nt_global_flag() {
#if defined(_M_X64)
    return *reinterpret_cast<ULONG*>(reinterpret_cast<uint8_t*>(peb()) + 0xBC);
#else
    return *reinterpret_cast<ULONG*>(reinterpret_cast<uint8_t*>(peb()) + 0x68);
#endif
}

using fnNtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
using fnNtQueryInformationThread = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
using fnNtSetInformationThread = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG);

inline HMODULE ntdll() { static HMODULE m = GetModuleHandleW(L"ntdll.dll"); return m; }

inline fnNtQueryInformationProcess nt_qip() {
    static auto fn = reinterpret_cast<fnNtQueryInformationProcess>(GetProcAddress(ntdll(), "NtQueryInformationProcess"));
    return fn;
}
inline fnNtQueryInformationThread nt_qit() {
    static auto fn = reinterpret_cast<fnNtQueryInformationThread>(GetProcAddress(ntdll(), "NtQueryInformationThread"));
    return fn;
}
inline fnNtSetInformationThread nt_sit() {
    static auto fn = reinterpret_cast<fnNtSetInformationThread>(GetProcAddress(ntdll(), "NtSetInformationThread"));
    return fn;
}

// SEH-only helpers kept in their own functions (no C++ objects) so /EHa is not
// required and the compiler is happy mixing SEH with the rest of the TU.
inline bool close_handle_raises() {
    __try {
        CloseHandle(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x1234)));
        return false;
    } __except (GetExceptionCode() == 0xC0000008 /*INVALID_HANDLE*/
                ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return true; // only raised when a debugger is attached
    }
}

inline bool int3_swallowed() {
    // Execute int3. With no debugger our __except runs; a debugger eats it.
    __try {
        __debugbreak();
        return true;  // handler did not run -> breakpoint was swallowed
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false; // we caught it -> no debugger
    }
}

} // namespace detail

// --- individual checks -----------------------------------------------------

// PEB.BeingDebugged flag (what IsDebuggerPresent reads, but inlined).
inline bool chk_peb_being_debugged() {
    return detail::peb()->BeingDebugged != 0;
}

inline bool chk_is_debugger_present() {
    return IsDebuggerPresent() != FALSE;
}

inline bool chk_remote_debugger() {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present != FALSE;
}

// Heap flags set by the loader when a debugger is attached at spawn.
inline bool chk_nt_global_flag() {
    const ULONG FLG = 0x70; // FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS
    return (detail::nt_global_flag() & FLG) == FLG;
}

// ProcessDebugPort (7): non-zero -> a debug port is attached.
inline bool chk_debug_port() {
    auto fn = detail::nt_qip();
    if (!fn) return false;
    DWORD_PTR port = 0;
    if (fn(GetCurrentProcess(), (PROCESSINFOCLASS)7, &port, sizeof(port), nullptr) == 0)
        return port != 0;
    return false;
}

// ProcessDebugObjectHandle (0x1e): a valid handle -> debugged.
inline bool chk_debug_object() {
    auto fn = detail::nt_qip();
    if (!fn) return false;
    HANDLE h = nullptr;
    if (fn(GetCurrentProcess(), (PROCESSINFOCLASS)0x1e, &h, sizeof(h), nullptr) == 0)
        return h != nullptr;
    return false;
}

// ProcessDebugFlags (0x1f): 0 -> NoDebugInherit cleared -> debugged.
inline bool chk_debug_flags() {
    auto fn = detail::nt_qip();
    if (!fn) return false;
    DWORD flags = 0;
    if (fn(GetCurrentProcess(), (PROCESSINFOCLASS)0x1f, &flags, sizeof(flags), nullptr) == 0)
        return flags == 0;
    return false;
}

// Hardware breakpoints: DR0-DR3 non-zero in the current thread context.
inline bool chk_hardware_breakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

// Timing: a single-stepping debugger blows the budget between two RDTSCs.
inline bool chk_timing_rdtsc(uint64_t budget = 0x40000) {
    unsigned aux;
    uint64_t a = __rdtscp(&aux);
    // trivial work the optimizer keeps
    volatile int s = 0; for (int i = 0; i < 16; ++i) s += i;
    uint64_t b = __rdtscp(&aux);
    (void)s;
    return (b - a) > budget;
}

// ThreadHideFromDebugger (0x11): set it, then query it back. If a debugger is
// present the query reflects a mismatch, or the value fails to stick.
inline bool chk_thread_hidden_mismatch() {
    auto set = detail::nt_sit();
    auto qit = detail::nt_qit();
    if (!set || !qit) return false;
    set(GetCurrentThread(), (THREADINFOCLASS)0x11, nullptr, 0); // ThreadHideFromDebugger
    BOOLEAN hidden = FALSE;
    if (qit(GetCurrentThread(), (THREADINFOCLASS)0x11, &hidden, sizeof(hidden), nullptr) == 0)
        return hidden == FALSE; // we just hid it; if it reads back not-hidden, interference
    return false;
}

// Actively detach this thread from the debugger's event stream. Not a check -
// a mitigation; call it early if you want breakpoints in this thread to stop
// reaching the debugger.
inline void hide_from_debugger() {
    if (auto set = detail::nt_sit())
        set(GetCurrentThread(), (THREADINFOCLASS)0x11, nullptr, 0);
}

inline bool chk_close_handle() { return detail::close_handle_raises(); }
inline bool chk_int3() { return detail::int3_swallowed(); }

// DbgUiRemoteBreakin is what a debugger calls to inject a break into us. Some
// anti-anti-debug tools patch it; a 0xCC/0xC3 at its head is a tell. We only
// report whether its first byte looks tampered (not a hard signal).
inline bool chk_dbgui_patched() {
    FARPROC p = GetProcAddress(detail::ntdll(), "DbgUiRemoteBreakin");
    if (!p) return false;
    uint8_t b = *reinterpret_cast<volatile uint8_t*>(p);
    return b == 0xCC || b == 0xC3; // int3 / ret planted over the stub
}

// Parent process: normal launches come from explorer.exe / a shell. A known
// debugger as the direct parent is suspicious.
inline bool chk_parent_is_debugger() {
    auto fn = detail::nt_qip();
    if (!fn) return false;
    PROCESS_BASIC_INFORMATION pbi{};
    if (fn(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) != 0) return false;
    DWORD ppid = (DWORD)(uintptr_t)pbi.Reserved3; // InheritedFromUniqueProcessId
    if (!ppid) return false;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    bool hit = false;
    static const wchar_t* dbg[] = {L"windbg.exe", L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe",
        L"ida.exe", L"ida64.exe", L"idag.exe", L"cdb.exe", L"devenv.exe", L"dbgview.exe", L"immunitydebugger.exe"};
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == ppid) {
                for (auto d : dbg) if (_wcsicmp(pe.szExeFile, d) == 0) { hit = true; break; }
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return hit;
}

// --- aggregate -------------------------------------------------------------

struct DebugReport {
    bool peb, api, remote, globalflag, port, object, flags, hwbp, timing;
    bool hidden, closeh, int3, dbgui, parent;
    int score() const {
        return peb + api + remote + globalflag + port + object + flags + hwbp + timing
             + hidden + closeh + int3 + dbgui + parent;
    }
};

inline DebugReport debugger_scan() {
    DebugReport r{};
    r.peb        = chk_peb_being_debugged();
    r.api        = chk_is_debugger_present();
    r.remote     = chk_remote_debugger();
    r.globalflag = chk_nt_global_flag();
    r.port       = chk_debug_port();
    r.object     = chk_debug_object();
    r.flags      = chk_debug_flags();
    r.hwbp       = chk_hardware_breakpoints();
    r.timing     = chk_timing_rdtsc();
    r.hidden     = chk_thread_hidden_mismatch();
    r.closeh     = chk_close_handle();
    r.int3       = chk_int3();
    r.dbgui      = chk_dbgui_patched();
    r.parent     = chk_parent_is_debugger();
    return r;
}

// True when the weighted evidence crosses a threshold (default 1 => any strong
// signal). Callers that want to tolerate flaky timing can raise it.
inline bool debugger_present(int threshold = 1) {
    return debugger_scan().score() >= threshold;
}

} // namespace hz
