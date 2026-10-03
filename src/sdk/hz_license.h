// hz_license.h - offline, signed software licenses bound to a machine.
//
// A license is a small fixed payload (features, HWID, expiry) plus an Ed25519
// signature. The app embeds only the PUBLIC key and calls verify_license();
// forging a license requires the private key (held only by you, offline), so a
// cracker must patch the check rather than mint a license. Pair it with the
// integrity stamp (hz_integrity.h) so patching the check is itself detected.
#pragma once
#ifndef _WIN32
#error "hz_license.h is Windows-only"
#endif
#include <windows.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>
#include <ctime>
#include "hz_sha256.h"
#include "hz_ed25519.h"
#pragma comment(lib, "advapi32.lib") // RegOpenKeyEx / RegQueryValueEx for MachineGuid

namespace hz {

#pragma pack(push, 1)
struct LicensePayload {
    uint32_t magic;     // 'HZLC' = 0x484C4C43 little-endian bytes {'C','L','L','H'} -> see MAGIC
    uint16_t version;   // 1
    uint16_t features;  // feature bitmask you define
    uint8_t  hwid[32];  // SHA-256 machine fingerprint; all-zero = any machine
    uint64_t expiry;    // unix seconds UTC; 0 = perpetual
    uint64_t issued;    // unix seconds UTC
};
#pragma pack(pop)
static const uint32_t HZ_LICENSE_MAGIC = 0x484C4C43u; // "HLLC"
static const uint16_t HZ_LICENSE_VERSION = 1;
static const size_t HZ_LICENSE_BLOB = sizeof(LicensePayload) + 64; // payload + sig

enum class LicenseStatus { Valid, BadFormat, BadSignature, WrongMachine, Expired };

struct LicenseInfo {
    LicenseStatus status;
    uint16_t features;
    uint64_t expiry;
    uint64_t issued;
};

// ---- machine fingerprint --------------------------------------------------
namespace detail {
inline void append(Sha256& s, const void* p, size_t n) { s.update(p, n); }

inline bool reg_machine_guid(char out[64]) {
    HKEY k; out[0] = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) return false;
    DWORD type = 0, len = 64;
    LONG r = RegQueryValueExA(k, "MachineGuid", nullptr, &type, (LPBYTE)out, &len);
    RegCloseKey(k);
    return r == ERROR_SUCCESS && type == REG_SZ;
}
} // namespace detail

// Stable-ish machine fingerprint: MachineGuid + system volume serial +
// computer name + CPU brand, hashed to 32 bytes.
inline void hwid(uint8_t out[32]) {
    Sha256 s;
    s.update("hzprotect-hwid-v1", 17);

    char guid[64]; if (detail::reg_machine_guid(guid)) s.update(guid, strlen(guid));

    char win[MAX_PATH]; UINT wl = GetWindowsDirectoryA(win, MAX_PATH);
    char root[8] = "C:\\"; if (wl >= 2) { root[0] = win[0]; }
    DWORD serial = 0; GetVolumeInformationA(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
    s.update(&serial, sizeof(serial));

    char name[256]; DWORD nl = sizeof(name);
    if (GetComputerNameA(name, &nl)) s.update(name, nl);

    int regs[4] = {0}; char brand[49] = {0};
    for (int i = 0; i < 3; ++i) { __cpuid(regs, 0x80000002 + i); memcpy(brand + i * 16, regs, 16); }
    s.update(brand, 48);

    s.final(out);
}

inline void hwid_hex(char out[65]) {
    uint8_t h[32]; hwid(h);
    static const char* d = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) { out[2*i] = d[h[i] >> 4]; out[2*i+1] = d[h[i] & 15]; }
    out[64] = 0;
}

// ---- base64 ---------------------------------------------------------------
namespace detail {
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62; if (c == '/') return 63; return -1;
}
inline size_t b64enc(const uint8_t* in, size_t n, char* out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = in[i] << 16;
        if (i + 1 < n) v |= in[i+1] << 8;
        if (i + 2 < n) v |= in[i+2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? B64[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < n) ? B64[v & 63] : '=';
    }
    out[o] = 0; return o;
}
inline size_t b64dec(const char* in, uint8_t* out, size_t cap) {
    int q[4]; int qi = 0; size_t o = 0;
    for (const char* p = in; *p; ++p) {
        if (*p == '=' || *p == '-') break; // '=' pad or '-' of an armor line terminates
        int v = b64val(*p);
        if (v < 0) continue; // skip whitespace/newlines
        q[qi++] = v;
        if (qi == 4) {
            if (o + 3 > cap) return o;
            out[o++] = (uint8_t)((q[0] << 2) | (q[1] >> 4));
            out[o++] = (uint8_t)((q[1] << 4) | (q[2] >> 2));
            out[o++] = (uint8_t)((q[2] << 6) | q[3]);
            qi = 0;
        }
    }
    if (qi >= 2 && o < cap) out[o++] = (uint8_t)((q[0] << 2) | (q[1] >> 4));
    if (qi >= 3 && o < cap) out[o++] = (uint8_t)((q[1] << 4) | (q[2] >> 2));
    return o;
}
} // namespace detail

// ---- verify (app side) ----------------------------------------------------
// licText: the base64 body of a license (wrapper lines are ignored by b64dec).
// pubkey: your embedded 32-byte Ed25519 public key.
inline LicenseInfo verify_license(const char* licText, const uint8_t pubkey[32]) {
    LicenseInfo info{LicenseStatus::BadFormat, 0, 0, 0};

    // Accept either a bare base64 body or a "-----BEGIN HZ LICENSE-----" armor:
    // start after the BEGIN line so the armor words (valid base64 letters) are
    // not decoded; b64dec then stops at the '-' of the END line.
    const char* body = licText;
    const char* beg = strstr(licText, "-----BEGIN");
    if (beg) { const char* nl = strchr(beg, '\n'); if (nl) body = nl + 1; }

    uint8_t blob[HZ_LICENSE_BLOB + 8];
    size_t n = detail::b64dec(body, blob, sizeof(blob));
    if (n != HZ_LICENSE_BLOB) return info;

    LicensePayload p; memcpy(&p, blob, sizeof(p));
    const uint8_t* sig = blob + sizeof(p);
    if (p.magic != HZ_LICENSE_MAGIC || p.version != HZ_LICENSE_VERSION) return info;

    if (!ed::verify_detached(sig, blob, sizeof(p), pubkey)) { info.status = LicenseStatus::BadSignature; return info; }

    info.features = p.features; info.expiry = p.expiry; info.issued = p.issued;

    uint8_t zero[32] = {0};
    if (memcmp(p.hwid, zero, 32) != 0) {
        uint8_t me[32]; hwid(me);
        if (memcmp(me, p.hwid, 32) != 0) { info.status = LicenseStatus::WrongMachine; return info; }
    }
    if (p.expiry != 0) {
        uint64_t now = (uint64_t)time(nullptr);
        if (now > p.expiry) { info.status = LicenseStatus::Expired; return info; }
    }
    info.status = LicenseStatus::Valid;
    return info;
}

inline bool license_ok(const char* licText, const uint8_t pubkey[32]) {
    return verify_license(licText, pubkey).status == LicenseStatus::Valid;
}

} // namespace hz
