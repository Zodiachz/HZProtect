// lickat.cpp - self-contained license tests (no files/tools): build a key pair
// from a fixed seed, mint licenses in memory, and check every verify outcome.
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <ctime>
#include "../src/sdk/hz_license.h"
#include "../src/sdk/hz_ed25519.h"

static const char* name(hz::LicenseStatus s) {
    switch (s) {
        case hz::LicenseStatus::Valid: return "VALID";
        case hz::LicenseStatus::BadFormat: return "BAD_FORMAT";
        case hz::LicenseStatus::BadSignature: return "BAD_SIGNATURE";
        case hz::LicenseStatus::WrongMachine: return "WRONG_MACHINE";
        case hz::LicenseStatus::Expired: return "EXPIRED";
        default: return "?";
    }
}

// Mint a base64 license from a payload, signed with sk.
static void mint(const hz::LicensePayload& p, const uint8_t sk[64], char* b64out) {
    uint8_t blob[hz::HZ_LICENSE_BLOB];
    memcpy(blob, &p, sizeof(p));
    hz::ed::sign_detached(blob + sizeof(p), blob, sizeof(p), sk);
    hz::detail::b64enc(blob, hz::HZ_LICENSE_BLOB, b64out);
}

static hz::LicensePayload base(uint16_t feat, uint64_t expiry, const uint8_t* hwid /*32 or null*/) {
    hz::LicensePayload p; memset(&p, 0, sizeof(p));
    p.magic = hz::HZ_LICENSE_MAGIC; p.version = hz::HZ_LICENSE_VERSION;
    p.features = feat; p.expiry = expiry; p.issued = (uint64_t)time(nullptr);
    if (hwid) memcpy(p.hwid, hwid, 32);
    return p;
}

int main() {
    bool pass = true;
    auto check = [&](const char* label, hz::LicenseStatus got, hz::LicenseStatus want) {
        bool ok = got == want;
        printf("  %-22s -> %-13s %s\n", label, name(got), ok ? "[PASS]" : "[FAIL]");
        if (!ok) pass = false;
    };

    uint8_t seed[32]; for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(i * 7 + 1);
    uint8_t pk[32], sk[64];
    hz::ed::keypair_from_seed(pk, sk, seed);

    char lic[512];
    uint64_t now = (uint64_t)time(nullptr);

    // 1) perpetual, any machine
    mint(base(0x00ff, 0, nullptr), sk, lic);
    check("any/perpetual", hz::verify_license(lic, pk).status, hz::LicenseStatus::Valid);

    // 2) bound to THIS machine
    uint8_t me[32]; hz::hwid(me);
    mint(base(0x000f, 0, me), sk, lic);
    check("bound/this-machine", hz::verify_license(lic, pk).status, hz::LicenseStatus::Valid);

    // 3) bound to a different machine
    uint8_t other[32]; memset(other, 0xAB, 32);
    mint(base(0x00ff, 0, other), sk, lic);
    check("bound/other-machine", hz::verify_license(lic, pk).status, hz::LicenseStatus::WrongMachine);

    // 4) expired yesterday
    mint(base(0x00ff, now - 86400, nullptr), sk, lic);
    check("expired", hz::verify_license(lic, pk).status, hz::LicenseStatus::Expired);

    // 5) valid future expiry
    mint(base(0x00ff, now + 86400, nullptr), sk, lic);
    check("future-expiry", hz::verify_license(lic, pk).status, hz::LicenseStatus::Valid);

    // 6) tampered signature (flip a byte in the base64 body region of the sig)
    mint(base(0x00ff, 0, nullptr), sk, lic);
    lic[150] = (lic[150] == 'A') ? 'B' : 'A';
    check("tampered-signature", hz::verify_license(lic, pk).status, hz::LicenseStatus::BadSignature);

    // 7) wrong public key must reject a genuine license
    mint(base(0x00ff, 0, nullptr), sk, lic);
    uint8_t seed2[32]; for (int i = 0; i < 32; ++i) seed2[i] = (uint8_t)(i * 3 + 9);
    uint8_t pk2[32], sk2[64]; hz::ed::keypair_from_seed(pk2, sk2, seed2);
    check("wrong-pubkey", hz::verify_license(lic, pk2).status, hz::LicenseStatus::BadSignature);

    printf("\n%s\n", pass ? "ALL PASS" : "FAILURE");
    return pass ? 0 : 1;
}
