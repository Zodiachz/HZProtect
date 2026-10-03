// hzprotect.h - umbrella header for the HZProtect SDK.
//
// A source-integrated protection toolkit the developer adds to their OWN
// application: debugger detection, on-disk self-integrity (anti-crack), and
// compile-time string encryption. Header-only, no external dependencies.
//
//   #include "hzprotect.h"
//   int main() {
//       if (hz::debugger_present()) return 0;          // bail quietly
//       if (hz::self_tampered(0xDEADBEEF)) return 0;    // baked CRC of .text
//       puts(HZ_STR("licensed build"));                 // never in cleartext
//   }
#pragma once

#include "hz_antidebug.h"
#include "hz_antivm.h"
#include "hz_hooks.h"
#include "hz_integrity.h"
#include "hz_strcrypt.h"
#include "hz_sha256.h"
#include "hz_aes.h"
#include "hz_blob.h"
#include "hz_ed25519.h"
#include "hz_license.h"

#define HZPROTECT_VERSION_MAJOR 0
#define HZPROTECT_VERSION_MINOR 4
#define HZPROTECT_VERSION_STR "0.4.0"
