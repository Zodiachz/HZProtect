// hz_antivm.h - virtual-machine / hypervisor detection. Useful to notice when
// your app is running inside an automated analysis sandbox. These are hints,
// not proof (plenty of legitimate users run in VMs), so treat the result as
// one input, never as a hard gate.
#pragma once
#ifndef _WIN32
#error "hz_antivm.h is Windows-only"
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <intrin.h>

namespace hz {

// CPUID leaf 1, ECX bit 31 is the "hypervisor present" hint set by every major
// VMM. True on bare metal only if something is lying to you.
inline bool vm_hypervisor_bit() {
    int regs[4] = {0};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 31)) != 0;
}

// CPUID leaf 0x40000000 returns the hypervisor vendor string in EBX:ECX:EDX.
inline bool vm_vendor(char out[13]) {
    int regs[4] = {0};
    __cpuid(regs, 0x40000000);
    memcpy(out + 0, &regs[1], 4);
    memcpy(out + 4, &regs[2], 4);
    memcpy(out + 8, &regs[3], 4);
    out[12] = 0;
    static const char* known[] = {
        "VMwareVMware", "KVMKVMKVM\0\0\0", "Microsoft Hv", "VBoxVBoxVBox",
        "XenVMMXenVMM", "prl hyperv\0\0", "TCGTCGTCGTCG", "bhyve bhyve "};
    for (auto k : known) if (memcmp(out, k, 12) == 0) return true;
    return false;
}

struct VmReport { bool hyperBit; bool knownVendor; char vendor[13]; };

inline VmReport vm_scan() {
    VmReport r{};
    r.hyperBit = vm_hypervisor_bit();
    r.knownVendor = vm_vendor(r.vendor);
    return r;
}

inline bool in_virtual_machine() {
    VmReport r = vm_scan();
    return r.hyperBit || r.knownVendor;
}

} // namespace hz
