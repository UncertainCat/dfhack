#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
// Verified Win64 Steam 53.16 entry instructions; intentionally no other build
// fallback. Shared with the portable fail-closed regression test.
namespace DFHack::Combat::Profile {
inline constexpr uint32_t timestamp=0x6a70a6d9, image_size=0x2711000;
inline constexpr uintptr_t attack_rva=0x64a350, copy_rva=0x642570;
inline constexpr std::array<unsigned char,21> attack={0x40,0x55,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0xac,0x24,0x78,0xf0,0xff,0xff};
inline constexpr std::array<unsigned char,16> copy={0x48,0x89,0x5c,0x24,0x8,0x57,0x48,0x83,0xec,0x20,0xf,0xb7,0x2,0x48,0x8b,0xfa};
inline bool matches(uint32_t stamp,uint32_t size,const unsigned char* actual,const unsigned char* expected,size_t n) {
    return stamp==timestamp && size==image_size && actual && expected && n>=14 && n<=32 && !std::memcmp(actual,expected,n);
}
}
