#pragma once
// Small, build-pinned observation detours. Every relocated operand is declared
// by the verified profile; this is deliberately not a general detour decoder.
#include <vector>
#include <limits>
namespace DFHack::Combat {
struct BranchSite {
    uintptr_t rva;
    Outcome outcome;
    std::vector<unsigned char> bytes;
    struct Relative {size_t offset,end;};
    std::vector<Relative> relatives;
};
class BranchPatch {
    unsigned char* address=nullptr;
    unsigned char* code=nullptr;
    std::vector<unsigned char> saved,installed;
    static void jump(std::vector<unsigned char>& v,void* dest) {
        v.insert(v.end(),{0xff,0x25,0,0,0,0});
        auto p=reinterpret_cast<unsigned char*>(&dest);v.insert(v.end(),p,p+8);
    }
public:
    bool install(const BranchSite& site,void(*callback)(uint32_t,const uint64_t*)) {
        if(address)return !std::memcmp(address,installed.data(),installed.size());
        auto* base=reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
        auto* pe=reinterpret_cast<IMAGE_NT_HEADERS*>(base+reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
        if(!Profile::matches(pe->FileHeader.TimeDateStamp,pe->OptionalHeader.SizeOfImage,
            base+site.rva,site.bytes.data(),site.bytes.size()))return false;
        // All RIP-relative targets must stay within rel32 reach after replay.
        const auto origin=reinterpret_cast<uintptr_t>(base+site.rva)&~uintptr_t(65535);
        for(uintptr_t distance=65536;distance<0x30000000 && !code;distance+=65536) {
            code=static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(origin+distance),4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
            if(!code && origin>distance)code=static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(origin-distance),4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
        }
        if(!code)return false;
        std::vector<unsigned char> v={0x9c,0x50,0x51,0x52,0x53,0x55,0x56,0x57};
        for(unsigned char reg=0;reg<8;++reg)v.insert(v.end(),{0x41,static_cast<unsigned char>(0x50+reg)});
        // Save all GP registers/flags; align a private call frame. RBX retains
        // the saved-register pointer across the ABI-preserving C++ observer.
        v.insert(v.end(),{0x48,0x89,0xe3,0x48,0x83,0xe4,0xf0,0x48,0x81,0xec,0x80,0,0,0});
        for(unsigned char reg=0;reg<6;++reg)v.insert(v.end(),{0xf3,0x0f,0x7f,static_cast<unsigned char>(0x44+reg*8),0x24,static_cast<unsigned char>(0x20+reg*16)});
        v.push_back(0xb9);auto value=static_cast<uint32_t>(site.outcome);
        auto* val=reinterpret_cast<unsigned char*>(&value);v.insert(v.end(),val,val+4);
        v.insert(v.end(),{0x48,0x89,0xda,0x48,0xb8});
        auto* fn=reinterpret_cast<unsigned char*>(&callback);v.insert(v.end(),fn,fn+8);v.insert(v.end(),{0xff,0xd0});
        for(unsigned char reg=0;reg<6;++reg)v.insert(v.end(),{0xf3,0x0f,0x6f,static_cast<unsigned char>(0x44+reg*8),0x24,static_cast<unsigned char>(0x20+reg*16)});
        v.insert(v.end(),{0x48,0x89,0xdc});
        for(int reg=7;reg>=0;--reg)v.insert(v.end(),{0x41,static_cast<unsigned char>(0x58+reg)});
        v.insert(v.end(),{0x5f,0x5e,0x5d,0x5b,0x5a,0x59,0x58,0x9d});
        const auto replay=v.size();v.insert(v.end(),site.bytes.begin(),site.bytes.end());
        for(const auto& relative:site.relatives) {
            int32_t old;std::memcpy(&old,site.bytes.data()+relative.offset,4);
            const int64_t delta=(reinterpret_cast<int64_t>(base+site.rva)+relative.end+old)-
                (reinterpret_cast<int64_t>(code)+replay+relative.end);
            if(delta<std::numeric_limits<int32_t>::min() || delta>std::numeric_limits<int32_t>::max()) {
                VirtualFree(code,0,MEM_RELEASE);code=nullptr;return false;
            }
            auto replacement=static_cast<int32_t>(delta);std::memcpy(v.data()+replay+relative.offset,&replacement,4);
        }
        jump(v,base+site.rva+site.bytes.size());std::memcpy(code,v.data(),v.size());
        DWORD previous;
        if(!VirtualProtect(code,4096,PAGE_EXECUTE_READ,&previous)) {VirtualFree(code,0,MEM_RELEASE);code=nullptr;return false;}
        FlushInstructionCache(GetCurrentProcess(),code,v.size());
        if(!VirtualProtect(base+site.rva,site.bytes.size(),PAGE_EXECUTE_READWRITE,&previous)) {VirtualFree(code,0,MEM_RELEASE);code=nullptr;return false;}
        address=base+site.rva;saved=site.bytes;installed.clear();jump(installed,code);installed.resize(saved.size(),0x90);
        std::memcpy(address,installed.data(),installed.size());DWORD ignored;
        VirtualProtect(address,installed.size(),previous,&ignored);FlushInstructionCache(GetCurrentProcess(),address,installed.size());return true;
    }
    bool remove() {
        if(!address)return true;
        DWORD previous;
        if(std::memcmp(address,installed.data(),installed.size()) || !VirtualProtect(address,saved.size(),PAGE_EXECUTE_READWRITE,&previous))return false;
        std::memcpy(address,saved.data(),saved.size());DWORD ignored;VirtualProtect(address,saved.size(),previous,&ignored);
        FlushInstructionCache(GetCurrentProcess(),address,saved.size());address=nullptr;VirtualFree(code,0,MEM_RELEASE);code=nullptr;return true;
    }
};
}
