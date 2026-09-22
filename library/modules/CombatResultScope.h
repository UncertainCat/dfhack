#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
namespace DFHack::Combat {
// Exact new-ID interval for one resolver scope. Nested scopes targeting the
// same unit are excluded even when they use the same attacker/action identity.
struct WoundInterval {
    struct Range {int32_t begin,end;};
    int32_t begin=-1,end=-1;
    std::array<Range,32> excluded{};
    size_t excluded_count=0;
    bool complete=true;
    void exclude(int32_t first,int32_t last) {
        if(first<0 || last<first){complete=false;return;}
        if(first==last)return;
        if(excluded_count==excluded.size()){complete=false;return;}
        excluded[excluded_count++]={first,last};
    }
    bool own(int32_t id) const {
        if(id<begin || id>=end)return false;
        for(size_t i=0;i<excluded_count;++i)if(id>=excluded[i].begin && id<excluded[i].end)return false;
        return true;
    }
    bool bounded(size_t max) const{return begin>=0 && end>=begin && static_cast<uint64_t>(end)-begin<=max;}
};
}
