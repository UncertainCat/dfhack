// DF3D fork: positive native equipment-contact observation for DF 53.16 Steam.
// The build profile and guarded detours are defined in the adjacent headers.
#include "modules/Combat.h"
#include "CombatContactProfile.h"
#include "CombatResultScope.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "df/world.h"
#include "df/unit.h"
#include "df/item.h"
#include "df/unit_action.h"
#include "df/unit_wound.h"
#include "df/combat_eventst.h"
#include "df/global_objects.h"
#include "df/proj_itemst.h"
#include "CombatBranchPatch.h"
#endif
namespace DFHack::Combat {
namespace {
std::vector<ItemContactCallback> callbacks;
std::vector<AttackCallback> attackCallbacks;
std::vector<ProjectileCallback> projectileCallbacks;
uint64_t nextOccurrence=1;
uint64_t nextProjectileOccurrence=1;
const char* status="inactive";
#ifdef _WIN32
// These two prologues contain only register/stack operations: no branches or
// RIP-relative operands require relocation. No general-purpose detour decoder
// or unverified offset fallback is used. PE identity AND every overwritten byte
// must match; the patch is installed/removed only with the simulation suspended.
struct Patch {
    unsigned char* address=nullptr;
    void* trampoline=nullptr;
    size_t size=0;
    std::array<unsigned char,32> saved{}, installed{};
    static void jump(unsigned char* dest,void* target) {
        dest[0]=0xff;dest[1]=0x25;std::memset(dest+2,0,4);
        std::memcpy(dest+6,&target,8);
    }
    bool install(uintptr_t rva,const unsigned char* expected,size_t n,void* target) {
        if(address) {
            if(size==n && !std::memcmp(address,installed.data(),n))return true;
            status="contact retained hook verification failed";return false;
        }
        auto base=reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
        auto pe=reinterpret_cast<IMAGE_NT_HEADERS*>(base+reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
        if(!Profile::matches(pe->FileHeader.TimeDateStamp,pe->OptionalHeader.SizeOfImage,base+rva,expected,n)) {
            status="unsupported DF executable or conflicting native hook";return false;
        }
        auto* code=static_cast<unsigned char*>(VirtualAlloc(nullptr,n+14,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
        if(!code){status="contact trampoline allocation failed";return false;}
        std::memcpy(code,expected,n);jump(code+n,base+rva+n);
        DWORD previous;
        if(!VirtualProtect(code,n+14,PAGE_EXECUTE_READ,&previous)) {
            VirtualFree(code,0,MEM_RELEASE);status="contact trampoline protection failed";return false;
        }
        FlushInstructionCache(GetCurrentProcess(),code,n+14);
        if(!VirtualProtect(base+rva,n,PAGE_EXECUTE_READWRITE,&previous)) {
            VirtualFree(code,0,MEM_RELEASE);status="contact entry protection failed";return false;
        }
        size=n;std::memcpy(saved.data(),expected,n);installed.fill(0x90);jump(installed.data(),target);
        address=base+rva;trampoline=code;
        std::memcpy(address,installed.data(),n);DWORD ignored;
        VirtualProtect(address,n,previous,&ignored);FlushInstructionCache(GetCurrentProcess(),address,n);
        return true;
    }
    bool remove() {
        if(!address)return true;
        // Never overwrite another extension's later patch. This library remains
        // loaded for the process lifetime, so a conflict can retain a pass-through
        // trampoline safely after all observers have been removed.
        DWORD previous;
        if(std::memcmp(address,installed.data(),size) ||
           !VirtualProtect(address,size,PAGE_EXECUTE_READWRITE,&previous)) {
            status="contact hook restoration conflict";return false;
        }
        std::memcpy(address,saved.data(),size);DWORD ignored;
        VirtualProtect(address,size,previous,&ignored);FlushInstructionCache(GetCurrentProcess(),address,size);
        address=nullptr;VirtualFree(trampoline,0,MEM_RELEASE);trampoline=nullptr;return true;
    }
};
Patch attackPatch,copyPatch,wrestlePatch;
using Attack=void(*)(df::unit*,df::unit*,void*,df::unit_action*);
using Copy=df::combat_eventst*(*)(df::combat_eventst*,const df::combat_eventst*);
struct Context {
    df::unit* attacker=nullptr;
    df::unit* defender=nullptr;
    int32_t weapon=-1, action=-1, timer1=0, timer2=0;
    uint64_t occurrence=0;
    uint32_t event_count=0;
    bool complete=true;
    std::array<int32_t,100> seen{};
    size_t seen_count=0;
    Context* parent=nullptr;
    WoundInterval wounds;
    Outcome outcome=Outcome::Unknown;
    bool outcome_conflict=false;
    df::proj_itemst* projectile=nullptr;
};
thread_local Context* context=nullptr;
void emitProjectile(ProjectileKind kind,df::proj_itemst* projectile,df::unit* target=nullptr) {
    if(!projectile || projectileCallbacks.empty())return;
    ProjectileEvent event{nextProjectileOccurrence++,kind,projectile,target};
    for(auto callback:projectileCallbacks)callback(event);
}
void observeOutcome(uint32_t value,const uint64_t* regs) {
    if(value==100){emitProjectile(ProjectileKind::Release,reinterpret_cast<df::proj_itemst*>(regs[9]));return;}
    if(value==101){emitProjectile(ProjectileKind::GroundImpact,reinterpret_cast<df::proj_itemst*>(regs[3]));return;}
    if(!context)return;
    const auto outcome=static_cast<Outcome>(value);
    // A conflict is exposed as incomplete rather than silently last-wins.
    if(context->outcome!=Outcome::Unknown && context->outcome!=outcome)context->outcome_conflict=true;
    else context->outcome=outcome;
}
const std::vector<BranchSite> outcomeSites={
    {0x64e871,Outcome::Miss,{0x83,0x3d,0x20,0xda,0x24,0x1,0x1,0xf,0x85,0xa0,0x4c,0,0,0x48,0x85,0xff},{{2,7},{9,13}}},
    {0x65037e,Outcome::Miss,{0x39,0x35,0x14,0xbf,0x24,0x1,0xf,0x85,0x9d,0x2,0,0,0x48,0x85,0xff},{{2,6},{8,12}}},
    {0x6520af,Outcome::Hit,{0x83,0x3d,0xe2,0xa1,0x24,0x1,0x1,0xf,0x85,0xb4,0x2,0,0,0x48,0x85,0xff},{{2,7},{9,13}}},
    {0x6516fc,Outcome::Blocked,{0x83,0x3d,0x95,0xab,0x24,0x1,0x1,0xf,0x85,0x16,0x3,0,0,0x48,0x85,0xff},{{2,7},{9,13}}},
    {0x64f554,Outcome::Blocked,{0x83,0x3d,0x3d,0xcd,0x24,0x1,0x1,0xf,0x85,0x6a,0x2,0,0,0x48,0x85,0xff},{{2,7},{9,13}}},
    {0x65137e,Outcome::Blocked,{0x83,0x3d,0x13,0xaf,0x24,0x1,0x1,0xf,0x85,0x72,0x2,0,0,0x48,0x85,0xff},{{2,7},{9,13}}},
    {0x64fd0f,Outcome::ParrySuccess,{0x83,0x3d,0x82,0xc5,0x24,0x1,0x1,0xf,0x85,0x40,0x2,0,0,0x48,0x85,0xff},{{2,7},{9,13}}},
    {0x651188,Outcome::Wrestle,{0x83,0x3d,0x9,0xb1,0x24,0x1,0x1,0xf,0x85,0x68,0x4,0,0,0x48,0x85,0xff},{{2,7},{9,13}}},
    {0x135fd65,static_cast<Outcome>(100),{0xba,0x9,0,0,0,0x44,0x89,0x6c,0x24,0x50,0x66,0x44,0x89,0x6c,0x24,0x48},{}},
    {0xeaa2ac,static_cast<Outcome>(101),{0x83,0x3d,0xe5,0x1f,0x9f,0,0x1,0xf,0x85,0xb1,0x22,0,0,0x66,0x45,0x85,0xf6},{{2,7},{9,13}}},
    {0xead905,static_cast<Outcome>(101),{0x83,0x3d,0x8c,0xe9,0x9e,0,0x1,0xf,0x85,0xca,0,0,0,0x45,0xf,0xb7,0x4c,0x24,0x30},{{2,7},{9,13}}},
    {0x64a045,Outcome::Wrestle,{0x44,0x39,0x3d,0x4c,0x22,0x25,0x1,0xf,0x85,0xbd,0x1,0,0,0x83,0x3d,0xa7,0xf5,0xff,0x1,0xa},{{3,7},{9,13},{15,20}}},
};
std::vector<BranchPatch> outcomePatches(outcomeSites.size());
bool removeOutcomes(){bool ok=true;for(auto& patch:outcomePatches)ok=patch.remove() && ok;return ok;}
bool resolve(df::unit* actor,df::unit* target,void* unknown,df::unit_action* action,bool wrestling) {
    Context current;
    current.parent=context;current.defender=target;
    current.projectile=wrestling?nullptr:static_cast<df::proj_itemst*>(unknown);
    if(target) {
        current.wounds.begin=target->body.wound_next_id;
    }
    if((!callbacks.empty() || !attackCallbacks.empty()) && actor && target && action && action->type==df::unit_action_type::Attack &&
       action->data.attack.target_unit_id==target->id) {
        current.attacker=actor;current.defender=target;
        current.weapon=action->data.attack.attack_item_id;current.action=action->id;
        current.occurrence=nextOccurrence++;
        current.timer1=action->data.attack.timer1;current.timer2=action->data.attack.timer2;
    }
    struct Scope {
        Context* prior;
        explicit Scope(Context* next):prior(context){context=next;}
        ~Scope(){context=prior;}
    } scope(&current);
    if(current.occurrence) {
        AttackEvent event{current.occurrence,AttackPhase::Begin,actor,target,df::item::find(current.weapon),nullptr,current.action,true,0,current.timer1,current.timer2};
        event.weapon_context_complete=current.weapon<0 || event.weapon;
        for(auto callback:attackCallbacks)callback(event);
    }
    bool result=false;
    if(wrestling)result=reinterpret_cast<bool(*)(df::unit*,df::unit*,df::unit_action*,void*)>(wrestlePatch.trampoline)(actor,target,action,unknown);
    else reinterpret_cast<Attack>(attackPatch.trampoline)(actor,target,unknown,action);
    if(current.projectile && !current.outcome_conflict) {
        if(current.outcome==Outcome::Hit)emitProjectile(ProjectileKind::HitCreature,current.projectile,target);
        else if(current.outcome==Outcome::Blocked)emitProjectile(ProjectileKind::Blocked,current.projectile,target);
    }
    if(target) {
        current.wounds.end=target->body.wound_next_id;
        for(auto* parent=current.parent;parent;parent=parent->parent)if(parent->defender==target) {
            parent->wounds.exclude(current.wounds.begin,current.wounds.end);
        }
    }
    if(current.occurrence) {
        bool wounds_complete=current.wounds.complete && current.wounds.bounded(128);
        if(wounds_complete)for(int32_t id=current.wounds.begin;id<current.wounds.end;++id)if(current.wounds.own(id)) {
            const auto index=df::unit_wound::binsearch_index(target->body.wounds,id,true);
            auto* wound=index>=0?target->body.wounds[index]:nullptr;
            if(!wound || wound->attacker_unit_id!=actor->id){wounds_complete=false;continue;}
            AttackEvent event{current.occurrence,AttackPhase::Wound,nullptr,nullptr,nullptr,nullptr,current.action,current.complete,current.event_count,current.timer1,current.timer2};
            event.wound_id=wound->id;event.wound_victim_id=target->id;
            event.severed_part=wound->flags.bits.severed_part;event.popped_out=wound->flags.bits.popped_out;
            event.wound=wound;event.defender=target;
            for(auto callback:attackCallbacks)callback(event);
        }
        AttackEvent event{current.occurrence,AttackPhase::End,nullptr,nullptr,nullptr,nullptr,current.action,current.complete,current.event_count,current.timer1,current.timer2};
        event.wounds_complete=wounds_complete;
        event.outcome=current.outcome;
        event.outcome_complete=current.outcome!=Outcome::Unknown && !current.outcome_conflict;
        for(auto callback:attackCallbacks)callback(event);
    }
    return result;
}
void attack(df::unit* actor,df::unit* target,void* unknown,df::unit_action* action) {resolve(actor,target,unknown,action,false);}
bool wrestle(df::unit* actor,df::unit* target,df::unit_action* action,void* unknown) {return resolve(actor,target,unknown,action,true);}
df::combat_eventst* copy(df::combat_eventst* dest,const df::combat_eventst* src) {
    if(context && context->attacker && src && df::global::world) {
        auto& slots=df::global::world->status.slots;
        const int index=slots.slots_used, item=src->field1[0];
        if(index>=0 && index<100 && dest==&slots.slotdata[index]) {
            ++context->event_count;
            if(index==99)context->complete=false;
            if(context->weapon>=0 && (src->type==df::combat_report_event_type::StruckItem ||
                src->type==df::combat_report_event_type::Deflected)) {
                auto begin=context->seen.begin(),end=begin+context->seen_count;
                if(item<0 || item==context->weapon)context->complete=false;
                else if(std::find(begin,end,item)==end) {
                    if(context->seen_count==context->seen.size())context->complete=false;
                    else {
                        auto* first=df::item::find(context->weapon);auto* second=df::item::find(item);
                        if(!first || !second)context->complete=false;
                        else {
                            context->seen[context->seen_count++]=item;
                            ItemContact contact{context->attacker,context->defender,first,second,context->action};
                            for(auto callback:callbacks)callback(contact);
                            AttackEvent event{context->occurrence,AttackPhase::Contact,context->attacker,context->defender,
                                first,second,context->action,context->complete,context->event_count,context->timer1,context->timer2};
                            for(auto callback:attackCallbacks)callback(event);
                        }
                    }
                }
            }
        }
    }
    return reinterpret_cast<Copy>(copyPatch.trampoline)(dest,src);
}
bool install() {
    for(size_t i=0;i<outcomeSites.size();++i)if(!outcomePatches[i].install(outcomeSites[i],observeOutcome)) {
        removeOutcomes();status="unsupported outcome branch or conflicting hook";return false;
    }
    const unsigned char wrestleBytes[]={0x40,0x55,0x53,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8d,0xac,0x24,0x28,0xfc,0xff,0xff};
    if(!wrestlePatch.install(0x646f00,wrestleBytes,sizeof(wrestleBytes),reinterpret_cast<void*>(&wrestle)) ||
       !attackPatch.install(Profile::attack_rva,Profile::attack.data(),Profile::attack.size(),reinterpret_cast<void*>(&attack)) ||
       !copyPatch.install(Profile::copy_rva,Profile::copy.data(),Profile::copy.size(),reinterpret_cast<void*>(&copy))) {
        copyPatch.remove();attackPatch.remove();wrestlePatch.remove();removeOutcomes();return false;
    }
    status="active: DF 53.16 Steam resolved melee equipment contacts";return true;
}
#endif
}
bool registerItemContactCallback(ItemContactCallback callback) {
    if(!callback)return false;
    if(std::find(callbacks.begin(),callbacks.end(),callback)!=callbacks.end())return true;
#ifdef _WIN32
    if(callbacks.empty() && attackCallbacks.empty() && projectileCallbacks.empty() && !install())return false;
    callbacks.push_back(callback);return true;
#else
    status="unsupported platform: no verified native contact boundary";return false;
#endif
}
void unregisterItemContactCallback(ItemContactCallback callback) {
    callbacks.erase(std::remove(callbacks.begin(),callbacks.end(),callback),callbacks.end());
#ifdef _WIN32
    if(callbacks.empty() && attackCallbacks.empty() && projectileCallbacks.empty()) {
        context=nullptr;const bool a=copyPatch.remove(),b=attackPatch.remove(),c=removeOutcomes(),d=wrestlePatch.remove();
        if(a && b && c && d)status="inactive";
    }
#endif
}
bool registerAttackCallback(AttackCallback callback) {
    if(!callback)return false;
    if(std::find(attackCallbacks.begin(),attackCallbacks.end(),callback)!=attackCallbacks.end())return true;
#ifdef _WIN32
    if(callbacks.empty() && attackCallbacks.empty() && projectileCallbacks.empty() && !install())return false;
    attackCallbacks.push_back(callback);return true;
#else
    status="unsupported platform: no verified native contact boundary";return false;
#endif
}
void unregisterAttackCallback(AttackCallback callback) {
    attackCallbacks.erase(std::remove(attackCallbacks.begin(),attackCallbacks.end(),callback),attackCallbacks.end());
#ifdef _WIN32
    if(callbacks.empty() && attackCallbacks.empty() && projectileCallbacks.empty()) {
        context=nullptr;const bool a=copyPatch.remove(),b=attackPatch.remove(),c=removeOutcomes(),d=wrestlePatch.remove();
        if(a && b && c && d)status="inactive";
    }
#endif
}
bool registerProjectileCallback(ProjectileCallback callback) {
    if(!callback)return false;
    if(std::find(projectileCallbacks.begin(),projectileCallbacks.end(),callback)!=projectileCallbacks.end())return true;
#ifdef _WIN32
    if(callbacks.empty() && attackCallbacks.empty() && projectileCallbacks.empty() && !install())return false;
    projectileCallbacks.push_back(callback);return true;
#else
    return false;
#endif
}
void unregisterProjectileCallback(ProjectileCallback callback) {
    projectileCallbacks.erase(std::remove(projectileCallbacks.begin(),projectileCallbacks.end(),callback),projectileCallbacks.end());
#ifdef _WIN32
    if(callbacks.empty() && attackCallbacks.empty() && projectileCallbacks.empty()) {
        context=nullptr;const bool a=copyPatch.remove(),b=attackPatch.remove(),c=removeOutcomes(),d=wrestlePatch.remove();
        if(a && b && c && d)status="inactive";
    }
#endif
}
const char* itemContactStatus(){return status;}
}


