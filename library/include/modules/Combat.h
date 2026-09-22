#pragma once
#include "Export.h"
#include <cstdint>
namespace df { struct unit; struct item; struct unit_wound; struct proj_itemst; }
namespace DFHack::Combat {
// Synchronous simulation-thread notification at a positively resolved equipment
// impact. Pointers are valid only during the callback. Observe only: do not
// modify simulation state, register callbacks, or retain native pointers here.
struct ItemContact {
    df::unit* attacker;
    df::unit* defender;
    df::item* attacking_item;
    df::item* struck_item;
    int32_t action_id;
};
using ItemContactCallback = void (*)(const ItemContact&);
enum class AttackPhase { Begin, Contact, End, Wound };
enum class Outcome : uint32_t { Unknown, Miss, Hit, Blocked, ParrySuccess, ParryFailed, Wrestle };
struct AttackEvent {
    uint64_t occurrence_id;
    AttackPhase phase;
    df::unit* attacker;
    df::unit* defender;
    df::item* weapon;
    df::item* struck_item;
    int32_t action_id;
    // Completeness applies only to this supported equipment-contact channel.
    // End without contacts is not evidence of a miss, dodge, or parry.
    bool equipment_contacts_complete;
    uint32_t native_event_count;
    int32_t entry_timer1;
    int32_t entry_timer2;
    int32_t wound_id=-1;
    int32_t wound_victim_id=-1;
    bool severed_part=false;
    bool popped_out=false;
    bool wounds_complete=false;
    df::unit_wound* wound=nullptr;
    Outcome outcome=Outcome::Unknown;
    bool outcome_complete=false;
    bool weapon_context_complete=false;
};
using AttackCallback = void (*)(const AttackEvent&);
enum class ProjectileKind { Unknown, Release, HitCreature, Blocked, GroundImpact };
struct ProjectileEvent {
    uint64_t occurrence_id;
    ProjectileKind kind;
    df::proj_itemst* projectile;
    df::unit* target;
};
using ProjectileCallback=void(*)(const ProjectileEvent&);
DFHACK_EXPORT bool registerProjectileCallback(ProjectileCallback callback);
DFHACK_EXPORT void unregisterProjectileCallback(ProjectileCallback callback);
DFHACK_EXPORT bool registerAttackCallback(AttackCallback callback);
DFHACK_EXPORT void unregisterAttackCallback(AttackCallback callback);
// Call while DF is suspended. Unsupported builds fail closed. This currently
// covers resolved melee armor contact; defense intents and report text are not
// inputs. Identical item pairs are emitted once per native attack invocation.
DFHACK_EXPORT bool registerItemContactCallback(ItemContactCallback callback);
DFHACK_EXPORT void unregisterItemContactCallback(ItemContactCallback callback);
DFHACK_EXPORT const char* itemContactStatus();
}
