//! CS2 signature database (ported + deduplicated from
//! `signature-dumper/cs2sign/CS2EnhancedSignatures.h`).
//!
//! Every entry is module-scoped to its DLL (.text first, .rdata fallback)
//! so scans stay fast and unambiguous.  Patterns that pointed into a
//! relative-addressing instruction use `Rel32` / `RipRel` resolution so the
//! reported address is the final function / global â€” not the midpoint of
//! whatever instruction matched.  Entries marked `StringRef` find the
//! function by the unique string it references (Ghidra workflow), which
//! is the most resilient kind across CS2 patches.

use super::{ResolveKind, Signature};

const NONE: ResolveKind = ResolveKind::None;
const STRREF: ResolveKind = ResolveKind::StringRef;
const REL32_1: ResolveKind = ResolveKind::Rel32 { rel_off: 1 };
const RIPREL_3: ResolveKind = ResolveKind::RipRel { rel_off: 3 };
const RIPREL_2: ResolveKind = ResolveKind::RipRel { rel_off: 2 };
const RIPREL_19: ResolveKind = ResolveKind::RipRel { rel_off: 19 };

pub static CS2_SIGNATURES: &[Signature] = &[
    // ---------- client.dll : input / movement --------------------------
    Signature {
        name: "CreateMove",
        module: "client.dll",
        needle: "48 8B C4 4C 89 40 18 48 89 48 08 55 53 41 54 41 55",
        resolve: NONE,
        extra_off: 0,
        prototype: "double __fastcall sub_180C5E7F0(__int64 a1, unsigned int a2, __int64 a3)",
    },
    Signature {
        // Build 14160 fix: original needle was register-tight (44 38 20 / 44 88 67).
        // Wildcard the spilled-register slots so it survives Valve re-allocating
        // r12b<->r15b across rebuilds (cheat-side wildcarded version, IDA-verified
        // 2026-05-09 — single hit at client!0x180AC85A0).
        name: "CCSPlayer::ThirdPersonReset",
        module: "client.dll",
        needle: "48 8B 40 08 44 38 ? 75 10 44 88 ? 01",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        name: "RegenerateWeaponSkins",
        module: "client.dll",
        needle: "48 83 EC ? E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 8B 10",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_1807B0D40()",
    },
    Signature {
        name: "CSkeletonInstance::SetMeshGroupMask",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8D 99",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180A2DB50(__int64 a1, __int64 a2)",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CCSGOViewAdvice::OverrideView",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B FA E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14154 (0 hits, IDA-verified 2026-04-25).
        // Use `GetWorldFovResolver` instead â€” see entry near bottom of
        // this file. Kept here so the dumper diff still surfaces 0/N
        // hits as a regression signal if a future build resurrects it.
        name: "SetWorldFov",
        module: "client.dll",
        // E8 disp32 at start of the match -> resolve as call target
        needle: "E8 ? ? ? ? F3 0F 11 45 ? 48 8B 5C 24",
        resolve: ResolveKind::Rel32 { rel_off: 1 },
        extra_off: 0,
        prototype: "",
    },
    Signature {
        name: "CalcViewmodel",
        module: "client.dll",
        needle: "40 55 53 56 41 56 41 57 48 8B EC",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_18084F430(__int64 a1, float *a2, float *a3)",
    },
    Signature {
        // Per-frame viewmodel offset / FOV resolver. Signature:
        //   void(this_viewmodel, float* outOffsets[3], float* outFov)
        // Reads cvars (viewmodel_fov / viewmodel_offset_*) or the pawn
        // fields at C_CSPlayerPawn +0x1B70..+0x1B7C, then HARD-CLAMPS:
        //     X   -> [-2.0, 2.5]
        //     Y/Z -> [-2.0, 2.0]
        //     FOV -> [60.0, 68.0]
        // Hooking after the original runs and overwriting the output
        // floats is the only reliable path to push viewmodel_fov outside
        // the clamps. Verified IDA build 14160 (RVA 0x84EE40).
        name: "GetViewModelOffsets",
        module: "client.dll",
        needle: "40 55 53 56 41 56 41 57 48 8B EC 48 83 EC 20 4D 8B F8 4C 8B F2 48 8B F1 E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_18084EE40(__int64 viewmodel, float *outOffsets, float *outFov)",
    },
    Signature {
        name: "NoSpread1",
        module: "client.dll",
        needle: "48 89 5C 24 08 57 48 81 EC F0 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180C7E2D0(__int64 a1, __int64 a2, int a3)",
    },
    Signature {
        name: "CalcSpread",
        module: "client.dll",
        needle: "48 8B C4 48 89 58 ? 48 89 68 ? 48 89 70 ? 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ? 4C 63 EA",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ---------- skin / knife / glove changer --------------------------
    Signature {
        name: "CBaseModelEntity::SetBodyGroup",
        module: "client.dll",
        needle: "85 D2 0F 88 ? ? ? ? 55 53 56 41 56 48 8B EC 48 83 EC 78",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        name: "CCSPlayerInventory::GetItemInLoadout",
        module: "client.dll",
        needle: "40 55 48 83 EC ? 49 63 E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 *__fastcall sub_1807C3D70(__int64 a1, unsigned int a2, unsigned int a3)",
    },
    Signature {
        name: "CCSInventoryManager::EquipItemInLoadout",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 89 54 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 0F B7 FA",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_1807C2150(_QWORD *a1, unsigned int a2, int a3, unsigned __int64 a4)",
    },
    Signature {
        name: "CEconItemView::GetCustomPaintKitIndex",
        module: "client.dll",
        needle: "48 89 5C 24 ? 57 48 83 EC ? 8B 15 ? ? ? ? 48 8B F9 65 48 8B 04 25 ? ? ? ? B9 ? ? ? ? 48 8B 04 D0 8B 04 01 39 05 ? ? ? ? 0F 8F ? ? ? ? E8 ? ? ? ? 8B 58 ? 39 1D ? ? ? ? 74 ? E8 ? ? ? ? 48 8B 15 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 89 05 ? ? ? ? 89 1D ? ? ? ? EB ? 48 8B 05 ? ? ? ? 48 85 C0 74",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1810A8A60(__int64 *a1)",
    },

    // ---------- econ schema -------------------------------------------
    Signature {
        name: "GetEconItemSystem",
        module: "client.dll",
        needle: "48 83 EC 28 48 8B 05 ? ? ? ? 48 85 C0 0F 85 ? ? ? ? 48 89 5C 24",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_180379830()",
    },
    Signature {
        name: "CEconItemSchema::GetAttributeDefinitionByName",
        module: "client.dll",
        needle: "48 89 5C 24 10 48 89 6C 24 18 57 41 56 41 57 48 83 EC 60 48 8D 05",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18104CEA0(__int64 a1, unsigned __int8 *a2)",
    },
    Signature {
        name: "SetDynamicAttributeValue",
        module: "client.dll",
        needle: "48 89 6C 24 ? 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B FA C7 44 24 ? ? ? ? ? 4D 8B F8",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_181004F60(__int64 a1, __int64 a2, _DWORD *a3)",
    },
    Signature {
        name: "CEconItemCreateInstance",
        module: "client.dll",
        needle: "48 83 EC 28 B9 48 00 00 00 E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "uintptr_t __cdecl CEconItemCreateInstance()",
    },
    Signature {
        name: "SOCreated",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B FA 48 8B F1",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall SOCreated(uintptr_t, uint64_t, uintptr_t, int)",
    },
    Signature {
        name: "GetItemViewByID",
        module: "client.dll",
        needle: "48 89 54 24 ? 53 48 83 EC ? 48 8B D9 48 85 D2 75 ? 33 C0 48 83 C4 ? 5B C3 48 83 C1 38 48 8D",
        resolve: NONE,
        extra_off: 0,
        prototype: "uintptr_t __fastcall GetItemViewByID(uintptr_t, uint64_t)",
    },

    // ---------- scenesystem.dll ---------------------------------------
    Signature {
        name: "DrawSkyboxArray",
        module: "scenesystem.dll",
        needle: "45 85 C9 0F 8E ? ? ? ? 4C 8B DC 55",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        name: "DrawObject_legacy",
        module: "scenesystem.dll",
        needle: "48 8B C4 53 57 41 54 48 81 EC D0 00 00 00 49 63 F9 49",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        name: "CSceneAnimatableObject::GeneratePrimitives",
        module: "scenesystem.dll",
        needle: "48 8B C4 48 89 58 08 48 89 50 10 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ?",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        name: "DrawSmokeVertex",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B 9C 24 ? ? ? ? 4D 8B F8",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180C7B290(__int64 a1, __int64 a2, int a3, int a4, __int64 a5, __int64 a6)",
    },

    // ---------- materialsystem2.dll -----------------------------------
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CMaterialSystem2::CreateMaterial",
        module: "materialsystem2.dll",
        needle: "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 48 8B 05",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        name: "FindParameter",
        module: "materialsystem2.dll",
        needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 59 20 48",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180011E30(__int64 a1, __int64 a2)",
    },
    Signature {
        name: "UpdateParameter",
        module: "materialsystem2.dll",
        needle: "48 89 7C 24 ? 41 56 48 83 EC ? 8B 81",
        resolve: NONE,
        extra_off: 0,
        prototype: "_QWORD *__fastcall sub_180012370(__int64 a1)",
    },

    // ---------- tier0.dll ---------------------------------------------
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "LoadKV3_callsite",
        module: "tier0.dll",
        needle: "48 8D 0D ? ? ? ? FF 15 ? ? ? ? 49 8B 06",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ---------- engine2.dll -------------------------------------------
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "ClientStateSignOnState",
        module: "engine2.dll",
        needle: "83 3D ? ? ? ? 06 0F 94 C0",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ---------- string-anchored (robust across patches) ---------------
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "Engine_GetTime",
        module: "engine2.dll",
        needle: "Engine_GetTime",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CL_FullyConnected",
        module: "engine2.dll",
        needle: "CL_FullyConnected",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "Host_AccumulateTime",
        module: "engine2.dll",
        needle: "Host_AccumulateTime",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CNetChan_ProcessMessages",      module: "engine2.dll", needle: "CNetChan::ProcessMessages",     resolve: STRREF, extra_off: 0, prototype: "" },

    Signature { name: "CCSPlayer_WeaponServices",      module: "client.dll",  needle: "CCSPlayer_WeaponServices",      resolve: STRREF, extra_off: 0, prototype: "__int64 *sub_180877810()" },
    Signature { name: "CCSPlayer_MovementServices",    module: "client.dll",  needle: "CCSPlayer_MovementServices",    resolve: STRREF, extra_off: 0, prototype: "__int64 *sub_18083DE80()" },
    Signature { name: "CCSPlayer_BulletServices",      module: "client.dll",  needle: "CCSPlayer_BulletServices",      resolve: STRREF, extra_off: 0, prototype: "void *__fastcall sub_180813BA0(__int64 a1)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CSGameRules",
        module: "client.dll",
        needle: "CSGameRules",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CCSPlayerController",           module: "client.dll",  needle: "CCSPlayerController",           resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1807E5220(int a1, _QWORD *a2)" },
    Signature { name: "CCSPlayerPawn",                 module: "client.dll",  needle: "CCSPlayerPawn",                 resolve: STRREF, extra_off: 0, prototype: "__int64 sub_180BB0E40()" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CHudWeaponSelection",
        module: "client.dll",
        needle: "CHudWeaponSelection",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CHudDeathNotice",
        module: "client.dll",
        needle: "CHudDeathNotice",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "paintkit_seed",                 module: "client.dll",  needle: "set item texture seed",         resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_180EF1330(__int64 a1)" },
    Signature { name: "paintkit_prefab",               module: "client.dll",  needle: "set item texture prefab",       resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_18105D3B0(__int64 *a1)" },
    Signature { name: "paintkit_wear",                 module: "client.dll",  needle: "set item texture wear",         resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_180EF1330(__int64 a1)" },
    Signature { name: "statTrak_killEater",            module: "client.dll",  needle: "kill eater",                    resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_180EF1330(__int64 a1)" },
    Signature { name: "statTrak_scoreType",            module: "client.dll",  needle: "kill eater score type",         resolve: STRREF, extra_off: 0, prototype: "__int64 sub_18011B7F0()" },

    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "VacNet_OnEvent",
        module: "client.dll",
        needle: "VAC-Net Detection",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "Matchmaking_AcceptMatch",
        module: "client.dll",
        needle: "AcceptInviteToParty",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },

    // ==================================================================
    // NUVORA APR-2026 EXPANSION (client.dll) ---------------------------
    // ==================================================================
    // Hooks / view / rendering -----------------------------------------
    Signature { name: "CGameEntitySystem::OnAddEntity",       module: "client.dll", needle: "48 89 74 24 ? 57 48 83 EC ? 41 B9 ? ? ? ? 41 8B C0 41 23 C1 48 8B F2 41 83 F8 ? 48 8B F9 44 0F 45 C8 41 81 F9 ? ? ? ? 73 ? FF 81", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180968640(__int64 a1, __int64 a2, int a3)" },
    Signature { name: "CGameEntitySystem::OnRemoveEntity",    module: "client.dll", needle: "48 89 74 24 ? 57 48 83 EC ? 41 B9 ? ? ? ? 41 8B C0 41 23 C1 48 8B F2 41 83 F8 ? 48 8B F9 44 0F 45 C8 41 81 F9 ? ? ? ? 73 ? FF 89", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180968EA0(__int64 a1, _QWORD *a2, int a3)" },
    Signature { name: "GetMatrixForView",                     module: "client.dll", needle: "40 53 48 83 EC 60 0F 29 74 24 50 0F 57 DB F3 0F 10 ? ? ? ? ? 49 8B D8", resolve: NONE, extra_off: 0, prototype: "double __fastcall sub_180169C50(__int64 a1, __int64 a2, __int64 a3)" },
    Signature { name: "IsGlowing",                            module: "client.dll", needle: "E8 ? ? ? ? 33 DB 84 C0 0F 84 ? ? ? ? 48 8B 4F", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_180B0C300(__int64 a1)" },
    Signature { name: "GetGlowColor",                         module: "client.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F2 48 8B F9 48 8B 54 24", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180B0ABC0(__int64 a1, float *a2)" },
    Signature { name: "FlashOverlay",                         module: "client.dll", needle: "85 D2 0F 88 ? ? ? ? 48 89 4C 24", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180DAB2C0(__int64 a1, int a2)" },
    Signature { name: "DrawOverHead",                         module: "client.dll", needle: "40 53 48 83 EC ? 48 8B D9 83 FA ? 75 ? 48 8B 0D ? ? ? ? 48 8D 54 24 ? 48 8B 01 FF 90 ? ? ? ? 8B 10", resolve: NONE, extra_off: 0, prototype: "unsigned __int8 __fastcall sub_180A66CF0(__int64 a1, unsigned int a2)" },
    Signature { name: "DrawCrosshair",                        module: "client.dll", needle: "48 89 5C 24 08 57 48 83 EC 20 48 8B D9 E8 ? ? ? ? 48 85", resolve: NONE, extra_off: 0, prototype: "bool __fastcall sub_1807B0BF0(_QWORD *a1)" },
    Signature { name: "FirstPersonLegs",                      module: "client.dll", needle: "40 55 53 56 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? F2 0F 10 42", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1810F0410(__int64 *a1, __int64 *a2, __int64 a3, __int64 a4, __int64 a5)" },
    Signature { name: "HandleTeamIntro",                      module: "client.dll", needle: "48 83 EC ? ? ? ? ? 44 38 89", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180703EB0(__int64 a1, __int64 a2, char *a3)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "DrawViewPunch",
        module: "client.dll",
        needle: "48 89 5C 24 ? 55 56 57 48 83 EC ? 48 83 79",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "DrawScopeOverlay",                     module: "client.dll", needle: "48 8B C4 53 57 48 83 EC ? 48 8B FA", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18085D530(__int64 a1, __int64 a2)" },
    Signature { name: "UpdatePostProcessing",                 module: "client.dll", needle: "48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 08 57 48 83 EC 60 80", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180F21F20(__int64 a1, _BYTE *a2)" },
    Signature { name: "SetupMove",                            module: "client.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 83 EC ? 48 8B EA 4C 8B F1 E8 ? ? ? ? 48 8D 15", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180D1D0E0(__int64 a1, int *a2)" },
    // RenderDecals â€” top-level dispatcher for bullet impact decals,
    // blood splatter, scorch marks, etc. Hook + early-return to disable
    // all decals (visual clarity / no-blood). Prologue:
    //   44 88 4C 24 ??  mov [rsp+?], r9b   ; pass_flag_B
    //   55              push rbp
    //   53              push rbx
    // 4-arg fastcall: (rcx=render_ctx, rdx=render_view**, r8b=flagA, r9b=flagB)
    Signature { name: "RenderDecals",                         module: "client.dll", needle: "44 88 4C 24 ? 55 53", resolve: NONE, extra_off: 0, prototype: "_BYTE *__fastcall sub_1810ECA50(__int64 a1, __int64 **a2, char a3, char a4)" },

    // Interface / global pointers --------------------------------------
    Signature { name: "GlobalVariables_ptr",                  module: "client.dll", needle: "48 89 15 ? ? ? ? 48 89 42", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "GameRules_ptr",                        module: "client.dll", needle: "48 8B 1D ? ? ? ? 48 8D 54 24 ? 0F 28 D0 48 8D 4C 24 ?", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "GameEntitySystemPtr",                  module: "client.dll", needle: "48 8B 1D ? ? ? ? 48 89 1D ? ? ? ?", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "ParticleManager_ptr",                  module: "client.dll", needle: "48 8B 0D ? ? ? ? 41 B8 ? ? ? ? F3 0F 11 74 24 ? 48 C7 44 24 ? ? ? ? ?", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "SwapChain_ptr",
        module: "client.dll",
        needle: "48 89 2D ? ? ? ? 48 C7 05 ? ? ? ? ? ? ? ? C7 05 ? ? ? ? ? ? ? ? 89 2D",
        resolve: RIPREL_3,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CSGOInput_ptr",                        module: "client.dll", needle: "48 8B 0D ? ? ? ? 4C 8B C6 8B 10 E8", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "ClientMode_ptr",                       module: "client.dll", needle: "48 8D 0D ? ? ? ? 48 69 C0 ? ? ? ? 48 03 C1 C3 CC CC", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "ViewRender_ptr",                       module: "client.dll", needle: "48 89 05 ? ? ? ? 48 8B C8 48 85 C0", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "VPhys2World_ptr",                      module: "client.dll", needle: "4C 8B 25 ? ? ? ? 24", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "PVSManager_ptr",
        module: "client.dll",
        needle: "48 8D 0D ? ? ? ? 33 D2 FF 50",
        resolve: RIPREL_3,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "GetBBox_ptr",                          module: "client.dll", needle: "48 8B 0D ? ? ? ? 48 85 C9 74 ? ? ? ? 48 FF A0 ? ? ? ? 48 8D 05", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "GetInstanceS",                         module: "client.dll", needle: "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 8B 91 ? ? ? ? B8", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "ChamsRenderGameSystem",
        module: "client.dll",
        needle: "48 8B 0D ? ? ? ? ? ? E8 ? ? ? ? 49 8B 8E ? ? ? ? 4C 8D 0D",
        resolve: RIPREL_3,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CAM_ThinkReturn",                      module: "client.dll", needle: "BA 04 00 00 00 FF 15 ? ? ? ? 84 C0 0F 84", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_18031A460(__int64 a1, _DWORD *a2)" },

    // a2x-derived globals (cs2-dumper, MIT). Battle-tested patterns.
    // GlowManager_ptr â€” client.dll g_pGlowManager. Read as qword pointer.
    Signature { name: "GlowManager_ptr",                      module: "client.dll", needle: "48 8B 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 8B 41", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    // Sensitivity_ptr â€” client.dll g_pSensitivity (mouse sens object).
    Signature { name: "Sensitivity_ptr",                      module: "client.dll", needle: "48 8D 0D ? ? ? ? 66 0F 6E CD", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    // BuildNumber_addr â€” engine2.dll dword build number global.
    // mov [rip+disp32], eax  ;  89 05 disp32
    Signature { name: "BuildNumber_addr",                     module: "engine2.dll", needle: "89 05 ? ? ? ? 48 8D 0D ? ? ? ? FF 15 ? ? ? ? 48 8B 0D", resolve: RIPREL_2, extra_off: 0, prototype: "" },
    // NetworkGameClient_ptr â€” engine2.dll g_pNetworkGameClient.
    Signature { name: "NetworkGameClient_ptr",                module: "engine2.dll", needle: "48 89 3D ? ? ? ? FF 87", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    // InputSystem_ptr â€” inputsystem.dll g_pInputSystem.
    Signature { name: "InputSystem_ptr",                      module: "inputsystem.dll", needle: "48 89 05 ? ? ? ? 33 C0", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    // GameTypes_ptr â€” matchmaking.dll IGameTypes singleton.
    Signature { name: "GameTypes_ptr",                        module: "matchmaking.dll", needle: "48 8D 0D ? ? ? ? FF 90", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    // SoundSystem_ptr â€” soundsystem.dll g_pSoundSystem (CSoundSystem instance).
    Signature { name: "SoundSystem_ptr",                      module: "soundsystem.dll", needle: "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 89 15", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // Engine2 Singletons
    Signature { name: "GameEventManager_ptr",                 module: "client.dll", needle: "48 8b 0d ? ? ? ? 48 8b 01 ff 50 20 48 85 c0", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "ResourceSystem_ptr",                   module: "engine2.dll", needle: "48 8b 0d ? ? ? ? 48 8b 01 ff 50 18 48 8b c8", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // ---------------------------------------------------------------------
    // Cheat-derived globals (cs2 internal cheat, github/scros22).
    // Battle-tested at runtime on build 14160 (single match each in IDA).
    // These cover the canonical "what's the local player / where's the
    // entity table / what's the view matrix" set that every external and
    // internal CS2 cheat needs but a2x didn't ship a pattern for.
    // ---------------------------------------------------------------------
    //
    // EntityList_ptr â€” client.dll g_pEntityList (CGameEntitySystem*).
    // The single qword every entity-walking ESP / aim path reads to
    // enumerate live entities. RIP-relative store sequence in the
    // entity-system bootstrapper:
    //   48 89 0D disp32   mov [rip+g_pEntityList], rcx
    //   E9 disp32         jmp continuation
    //   CC                int3 pad
    Signature { name: "EntityList_ptr",                       module: "client.dll", needle: "48 89 0D ? ? ? ? E9 ? ? ? ? CC", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // ViewMatrix_addr â€” client.dll g_dwViewMatrix (float[4][4] world->screen).
    // Updated every frame by the renderer. Multiplies any world-space
    // float3 into clip-space â€” the standard W2S input for ESP/menus.
    //   48 8D 0D disp32   lea rcx, [rip+g_ViewMatrix]
    //   48 C1 E0 06       shl rax, 6      ; index by 64-byte stride
    Signature { name: "ViewMatrix_addr",                      module: "client.dll", needle: "48 8D 0D ? ? ? ? 48 C1 E0 06", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // PlantedC4Alt_ptr â€” client.dll g_pPlantedC4 (single-instance variant).
    // Different call site than the existing `PlantedC4sPointer` (which is
    // the LIST resolver via 0F ?? ... 39 ... 7E ... 48 8B 0D).
    // This one is the SCALAR live-pointer the bomb timer reads:
    //   48 8B 15 disp32   mov rdx, [rip+g_pPlantedC4]
    //   41 FF C0          inc r8d
    //   48 8D 4C 24 ??    lea rcx, [rsp+ofs]
    Signature { name: "PlantedC4Alt_ptr",                     module: "client.dll", needle: "48 8B 15 ? ? ? ? 41 FF C0 48 8D 4C 24", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // GameRulesAlt_addr â€” client.dll alternate dwGameRules write site.
    // Distinct from `GameRules_ptr` (which is a load via 48 8B 1D).
    // This one is the lea-rip store inside the gamerules constructor:
    //   48 8D 05 disp32   lea rax, [rip+g_pCSGameRules]
    //   48 89 06          mov [rsi], rax
    //   48 8D 4E 44       lea rcx, [rsi+44h]
    Signature { name: "GameRulesAlt_addr",                    module: "client.dll", needle: "48 8D 05 ? ? ? ? 48 89 06 48 8D 4E 44", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // ---------------------------------------------------------------------
    // Skin-changer / inventory-manager helpers (ARCHILIX + Ghidra refs).
    // Each verified single-match on build 14160. These are the client.dll
    // exports the in-game skin / knife / glove changer drives.
    // ---------------------------------------------------------------------

    // CCSInventoryManager::GetInstance â€” call-site resolver.
    // The first 5 bytes are an `E8 disp32` to the GetInstance accessor
    // (returns the global CCSInventoryManager* via the `8B F7` mov-then-
    // shift pattern in the caller). REL32_1 resolves to the accessor fn.
    Signature { name: "GetCSInvMgr_call",                     module: "client.dll", needle: "E8 ? ? ? ? 48 8B D8 8B F7", resolve: REL32_1, extra_off: 0, prototype: "" },

    // CreateBaseTypeCache â€” inventory subsystem helper that builds the
    // per-loadout-slot type cache used when querying GetItemInLoadout.
    // 13-byte unique prologue: push rbx + sub rsp,?? + mov r9, [rcx+?] +
    // mov r10d, edx.
    Signature { name: "CreateBaseTypeCache",                  module: "client.dll", needle: "40 53 48 83 EC ? 4C 8B 49 ? 44 8B D2", resolve: NONE, extra_off: 0, prototype: "" },

    // CreateEconItem â€” allocator for CEconItem (size 0x48). Required by
    // the skin/knife injector pipeline before SetDynamicAttributeValue.
    //   48 83 EC 28        sub rsp, 28h
    //   B9 48 00 00 00     mov ecx, 48h    ; sizeof(CEconItem)
    //   E8 disp32          call operator_new
    //   48 85 ??           test rax, rax
    Signature { name: "CreateEconItem",                       module: "client.dll", needle: "48 83 EC 28 B9 48 00 00 00 E8 ? ? ? ? 48 85", resolve: NONE, extra_off: 0, prototype: "" },

    // CEconItemSchema::GetAttributeDefinitionByName â€” Ghidra-verified
    // canonical attribute lookup. Used by the skin-changer to translate
    // attribute display names ("set item texture prefab" etc.) into
    // CEconItemAttributeDefinition pointers before SetDynamicAttributeValue.
    Signature { name: "GetAttributeDefByName",                module: "client.dll", needle: "48 89 5C 24 10 48 89 6C 24 18 57 41 56 41 57 48 83 EC 60 48 8D 05", resolve: NONE, extra_off: 0, prototype: "" },

    // RegenerateWeaponSkins â€” big leaf in the local-player loadout pipeline
    // that re-applies paint-kit / wear / seed to every weapon entity in the
    // player's loadout. Standard hook target for skin-changers that want
    // their visuals to survive map-load / round-restart. 1 hit @ build 14160.
    //   40 55                  push rbp
    //   53                     push rbx
    //   41 57                  push r15
    //   48 8D AC 24 00 FE FF FF lea rbp, [rsp-200h]
    //   48 81 EC ? ? ? ?       sub rsp, imm32
    Signature { name: "RegenerateWeaponSkins",                module: "client.dll", needle: "40 55 53 41 57 48 8D AC 24 00 FE FF FF 48 81 EC", resolve: NONE, extra_off: 0, prototype: "" },

    // ---------------------------------------------------------------------
    // Stealth / VAC-flag-suppression chain (cs2 internal cheat).
    // These two patterns isolate the "untrusted-mode" cooldown machinery
    // that ships the 20-hour competitive lockout on the next launch
    // after a launch is flagged. Every CS2 cheat that wants to avoid
    // the cooldown silences this chain in some form.
    // ---------------------------------------------------------------------

    // UntrustedFlag setter â€” inside sub_1801569B0. The matched bytes are:
    //   74 26                  jz +26h
    //   C6 05 disp32 01        mov  byte [rip+g_untrustedFlag], 1
    //   33 C0                  xor  eax, eax
    //   83 F8 01               cmp  eax, 1
    // To get g_untrustedFlag itself: read disp32 at hit+4 then add hit+9.
    Signature { name: "UntrustedFlagSetter",                  module: "client.dll", needle: "74 26 C6 05 ? ? ? ? 01 33 C0 83 F8 01", resolve: NONE, extra_off: 0, prototype: "" },

    // InsecureBlocked GC-report emitter â€” the only function that calls
    // Game::ChatReportError(InsecureBlocked) and posts the result to the
    // Steam Game Coordinator. Blocking / no-op'ing this fn neutralises
    // the cooldown emission path even if the flag byte is briefly set.
    // 1 hit @ client!0x180C4D030 on build 14160.
    Signature { name: "InsecureEmitter",                      module: "client.dll", needle: "48 89 5C 24 20 56 48 83 EC 20 48 8B D9 48 89 6C 24 30 48 8B E9 48 8B 0D ? ? ? ? 48 8B 01", resolve: NONE, extra_off: 0, prototype: "" },

    // ---------------------------------------------------------------------
    // Entity-lifecycle + RNG hooks â€” classic CSGO/CS2 cheat targets
    // that aren't strref-able through clean unique strings, so they're
    // sigscanned here. All three IDA-verified single-match on build 14160.
    // ---------------------------------------------------------------------

    // CEntityInstance::UpdateOnRemove â€” fires for every entity right before
    // it leaves the entity-list. Universal hook for "track entity death /
    // bomb defuse / weapon drop" pipelines. Refs the "UpdateOnRemove"
    // string at +0x3C. 1 hit @ client!0x1814CA280.
    Signature { name: "UpdateOnRemove",                       module: "client.dll", needle: "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 40 48 8B D9 C6 05 ? ? ? ? 01 48 8B 49", resolve: NONE, extra_off: 0, prototype: "" },

    // CEntitySystem::DispatchUpdateOnRemove â€” the dispatcher that walks
    // the pending-removal queue and invokes per-entity UpdateOnRemove.
    // Hooking here gives a single chokepoint for every removal that
    // frame, instead of per-entity. 1 hit @ client!0x1814D3CE0.
    Signature { name: "DispatchUpdateOnRemove",               module: "client.dll", needle: "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 41 56 41 57 48 8B EC 48 83 EC 60 48 8D B9 80 00 00 00 45 33 FF 4D 8B F0", resolve: NONE, extra_off: 0, prototype: "" },

    // SharedRandomFloat â€” seeded RNG used by spread / recoil / damage
    // calculators on both client and server. Predicting / replicating
    // its output is the basis of "no-spread" implementations and any
    // serverside spread predictor. The matched site is the C-shim
    // wrapper that calls the underlying CUniformRandomStream. Refs the
    // "SharedRandomFloat" string. 1 hit @ client!0x180A2EC90.
    Signature { name: "SharedRandomFloat",                    module: "client.dll", needle: "4C 8B DC 49 89 5B 08 49 89 73 10 57 48 81 EC 00 01 00 00 8B 05 ? ? ? ? 48 8D 54 24 40", resolve: NONE, extra_off: 0, prototype: "" },

    // CreateInterface â€” client.dll exported factory dispatcher
    // (DLL ordinal #2). Internals load any client interface
    // (Source2Client002, GameClientExports001, ClientToolsInfo_001,
    // EmptyWorldService001_Client, etc.) by calling
    //   void* CreateInterface(const char* name, int* outStatus);
    // Prologue chains to s_pInterfaceRegs head:
    //   4C 8B 0D ?? ?? ?? ?? mov r9, [rip+s_pInterfaceRegs]
    //   4C 8B D2             mov r10, rdx
    //   4C 8B D9             mov r11, rcx
    //   4D 85 C9             test r9, r9
    //   74 ?                 jz <ret_null>
    //   49 8B 41 08          mov rax, [r9+8]   ; reg->m_pName
    Signature { name: "CreateInterface",                      module: "client.dll", needle: "4C 8B 0D ? ? ? ? 4C 8B D2 4C 8B D9 4D 85 C9 74 ? 49 8B 41 08", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall CreateInterface(__int64 a1, _DWORD *a2)" },

    // Prediction_ptr â€” client.dll g_pPrediction (CPrediction instance).
    // Used by SetupMove/RunCommand chain. a2x dwPrediction pattern.
    //   48 8D 05 ?? ?? ?? ?? lea rax, [rip+g_pPrediction]
    //   C3                   ret
    //   CC CC CC CC CC CC CC CC                pad
    //   40 53 56 41 54       push rbx/rsi/r12  (next fn prologue)
    Signature { name: "Prediction_ptr",                       module: "client.dll", needle: "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 40 53 56 41 54", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // WeaponC4_ptr â€” client.dll g_pWeaponC4 (currently held / planted
    // bomb instance). a2x dwWeaponC4 pattern. Useful for bomb timer
    // ESP, defuse helpers, and round-state tracking. Chain:
    //   48 8B 15 disp32  mov rdx, [rip+g_pWeaponC4]
    //   48 8B 5C 24 ??   mov rbx, [rsp+save]
    //   FF C0            inc eax
    //   89 05 disp32     mov [rip+nWeaponC4Count], eax
    //   48 8B C6         mov rax, rsi
    //   48 89 34 EA      mov [rdx+rbp*8], rsi  ; insert into list
    //   80 BE ...        cmp byte [rsi+disp32], ?
    Signature { name: "WeaponC4_ptr",                         module: "client.dll", needle: "48 8B 15 ? ? ? ? 48 8B 5C 24 ? FF C0 89 05 ? ? ? ? 48 8B C6 48 89 34 EA 80 BE", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // LocalPlayerController_ptr Ã”Ã‡Ã¶ client.dll g_pLocalPlayerController[1].
    // Cached pointer to the local CCSPlayerController, used by ESP team
    // checks, scoreboard, observer-target lookup, and money/ping HUD.
    // a2x dwLocalPlayerController pattern:
    //   48 8B 05 disp32   mov rax, [rip+g_pLocalPlayerController]
    //   41 89 BE ...      mov [r14+disp32], edi
    Signature { name: "LocalPlayerController_ptr",            module: "client.dll", needle: "48 8B 05 ? ? ? ? 41 89 BE", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // WindowWidth_addr Ã”Ã‡Ã¶ engine2.dll g_nWindowWidth. Updated every
    // frame to the current swap-chain width; perfect screen-space
    // anchor for menus, ESP, world-to-screen sanity checks. Also
    // survives windowed/borderless/resolution swaps without re-hooking.
    // a2x dwWindowWidth pattern: 8B 05 disp32  mov eax, [rip+w]
    //                            89 07         mov [rdi], eax
    Signature { name: "WindowWidth_addr",                     module: "engine2.dll", needle: "8B 05 ? ? ? ? 89 07", resolve: RIPREL_2, extra_off: 0, prototype: "" },

    // WindowHeight_addr Ã”Ã‡Ã¶ engine2.dll g_nWindowHeight. Companion to
    // WindowWidth_addr; same instruction pair, different sink reg.
    //   8B 05 disp32  mov eax, [rip+h]
    //   89 03         mov [rbx], eax
    Signature { name: "WindowHeight_addr",                    module: "engine2.dll", needle: "8B 05 ? ? ? ? 89 03", resolve: RIPREL_2, extra_off: 0, prototype: "" },

    // Cross-module interface singletons ---------------------------------
    // Each module's CreateInterface() registers an InterfaceReg for every
    // exposed singleton. The factory each Reg holds is a 1-instruction
    // thunk shaped exactly:
    //     48 8D 05 disp32   lea rax, [rip+g_pSingleton]
    //     C3                ret
    //     CC ... CC         (16-byte alignment pad)
    // The pattern below anchors that thunk so we recover the singleton
    // pointer for free Ã”Ã‡Ã¶ no CreateInterface call, no string scan, no
    // module-walk required by the host process. Resolves to &g_pX (the
    // static instance the engine itself uses internally).

    // CVar_ptr Ã”Ã‡Ã¶ tier0.dll g_pCVar (singleton ICvar). Backbone for any
    // cvar read/write feature: third-person, FOV, sky_name, sv_cheats
    // probes, etc. Followed in tier0 by an `E9` thunk that distinguishes
    // it from the other 30+ tier0 factories.
    Signature { name: "CVar_ptr",                             module: "tier0.dll", needle: "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC E9", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // NetworkSystem_ptr Ã”Ã‡Ã¶ networksystem.dll g_pNetworkSystem (singleton
    // INetworkSystem). Owns CNetChan registry, NetMessages send queue,
    // and channel allocation. Foundation for network-side features:
    // packet inject, choke control, real fakelag (not the in-engine
    // sv_fakelag clamp), bandwidth metering. Trailing
    // `48 83 EC 28 BA FF FF FF` is the next function (mov edx, -1) and
    // is unique among the 3 lea-factory thunks in this module.
    Signature { name: "NetworkSystem_ptr",                    module: "networksystem.dll", needle: "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 83 EC 28 BA FF FF FF", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // SceneSystem_ptr Ã”Ã‡Ã¶ scenesystem.dll g_pSceneSystem (ISceneSystem).
    // Owns the per-view render scene, scene-object lists, frustum data,
    // and is the entry point for custom draw-call injection (chams,
    // outlines, post-fx). Trailing `48 8D 0D ? ? ? ? E9` is the next
    // function's lea+jmp tail-call Ã”Ã‡Ã¶ unique anchor in scenesystem.dll.
    Signature { name: "SceneSystem_ptr",                      module: "scenesystem.dll", needle: "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 8D 0D ? ? ? ? E9", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // RenderDeviceMgr_ptr Ã”Ã‡Ã¶ rendersystemdx11.dll g_pRenderDeviceMgr
    // (IRenderDeviceMgr). Direct gateway to the live ID3D11Device,
    // IDXGISwapChain, and per-frame ID3D11DeviceContext. Lets us hook
    // Present / ResizeBuffers without VTable scanning a DXGI dummy.
    // The 16-byte preceding tail `8B 5C 24 38 48 83 C4 20 5E C3` is
    // movsd-style epilogue of the previous func Ã”Ã‡Ã¶ unique anchor that
    // disambiguates from the 10 other identical lea-factory thunks
    // chained right after this one (one per render sub-interface).
    Signature { name: "RenderDeviceMgr_ptr",                  module: "rendersystemdx11.dll", needle: "8B 5C 24 38 48 83 C4 20 5E C3 CC CC CC CC CC CC 48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 8D 05 ? ? ? ? C3", resolve: RIPREL_19, extra_off: 0, prototype: "" },

    // FullFileSystem_ptr Ã”Ã‡Ã¶ filesystem_stdio.dll g_pFullFileSystem
    // (IFileSystem). Mounts VPKs, opens game files, reads pak1_dir
    // entries. Required for custom-camo / model-replacement loaders
    // and any feature that reads game data without sv_pure tripping.
    // Preceded by `8B 41 28 C3` (`mov eax, [rcx+28]; ret`) which is
    // a unique 4-byte epilogue at exactly 16 bytes before this factory
    // among the 30 lea-factory thunks in filesystem_stdio.dll.
    Signature { name: "FullFileSystem_ptr",                   module: "filesystem_stdio.dll", needle: "8B 41 28 C3 CC CC CC CC CC CC CC CC CC CC CC CC 48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 8D 05 ? ? ? ? C3", resolve: RIPREL_19, extra_off: 0, prototype: "" },

    // InputSystemSvc_ptr Ã”Ã‡Ã¶ inputsystem.dll g_pInputSystem
    // (IInputSystem). Different singleton from client.dll's
    // CCSGOInput / "InputSystem_ptr" Ã”Ã‡Ã¶ this is the engine-side input
    // service that owns the raw mouse delta accumulator, button state
    // arrays, and IME/joystick routing. Combine with InputSystem_ptr
    // for pre-CCSGOInput mouse hooks (perfect-aim, true raw delta).
    // Trailing `40 53 48 83 EC 20 33 DB` is the next func's prologue Ã”Ã‡Ã¶
    // unique anchor in inputsystem.dll.
    Signature { name: "InputSystemSvc_ptr",                   module: "inputsystem.dll", needle: "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 40 53 48 83 EC 20 33 DB", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // SchemaSystem_ptr Ã”Ã‡Ã¶ schemasystem.dll g_pSchemaSystem
    // (CSchemaSystem). Runtime-resolves any schema field offset, class
    // metadata, or enum value WITHOUT a re-dump every game build.
    // Pair with FindTypeScopeForModule + FindDeclaredClass and netvars
    // become self-healing across CS2 patches. Trailing
    // `48 89 5C 24 08 48 89 74` is the next func's stack-spill
    // prologue Ã”Ã‡Ã¶ unique anchor in schemasystem.dll.
    Signature { name: "SchemaSystem_ptr",                     module: "schemasystem.dll", needle: "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 89 5C 24 08 48 89 74", resolve: RIPREL_3, extra_off: 0, prototype: "" },

    // ================================================================
    // Wave-5 cross-module hookpoints (12 sigs across 7 modules)
    // ================================================================
    // Continuing the multi-instance IDA mining pass (14 modules loaded).
    // Each entry below is a RAW function-prologue (or factory-thunk for
    // the animationsystem singleton) that public CS2 dumpers do NOT ship.
    // All verified 1-match on build 14155 + live-resolved against the
    // running game.

    // ---------- animationsystem.dll -----------------------------------
    // AnimationSystemUtils_ptr Ã”Ã‡Ã¶ animationsystem.dll g_pAnimationSystemUtils
    // (IAnimationSystemUtils). Singleton accessor for animation-graph
    // helpers (stringÃ”Ã¥Ã†bone, sequence resolution, parameter fetch). Pairs
    // with the existing `Animation::ShouldUpdateSequences` sig to drive
    // arbitrary-frame skeleton manipulation (custom poses, freeze-bones,
    // server-style ragdoll). Anchored on the factory thunk
    // `48 8D 05 disp32; C3` followed by the unique
    // `CreateInterface(name)` stub that compares interface name and
    // dispatches via vtable+stored-singleton. Resolves to the pointer
    // backing g_pAnimationSystemUtils inside animationsystem.dll.
    Signature { name: "AnimationSystemUtils_ptr",             module: "animationsystem.dll", needle: "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 83 EC 28 48 8B CA 48 8D 15", resolve: RIPREL_3, extra_off: 0, prototype: "" },



    // ---------- schemasystem.dll --------------------------------------
    // CSchemaSystem_VerifySchemaBindingConsistency Ã”Ã‡Ã¶ schemasystem!
    // sub_1800058F0 (~0x65d). Walks every registered class binding and
    // verifies field offset / size / type consistency against per-module
    // declarations. Refs the unique
    // "CSchemaSystem::VerifySchemaBindingConsistency" string. Hook to
    // observe which class bindings the engine considers valid this
    // build (any disagreement is logged here before runtime asserts).
    Signature { name: "CSchemaSystem_VerifySchemaBindingConsistency", module: "schemasystem.dll", needle: "88 54 24 10 55 53 57 41 54 41 55 48 8B EC 48 81 EC 80 00 00 00 65 48 8B 04 25 58 00 00 00", resolve: NONE, extra_off: 0, prototype: "" },

    // CSchemaSystem_RegisterModuleAndBuiltins Ã”Ã‡Ã¶ schemasystem!sub_1800106F0
    // (~0x3ca). Combined ref to "SchemaSystem_001" + "InsertNewClassBinding"
    // Ã”Ã‡Ã¶ registers the SchemaSystem InterfaceReg AND the built-in primitive
    // class bindings (Vector/QAngle/CUtlSymbolLarge/etc) in one shot.
    // Critical bootstrap point Ã”Ã‡Ã¶ hook here to intercept every class
    // schema before any module's typescope opens.
    Signature { name: "CSchemaSystem_RegisterModuleAndBuiltins", module: "schemasystem.dll", needle: "48 89 54 24 10 53 56 57 41 55 41 56 41 57 48 83 EC 48 45 33 ED 49 63 C0 33 FF 44 89 AC 24 90 00", resolve: NONE, extra_off: 0, prototype: "" },

    // CSchemaSystem_InstallSchemaBindings Ã”Ã‡Ã¶ schemasystem!sub_1800375D0
    // (~0x4b). Per-module installer called from each .dll's startup with
    // its serialized schema-binding blob. Hook to enumerate every
    // module-local schema scope as it loads (lets the cheat snapshot
    // offsets without ever calling FindDeclaredClass).
    Signature { name: "CSchemaSystem_InstallSchemaBindings",  module: "schemasystem.dll", needle: "40 53 48 83 EC 20 48 8B DA 48 8B D1 48 8D 0D ? ? ? ? E8 ? ? ? ? 85 C0 74 08 32 C0", resolve: NONE, extra_off: 0, prototype: "" },

    // ---------- networksystem.dll -------------------------------------
    // CNetworkSystem_Init Ã”Ã‡Ã¶ networksystem!sub_1800EC0C0 (~0x89d). Module
    // boot for INetworkSystem: brings up SteamNetworkingSockets, builds
    // the netmessage registry, and prepares CNetChan factory. Refs the
    // unique "CNetworkSystem::Init() failed - no SteamNetworking()" log.
    // Hook for: blocking the cheat from registering against Steam-relays,
    // or short-circuiting the SteamNetworkingSockets init for offline use.
    Signature { name: "CNetworkSystem_Init",                  module: "networksystem.dll", needle: "40 55 53 57 41 54 41 55 41 57 48 8D AC 24 98 FC FF FF 48 81 EC 68 04 00 00 4C 8B E9", resolve: NONE, extra_off: 0, prototype: "" },

    // CNetworkSystem_RegisterNetMessageHandlerAbstract Ã”Ã‡Ã¶ networksystem!
    // sub_1800BBC00 (~0x270). Every protobuf netmessage type registers its
    // handler through this funnel between StartRegisteringMessageHandlers
    // and FinishRegisteringMessageHandlers. Hook to (a) enumerate every
    // netmessage the build supports, (b) hot-swap a custom handler that
    // intercepts/mutates a specific message before normal dispatch.
    Signature { name: "CNetworkSystem_RegisterNetMessageHandlerAbstract", module: "networksystem.dll", needle: "48 89 5C 24 10 48 89 6C 24 18 57 41 56 41 57 48 83 EC 50 4C 8B B4 24 90 00 00 00 41 8B D9", resolve: NONE, extra_off: 0, prototype: "" },

    // ---------- scenesystem.dll ---------------------------------------
    // CSceneSystem_CreateStaticShape Ã”Ã‡Ã¶ scenesystem!sub_1800B1AF0 (~0x648).
    // Builds the GPU-side shape buffer for a static scene primitive.
    // Refs "CSceneSystem::CreateStaticShape(322): " unique log. Pairs
    // with CSceneSystem::DrawStaticPrimitive to inject custom debug
    // overlays / 3D wireframe ESP that survives the engine cull.
    Signature { name: "CSceneSystem_CreateStaticShape",       module: "scenesystem.dll", needle: "48 8B C4 48 89 48 08 55 41 54 41 56 48 8D 68 D8 48 81 EC 10 01 00 00 4C 8B 65 50 48 8D 4D 80", resolve: NONE, extra_off: 0, prototype: "" },

    // CSceneSystem_InitGfxObjects Ã”Ã‡Ã¶ scenesystem!sub_1800B3E30 (~0x1b1d).
    // Master GPU-side init: creates persistent vertex/index buffers, the
    // shadow-cube atlas, particle batchers, and the CRenderingPipelineDx11
    // hookup. Refs "CSceneSystem::InitGfxObjects(976): " unique log. Hook
    // to swap-in custom vertex layouts / shader includes BEFORE any scene
    // primitive is drawn.
    Signature { name: "CSceneSystem_InitGfxObjects",          module: "scenesystem.dll", needle: "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 08 FE FF FF 48 81 EC F8 02 00 00", resolve: NONE, extra_off: 0, prototype: "" },

    // CSceneSystem::FrameUpdate â€” scenesystem!sub_1800E1C30. The per-tick
    // scene driver: integrates pending object adds/removes, advances the
    // queued light-data ring, and kicks the render-view dispatch. Refs
    // the unique "CSceneSystem::FrameUpdate" job-name string at +0x10.
    // Hooking here is the cleanest "once per scene tick, after gameplay
    // but before render thread" anchor for cheats that need to mutate
    // scene-side state (light overrides, fog params, env-map bias) in a
    // race-free spot. 1 hit @ scenesystem!0x1800E1C30 on build 14160.
    Signature { name: "CSceneSystem_FrameUpdate",             module: "scenesystem.dll", needle: "48 8B C4 88 50 10 48 89 48 08 55 53 41 54 41 55 48 8D 68 A1 48 81 EC 98 00 00 00", resolve: NONE, extra_off: 0, prototype: "" },

    // CSceneSystem::DeleteObjectForReal â€” scenesystem!sub_1800CA530. The
    // back-end deleter that actually frees a CSceneObject after the
    // refcount on its CRefCountAccessor (the `lock dec [rcx+0x30CC]` at
    // the top of the prologue) reaches zero. Distinct from the public
    // DeleteSceneObject queueing wrapper. Hook to track / suppress
    // teardown of specific renderable objects (e.g. keep a chams
    // material alive past the entity's natural lifetime, or null-out
    // a CWeaponSceneObject before its native cleanup runs). 1 hit.
    Signature { name: "CSceneSystem_DeleteObjectForReal",     module: "scenesystem.dll", needle: "40 53 56 41 54 48 83 EC 50 0F B6 82 9B 00 00 00 45 33 E4 48 8B DA 48 8B F1 F0 FF 8C 81 CC 30 00 00", resolve: NONE, extra_off: 0, prototype: "" },

    // ---------- inputsystem.dll ---------------------------------------
    // CInputSystem_PollInputState Ã”Ã‡Ã¶ inputsystem!sub_180005500 (~0x459).
    // Per-frame raw input poll: pulls SDL keyboard/mouse/joystick events,
    // drains the OS message queue, and writes into the inputsystem ring.
    // Refs the unique "PollInputState_SDL" string. Hook here to inject
    // synthetic mouse-deltas or filter specific keys before they hit the
    // engine's button table Ã”Ã‡Ã¶ perfect anchor for raw aim-step / no-recoil
    // mouse-comp without touching CCSGOInput.
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CInputSystem_PollInputState",
        module: "inputsystem.dll",
        needle: "40 53 41 56 48 81 EC 28 01 00 00 48 8D 05 ? ? ? ? 48 C7 44 24 38 46 04 00 00 4C 8B F1",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ---------- materialsystem2.dll -----------------------------------
    // CMaterial2_GetMode Ã”Ã‡Ã¶ materialsystem2!sub_18000BD40 (~0x16e). Per-
    // material rendering-mode resolver (default / wireframe / shadow /
    // depth-only / picking). Refs "CMaterial2::GetMode(644): Material
    // \"%s\" is requesting a bad mode \"%s\"!\n". Hook to force-override
    // per-material mode (e.g. promote everything to wireframe = clean
    // chams without shader patching).
    Signature { name: "CMaterial2_GetMode",                   module: "materialsystem2.dll", needle: "48 89 5C 24 18 57 48 83 EC 30 8B 02 48 8B D9 39 05 ? ? ? ? 48 8B 0D ? ? ? ? 48 89 74 24", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18000BD40(__int64 a1, unsigned int *a2)" },

    // CMaterial2_GetVertexShaderInputSignature Ã”Ã‡Ã¶ materialsystem2!
    // sub_18000C8C0 (~0x2af). Returns the CVsInputSignatureVector for the
    // material's currently-bound layer (used by the renderer to validate
    // that a model's vertex layout matches the shader). Refs unique
    // "CMaterial2::GetVertexShaderInputSignature(767):" log. Hook to
    // spoof signature compatibility Ã”Ã‡Ã¶ required when forcing one material
    // onto a model with an incompatible vertex layout (e.g. character
    // vfx onto props for cross-class chams).
    Signature { name: "CMaterial2_GetVertexShaderInputSignature", module: "materialsystem2.dll", needle: "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 30 F6 41 0B 01 4C 8B", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18000C8C0(__int64 a1)" },

    // Features / aimbot / autowall / movement ---------------------------
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CalculateShootPosition",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 44 8B 92 ? ? ? ?",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "AutowallInit",                         module: "client.dll", needle: "40 53 48 83 EC ? 48 8B D9 48 81 C1 ? ? ? ? E8 ? ? ? ?", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1808E1EE0(__int64 a1)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "AutowallResolveTracePos",
        module: "client.dll",
        needle: "E8 ? ? ? ? 48 63 83 ? ? ? ? 48 8D 14 40",
        resolve: REL32_1,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "AutowallTracePos",                     module: "client.dll", needle: "40 55 56 41 54 41 55 41 57 48 8B EC", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_180807780(__int64 a1, __int64 a2)" },
    Signature { name: "AutowallTraceData",                    module: "client.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 09", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_18098E9C0(_QWORD *a1, int *a2, int a3, int a4, _BYTE *a5, int a6)" },
    Signature { name: "TestSurfaces",                         module: "client.dll", needle: "40 53 57 41 56 48 83 EC 50 8B", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180806E30(__int64 a1, float a2, float a3, float a4, int a5, int a6, __int64 a7)" },
    Signature { name: "ReportHit",                            module: "client.dll", needle: "E8 ? ? ? ? 48 8B AC 24 D8 00 00 00 48 81 C4", resolve: REL32_1, extra_off: 0, prototype: "char __fastcall sub_180602290(_QWORD *a1)" },
    Signature { name: "SetTraceData",                         module: "client.dll", needle: "E8 ? ? ? ? 8B 85 ? ? ? ? 48 8D 54 24 ? F2 0F 10 45", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_1807D4810(int *a1, _OWORD *a2)" },
    // Build 14160 fix: wildcarded the source-XMM and dest-register bytes (was 0B/0D).
    Signature { name: "SetTraceInit",                         module: "client.dll", needle: "E8 ? ? ? ? F2 0F 10 ? 4C 8D ?", resolve: REL32_1, extra_off: 0, prototype: "" },
    Signature { name: "HandleEntityList",                     module: "client.dll", needle: "E8 ? ? ? ? 84 C0 74 ? 48 63 03", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_1801C3700(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, int a6, int a7)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "GetBasePlayerController",
        module: "client.dll",
        needle: "48 8B F8 48 85 C0 74 ? 48 8B C8 E8 ? ? ? ? 44 39 A8",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "GetTickBase",                          module: "client.dll", needle: "E8 ? ? ? ? EB ? 48 8B 05 ? ? ? ? 8B 40", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_1808BDA00(__int64 a1)" },
    Signature { name: "FindHudElement",                       module: "client.dll", needle: "48 8D 15 ? ? ? ? 45 33 C0 B9 ? ? ? ? FF 15 ? ? ? ? EB ? 48 8B 15", resolve: NONE, extra_off: 0, prototype: "_QWORD **__fastcall sub_180DC1D50(__int64 a1, unsigned __int8 a2)" },
    Signature { name: "FindHudElement_panorama",              module: "client.dll", needle: "4C 8B DC 53 48 83 EC 50 48 8B 05", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180DC3E70(const char *a1)" },
    Signature { name: "HudChatPrintf",                        module: "client.dll", needle: "E8 ? ? ? ? 49 8B 4E 20 BA ? ? ? ?", resolve: REL32_1, extra_off: 0, prototype: "__int64 sub_1810C10F0(__int64 a1, unsigned int a2, __int64 a3, ...)" },
    Signature { name: "Scope_callsite",                       module: "client.dll", needle: "E8 ? ? ? ? 80 7C 24 34 ? 74 ?", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_18085D530(__int64 a1, __int64 a2)" },
    Signature { name: "GetRemovedAimpunch",                   module: "client.dll", needle: "F2 0F 10 44 24 ? F2 0F 11 84 24 ? ? ? ? FF 15", resolve: NONE, extra_off: 0, prototype: "__int64 sub_1801128E0()" },
    Signature { name: "GetRemovedAimPunch_E8",                module: "client.dll", needle: "E8 ? ? ? ? 4C 8B C0 48 8D 55 ? 48 8B CB E8 ? ? ? ? 48 8D 0D", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_18084D6E0(__int64 a1, __int64 a2)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "ChamsGetWorldGroupID",
        module: "client.dll",
        needle: "E8 ? ? ? ? 48 8B 0D ? ? ? ? ? ? E8 ? ? ? ? 49 8B 8E ? ? ? ? 4C 8D 0D",
        resolve: REL32_1,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "ModulationUpdate",                     module: "client.dll", needle: "48 89 5C 24 08 57 48 83 EC 20 8B FA 48 8B D9 E8 ? ? ? ? 84 C0 0F 84", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1809DA450(__int64 a1, char a2)" },
    Signature { name: "ClearHUDWeaponIcon",                   module: "client.dll", needle: "E8 ? ? ? ? 8B F8 C6 84 24 ? ? ? ? ?", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_180DEDDD0(__int64 a1, int a2, __int64 a3)" },
    Signature { name: "PlayVSound_client",                    module: "client.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 48 8D 6C 24 ? 48 81 EC ? ? ? ? 33 FF", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18150ED00(__int64 a1)" },
    Signature { name: "ConvarGet",                            module: "client.dll", needle: "8B D0 48 8D 0D ? ? ? ? E8 ? ? ? ? 0F 10 45 ? 83 F0 74", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1808BE720(__int64 a1, unsigned int *a2)" },

    // Player / pawn / entity functions ---------------------------------
    Signature { name: "SetViewAngle",                         module: "client.dll", needle: "85 D2 75 3D 48 63 81 ? ? ? ?", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180AE4CE0(__int64 a1, int a2, __int64 *a3)" },
    Signature { name: "GetViewAngles",                        module: "client.dll", needle: "4C 8B C1 85 D2 74 08 48 8D 05 ? ? ? ? C3", resolve: NONE, extra_off: 0, prototype: "__int64 *__fastcall sub_180AD5CA0(__int64 a1, int a2)" },
    Signature { name: "GetBaseEntity",                        module: "client.dll", needle: "4C 8D 49 ? 81 FA", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180967600(__int64 a1, int a2)" },
    Signature { name: "CalculateWorldSpaceBones",             module: "client.dll", needle: "48 89 4C 24 ? 55 53 56 57 41 54 41 55 41 56 41 57 B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 8D 6C 24 ? 48 8B 81", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180A0B070(__int64 a1, unsigned int a2)" },
    Signature { name: "TraceShape",                           module: "client.dll", needle: "48 89 5C 24 ? 48 89 4C 24 ? 55 57", resolve: NONE, extra_off: 0, prototype: "bool __fastcall sub_18098EAA0(_QWORD *a1, __int64 a2, __int64 a3, __int64 a4, _BYTE *a5, __int64 a6)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "ClipRayToEntity",
        module: "client.dll",
        needle: "48 8B C4 48 89 58 ? 55 56 57 41 54 41 56 48 8D 68 ? 48 81 EC ? ? ? ? 48 8B 5D",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "GetSurfaceData",                       module: "client.dll", needle: "E8 ? ? ? ? 80 78 18 00", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_180953540(__int64 a1)" },
    Signature { name: "SetTypeKV3",                           module: "client.dll", needle: "40 53 48 83 EC 30 4C 8B 11 41 B9 ? ? ? ? 49 83 CA 01 0F B6 C2 80 FA 06 48 8B D9 44 0F 45 C8", resolve: NONE, extra_off: 0, prototype: "unsigned __int64 *__fastcall sub_18181AEB0(unsigned __int64 *a1, unsigned __int8 a2, unsigned __int8 a3)" },
    Signature { name: "CreateParticleEffect",                 module: "client.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? F3 0F 10 1D ? ? ? ? 41 8B F8 8B DA 4C 8D 05", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180987020(int a1, int a2, int a3, __int64 a4, int a5)" },
    Signature { name: "SetPlayerReady",                       module: "client.dll", needle: "40 53 48 83 EC 20 48 8B DA 48 8D 15 ? ? ? ? 48 8B CB FF 15 ? ? ? ? 85 C0 75 14 BA", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_180F1DD90(__int64 a1, __int64 a2)" },
    Signature { name: "CacheParticleEffect",                  module: "client.dll", needle: "4C 8B DC 53 48 81 EC ? ? ? ? F2 0F 10 05", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "GetEntityHandle",                      module: "client.dll", needle: "48 85 C9 74 32 48 8B 49 10 48 85 C9 74 29 44 8B 41 10 BA", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18094E8D0(__int64 a1)" },
    Signature { name: "LookupBone",                           module: "client.dll", needle: "E8 ? ? ? ? 48 8B 8D ? ? ? ? B3", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_1808C81E0(__int64 a1, __int64 a2)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "TraceSmokeDensity",
        module: "client.dll",
        needle: "E8 ? ? ? ? 0F 28 F8 44 0F 28 54 24 ?",
        resolve: REL32_1,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "GetInventoryManager",                  module: "client.dll", needle: "E8 ? ? ? ? 48 8B D3 48 8B C8 4C 8B 00 41 FF 90 00 02", resolve: REL32_1, extra_off: 0, prototype: "__int64 *sub_1807C6430()" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "UpdateCompositeMaterial",
        module: "client.dll",
        needle: "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 41 56 41 57 48 83 EC 20 44 0F B6 F2 48 8B F1 E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "RegenerateWeaponSkin",                 module: "client.dll", needle: "40 55 53 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 44 0F B6 FA 48 8B D9 BA ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ?", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_18078C2A0(__int64 a1, char a2)" },
    Signature { name: "SetModel",                             module: "client.dll", needle: "40 53 48 83 EC ? 48 8B D9 4C 8B C2 48 8B 0D ? ? ? ? 48 8D 54 24", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1808DB1C0(__int64 a1, __int64 a2)" },
    Signature { name: "SetMeshGroupMask",                     module: "client.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8D 99 ? ? ? ? 48 8B 71", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180A2DB50(__int64 a1, __int64 a2)" },
    Signature { name: "AddNametagEntity",                     module: "client.dll", needle: "40 55 53 56 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B DA", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_18078B070(__int64 a1, __int64 a2)" },
    Signature { name: "AddStattrakEntity",                    module: "client.dll", needle: "48 8B C4 48 89 58 08 48 89 70 10 57 48 83 EC 50 33 F6 8B FA 48 8B D1", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180A4C790(__int64 a1, unsigned int a2)" },
    Signature { name: "CreateSOSubclassEconItem",             module: "client.dll", needle: "48 83 EC 28 B9 48 00 00 00 E8 ? ? ? ? 48 85", resolve: NONE, extra_off: 0, prototype: "__int64 sub_180FF7770()" },
    Signature { name: "CreateBaseTypeCache",                  module: "client.dll", needle: "40 53 48 83 EC ? 4C 8B 49 ? 44 8B D2", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_181510EA0(__int64 a1, unsigned int a2)" },
    Signature { name: "GetClientSystem",                      module: "client.dll", needle: "E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 8B D8 85 C0 74 33", resolve: REL32_1, extra_off: 0, prototype: "__int64 *sub_181036570()" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "GetClientSystem_inv",
        module: "client.dll",
        needle: "E8 ? ? ? ? 48 8B 47 10 8B 48 30 D1 E9 F6 C1 01 0F 84 8E",
        resolve: REL32_1,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CAttributeStringInit",                 module: "client.dll", needle: "E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 7D ? 48 89 45 ? 49 8D 4F", resolve: REL32_1, extra_off: 0, prototype: "_QWORD *__fastcall sub_1805F86B0(_QWORD *a1, __int64 a2, char a3)" },
    Signature { name: "CAttributeStringFill",                 module: "client.dll", needle: "E8 ? ? ? ? 41 83 CF 08", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_180EAEC20(__int64 a1, __int64 a2)" },
    Signature { name: "CBufferStringInit",                    module: "client.dll", needle: "48 89 5C 24 ? 57 48 83 EC ? 8B 41 ? 48 8D 79", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_1817E29D0(__int64 a1, const char *a2)" },
    Signature { name: "DispatchEffect",                       module: "client.dll", needle: "48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 48 8B DA 48 8D 4C 24", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18035A570(__int64 a1, __int64 a2)" },
    Signature { name: "LoadFileForMe",                        module: "client.dll", needle: "40 55 57 41 56 48 83 EC 20 4C", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_18091BF40(__int64 a1)" },
    Signature { name: "UpdateSubClass",                       module: "client.dll", needle: "4C 8B DC 53 48 81 EC ? ? ? ? 48 8B 41 10 48 8B D9 8B 50 30 C1 EA 04", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1801FA930(_QWORD *a1)" },
    Signature { name: "CreateNewSubtickMoveStep",             module: "client.dll", needle: "E8 ? ? ? ? 48 8B D0 48 8B CE E8 ? ? ? ? 48 8B C8", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_1804B1D80(__int64 a1)" },

    // -----------------------------------------------------------------
    // Subtick move pipeline / bhop primitives â€” scarce in public dumpers.
    // These four anchors give read+write access to every input-side
    // subtick the engine produces / consumes per CUserCmd.
    // -----------------------------------------------------------------

    // CUserCmd::ParseSubtickDuration â€” client!sub_1800AD420. Reads the
    // wire field "subtick_duration_fraction" off the network message and
    // populates the per-subtick `duration` slot. Hooking lets you
    // legally rewrite the fractional duration (basis of "subtick aim
    // smoothing" / shoot-on-the-frame-the-bullet-actually-fires hacks).
    // 1 hit on 14160.
    Signature { name: "CUserCmd_ParseSubtickDuration",        module: "client.dll", needle: "40 55 48 8D AC 24 70 FD FF FF 48 81 EC 90 03 00 00 F2 0F 10 05 ? ? ? ? 48 8D 05", resolve: NONE, extra_off: 0, prototype: "" },

    // CUserCmd::ParseSubtickFraction â€” client!sub_1800AD760. Reads the
    // wire fields "start_subtick_fraction" / "end_subtick_fraction" and
    // writes them into the CSubtickMoveStep. The exact pre-engine spot
    // to inject a custom subtick fraction (e.g. force-fire @ frac=0.0
    // for "perfect-tick" shoot timing without touching CCSGOInput).
    // 1 hit on 14160.
    Signature { name: "CUserCmd_ParseSubtickFraction",        module: "client.dll", needle: "40 55 48 8D AC 24 40 FE FF FF 48 81 EC C0 02 00 00 F2 0F 10 05 ? ? ? ? 48 8D 05", resolve: NONE, extra_off: 0, prototype: "" },

    // CCSPlayer_MovementServices::ProcessForceSubtickMoves â€” client!
    // sub_1809D5D40 (~0x85F). Per-tick consumer of the
    // `m_arrForceSubtickMoveWhen[MAX_FUTURE_FORCED_SUBTICKS]` queue.
    // This is THE jump-bug / forced-subtick-jump anchor: the engine
    // walks the queue here and inserts synthetic subtick edge events
    // (jump press / release / land) into the move pipeline. Hooking
    // lets you force a jump on an arbitrary subtick fraction
    // (sub-tick perfect bhop, jump-bug land-cancel). 1 hit on 14160.
    Signature { name: "CCSPlayer_ProcessForceSubtickMoves",   module: "client.dll", needle: "40 55 53 48 8D AC 24 68 FF FF FF 48 81 EC 98 01 00 00 8B 15 ? ? ? ? 48 8B D9 65 48 8B 04 25 58 00 00 00 B9 98 00 00 00 48 8B 04 D0 8B 04 01 39 05 ? ? ? ? 0F 8F B6 07 00 00", resolve: NONE, extra_off: 0, prototype: "" },

    // CCSPlayer_MovementServices::QueueForceSubtickMove â€” client!
    // sub_1809C76E0 (~0x1255). Producer side of the same
    // `m_arrForceSubtickMoveWhen` ring. Called when the input layer
    // decides a button-edge needs to fire on a future subtick (jump
    // released between ticks, etc). Hook to *enqueue* arbitrary
    // forced subtick moves â€” the canonical primitive for the
    // "release-on-land subtick" half of jump-bug. 1 hit on 14160.
    Signature { name: "CCSPlayer_QueueForceSubtickMove",      module: "client.dll", needle: "48 83 EC 28 8B 0D ? ? ? ? 65 48 8B 04 25 58 00 00 00 BA 98 00 00 00 48 8B 04 C8 8B 04 02 39 05 ? ? ? ? 0F 8F F4 11 00 00", resolve: NONE, extra_off: 0, prototype: "" },

    Signature { name: "SetCollisionBounds",                   module: "client.dll", needle: "48 83 EC ? F2 0F 10 02 8B 42 08", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180803980(__int64 a1, __int64 *a2)" },
    Signature { name: "CalculateInterpolation",               module: "client.dll", needle: "E8 ? ? ? ? 8B 45 ? 3B 45 60 75 04 32 D2 EB 09 BA 01 00 00 00 41 0F 4C D5 C0 EA 07 84 D2 0F 85 87", resolve: REL32_1, extra_off: 0, prototype: "int *__fastcall sub_1814C7E70(__int64 a1, int *a2)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CalculateAnimState",
        module: "client.dll",
        needle: "40 55 56 57 41 54 41 55 41 56 41 57 B8 10 11 00 00 E8 ? ? ? ? 48 2B E0 48 8D 6C 24 40 48 8D 05 ? ? ? ? 48 C7 45 08 4B 0C 00 00 48 8B F1",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "SetAbsOrigin_BaseModel",
        module: "client.dll",
        needle: "48 89 5C 24 08 57 48 83 EC 40 48 8B 01 48 8B FA",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "SetAbsOrigin_Pawn",                    module: "client.dll", needle: "48 89 5C 24 ? 57 48 83 EC ? ? ? ? 48 8B FA 48 8B D9 FF 90 ? ? ? ? 84 C0 0F 85", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18021EF50(__int64 a1, __int64 a2)" },
    Signature { name: "PhysicsRunThink_Pawn",                 module: "client.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B 81 ? ? ? ? 48 8B F9", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_180B0ED50(__int64 a1)" },
    Signature { name: "SomeTimingFromPawn",                   module: "client.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 49 63 D8 48 8B F1", resolve: NONE, extra_off: 0, prototype: "float __fastcall sub_180A572B0(__int64 a1, int a2, unsigned int a3)" },
    Signature { name: "GetUserCmdManager",                    module: "client.dll", needle: "41 56 41 57 48 83 EC ? 48 8D 54 24", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1808BDC90(__int64 a1)" },
    Signature { name: "GetPlayerInterp",                      module: "client.dll", needle: "40 53 48 83 EC ? 48 8B D9 48 8B 0D ? ? ? ? 48 83 C1", resolve: NONE, extra_off: 0, prototype: "float __fastcall sub_1808B9460(__int64 a1)" },
    Signature { name: "PhysicsRunThink_Ctrl",                 module: "client.dll", needle: "48 89 5C 24 ? 57 48 81 EC ? ? ? ? ? ? ? 48 8B F9 FF 90", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1808D7310(__int64 a1)" },
    Signature { name: "RunCommand",                           module: "client.dll", needle: "48 8B C4 48 81 EC ? ? ? ? 48 89 58 10", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1809DBAF0(__int64 a1, __int64 a2)" },
    Signature { name: "ProcessMovement",                      module: "client.dll", needle: "E8 ? ? ? ? 48 8B 06 48 8B CE FF 90 ? ? ? ? 48 85 DB", resolve: REL32_1, extra_off: 0, prototype: "__int64 __fastcall sub_1809D9A30(__int64 a1, __int64 a2)" },
    Signature { name: "ForceButtonsDown",                     module: "client.dll", needle: "40 53 57 41 56 48 81 EC ? ? ? ? 48 83 79", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1809D0130(_QWORD *a1, __int64 a2)" },
    Signature { name: "SetupMovementMoves",                   module: "client.dll", needle: "48 8B ? E8 ? ? ? ? 48 8B 5C 24 ? 48 8B 6C 24 ? 48 83 C4 30", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_181186C10(__int64 a1, __int64 a2, __int64 a3, __int64 a4)" },
    Signature { name: "ProcessImpacts",                       module: "client.dll", needle: "48 8B C4 53 56 41 55", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1809CEA50(_QWORD *a1, __int64 a2, __int64 a3)" },
    Signature { name: "CSBaseGunFireData",                    module: "client.dll", needle: "48 8B C4 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 68 A8 48 81 EC ? ? ? ? 4C 8B 69", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1814E8140(__int64 a1)" },
    Signature { name: "GetWeaponInAccuracyRecoveryTime",      module: "client.dll", needle: "E8 ? ? ? ? F3 0F 10 B7 ? ? ? ? F3 0F 5E F8", resolve: REL32_1, extra_off: 0, prototype: "__m128 __fastcall sub_180796600(__int64 a1)" },
    Signature { name: "UpdateTurningInAccuracy",              module: "client.dll", needle: "E8 ? ? ? ? F3 0F 10 87 ? ? ? ? 44 0F 2F C8", resolve: REL32_1, extra_off: 0, prototype: "float *__fastcall sub_1807AFDA0(float *a1)" },

    // Trace manager / filters ------------------------------------------
    Signature { name: "TraceToExit",                          module: "client.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? F2 0F 10 02", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_180804900(__int64 a1, __int64 a2, int a3, __int64 a4, int a5, char a6)" },
    Signature { name: "GetTraceInfo",                         module: "client.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B E9 0F 29 74 24 ? 48 8B CA", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180806F50(__int64 a1, __int64 a2, float a3, unsigned __int64 *a4)" },
    Signature { name: "InitFilter",                           module: "client.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F B6 41 ? 33 FF 24 C9 C7 41 ?", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18032BBF0(__int64 a1, _DWORD *a2, __int64 a3, char a4, char a5)" },
    Signature { name: "HandleBulletPenetration",              module: "client.dll", needle: "48 8B C4 44 89 48 ? 48 89 50 ? 48 89 48 ? 55", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_1808211F0(__int64 a1, float *a2, __int64 a3, int a4, __int64 a5)" },
    Signature { name: "InitTraceInfo",                        module: "client.dll", needle: "40 55 41 55 41 57 48 83 EC", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1815FC2A0(__int64 a1)" },
    Signature { name: "InitPlayerMovementTraceFilter",        module: "client.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F B6 41 ? 33 FF C7 41 ?", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180840660(__int64 a1, _DWORD *a2, __int64 a3, char a4)" },
    Signature { name: "TracePlayerBBox",                      module: "client.dll", needle: "48 89 5C 24 ? 55 57 41 54 41 55 41 56", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180B70E30(__int64 a1, __int64 *a2, __int64 *a3)" },
    Signature { name: "CreateEntityByClassName",              module: "client.dll", needle: "4C 8D 05 ? ? ? ? 4C 8B CF BA 03 00 00 00 FF 15 ? ? ? ? EB ? 0F B7 C8 48", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_181604AB0(__int64 a1, int a2, __int64 a3, __int64 a4)" },
    Signature { name: "DestroyParticle",                      module: "client.dll", needle: "83 FA ? 0F 84 ? ? ? ? 41 54", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1809463E0(__int64 a1, __int64 a2, unsigned __int8 a3, char a4)" },
    Signature { name: "LoadPath",                             module: "client.dll", needle: "E8 ? ? ? ? 8B 44 24 2C", resolve: REL32_1, extra_off: 0, prototype: "void __fastcall sub_1806BB200(signed int *a1, signed int a2, unsigned int a3)" },
    Signature { name: "GetChatObject",                        module: "client.dll", needle: "E8 ? ? ? ? 48 8B E8 48 85 C0 0F 84 ? ? ? ? 4C 8D 05", resolve: REL32_1, extra_off: 0, prototype: "__int64 sub_1810C3670()" },
    Signature { name: "SendChatMessage",                      module: "client.dll", needle: "E8 ? ? ? ? 49 8B 4E 20 BA ? ? ? ?", resolve: REL32_1, extra_off: 0, prototype: "__int64 sub_1810C10F0(__int64 a1, unsigned int a2, __int64 a3, ...)" },
    Signature { name: "GetInt2_Event",                        module: "client.dll", needle: "48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC 20 48 63 FA 41", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1804AAB40(__int64 a1, unsigned int a2, int a3)" },
    Signature { name: "FindSOCache",                          module: "client.dll", needle: "48 89 5C 24 08 57 48 83 EC 30 4C 8B 52 08 48 8B D9 8B 0A", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18181F080(__int64 a1, int *a2, __int64 a3, __int64 a4)" },
    Signature { name: "SetDynamicAttributeValue_raw",         module: "client.dll", needle: "48 89 6C 24 ? 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B FA C7 44 24", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_181004F60(__int64 a1, __int64 a2, _DWORD *a3)" },
    Signature { name: "SetBodyGroup_inv",                     module: "client.dll", needle: "85 D2 0F 88 ? ? ? ? 53 55", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180D972A0(__int64 a1, int a2, const char *a3)" },
    Signature { name: "LevelInit",                            module: "client.dll", needle: "40 55 56 41 56 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1808D0100(__int64 a1)" },
    Signature { name: "ParticleCollection",                   module: "client.dll", needle: "48 89 5C 24 ? 57 48 83 EC ? 0F 28 05", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1801F4D90(__int64 a1)" },
    Signature { name: "GetLocalControllerById",               module: "client.dll", needle: "48 83 EC 28 83 F9 FF 75 ? 48 8B 0D ? ? ? ? 48 8D 54 24 ? 48 8B 01 FF 90 ? ? ? ? 8B 08 48 63 C1 4C 8D 05", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1808E1070(int a1)" },
    Signature { name: "SetupCmd",                             module: "client.dll", needle: "48 83 EC 28 E8 ? ? ? ? 8B 80", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1808BAF20(__int64 a1)" },
    Signature { name: "GetControllerCmd",                     module: "client.dll", needle: "40 53 48 83 EC 20 8B DA E8 ? ? ? ? 4C", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1808BDC00(__int64 a1, int a2)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "PhysicsRunThink",
        module: "client.dll",
        needle: "E8 ? ? ? ? 49 8B D6 48 8B CE E8 ? ? ? ? 48 8B 06",
        resolve: REL32_1,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "GetBasePlayerCtrl_Entity",
        module: "client.dll",
        needle: "E8 ? ? ? ? 48 8B F8 48 85 C0 74 ? 48 8B C8 E8 ? ? ? ? EB",
        resolve: REL32_1,
        extra_off: 0,
        prototype: "",
    },

    // ==================================================================
    // scenesystem.dll --------------------------------------------------
    // ==================================================================
    Signature { name: "SceneSystem::DrawAggeregateObject",    module: "scenesystem.dll", needle: "48 8B C4 4C 89 48 20 4C 89 40 ? 48 89 50 ? 55 53 41 57 48 8D A8", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "SceneSystem::DrawArrayLight",          module: "scenesystem.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 54 24", resolve: NONE, extra_off: 0, prototype: "" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "SceneSystem::DrawAggregateSceneObject",
        module: "scenesystem.dll",
        needle: "48 8B C4 4C 89 48 20 48 89 50 ? 48 89 48 ? 55 48 8D A8 ? ? ? ? 48 81 EC 70 07 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ==================================================================
    // particles.dll ----------------------------------------------------
    // ==================================================================
    Signature { name: "Particles::DrawArray",                 module: "particles.dll", needle: "40 55 53 56 57 48 8D 6C 24", resolve: NONE, extra_off: 0, prototype: "_BYTE *__fastcall sub_1800220B0(__int64 a1, __int64 a2, __int64 a3, int a4, __int64 a5, __int64 a6, __int64 a7)" },
    Signature { name: "Particles::FindKeyVar",                module: "particles.dll", needle: "48 89 5C 24 ? 57 48 81 EC ? ? ? ? 33 C0 8B DA", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18003A650(const char *a1, unsigned int a2, int a3)" },
    Signature { name: "Particles::SetMaterialShaderType",     module: "particles.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 54 41 56 41 57 48 81 EC ? ? ? ? 4C 63 32", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_18009D8D0(__int64 a1, int *a2)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "Particles::SetMaterialFunction",
        module: "particles.dll",
        needle: "48 89 54 24 10 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC E8 05 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    // CParticleSystemMgr::FindParticleSystem(name, out_handle, blocking_load) — looks up
    // a precached particle system definition by string name. The "FindParticleSystem"
    // log/profile string is referenced exactly once from this function. Useful as a hook
    // point for swapping/recoloring particle effects (smokes, molotovs, tracers).
    Signature { name: "Particles::CParticleSystemMgr_FindParticleSystem", module: "particles.dll",
        needle: "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 81 EC 40 01 00 00 48 8D 05 ? ? ? ? 48 C7 44 24 28 ? ? 00 00 48 89 44 24 20",
        resolve: NONE, extra_off: 0, prototype: "__int64 *__fastcall sub_1800A0BC0(__int64 a1, __int64 *a2, const char *a3, char a4)" },
    // CParticleSystemMgr::CreateParticleCollection — instantiates a particle collection
    // from a previously-found definition. The "CParticleSystemMgr::CreateParticleCollection( Name String )"
    // VProf string sits at the function head.
    Signature { name: "Particles::CParticleSystemMgr_CreateParticleCollection", module: "particles.dll",
        needle: "4C 8B DC 49 89 5B 10 49 89 6B 18 49 89 73 20 57 41 56 41 57 48 81 EC 80 00 00 00 49 C7 43 B0 ? ? 00 00 48 8D 05 ? ? ? ? 49 89 43 A8",
        resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1800A0DD0(__int64 a1, const char *a2, __int64 a3, __int64 a4, char a5, int a6, int a7)" },

    // ==================================================================
    // soundsystem.dll --------------------------------------------------
    // ==================================================================
    Signature { name: "SoundSystem::SomeUtlSymbolFunc",       module: "soundsystem.dll", needle: "48 89 74 24 18 57 48 83 EC 20 48 63 F2 48 8B F9 3B 71 30", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1800B0740(__int64 a1, unsigned int a2)" },
    Signature { name: "SoundSystem::PlayVSound",              module: "soundsystem.dll", needle: "48 8B C4 48 89 58 08 57 48 81 EC ? ? ? ? 33 FF 48 8B D9", resolve: NONE, extra_off: 0, prototype: "_UNKNOWN **__fastcall sub_180349840(__int64 a1, __int64 a2, int a3, int a4)" },

    // ==================================================================
    // animationsystem.dll ----------------------------------------------
    // ==================================================================
    Signature { name: "Animation::ShouldUpdateSequences",     module: "animationsystem.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 49 8B 40 48", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18014F0A0(__int64 a1, __int64 a2, __int64 a3)" },

    // ==================================================================
    // materialsystem2.dll ----------------------------------------------
    // ==================================================================
    Signature { name: "MatSys::PrepareSceneMaterial",         module: "materialsystem2.dll", needle: "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 48 8B 59 ? 48 8B F2 48 63 79 ? 48 C1 E7 06", resolve: NONE, extra_off: 0, prototype: "float __fastcall sub_180011BE0(__int64 a1, __int64 a2, float a3)" },

    // ==================================================================
    // tier0.dll --------------------------------------------------------
    // ==================================================================
    Signature { name: "Tier0::UtlBuffer",                     module: "tier0.dll", needle: "48 89 5C 24 ? 57 48 83 EC ? 8B 41 ? 8D 7A", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "Tier0::LoadKeyValues",                 module: "tier0.dll", needle: "E8 ? ? ? ? 8B 4C 24 34 0F B6 D8", resolve: REL32_1, extra_off: 0, prototype: "" },

    // Plat_FloatTime — tier0!sub_180146AF0. Returns engine wall-clock as
    // a `double` (seconds since startup). The float-precision sibling of
    // Plat_MSTime; this is what most of the engine actually queries when
    // timestamping events. Hookable for time-warp / speedhack scaffolds
    // and for getting a tier0-relative monotonic clock without going
    // through QueryPerformanceCounter yourself. 1 hit on 14160.
    Signature { name: "Tier0::Plat_FloatTime",                module: "tier0.dll", needle: "48 83 EC 28 48 83 3D ? ? ? ? 00 75 05 E8 ? ? ? ? 48 8D 4C 24 30 FF 15 ? ? ? ? 48 8B 4C 24 30 48 8B 05 ? ? ? ? 48 3B C8 73 05 48 8B C8 EB 07 48 89 0D ? ? ? ? 48 2B 0D ? ? ? ? 0F 57 C0 78 12", resolve: NONE, extra_off: 0, prototype: "double __fastcall Plat_FloatTime()" },

    // Plat_MSTime — tier0!sub_180146B70. Integer-millisecond wall-clock
    // (Plat_FloatTime * 1000). Distinguished from its sibling helpers
    // (USTime / NSTime, all sharing the same prologue) by the missing
    // REX prefix on the `imul rcx, 1000` — the only byte-level
    // difference between the three. Useful as a cheap tick source and
    // as a hook target for low-resolution speedhacks. 1 hit on 14160.
    Signature { name: "Tier0::Plat_MSTime",                   module: "tier0.dll", needle: "40 53 48 83 EC 20 48 8B 1D ? ? ? ? 48 85 DB 75 0C E8 ? ? ? ? 48 8B 1D ? ? ? ? 48 8D 4C 24 30 FF 15 ? ? ? ? 48 8B 44 24 30 48 8B 0D ? ? ? ? 48 3B C1 73 05 48 8B C1 EB 07 48 89 05 ? ? ? ? 48 2B 05 ? ? ? ? 33 D2 48 F7 F3 48 8B C8 48 69 C2 E8 03 00 00 69 C9 E8 03 00 00", resolve: NONE, extra_off: 0, prototype: "unsigned __int64 __fastcall Plat_MSTime()" },

    // Plat_GetTime — tier0!sub_180146930. Thin wrapper over the
    // tier0 high-resolution clock thunk; returns raw QPC ticks. The
    // primitive every other Plat_*Time helper sits on top of, and the
    // canonical hook point for a single-source-of-truth speedhack
    // (one stomp here scales every game subsystem's clock at once).
    // 1 hit on 14160.
    Signature { name: "Tier0::Plat_GetTime",                  module: "tier0.dll", needle: "48 83 EC 28 48 8D 4C 24 30 E8 ? ? ? ? 48 8B 44 24 30 48 83 C4 28 C3", resolve: NONE, extra_off: 0, prototype: "unsigned __int64 __fastcall Plat_GetTime()" },

    // tier0!CreateInterface — sub_180210B90. The standard Source-style
    // factory exported by every Source 2 module, but THIS specific
    // copy is tier0's and is the bootstrap factory the loader walks
    // first. Convenient single anchor when you want to enumerate /
    // hook the global interface registration list (the `s_pInterfaceRegs`
    // it walks lives at the rip-relative reference at +3). 1 hit.
    Signature { name: "Tier0::CreateInterface",               module: "tier0.dll", needle: "4C 8B 0D ? ? ? ? 4C 8B D2 4C 8B D9 4D 85 C9 74 2E 49 8B 41 08 4D 8B C3 4C 2B C0", resolve: NONE, extra_off: 0, prototype: "void *__fastcall CreateInterface(const char *pName, int *pReturnCode)" },

    // ==================================================================
    // engine2.dll ------------------------------------------------------
    // ==================================================================
    Signature { name: "Engine::PVSManager_ptr",               module: "engine2.dll", needle: "48 8D 0D ? ? ? ? 33 D2 FF 50", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "Engine::RunPrediction",                module: "engine2.dll", needle: "40 55 41 56 48 83 EC ? 80 B9", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180066490(__int64 a1, unsigned int a2)" },
    Signature { name: "Engine::GetScreenAspectRatio",         module: "engine2.dll", needle: "48 89 5C 24 08 57 48 83 EC 20 8B FA 48 8D 0D", resolve: NONE, extra_off: 0, prototype: "float __fastcall sub_1800769D0(__int64 a1, int a2, int a3)" },

    // CNetworkGameClient::InternalProcessPacketEntities — engine2!
    // sub_1800483A0 (~0xBBB). The client-side decoder for CSVCMsg_PacketEntities:
    // walks the delta against the previous baseline, allocates / frees
    // CSerializedEntity records, and dispatches per-class deserializers
    // BEFORE the entity ever reaches the client DLL. THE choke point for
    // pre-game-DLL netvar tampering, baseline mutation, and silent
    // entity injection (CSGOMM-style "fake spectator" hacks). 1 hit.
    Signature { name: "Engine::CNetworkGameClient_InternalProcessPacketEntities", module: "engine2.dll", needle: "40 55 56 57 41 56 41 57 48 8D AC 24 40 FF FF FF 48 81 EC C0 01 00 00 65 48 8B 04 25 58 00 00 00", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1800483A0(__int64 a1, __int64 a2)" },

    // CNetworkGameClient::ProcessServerInfo — engine2!sub_18006B120
    // (~0x16B). Handles CSVCMsg_ServerInfo on the client side: stamps
    // tickrate / max_clients / map name into the local client state.
    // Hooked by anti-tickrate-fingerprint suites (override server tick
    // before the game DLL learns about it) and by FOV-stretch / aspect
    // ratio fixups that need the *real* server resolution. 1 hit.
    Signature { name: "Engine::CNetworkGameClient_ProcessServerInfo", module: "engine2.dll", needle: "48 89 5C 24 08 57 48 83 EC 30 48 8B FA 48 8B D9 8B 0D ? ? ? ? BA 02 00 00 00 FF 15", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_18006B120(__int64 a1, __int64 a2)" },

    // CHLTVClient::SetSignonState — engine2!sub_180123630 (~0x8AF).
    // SourceTV/HLTV variant of SetSignonState; called as the demo /
    // SourceTV pipeline transitions through CONNECTED → NEW → PRESPAWN
    // → SPAWN → FULL. Anchor for demo-record / demo-playback
    // interception and for "spectate as HLTV" features that need to
    // suppress or rewrite the state machine. 1 hit.
    Signature { name: "Engine::CHLTVClient_SetSignonState",   module: "engine2.dll", needle: "40 55 53 41 55 41 56 41 57 48 8D 6C 24 C9 48 81 EC E0 00 00 00 45 8B E8 8B DA 4C 8B F9 45 33 F6", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_180123630(__int64 a1, int a2, __int64 a3, int a4)" },

    // CServerSideClientBase::ProcessServerInfo — engine2!sub_180084B00
    // (~0x7EF). Server-side counterpart that builds the per-client
    // ServerInfo packet (logs `OnLevelLoadingServerInfo` and
    // `CServerSideClientBase::ProcessServerInfo(done)`). Hookable by
    // listen-server / community-server tooling to inject custom
    // session manifests or to spoof the advertised tickrate to
    // joining clients. 1 hit.
    Signature { name: "Engine::CServerSideClient_ProcessServerInfo", module: "engine2.dll", needle: "48 89 5C 24 20 55 56 57 41 54 41 56 48 8D AC 24 10 FE FF FF 48 81 EC F0 02 00 00", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_180084B00(__int64 a1, __int64 a2)" },

    // CNetworkStringTableContainer::CreateStringTable — engine2!
    // sub_18010C690 (~0x3B9). The single function every networked
    // string table funnels through at creation (userinfo, modelprecache,
    // soundprecache, instancebaseline, …). Hook to enumerate / log /
    // mutate the table set as it's built — base of every "modelchams
    // via baseline rewrite" trick and of every dumper that wants to
    // capture the string table catalog deterministically. 1 hit.
    Signature { name: "Engine::CNetworkStringTableContainer_CreateStringTable", module: "engine2.dll", needle: "40 53 41 56 48 83 EC 48 4C 8B F2 48 8B D9 48 8B 12 48 85 D2 0F 84 ? ? ? ? 80 79 34 00", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18010C690(__int64 a1, const char *a2, __int64 a3)" },

    // CNetworkStringTableContainer::WriteUpdateMessageAtTick — engine2!
    // sub_18010D310 (~0x4C2). Server-side serializer that emits the
    // CSVCMsg_UpdateStringTable delta for a given tick. The exact spot
    // where SourceTV / demo recorders capture string table mutations,
    // and the right hook for community servers wanting to rewrite
    // baselines / userinfo on the wire. 1 hit.
    Signature { name: "Engine::CNetworkStringTableContainer_WriteUpdateMessageAtTick", module: "engine2.dll", needle: "44 89 4C 24 20 44 89 44 24 18 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 57 48 8D 6C 24 F0", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_18010D310(__int64 a1, __int64 a2, int a3, int a4, int a5)" },

    // CHostState::FilterTime — engine2!sub_180210BF0 (~0x412). Logs the
    // unique `FilterTime took target %g…` warning. THE per-frame gate
    // that decides whether enough real time has elapsed to advance the
    // host frame; clamps `host_remainder` against `fps_max` and
    // `host_timescale`. Patching the early-return / clamp here is the
    // canonical "engine-side fps unlock" — works regardless of what
    // the engine ConVar layer reports back. 1 hit.
    Signature { name: "Engine::Host_FilterTime",              module: "engine2.dll", needle: "48 89 5C 24 10 48 89 74 24 18 48 89 4C 24 08 57 48 81 EC A0 00 00 00 48 8B BC 24 D0 00 00 00", resolve: NONE, extra_off: 0, prototype: "bool __fastcall sub_180210BF0(__int64 a1, float *a2)" },

    // CClient::SendMovePacket — engine2!sub_180064F80 (~0x924). The
    // per-tick client→server path: walks the queued usercmd ring,
    // serializes them into a CCLCMsg_Move (logging
    // `CL: SendMovePacket sending %d commands ...` and downgrading on
    // overflow with `SendMovePacket overflowed trying to send %d
    // commands, will try using %d!`), then appends a CNETMsg_Tick_t.
    // Hooking here gives byte-level control over every outbound
    // user-command packet — the canonical anchor for "rewrite
    // outgoing CCLCMsg_Move", choked-packet exploits, and any tool
    // that needs to inject / suppress / reorder usercmds AFTER the
    // game DLL has produced them. 1 hit on 14160.
    Signature { name: "Engine::CClient_SendMovePacket",       module: "engine2.dll", needle: "40 55 57 41 55 48 8D AC 24 90 E0 FF FF B8 70 20 00 00 E8 ? ? ? ? 48 2B E0 4C 8B E9 C7 44 24 20 FF FF FF FF", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_180064F80(__int64 a1)" },

    // CGameEventSystem::PostEventAbstract — engine2!sub_180215830
    // (~0x333). Every IGameEvent fired through the engine — server
    // OR client — funnels through this single function (logs
    // `GameEvent: Posting %s (id:%d group:'%s') from code`). Hook to
    // intercept / log / drop / mutate any game event before it
    // reaches its registered listeners (player_death, weapon_fire,
    // round_start, …) — the universal "see every event" anchor that
    // beats the per-listener vtable thunks. Also branches into
    // CBidirMsg_RebroadcastGameEvent serialization so events on the
    // server side can be diverted from the wire here. 1 hit.
    Signature { name: "Engine::CGameEventSystem_PostEventAbstract", module: "engine2.dll", needle: "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 41 54 41 55 41 56 41 57 48 8D 6C 24 F1 48 81 EC A0 00 00 00 4C 8B 65 67 4C 8B F1", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180215830(_BYTE *a1, unsigned int a2, char a3, int a4, __int64 *a5, __int64 a6, __int64 a7, __int64 a8, char a9)" },

    // CInputService::ProcessConVar — engine2!sub_1801C30B0 (~0x4B6).
    // Engine-side handler that takes a CNETMsg_SetConVar tied to an
    // input-service slot and applies it (player name, voice volume,
    // network rate, etc.). The single dispatch point that bridges
    // CCSGOInput convars from the protobuf layer into the live
    // CCvar registry — useful for blocking server-pushed convar
    // overrides (e.g. fps_max stomps, sv_cheats-tied feature flips)
    // and for spoofing the client's reported input convars to the
    // server. 1 hit.
    Signature { name: "Engine::CInputService_ProcessConVar",  module: "engine2.dll", needle: "48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 55 41 54 41 55 41 56 41 57 48 8D AC 24 40 F3 FF FF 48 81 EC C0 0D 00 00", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1801C30B0(__int64 a1, __int64 a2)" },

    // CHostStateMgr::HostStateRequest::Start — engine2!sub_180218DF0
    // (~0x7A4). The state-transition kernel of the engine: every
    // disconnect → main-menu → map-load → map-change → quit cycle is
    // dispatched through this function (logs `HostStateRequest::Start(
    // HSR_GAME / HSR_QUIT / HSR_SOURCETV_RELAY / HSR_IDLE )`). Hook
    // to gate / intercept / log map changes (good for "auto-reconnect
    // on kick", server-list bootstrap automation, demo session
    // splitting, anti-disconnect features). 1 hit.
    Signature { name: "Engine::CHostStateMgr_HostStateRequest_Start", module: "engine2.dll", needle: "40 53 48 83 EC 40 8B 01 48 8B D9 C6 41 18 01 83 F8 02 74 07 83 F8 04 75 21 EB 0D 8B 49 20 83 E9 06 74 17 83 F9 01 74 12", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180218DF0(__int64 a1, __int64 a2)" },

    // CHLTVClient::SendSnapshot — engine2!sub_180121FC0 (~0xAC2).
    // The per-tick HLTV/SourceTV snapshot writer: builds the delta
    // packet entities + string-table updates that get broadcast to
    // every spectator client and recorded into the demo file (logs
    // `CHLTVClient::SendSnapshot: Failed to serialize CNETMsg_Tick_t`).
    // Hookable for SourceTV-side tooling (anti-leak / demo
    // sanitization, per-spectator entity filtering, custom relay
    // replay rewrites). 1 hit.
    Signature { name: "Engine::CHLTVClient_SendSnapshot",     module: "engine2.dll", needle: "48 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 56 41 57 48 8D 6C 24 88 48 81 EC 78 01 00 00 48 8D 05 ? ? ? ? 48 C7 45 18 7A 02 00 00", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_180121FC0(__int64 a1, __int64 a2)" },

    // CCSGOHudVote::OnVoteResult — client.dll!sub_180E14250 (~0x704).
    // Single dispatch the engine calls into when a vote transitions
    // (cast / passed / failed / active / call-vote-failed). Resolves
    // the localized #SFUI_vote_… or #Panorama_vote_… string the chat
    // line will display ("X is voting to kick Y", "Vote failed:
    // VOTE_FAILED_…", etc.) and pumps the matching panorama event
    // (`hud-vote--cast`, `hud-vote--passed`, `hud-vote--failed`,
    // `hud-vote--active`, `hud-vote--callvotefailed`) plus the
    // vote{kick|changelevel|surrender|pausematch|loadbackup|…} icon
    // path. Hooking here is THE one-stop point to: see every vote in
    // real time (including enemy-team votes you'd normally not see in
    // chat), suppress the "Vote failed" toast, replace the displayed
    // localization key, or auto-populate features that need to react
    // to vote state. 1 hit.
    Signature { name: "Client::CCSGOHudVote_OnVoteResult",    module: "client.dll",  needle: "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 81 EC 90 01 00 00 65 48 8B 04 25 58 00 00 00 49 8B E8 44 8B 15 ? ? ? ? 8B FA", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180E14250(__int64 a1, int a2, const char *a3, int a4, __int64 a5)" },

    // CCSGO_HudChat::OnSayText2 — client.dll!sub_1810C3D50 (~0x808).
    // Per-message handler for inbound CUserMessageSayText2 (every
    // chat / radio / vote-system / death-notice line that lands in
    // the chat HUD). Resolves the localized template, expands the
    // `#SLOTNAME[idx]` token to the actual player name, sanitizes
    // unicode zero-width joiners, prefixes the radio-team key
    // (`game_radio_team_prefix_%d`), then plays `HudChat.Message` and
    // emits the panorama line. The single canonical anchor for chat
    // overlays / chat loggers / "show all enemy chat regardless of
    // mute" / silently injecting fake chat into the local HUD.
    // Sibling to the existing `HudChatPrintf` low-level Printf —
    // this one sees the structured SayText2 envelope (slot, raw
    // string, sanitized name) before formatting. 1 hit.
    Signature { name: "Client::CCSGO_HudChat_OnSayText2",     module: "client.dll",  needle: "48 89 5C 24 08 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 70 F3 FF FF 48 81 EC 90 0D 00 00 81 A5 DC 0C 00 00 FF FF 0F FF 33 F6 8B 5A 6C 48 8B", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1810C3D50(int a1, __int64 a2)" },

    // -------- More high-value client.dll anchors (string-ref) --------
    // Universal client-side particle / effect dispatcher. Looks up an
    // effect by name in a global symbol table and invokes its callback.
    // Hookable to log every dispatched FX, suppress unwanted ones
    // (smoke / flashbang / impact effects), or inject custom effects.
    // The unique log line is only emitted from this function.
    Signature { name: "Client::C_DispatchEffect",             module: "client.dll",  needle: "DispatchEffect: effect \"%s\" not found on client\n", resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_180ACDB70(const char *name, __int64 data)" },

    // C_GameRules constructor. Stores the singleton into the global
    // qword_18232AF48 (`g_pGameRules`) and writes the unique
    // `CGameRules::CGameRules constructed` log line on init. Hooking
    // (or just sigging) gives a deterministic anchor for finding the
    // C_GameRules pointer at module-init time, plus the dtor sibling.
    Signature { name: "Client::C_GameRules_ctor",             module: "client.dll",  needle: "%s:  CGameRules::CGameRules constructed\n", resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_180B03BD0(__int64 thisptr)" },

    // CLegacyGameUI::Initialize -- the legacy GameUI bootstrap. Single
    // function that emits the `failed to get necessary interfaces`
    // line; useful as a reliable anchor inside the GameUI plumbing and
    // as a hook point for swapping GameUI vtables before they are
    // wired up.
    Signature { name: "Client::CLegacyGameUI_Initialize",     module: "client.dll",  needle: "CLegacyGameUI::Initialize() failed to get necessary interfaces\n", resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_180CA6A40(__int64 thisptr)" },

    // C_BasePlayerPawn::PrePhysicsSimulate -- the per-tick pre-physics
    // hook called before predicted movement runs. Drives the predicted
    // weapon-services + view-model interpolation each command. Anchor
    // string `"C_BasePlayerPawn::PrePhysicsSimulate"` is the VProf
    // budget label and is referenced from exactly one function.
    Signature { name: "Client::C_BasePlayerPawn_PrePhysicsSimulate", module: "client.dll", needle: "C_BasePlayerPawn::PrePhysicsSimulate", resolve: STRREF, extra_off: 0, prototype: "bool __fastcall sub_1808CF580(__int64 pawn)" },

    // -------- Batch 11: bomb damage prediction + forum-sourced engine prediction --------
    //
    // Client::CPrediction_Update -- client!sub_180B4DA50. The per-tick
    // engine-prediction core. Source: yougame.biz/threads/379565 (post by
    // user `Ozelotick`). Wraps `pPrediction->Update(PREDICTION_REASON_*)`
    // and processes a single CUserCmd against the local pawn -- the exact
    // function HVH/legit cheats hook to (a) detect predicted vs replayed
    // ticks via `bInPrediction`, (b) read CNetworkGameClient timing
    // (`iServerTick`, `iDeltaTick`), and (c) advance `iSequenceNumber`
    // on the active CUserCmd. Decompile-vetted: confirmed VProf budget
    // label + "prediction.cpp" string + "CPrediction::Update" inside
    // the function. Pattern verified 1-hit (forum's IDA pattern):
    //   48 8B C4 89 50 ?? 48 89 48 ?? 55 53 57
    //                ^^             ^^ wildcards = stack frame disp.
    Signature { name: "Client::CPrediction_Update",           module: "client.dll", needle: "48 8B C4 89 50 ? 48 89 48 ? 55 53 57", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180B4DA50(__int64 thisptr, int reason)" },

    // Client::C_PlantedC4_ClientThink -- client!sub_180C09800. The
    // per-tick handler on the planted C4 (timer beeps, LED flicker,
    // detonation countdown). Anchor string is the VPK soundevent
    // "C4.ExplodeTriggerTrip" (1 xref, exclusive to ClientThink).
    // CRITICAL for bomb-damage prediction overlays: this fires every
    // sub-tick on the planted bomb so a hook here sees the live
    // `m_flC4Blow` countdown + `m_vecAbsOrigin` -- pair with the
    // m_flBombRadius netvar and the local pawn's eye position to
    // compute live "damage you'd take if it blew now" using the
    // canonical CS damage falloff `dmg = 500 * (1 - dist/radius*1.6)`
    // and subtract armor. Updates every frame as the player moves.
    Signature { name: "Client::C_PlantedC4_ClientThink",      module: "client.dll", needle: "C4.ExplodeTriggerTrip",                 resolve: STRREF, extra_off: 0, prototype: "_DWORD *__fastcall sub_180C09800(__int64 plantedC4)" },

    // Client::CCSPlayer_MovementServices_ProcessMovement -- client!sub_1808476D0.
    // The per-tick movement sanity validator that emits the four
    // canonical `CCSPlayer_MovementServices(%s):  %d/%s Got a NaN ...`
    // / `Got a velocity too low/high` Warning() lines. All four format
    // strings xref this single function (size 0x704). Hook this to:
    //   * detect server velocity-clamp events (movement-desync trigger),
    //   * gate fakelag/edge-bug heuristics (the function runs *after*
    //     ProcessUsercmds so origin/velocity are already-applied),
    //   * read post-physics velocity for predicted recoil compensation.
    // String chosen contains a literal newline so we use the four-arg
    // prefix as the unique needle.
    Signature { name: "Client::CCSPlayer_MovementServices_ValidateVelocity", module: "client.dll", needle: "CCSPlayer_MovementServices(%s):  %d/%s Got a NaN velocity on %s\n", resolve: STRREF, extra_off: 0, prototype: "void __fastcall sub_1808476D0(__int64 movementServices)" },

    // ==================================================================
    // Additional string-ref anchors (enhanced_signatures.h) ------------
    // ==================================================================
    Signature { name: "CTonemapController2",                  module: "client.dll", needle: "CTonemapController2",                  resolve: STRREF, extra_off: 0, prototype: "__int64 sub_180257C90()" },
    Signature { name: "CFogController",                       module: "client.dll", needle: "CFogController",                       resolve: STRREF, extra_off: 0, prototype: "__int64 sub_18027EFD0()" },
    Signature { name: "CPostProcessingVolume",                module: "client.dll", needle: "CPostProcessingVolume",                 resolve: STRREF, extra_off: 0, prototype: "__int64 sub_1802A3D60()" },
    Signature { name: "CCSPlayer_ItemServices",               module: "client.dll", needle: "CCSPlayer_ItemServices",                resolve: STRREF, extra_off: 0, prototype: "void *__fastcall sub_180850B00(__int64 a1)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CCSPlayer_ViewModelServices",
        module: "client.dll",
        needle: "CCSPlayer_ViewModelServices",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CCSPlayer_CameraServices",             module: "client.dll", needle: "CCSPlayer_CameraServices",              resolve: STRREF, extra_off: 0, prototype: "__int64 sub_18080FCB0()" },
    Signature { name: "C_CSWeaponBase",                       module: "client.dll", needle: "C_CSWeaponBase",                       resolve: STRREF, extra_off: 0, prototype: "_QWORD *__fastcall sub_180742170(int a1, _QWORD *a2)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "C_BaseViewModel",
        module: "client.dll",
        needle: "C_BaseViewModel",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "C_BaseFlex",
        module: "client.dll",
        needle: "C_BaseFlex",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "C_EconItemView",                       module: "client.dll", needle: "C_EconItemView",                       resolve: STRREF, extra_off: 0, prototype: "_QWORD *__fastcall sub_18070B570(int a1, _QWORD *a2)" },
    Signature { name: "C_AttributeContainer",                 module: "client.dll", needle: "C_AttributeContainer",                  resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_180C18BB0(int a1, _QWORD *a2)" },

    // ==================================================================
    // Community drops (UC forum, Apr 2026) -----------------------------
    // ==================================================================
    Signature { name: "draw_view_punch_v2",                   module: "client.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC ? 49 8B E9 49 8B F8", resolve: NONE, extra_off: 0, prototype: "float *__fastcall sub_1808041C0(int a1, __int64 a2, __int64 a3, float *a4, float *a5, float *a6)" },
    Signature { name: "global_vars_v2",                       module: "client.dll", needle: "48 89 1D ? ? ? ? FF 15 ? ? ? ? 84 C0 74 ? 8B 0D ? ? ? ? 4C 8D 0D ? ? ? ? 4C 8D 05 ? ? ? ? BA ? ? ? ? FF 15 ? ? ? ? 48 8B 74 24 ? 48 8B C3", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "local_controller",                     module: "client.dll", needle: "48 8B 05 ? ? ? ? 41 89 BE", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "entity_list_ptr",                      module: "client.dll", needle: "48 8B 1D ? ? ? ? 48 8D 46", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "view_matrix_ptr",                      module: "client.dll", needle: "48 8D 0D ? ? ? ? 48 89 44 24 ? 48 89 4C 24 ? 4C 8D 0D", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "planted_c4_ptr",                       module: "client.dll", needle: "48 8B 15 ? ? ? ? 48 8B 5C 24 ? FF C0 89 05 ? ? ? ? 48 8B C6 ? ? ? ? 80 BE ? ? ? ? 00", resolve: RIPREL_3, extra_off: 0, prototype: "" },
    Signature { name: "frame_stage_notify",                   module: "client.dll", needle: "4C 8B 0D ? ? ? ? 48 8D 15 ? ? ? ? 48 8B 8F ? ? ? ? F3 41 0F 10 51 ? 45 8B 49 ? 0F 5A D2 66 49 0F 7E D0 FF 15 ? ? ? ? 48 8B 97 ? ? ? ? 48 8B 0D ? ? ? ? E8 ? ? ? ? E9", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180AD28A0(__int64 a1, int a2)" },
    Signature { name: "override_view_short",                  module: "client.dll", needle: "40 57 48 83 EC ? 48 8B FA E8 ? ? ? ? BA", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180C5F840(__int64 a1, __int64 a2)" },
    Signature { name: "level_shutdown",                       module: "client.dll", needle: "48 83 EC ? 48 8B 0D ? ? ? ? 48 8D 15 ? ? ? ? 45 33 C9 45 33 C0 ? ? ? FF 50 ? 48 85 C0 74 ? 48 8B 0D ? ? ? ? 48 8B D0 ? ? ? 41 FF 50 ? 48 83 C4", resolve: NONE, extra_off: 0, prototype: "__int64 sub_180AFAC10()" },
    Signature { name: "level_init_v2",                        module: "client.dll", needle: "40 55 56 41 56 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 0D", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180AFA990(__int64 a1, __int64 a2)" },
    Signature { name: "update_post_processing_v2",            module: "client.dll", needle: "48 89 AC 24 ? ? ? ? 45 33 ED", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180F264C0(__int64 a1)" },
    Signature { name: "remove_legs",                          module: "client.dll", needle: "40 55 53 56 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? F2 0F 10 42", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_1810F0410(__int64 *a1, __int64 *a2, __int64 a3, __int64 a4, __int64 a5)" },
    Signature { name: "mark_interp_latch_flags_dirty",        module: "client.dll", needle: "40 53 56 57 48 83 EC ? 80 3D ? ? ? ? 00", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180218070(__int64 a1, unsigned int a2)" },
    Signature { name: "get_fov",                              module: "client.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC ? 49 8B E9 49 8B F8", resolve: NONE, extra_off: 0, prototype: "float *__fastcall sub_1808041C0(int a1, __int64 a2, __int64 a3, float *a4, float *a5, float *a6)" },
    Signature { name: "create_move_v2",                       module: "client.dll", needle: "85 D2 0F 85 ? ? ? ? 48 8B C4 44 88 40", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180ACC120(__int64 *a1, int a2, char a3)" },
    Signature { name: "update_global_vars",                   module: "client.dll", needle: "48 8B 0D ? ? ? ? 4C 8D 05 ? ? ? ? 48 85 D2", resolve: NONE, extra_off: 0, prototype: "void *__fastcall sub_180AE4730(__int64 a1, void *a2)" },
    Signature { name: "on_add_entity_v2",                     module: "client.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B 81 ? ? ? ? 49 8B F0", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180968BB0(__int64 a1, __int64 a2, __int64 a3)" },
    Signature { name: "draw_smoke_array",                     module: "client.dll", needle: "40 55 41 54 41 55 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 4C 8B E2", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_180C7B380(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, unsigned int *a6)" },
    Signature { name: "get_view_angles_v2",                   module: "client.dll", needle: "4D 85 C0 74 ? 85 D2 74", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_180AD4600(__int64 a1, int a2, __int64 a3)" },
    Signature { name: "unlock_inventory",                     module: "client.dll", needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B E9 48 8B 0D ? ? ? ? ? ? ? FF 50", resolve: NONE, extra_off: 0, prototype: "char __fastcall sub_1807011C0(__int64 a1)" },
    Signature { name: "is_demo_or_hltv",                      module: "client.dll", needle: "48 83 EC ? 48 8B 0D ? ? ? ? ? ? ? FF 90 ? ? ? ? 84 C0 75 ? 38 05", resolve: NONE, extra_off: 0, prototype: "char sub_180EFE9B0()" },
    Signature { name: "get_map_name",                         module: "client.dll", needle: "48 83 EC ? 48 8B 0D ? ? ? ? ? ? ? FF 90 ? ? ? ? 48 8B C8 48 83 C4", resolve: NONE, extra_off: 0, prototype: "__int64 sub_180EDD4F0()" },
    Signature { name: "get_view_model",                       module: "client.dll", needle: "40 55 53 56 41 56 41 57 48 8B EC", resolve: NONE, extra_off: 0, prototype: "void __fastcall sub_18084F430(__int64 a1, float *a2, float *a3)" },
    // CSGOInput global: 48 8B 0D xx xx xx xx ; disp32 at +3, then post-resolve add 0x7
    Signature { name: "CSGOInput_resolved",                   module: "client.dll", needle: "48 8B 0D ? ? ? ? 8B 10 E8 ? ? ? ? 45 32 FF", resolve: RIPREL_3, extra_off: 7, prototype: "" },
    // CreateMaterial(material, name, kv3, ...) callsite prologue
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CreateMaterial_caller",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 8B F2",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "GetBonePositionByName",                module: "client.dll", needle: "40 53 48 83 EC ? 48 8B 89 ? ? ? ? 48 8B DA 48 8B 01 FF 50 ? 48 8B C8", resolve: NONE, extra_off: 0, prototype: "__int64 __fastcall sub_1808C81E0(__int64 a1, __int64 a2)" },

    // ==================================================================
    // String-ref class anchors (resilient across patches: the schema
    // class name string survives even when surrounding bytes shift).
    // Internals use these to resolve weapon/player/HUD class vftables
    // without hand-maintaining byte patterns.
    // ==================================================================
    Signature { name: "C_BaseEntity",                          module: "client.dll", needle: "C_BaseEntity",                          resolve: STRREF, extra_off: 0, prototype: "__int64 (__fastcall *sub_18004E260())()" },
    Signature { name: "C_BaseModelEntity",                     module: "client.dll", needle: "C_BaseModelEntity",                     resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_180158010(int a1, _QWORD *a2)" },
    Signature { name: "C_BasePlayerPawn",                      module: "client.dll", needle: "C_BasePlayerPawn",                      resolve: STRREF, extra_off: 0, prototype: "__int64 (__fastcall *sub_18006DA20())()" },
    Signature { name: "C_CSPlayerPawn",                        module: "client.dll", needle: "C_CSPlayerPawn",                        resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1806C2430(int a1, _QWORD *a2)" },
    Signature { name: "C_CSPlayerPawnBase",                    module: "client.dll", needle: "C_CSPlayerPawnBase",                    resolve: STRREF, extra_off: 0, prototype: "__int64 *sub_180BD7140()" },
    Signature { name: "CCSPlayerController",                   module: "client.dll", needle: "CCSPlayerController",                   resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1807E5220(int a1, _QWORD *a2)" },
    Signature { name: "CCSPlayerController_ActionTrackingServices", module: "client.dll", needle: "CCSPlayerController_ActionTrackingServices", resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1807E5220(int a1, _QWORD *a2)" },
    Signature { name: "CCSPlayerController_DamageServices",    module: "client.dll", needle: "CCSPlayerController_DamageServices",    resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1807E5220(int a1, _QWORD *a2)" },
    Signature { name: "CCSPlayerController_InGameMoneyServices", module: "client.dll", needle: "CCSPlayerController_InGameMoneyServices", resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1807E5220(int a1, _QWORD *a2)" },
    Signature { name: "CCSPlayerController_InventoryServices", module: "client.dll", needle: "CCSPlayerController_InventoryServices", resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1807E5220(int a1, _QWORD *a2)" },
    Signature { name: "CCSPlayer_BulletServices",              module: "client.dll", needle: "CCSPlayer_BulletServices",              resolve: STRREF, extra_off: 0, prototype: "void *__fastcall sub_180813BA0(__int64 a1)" },
    Signature { name: "CCSPlayer_HostageServices",             module: "client.dll", needle: "CCSPlayer_HostageServices",             resolve: STRREF, extra_off: 0, prototype: "void *__fastcall sub_180813BA0(__int64 a1)" },
    Signature { name: "CCSPlayer_PingServices",                module: "client.dll", needle: "CCSPlayer_PingServices",                resolve: STRREF, extra_off: 0, prototype: "void *__fastcall sub_180850ED0(__int64 a1)" },
    Signature { name: "CCSPlayer_UseServices",                 module: "client.dll", needle: "CCSPlayer_UseServices",                 resolve: STRREF, extra_off: 0, prototype: "__int64 sub_1808821D0()" },
    Signature { name: "CCSPlayer_WaterServices",               module: "client.dll", needle: "CCSPlayer_WaterServices",                resolve: STRREF, extra_off: 0, prototype: "__int64 *sub_180877460()" },
    Signature { name: "CCSPlayer_WeaponServices",              module: "client.dll", needle: "CCSPlayer_WeaponServices",               resolve: STRREF, extra_off: 0, prototype: "__int64 *sub_180877810()" },
    Signature { name: "CCSPlayer_MovementServices",            module: "client.dll", needle: "CCSPlayer_MovementServices",             resolve: STRREF, extra_off: 0, prototype: "__int64 *sub_18083DE80()" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CCSPlayer_MovementServices_Humanoid",
        module: "client.dll",
        needle: "CCSPlayer_MovementServices_Humanoid",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CCSWeaponBase",                         module: "client.dll", needle: "CCSWeaponBase",                          resolve: STRREF, extra_off: 0, prototype: "__int64 sub_18077F3D0()" },
    Signature { name: "CCSWeaponBaseGun",                      module: "client.dll", needle: "CCSWeaponBaseGun",                       resolve: STRREF, extra_off: 0, prototype: "__int64 sub_18077F470()" },
    Signature { name: "CCSWeaponBaseVData",                    module: "client.dll", needle: "CCSWeaponBaseVData",                     resolve: STRREF, extra_off: 0, prototype: "const char *sub_18075A2B0()" },
    Signature { name: "CSmokeGrenadeProjectile",               module: "client.dll", needle: "CSmokeGrenadeProjectile",                resolve: STRREF, extra_off: 0, prototype: "__int64 sub_18074E460()" },
    Signature { name: "CMolotovProjectile",                    module: "client.dll", needle: "CMolotovProjectile",                     resolve: STRREF, extra_off: 0, prototype: "__int64 sub_18074E3C0()" },
    Signature { name: "CFlashbangProjectile",                  module: "client.dll", needle: "CFlashbangProjectile",                   resolve: STRREF, extra_off: 0, prototype: "__int64 sub_180FE03F0()" },
    Signature { name: "CHEGrenadeProjectile",                  module: "client.dll", needle: "CHEGrenadeProjectile",                   resolve: STRREF, extra_off: 0, prototype: "__int64 sub_180FE0490()" },
    Signature { name: "CDecoyProjectile",                      module: "client.dll", needle: "CDecoyProjectile",                       resolve: STRREF, extra_off: 0, prototype: "__int64 sub_18074E1E0()" },
    Signature { name: "C_PlantedC4",                           module: "client.dll", needle: "C_PlantedC4",                            resolve: STRREF, extra_off: 0, prototype: "__int64 (__fastcall *sub_1800F07A0())()" },

    // CPlantedC4::Use â€” client!sub_1807B05B0. Per-tick `+use` handler on
    // the planted bomb: validates defuser, kicks defuse-progress timers,
    // emits the "start defusal" log line at +0x459. The single anchor
    // every "auto-defuse / defuse-time predictor / bomb-timer ESP" wants;
    // hooking lets you read the validated defuser handle, the time-left
    // local, and intercept the "can defuse" gate in one place. Refs the
    // unique "CPlantedC4::Use() start defusal" string. 1 hit on 14160.
    Signature { name: "CPlantedC4_Use",                        module: "client.dll", needle: "40 55 53 56 48 8D AC 24 C0 FE FF FF 48 81 EC 40 02 00 00 48 8B DA 48 8B F1 BA FF FF FF FF", resolve: NONE, extra_off: 0, prototype: "" },

    // C_BaseEntity::StartParticleSystem â€” client!sub_180DA3890. The
    // public API CSGO entities use to attach a particle effect (smoke,
    // tracer, blood, flashbang, deathcam, etc) and start it ticking.
    // Refs the unique "StartParticleSystem" symbol-name string used by
    // the schema-bound script binding. Hook for tracer / smoke control,
    // forced flashbang particle suppress, or to swap the effect handle
    // with a custom CParticleSystemDefinition. 1 hit on 14160.
    Signature { name: "C_BaseEntity_StartParticleSystem",      module: "client.dll", needle: "48 89 5C 24 08 55 48 8B EC 48 83 EC 40 E8 ? ? ? ? 48 8D 05 ? ? ? ? 33 DB 48 8D 15", resolve: NONE, extra_off: 0, prototype: "" },

    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "C_C4",
        module: "client.dll",
        needle: "C_C4",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 (__fastcall *sub_18009A420())()",
    },
    Signature { name: "C_Hostage",                             module: "client.dll", needle: "C_Hostage",                              resolve: STRREF, extra_off: 0, prototype: "__int64 (__fastcall *sub_1800E7480())()" },
    Signature { name: "C_Inferno",                             module: "client.dll", needle: "C_Inferno",                              resolve: STRREF, extra_off: 0, prototype: "__int64 (__fastcall *sub_1800F7440())()" },
    Signature { name: "C_SmokeGrenadeProjectile",              module: "client.dll", needle: "C_SmokeGrenadeProjectile",               resolve: STRREF, extra_off: 0, prototype: "__int64 (__fastcall *sub_180095A10())()" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "C_RecipientFilter",
        module: "client.dll",
        needle: "C_RecipientFilter",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CGameSceneNode",                        module: "client.dll", needle: "CGameSceneNode",                         resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1801A38F0(int a1, __int64 a2)" },
    Signature { name: "CSkeletonInstance",                     module: "client.dll", needle: "CSkeletonInstance",                      resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1801A3A20(int a1, __int64 a2)" },
    Signature { name: "CBodyComponent",                        module: "client.dll", needle: "CBodyComponent",                         resolve: STRREF, extra_off: 0, prototype: "__int64 sub_1801BC160()" },
    Signature { name: "CBodyComponentSkeletonInstance",        module: "client.dll", needle: "CBodyComponentSkeletonInstance",         resolve: STRREF, extra_off: 0, prototype: "__int64 (__fastcall ***sub_1801C3040())()" },
    Signature { name: "CGlowProperty",                         module: "client.dll", needle: "CGlowProperty",                          resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1802E11A0(int a1, __int64 a2, __int64 a3, __int64 a4)" },
    Signature { name: "CCollisionProperty",                    module: "client.dll", needle: "CCollisionProperty",                     resolve: STRREF, extra_off: 0, prototype: "__int64 __fastcall sub_1802E0F90(int a1, __int64 a2, __int64 a3, __int64 a4)" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CWeaponCSBase",
        module: "client.dll",
        needle: "CWeaponCSBase",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CCSGameRules",                          module: "client.dll", needle: "CCSGameRules",                           resolve: STRREF, extra_off: 0, prototype: "_QWORD *sub_18007E160()" },
    Signature { name: "CCSGameRulesProxy",                     module: "client.dll", needle: "CCSGameRulesProxy",                      resolve: STRREF, extra_off: 0, prototype: "__int64 sub_1806E9500()" },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CSGameRulesObjectives",
        module: "client.dll",
        needle: "CSGameRulesObjectives",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },

    // engine2.dll string-ref anchors
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CNetworkGameClient",
        module: "engine2.dll",
        needle: "CNetworkGameClient",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CNetworkGameServer",
        module: "engine2.dll",
        needle: "CNetworkGameServer",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CGameEventManager",
        module: "engine2.dll",
        needle: "CGameEventManager",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },
    Signature { name: "CSplitScreenSlot",                      module: "engine2.dll", needle: "CSplitScreenSlot",                      resolve: STRREF, extra_off: 0, prototype: "char __fastcall sub_18024A250(__int64 a1, __int64 a2, int a3, __int64 a4)" },

    // ==================================================================
    // NUVORA APR-26-2026 EXPANSION  v0.6.0
    // ------------------------------------------------------------------
    // Functions reverse-engineered while building the CS2 cosmetics +
    // third-person internals on build 14154.  Every pattern below was
    // verified UNIQUE (single match) on client.dll 14154 via IDA Pro,
    // captured at the function entry, and uses literal byte runs that
    // are structurally stable (instruction selectors, not register
    // colourings).  These are the exact functions our internal calls
    // into directly â€” community use cases include drop-in skin/glove
    // changers and a console-quality third-person camera.
    // ==================================================================

    // -- Cosmetics: skin / knife / glove direct-call pipeline ----------
    // RegenerateWeaponSkin(weapon, bForce) â€” 0x18078C050 on 14154.
    // Bypasses the bulk-iterator gate at weapon+0xAA8/+0xAC0 so a
    // cheat can apply skins without spawning a fake EconItem first.
    Signature {
        name: "RegenerateWeaponSkin_v2",
        module: "client.dll",
        needle: "40 55 53 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 44 0F B6 FA 48 8B D9 BA ? ? ? ? 48 8D 0D ? ? ? ? E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_18078C2A0(__int64 a1, char a2)",
    },
    // GloveApply orchestrator â€” sub_180BBFAA0 â€” runs every spawner tick
    // inside sub_180BC2620.  Reads m_EconGloves (embedded view at
    // pawn+0x1658), checks m_bNeedToReApplyGloves @ pawn+0x1655,
    // destroys old C_WorldModelGloves, spawns new bonemerged glove
    // entity with paint params written from the embedded view.
    Signature {
        name: "GloveApply_PerTick",
        module: "client.dll",
        needle: "40 55 56 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B B9 A0 00 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180BC1460(int *a1)",
    },
    // Spawner orchestrator â€” sub_180BC2620 â€” checks pawn+0x13B1 each
    // tick to drive GloveApply_PerTick.  Useful for entities/loadout
    // refresh hooks.
    Signature {
        name: "Spawner_PerTickOrchestrator",
        module: "client.dll",
        needle: "48 8B C4 55 53 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 80 B9 B1 13 00 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_180BC3FE0(_QWORD *a1)",
    },
    // Bulk regen iterator â€” sub_18078E320 â€” iterates all C_CSWeaponBase,
    // gates per-weapon on weapon[0xAA8] || weapon[0xAC0], calls
    // RegenerateWeaponSkin.  Knowing this gate is the reason custom
    // skins are silently dropped without setting the fallback fields.
    Signature {
        name: "BulkRegenIterator",
        module: "client.dll",
        needle: "57 48 83 EC 40 0F B6 F9 E8 ? ? ? ? 48 85 C0 0F 84",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18078E570(char a1)",
    },

    // -- Third-person: native ConCommand handlers ----------------------
    // sub_180AC8BD0 â€” `thirdperson` ConCommand handler.  Calling this
    // directly is identical to typing `thirdperson` in console: sets
    // CInput+0x229=1, seeds camera anchor at CInput+0x230..+0x238,
    // calls localPawn->vtable[+0x9C8](true) so the local pawn
    // renders.  ConCommand flags = 0x20002080 (NOT FCVAR_CHEAT).
    Signature {
        name: "ConCommand_thirdperson",
        module: "client.dll",
        needle: "48 83 EC 38 48 8B 0D ? ? ? ? 48 8D 54 24 ? 48 8B 01 FF 90 08 03 00 00 83 7C 24 ? 00 0F 85 ? ? ? ? 4C 8B 05 ? ? ? ? 41 8B 80 50 0B 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_180ACA390()",
    },
    // sub_180AC8AF0 â€” `firstperson` ConCommand handler.  Sister of the
    // above: clears CInput+0x229, calls localPawn->vtable[+0x9C8](false)
    // and broadcasts viewmodel/HUD reset.
    Signature {
        name: "ConCommand_firstperson",
        module: "client.dll",
        needle: "48 83 EC 28 48 8B 0D ? ? ? ? 48 8D 54 24 ? 48 8B 01 FF 90 08 03 00 00 83 7C 24 ? 00 75 ? 48 8B 05 ? ? ? ? C6 80 29 02 00 00 00 C7 80 A8 06 00 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_180ACA2B0()",
    },
    // CInput global pointer slot â€” `off_1820613C0` in IDA.  This is the
    // ACTUAL CInput pointer (deref the qword at this RVA).  The
    // cs2-dumper `dwCSGOInput = 0x23386E0` value points to a separate
    // C_Item entity reservoir and is NOT useful for camera flags.
    // RIP-relative load pattern; rel32 disp lives at +3 of the match.
    Signature {
        name: "CInputPtrGlobal",
        module: "client.dll",
        needle: "4C 8B 05 ? ? ? ? 41 8B 80 50 0B 00 00 85 C0",
        resolve: RIPREL_3,
        extra_off: 0,
        prototype: "",
    },

    // ==================================================================
    // NUVORA APR-25-2026 EXPANSION  (build 14154 audit pass)
    // ------------------------------------------------------------------
    // Functions hooked / referenced by the live internal that were
    // missing from the dumper catalog. All UNIQUE on client.dll 14154,
    // verified via 8-instance IDA Pro MCP (ports 13337-13344).
    // ==================================================================

    // GetWorldFov resolver â€” sub_18080BE50. Renderer's actual FOV-read
    // entry point. Replaces the now-dead `SetWorldFov` E8 callsite
    // (which has 0 hits on 14154 â€” see comment block at top of section
    // around line 57). The resolver:
    //   1. Honours fov_cs_debug ConVar override.
    //   2. Calls camera-services vfunc[33] for base world FOV.
    //   3. Applies weapon-zoom / desired-FOV math.
    //   4. Returns final view FOV float.
    // Hooking here is the clean way to globally override view FOV
    // without writing m_iFOV every tick. Pattern keys on prologue +
    // distinctive tail-call jmp opcode that wraps the cleanup.
    Signature {
        name: "GetWorldFovResolver",
        module: "client.dll",
        needle: "40 53 48 83 EC 50 48 8B D9 E8 ? ? ? ? 48 85 C0 74 ? 48 8B C8 48 83 C4 50 5B E9",
        resolve: NONE,
        extra_off: 0,
        prototype: "float __fastcall sub_18080CEF0(__int64 a1)",
    },

    // CCSGOInput::WriteSubtickFromEntry â€” sub_180C53DB0 (drifted to
    // 0x180C53E10 on 14154 â€” sig auto-resolves either way). Per-subtick
    // writer that copies CInput entry+0x10..+0x18 (view angles) and
    // entry+0x1C..+0x24 (shoot angles) into outgoing CUserCmd subtick
    // message fields. Hooked by the silent-aim path to redirect BOTH
    // view and shoot blocks per subtick (server uses shoot angles for
    // hit-verification â€” view-only rewrite leaves bullets going to the
    // original aim direction).
    Signature {
        name: "WriteSubtickFromEntry",
        module: "client.dll",
        needle: "48 89 5C 24 ? 55 57 41 56 48 8D 6C 24 ? 48 81 EC B0 00 00 00 8B 01 48 8B F9 81 4A 10 00 02",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ClientModeCSNormal::OnEvent â€” sub_180C5A0B0 (drifted +0x60 to
    // 0x180C5A110 on 14154; sig still unique). The dispatcher CS2 uses
    // for VAC/untrusted disconnect events. Inspects KeyValues::GetName
    // and branches on:
    //   "OnClientInsecureBlocked"        â€” VAC kicked us
    //   "OnClientUntrustedLaunch"        â€” unsigned/injected module
    //   "OnClientUntrustedSystemFiles"   â€” tampered files / cheat
    //   "OnClientUntrustedDisallowed"    â€” disallowed launch
    //   "OnTrustedLaunchFailed"          â€” trusted-mode init failed
    //   "OnClientPureFileStateDirty"     â€” sv_pure mismatch
    // Hooked by the watchdog so cleanup runs BEFORE the dialog renders.
    Signature {
        name: "ClientModeCSNormal_OnEvent",
        module: "client.dll",
        needle: "40 53 57 48 81 EC 78 02 00 00 48 8B CA 48 8B FA",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180C5C660(__int64 a1, KeyValues *a2)",
    },

    // ==================================================================
    // NUVORA APR-25-2026 EXPANSION v2 (build 14155)
    // ------------------------------------------------------------------
    // Cross-module deep-dive across 8 IDA instances (client/scenesystem
    // /engine2/networksystem/materialsystem2/resourcesystem
    // /animationsystem/rendersystemdx11). All UNIQUE on respective DLLs,
    // anchored from log-string xrefs (most resilient anchor type).
    // ==================================================================

    // -- client.dll: combat / world ------------------------------------

    // FX_FireBullets â€” sub_180C7BE80. Refs the "FX_FireBullets:
    // GetItemDefinition failed" / "GetWeaponEconDataFromItem failed"
    // / "GetCSWeaponDataFromItem failed" log strings. Single anchor
    // function for all client-side bullet trace effects (tracers,
    // impact decals, hit-feedback). Hook here for custom tracer or
    // bullet-impact features without touching the actual fire path.
    Signature {
        name: "FX_FireBullets",
        module: "client.dll",
        needle: "48 8B C4 4C 89 48 20 48 89 50 10 55 53 57 41 54 41 55 48 8D A8 58 FB FF FF 48 81 EC A0 05",
        resolve: NONE,
        extra_off: 0,
        prototype: "void sub_180C7E380(unsigned int a1, __int64 a2, __int64 a3, __int64 *a4, __int64 a5, int a6, int a7, ...)",
    },

    // DispatchSpawn caller â€” sub_1814D32A0. Iterates the pending-spawn
    // queue and calls per-entity DispatchSpawn vfunc. Refs the
    // "DispatchSpawn" string. Useful as a "wait until entity is
    // spawned" hook anchor for features that need post-spawn state
    // (e.g. inventory_changer applies after this fires).
    Signature {
        name: "DispatchSpawn_caller",
        module: "client.dll",
        needle: "4C 8B DC 55 56 48 83 EC 78 49 8B 68 08 48 8B F1 48 85 ED 0F 84 72 01 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1814D5B10(_QWORD *a1, __int64 a2, __int64 a3, __int64 a4)",
    },

    // m_bNoClipEnabled OnChange â€” sub_1808ADB40. Schema OnChange
    // callback for noclip flag (loads m_bNoClipEnabled string by lea
    // immediately at prologue). Useful if implementing client-side
    // noclip for spectator demos / map exploration.
    Signature {
        name: "NoClipOnChange",
        module: "client.dll",
        needle: "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 48 8B EC 48 83 EC 30 48 8D 05",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180166C00(__int64 a1)",
    },

    // SpectatorInput â€” sub_1807D9130. Refs "spec_next" / "spec_prev"
    // / "spec_player %d" â€” handles the spec_* ConCommand input. Useful
    // for spectator-list UI / coach-cam features.
    Signature {
        name: "SpectatorInput",
        module: "client.dll",
        needle: "48 89 5C 24 10 55 56 57 41 56 41 57 48 8B EC 48 83 EC 60 48 8B 01 41 8B F8 48 8B DA 48 8B F1 FF",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1807D92E0(_DWORD *a1, __int64 a2, unsigned int a3)",
    },

    // ViewModel HideZoomed handler â€” sub_1807A03D0. Refs
    // m_bHideViewModelWhenZoomed; the function that gates viewmodel
    // visibility on zoom state. Hook to force viewmodel-on-while-scoped
    // (or always-hidden viewmodel for a clean screen).
    Signature {
        name: "ViewModelHideZoomed",
        module: "client.dll",
        needle: "48 89 5C 24 20 55 56 57 41 54 41 56 48 8B EC 48 83 EC 50 48 8D 05",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1807A0460(__int64 a1, __int64 a2, __int64 **a3)",
    },

    // CalcViewmodelTransform v2 â€” sub_1807A2460. The much larger
    // (0x1E8E byte) viewmodel-transform calculator. Hook for
    // viewmodel offset / FOV / hand-position customisation.
    Signature {
        name: "CalcViewmodelTransform_v2",
        module: "client.dll",
        needle: "48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 80 48 81 EC 80 01 00 00 48 8B FA",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1807A24F0(__int64 a1, __int64 a2)",
    },

    // -- engine2.dll ---------------------------------------------------

    // RegisterConCommand impl â€” engine2!sub_1803FD270. Refs the
    // "RegisterConCommand: Unknown error..." log string. The function
    // to call directly to register a custom ConCommand from inside a
    // cheat (lets you bind cheat features to console commands).
    Signature {
        name: "Engine_RegisterConCommand",
        module: "engine2.dll",
        needle: "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 60 44 8B 15",
        resolve: NONE,
        extra_off: 0,
        prototype: "_QWORD *__fastcall sub_1803FD270(_QWORD *a1, __int64 a2, __int128 *a3, __int64 a4, __int64 a5, __int128 *a6)",
    },

    // Client-side Disconnect_main â€” engine2!sub_1801D1510. Primary
    // disconnect handler (0x751 bytes), refs "disconnect" string and
    // "CL: SendStringCmd(disconnect)". Used by VAC watchdog as a
    // clean-eject path: invoke this before tearing down hooks so the
    // game cleanly reports "user disconnected" instead of crashing.
    Signature {
        name: "Engine_Disconnect_main",
        module: "engine2.dll",
        needle: "48 89 5C 24 20 55 57 41 54 48 8B EC 48 83 EC 70 45 33 E4 48 C7 05",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 *sub_1801D1510()",
    },

    // Netchan timeout disconnect â€” engine2!sub_180069780. Refs
    // "CL: Disconnected - Client delta ticks out of order!". Fires
    // when the netchan detects desync. Hook to suppress / log these
    // events (anti-VAC heuristic â€” desyncs from cheat hooks can
    // trigger this).
    Signature {
        name: "Engine_NetTimeoutDisconnect",
        module: "engine2.dll",
        needle: "40 53 55 56 57 41 56 48 81 EC 80 00 00 00 0F 29 74 24 70 49 8B F8",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180069780(__int64 a1, unsigned int a2, __int64 a3)",
    },

    // -- networksystem.dll ---------------------------------------------

    // CNetChan::ProcessMessages impl â€” networksystem!sub_1800BB280.
    // Refs "CNetChan::ProcessMessages" log string. NOTE: distinct from
    // the client.dll string-anchored entry of the same name which
    // resolves a thunk; this is the actual impl. Hook here for
    // wholesale net-message inspection (anti-cheat detection bypass /
    // per-message logging / message-drop).
    Signature {
        name: "NetSystem_CNetChan_ProcessMessages",
        module: "networksystem.dll",
        needle: "48 8B C4 53 57 41 54 41 56 48 81 EC A8 00 00 00 48 89 70 D0 45 33 E4 4C 89 68 C8 48 8B D9 48 89",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CNetChan::SendNetMessage impl â€” networksystem!sub_1800BD670.
    // Refs all 3 SendNetMessage error log strings ("invalid category
    // for this channel", "buffer is full", "SerializeAbstract failed").
    // Send-side counterpart for outgoing protobuf monitoring/blocking.
    Signature {
        name: "NetSystem_CNetChan_SendNetMessage",
        module: "networksystem.dll",
        needle: "48 89 5C 24 10 48 89 6C 24 18 56 57 41 56 48 83 EC 40 41 0F B6 F0 48 8D 99 F8 73 00 00 4C 8B F2",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ==================================================================
    // NUVORA APR-26-2026 EXPANSION v3 (build 14155 â€” feature-focused)
    // ------------------------------------------------------------------
    // Sigs hand-picked for direct utility in internal/external feature
    // code: usercmd processing, world traces, local-player accessors,
    // viewmodel calc, console-command/cvar registration, the engine
    // command-buffer dispatcher, host-state transitions, the material
    // shader-loader, and the DX11 device entry points (SetMode / Present
    // wait / gamma ramp). All anchored from log strings (most stable
    // across CS2 patches) and verified UNIQUE on respective DLLs.
    // ==================================================================

    // -- client.dll: combat/usercmd/world ------------------------------

    // RunCommand processor â€” sub_1809DA390. Refs the per-tick log
    // "runcommand:%04d,tick:%u". Single anchor for the function CS2
    // calls *before* prediction runs each subtick â€” useful as the
    // canonical entry to inject anti-aim / fake-lag manipulation
    // because angles in m_pCmd are still mutable here.
    Signature {
        name: "RunCommand_processor",
        module: "client.dll",
        needle: "48 8B C4 48 81 EC C8 00 00 00 48 89 58 10 48 89 68 18 48 8B EA 48 89 70 20 48 8B F1 48 89 78 F8",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_1809DBAF0(__int64 a1, __int64 a2)",
    },

    // TraceShape (Client) â€” sub_18098D340. Refs the
    // "Physics/TraceShape (Client)" perfetto category. The client-side
    // raycast/sweep entry every visibility check funnels through.
    // ESSENTIAL for: aimbot visibility filter, autowall, no-spread
    // bullet path simulation, prediction-aware grenade lines.
    Signature {
        name: "TraceShape_Client",
        module: "client.dll",
        needle: "48 89 5C 24 20 48 89 4C 24 08 55 57 41 54 41 55 41 56 48 8D AC 24 10 E0 FF FF B8 F0 20 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "bool __fastcall sub_18098EAA0(_QWORD *a1, __int64 a2, __int64 a3, __int64 a4, _BYTE *a5, __int64 a6)",
    },

    // GetLocalPlayer accessor â€” sub_180379150. Refs *both*
    // "GetLocalPlayerPawn" and "GetLocalPlayerController" interface
    // export strings (single dispatcher). The cleanest, version-stable
    // way to fetch the local controller/pawn without poking the entity
    // list directly. Hook target also lets you "spoof" who is local
    // for spectator-cam / replay tooling.
    Signature {
        name: "GetLocalPlayer_dispatcher",
        module: "client.dll",
        needle: "48 83 EC 38 48 8B 05 ? ? ? ? 48 85 C0 0F 85 14 06 00 00 48 89 5C 24 40 B9 50 00 00 00 48 89",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_180379200()",
    },

    // GetPlayerByIndex export â€” sub_180F02D60. Refs the
    // "GetPlayerByIndex" interface export string. Server-authoritative
    // controller lookup by entity index (1..maxclients). Useful for
    // ESP/aimbot enumeration when you don't want to walk the entity
    // list raw.
    Signature {
        name: "GetPlayerByIndex_export",
        module: "client.dll",
        needle: "48 83 EC 28 4C 8D 05 ? ? ? ? 48 8D 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8D",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_180F00910()",
    },

    // CalcViewmodelView â€” sub_180C699D0. Reads m_flFOVSensitivityAdjust
    // and the viewmodel_offset_{x,y,z} convars to build the viewmodel
    // transform. Hook target for: viewmodel FOV override (to match
    // world FOV without the sensitivity penalty), custom viewmodel
    // position, "true left-hand" mode swap.
    Signature {
        name: "CalcViewmodelView",
        module: "client.dll",
        needle: "40 53 48 83 EC 60 48 8B 41 08 49 8B D8 8B 48 30 48 C1 E9 0C F6 C1 01 0F 85 48 01 00 00 41 B8 07",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180C6BF20(__int64 a1, __int64 a2, _DWORD *a3)",
    },

    // -- engine2.dll: cvar / command / host-state ----------------------

    // RegisterConVar impl â€” engine2!sub_1803FC080. Refs the
    // "RegisterConVar: Unknown error registering convar" log. Direct
    // entry for *registering* a custom ConVar from inside a cheat
    // (mirrors RegisterConCommand). Combine with the existing
    // Engine_RegisterConCommand sig to give your menu console-bindable
    // settings.
    Signature {
        name: "Engine_RegisterConVar",
        module: "engine2.dll",
        needle: "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54 41 56 41 57 48 81 EC D0 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int128 *__fastcall sub_1803FC080(_QWORD *a1, __int64 a2, __int64 a3, __int64 a4, __int128 *a5)",
    },

    // CHLTVClient::ExecuteStringCommand â€” engine2!sub_180120D70. Refs
    // "CHLTVClient::ExecuteStringCommand: Unknown command %s.". The
    // server-side string-command dispatcher used while in HLTV/GOTV
    // demo playback. Useful for replay/demo tooling, and for pushing
    // custom HLTV commands (e.g. forced spec-target switch).
    Signature {
        name: "Engine_HLTVClient_ExecuteStringCommand",
        module: "engine2.dll",
        needle: "40 53 56 48 81 EC 48 07 00 00 48 8B F1 48 8B DA 48 8B 4A 48 48 83 E1 FC 48 83 79 18 0F 76 03 48",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_180120D70(__int64 a1, __int64 a2)",
    },

    // CHostStateMgr::QueueNewRequest â€” engine2!sub_18021AFC0. Refs
    // the "CHostStateMgr::QueueNewRequest( %s, %u )" log. Single entry
    // for transitioning host state (HSR_GAME / HSR_QUIT / HSR_IDLE /
    // HSR_SOURCETV_RELAY). Useful for VAC watchdog clean-eject (queue
    // HSR_IDLE before unhooking) and for "rejoin last server" / map
    // change automation.
    Signature {
        name: "Engine_HostStateMgr_QueueNewRequest",
        module: "engine2.dll",
        needle: "48 89 6C 24 18 48 89 7C 24 20 41 56 48 83 EC 30 48 8B EA 48 8B F9 8B 0D ? ? ? ? BA 02 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18021AFC0(__int64 a1, __int64 a2)",
    },

    // -- materialsystem2.dll -------------------------------------------

    // CMaterial2::LoadShadersAndSetupModes â€” materialsystem2!
    // sub_180010040. Refs the "Error creating shader %s for material
    // %s!" log block (multiple anchors). The function CS2 calls when
    // a material is loaded and its shader passes are compiled.
    // Useful for: chams (swap shader at load time so the override is
    // baked-in instead of swapped per-frame), shader-error diagnosis,
    // forcing a specific shader fallback for unsupported materials.
    Signature {
        name: "CMaterial2_LoadShadersAndSetupModes",
        module: "materialsystem2.dll",
        needle: "44 89 44 24 18 48 89 54 24 10 53 56 41 54 41 55 48 81 EC 88 00 00 00 4C 8B E9 48 C7 44 24 60",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180010040(__int64 a1, __int64 a2, unsigned int a3)",
    },

    // -- rendersystemdx11.dll ------------------------------------------

    // CRenderDeviceDx11::SetMode â€” rendersystemdx11!sub_1800399E0.
    // Refs "CRenderDeviceDx11::SetMode: Previous mode has not been
    // shut down!". The HUGE (0x2183 byte) function that
    // creates/recreates the swapchain + RTVs whenever resolution /
    // fullscreen / refresh-rate changes. Hook target to react to
    // resolution change (re-init D3D11 ImGui backend, recreate cham
    // textures sized to the new RT).
    Signature {
        name: "RenderSystemDx11_SetMode",
        module: "rendersystemdx11.dll",
        needle: "44 89 4C 24 20 44 89 44 24 18 89 54 24 10 55 53 56 57 41 54 41 55 41 56 41 57 48 81 EC D8 02 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CSwapChainBase::QueuePresentAndWait â€” rendersystemdx11!
    // sub_180034650. Refs the "CSwapChainBase::QueuePresentAndWait()
    // looped for %d iterations without a present event" warning.
    // The wrapper around IDXGISwapChain::Present that CS2 actually
    // funnels every frame through. PRIMARY hook anchor for ImGui
    // overlay / external menu rendering when not hooking the vtable
    // directly. Fires exactly once per frame.
    Signature {
        name: "RenderSystemDx11_QueuePresentAndWait",
        module: "rendersystemdx11.dll",
        needle: "40 55 53 57 41 54 41 55 48 8D 6C 24 C9 48 81 EC C0 00 00 00 48 8D 05 ? ? ? ? 4C 89 B4 24",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CRenderDeviceDx11::SetHardwareGammaRamp â€” rendersystemdx11!
    // sub_18003F790. Refs "CRenderDeviceDx11::SetHardwareGammaRamp:
    // Unable to set gamma controls!". Lets you set/read the live
    // gamma ramp â€” useful for nightmode/wallhack-style global
    // brightness boost without touching shaders, and for restoring
    // gamma cleanly on detach.
    Signature {
        name: "RenderSystemDx11_SetHardwareGammaRamp",
        module: "rendersystemdx11.dll",
        needle: "48 89 5C 24 18 57 B8 B0 40 00 00 E8 ? ? ? ? 48 2B E0 0F 29 BC 24 90 40 00 00 0F 57 C9 0F 28",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ==================================================================
    // NUVORA APR-26-2026 EXPANSION v4 (build 14155 â€” events/scene/net)
    // ------------------------------------------------------------------
    // Round 4: hooks for the game-event system (incoming server events
    // + client-side dispatch), the scene-node bone hierarchy (chams /
    // ESP bone-screen projection), entity team-number lookup, plus the
    // engine signon-state path (the canonical "we are now in-game"
    // moment used by every cheat for late-init).
    // ==================================================================

    // -- client.dll ----------------------------------------------------

    // CGameEventManager::AddListener â€” sub_180938970. Refs the
    // "CGameEventManager::AddListener: event '%s' unknown." log.
    // The function to call to register a client-side game-event
    // listener (round_start / player_death / item_purchase / bomb_*
    // etc.) without touching IGameEventManager2 vtable directly.
    // PRIMARY anchor for damage_indicator, kill-feed, auto-buy.
    Signature {
        name: "GameEventManager_AddListener",
        module: "client.dll",
        needle: "48 89 5C 24 10 48 89 6C 24 18 56 57 41 56 48 83 EC 50 41 0F B6 E9 48 8D 99 E0 00 00 00 49 8B F0",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180939FF0(__int64 a1, __int64 a2, const char *a3, unsigned __int8 a4)",
    },

    // CGameEventManager::UnserializeEvent â€” sub_1809911A0. Refs the
    // "CGameEventManager::UnserializeEvent:: unknown event id %i."
    // log. Where every server-pushed game event is reconstructed on
    // the client. Hook here to inspect/drop server events server-side
    // before any listener fires (e.g. block round_end clutter,
    // auto-skip warmup notifications).
    Signature {
        name: "GameEventManager_UnserializeEvent",
        module: "client.dll",
        needle: "48 8B C4 48 89 50 10 55 41 54 41 55 41 56 48 8D 68 D8 48 81 EC 08 01 00 00 48 89 58 D8 4C 8D B1",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180992900(__int64 a1, __int64 a2)",
    },

    // CGameSceneNode::BuildBoneMergeWork â€” sub_18093E3C0. Refs the
    // "CGameSceneNode::BuildBoneMergeWork: Invalid use of
    // bonemerge-based hierarchy" log. Walks the bone hierarchy when
    // an entity is parented bone-to-bone (weapons, attachments).
    // Useful anchor for: weapon ESP, finding attached entities, and
    // detecting parent->child bone-merge relationships.
    Signature {
        name: "CGameSceneNode_BuildBoneMergeWork",
        module: "client.dll",
        needle: "40 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 50 48 8D 6C 24 50 80 A1 06 01 00 00 FB 4C 8B F9 80",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_18093FA40(__int64 a1, _QWORD *a2, char a3)",
    },

    // CGameSceneNode::StartHierarchicalAttachment â€” sub_18098AE80.
    // Refs "CGameSceneNode::StartHierarchicalAttachment: Cannot start
    // hierarchical attachment on a skeleton instance that has no
    // owner!". Resolves attachment-name strings to bone indices â€”
    // the function ESP/chams use to locate (e.g.) "muzzle_flash" or
    // "head" attachments on a model.
    Signature {
        name: "CGameSceneNode_StartHierarchicalAttachment",
        module: "client.dll",
        needle: "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 41 54 41 55 41 56 41 57 48 83 EC 30 48 8B F9 8B",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_18098C5E0(__int64 a1)",
    },

    // CGameSceneNode::PerformBatchedInvalidatePhysicsRecursive â€”
    // sub_18093E660. The only function that references the
    // "PerformInvalidatePhysicsRecursive" VProf string. Toggles a
    // global counter and, when balanced, walks 8 internal queues to
    // dispatch deferred InvalidatePhysicsRecursive calls (transform /
    // bone / parented entity invalidation). Called from ~10
    // ParallelFor lambdas every frame; valuable as an anchor for
    // grabbing the deferred-invalidation table and for hooking the
    // pose-update batching path used by viewmodel and animation
    // chams.
    Signature {
        name: "CGameSceneNode_PerformBatchedInvalidatePhysicsRecursive",
        module: "client.dll",
        needle: "40 57 48 81 EC 90 00 00 00 84 C9 74 4D BF 01 00 00 00 F0 0F C1 3D ? ? ? ? FF C7 83 FF 01 0F 85 63 05 00 00 48 8D 0D ? ? ? ? 48 8D 15",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_18093E660(char a1)",
    },

    // -- engine2.dll ---------------------------------------------------

    // Application::LoadGameInfo â€” engine2!sub_18018D760. Refs
    // "Application unable to load gameinfo.gi file from directory".
    // Parses gameinfo.gi at startup. Useful as a very early init
    // hook (this fires before signon, before client.dll loads its
    // entity factories) â€” gives a deterministic place to install
    // engine-level VMT hooks before anything sees them.
    Signature {
        name: "Engine_LoadGameInfo",
        module: "engine2.dll",
        needle: "40 55 56 41 56 48 8D 6C 24 F0 48 81 EC 10 01 00 00 4C 8B F1 C7 44 24 40 00 00 00 00 48 8B CA 48",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_18018D760(__int64 a1, const char *a2)",
    },

    // CNetworkGameClient::SetSignonState â€” engine2!sub_180060F80.
    // Refs "CNetworkGameClient::SetSignonState: start %i" / "end %i".
    // The function that drives the connection state machine
    // (NONE -> CHALLENGE -> CONNECTED -> NEW -> PRESPAWN -> SPAWN ->
    // FULL). When state == FULL we are in-game; when state drops
    // below CONNECTED we've disconnected. ESSENTIAL for late-init,
    // mid-round detach, and re-init-on-reconnect logic.
    Signature {
        name: "Engine_NetworkGameClient_SetSignonState",
        module: "engine2.dll",
        needle: "44 89 44 24 18 89 54 24 10 55 53 56 57 41 55 41 56 41 57 48 8D 6C 24 D9 48 81 EC D0 00 00 00 8B",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_180060F80(__int64 a1, unsigned int a2, unsigned int a3, __int64 a4)",
    },

    // CNetworkGameClientBase::Connect â€” engine2!sub_18007F400. Refs
    // "CL: CNetworkGameClientBase::Connect() calling
    // SetSignonState( SIGNONSTATE_CONNECTED )". The function that
    // *initiates* a connection to a server. Hook to: log/whitelist
    // server IPs, force-reject connections to certain sv_addresses,
    // or kick off pre-connect setup (e.g. grab the new netchan).
    Signature {
        name: "Engine_NetworkGameClient_Connect",
        module: "engine2.dll",
        needle: "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 40 44 89 81 3C 02 00 00 49 8B E9 44 8B",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_18007F400(__int64 a1, int a2, unsigned int a3, __int64 a4, unsigned int a5, char a6)",
    },

    // MountAddon â€” engine2!sub_180193440. Refs "MountAddon: Failed
    // to find ADDONS search path." (single hit, 0xAE4 byte function).
    // Programmatic addon-mounting entry. Useful for workshop-map /
    // custom-content tooling â€” and as a hook target if you want to
    // intercept which addons CS2 actually loads.
    Signature {
        name: "Engine_MountAddon",
        module: "engine2.dll",
        needle: "48 85 D2 0F 84 DA 0A 00 00 48 8B C4 44 88 40 18 55 57 41 54 41 57 48 8D A8 C8 FC FF FF 48 81 EC",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180193440(__int64 a1, const char *a2, char a3)",
    },

    // ====================================================================
    // NUVORA APR-26-2026 EXPANSION v5 (build 14155 â€” convars / commands)
    // ====================================================================

    // ConVar registration â€” engine2!sub_1803FC080. The internal
    // CCvar::RegisterConVar entry; refs "RegisterConVar: Unknown
    // error registering convar \"%s\"!". Hook here to enumerate /
    // patch every ConVar at registration time, or block creation
    // of unwanted dev-only convars. Used by every ConVar in CS2.
    Signature {
        name: "Cvar_RegisterConVar",
        module: "engine2.dll",
        needle: "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54 41 56 41 57 48 81 EC D0 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int128 *__fastcall sub_1803FC080(_QWORD *a1, __int64 a2, __int64 a3, __int64 a4, __int128 *a5)",
    },

    // ConCommand registration â€” engine2!sub_1803FD270. The internal
    // CCvar::RegisterConCommand entry; refs "RegisterConCommand:
    // Unknown error registering con command \"%s\"!". Hook to
    // enumerate / patch / hide console commands at startup.
    Signature {
        name: "Cvar_RegisterConCommand",
        module: "engine2.dll",
        needle: "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 60 44 8B 15 ? ? ? ? 48 8B D9 65 48",
        resolve: NONE,
        extra_off: 0,
        prototype: "_QWORD *__fastcall sub_1803FD270(_QWORD *a1, __int64 a2, __int128 *a3, __int64 a4, __int64 a5, __int128 *a6)",
    },

    // CCommand::Tokenize â€” engine2!sub_1803FD710. Refs "CCommand::
    // Tokenize: Encountered command which overflows the tokenizer
    // buffer.. Skipping!". Every console command (typed, alias,
    // exec, RCON, scripted) flows through here before dispatch.
    // Hook for command logging / blocking / rewriting.
    Signature {
        name: "CCommand_Tokenize",
        module: "engine2.dll",
        needle: "48 89 6C 24 20 4C 89 44 24 18 56 57 41 54 41 56 41 57 48 83 EC 70 48 8B F2 49 8B E8 8B 51 08 4C",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CGameClient::ClientCommand â€” engine2!sub_1800A1240. Refs
    // "ClientCommand, 0 length string supplied.". Server-side
    // dispatcher for stringcmds received from clients (e.g.
    // "buy", "menuselect", "kill"). Useful for server-tooling
    // anti-cheat hooks and command-flood detection.
    Signature {
        name: "CGameClient_ClientCommand",
        module: "engine2.dll",
        needle: "48 8B C4 4C 89 40 18 4C 89 48 20 55 53 57 48 8D 68 A1 48 81 EC C0 00 00 00 33 FF 48 63 DA 48 39",
        resolve: NONE,
        extra_off: 0,
        prototype: "char sub_1800A1240(__int64 a1, int a2, __int64 a3, ...)",
    },

    // CHLTVClient::ExecuteStringCommand â€” engine2!sub_180120D70.
    // Refs "CHLTVClient::ExecuteStringCommand: Unknown command %s.".
    // GOTV / HLTV-side stringcmd dispatcher. Useful for HLTV
    // bot tooling and demo-recorder hooks.
    Signature {
        name: "CHLTVClient_ExecuteStringCommand",
        module: "engine2.dll",
        needle: "40 53 56 48 81 EC 48 07 00 00 48 8B F1 48 8B DA 48 8B 4A 48 48 83 E1 FC 48 83 79 18 0F 76 03 48",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_180120D70(__int64 a1, __int64 a2)",
    },

    // ====================================================================
    // NUVORA APR-26-2026 EXPANSION v5 (build 14155 â€” client gameplay)
    // ====================================================================

    // FX_FireBullets â€” client!sub_180C7BE80. Refs "FX_FireBullets:
    // GetItemDefinition failed", "...GetWeaponEconDataFromItem failed
    // for weapon %s", "...GetCSWeaponDataFromItem failed for weapon
    // %s" â€” three unique strings inside a single ~0x869 byte
    // function. Client-side bullet-fire effect / tracer / decal /
    // event dispatcher. PRIME hook target for tracers, hit markers,
    // bullet impact replay, recoil-reset detection.
    Signature {
        name: "FX_FireBullets",
        module: "client.dll",
        needle: "48 8B C4 4C 89 48 20 48 89 50 10 55 53 57 41 54 41 55 48 8D A8 58 FB FF FF 48 81 EC A0 05 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "void sub_180C7E380(unsigned int a1, __int64 a2, __int64 a3, __int64 *a4, __int64 a5, int a6, int a7, ...)",
    },

    // RunCommand context â€” client!sub_1809DA390. Refs "runcommand:
    // %04d,tick:%u" log format. The per-tick CSPlayer movement
    // RunCommand wrapper that drives prediction, where CUserCmd is
    // applied. KEY hook for movement cheats (auto-strafe, perfect
    // bhop), no-recoil compensators, fake-lag, and prediction
    // observability. Pairs with the existing CCSGOInput_CreateMove.
    Signature {
        name: "CCSPlayer_RunCommand_Context",
        module: "client.dll",
        needle: "48 8B C4 48 81 EC C8 00 00 00 48 89 58 10 48 89 68 18 48 8B EA 48 89 70 20 48 8B F1 48 89 78 F8",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_1809DBAF0(__int64 a1, __int64 a2)",
    },

    // ====================================================================
    // NUVORA APR-26-2026 EXPANSION v6 (build 14155 â€” present / scene render)
    // ====================================================================

    // CSwapChainBase::QueuePresentAndWait â€” rendersystemdx11!
    // sub_180034650. Refs "CSwapChainBase::QueuePresentAndWait()
    // looped for %d iterations without a present event.". The
    // engine-level wrapper around IDXGISwapChain::Present.
    // GOLD STANDARD frame hook for ImGui menus, ESP overlay,
    // chams setup â€” runs every present, has full device context.
    Signature {
        name: "CSwapChainDx11_QueuePresentAndWait",
        module: "rendersystemdx11.dll",
        needle: "40 55 53 57 41 54 41 55 48 8D 6C 24 C9 48 81 EC C0 00 00 00 48 8D 05 ? ? ? ? 4C 89 B4 24",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // Swapchain ResizeBuffers â€” rendersystemdx11!sub_18003DD20. Refs
    // both "m_pSwapChain->ResizeTarget(...)" and "m_pSwapChain->
    // ResizeBuffers(...)" (two strings, single function). Hook to
    // re-create your render targets / ImGui backbuffer view when
    // window is resized or fullscreen toggled â€” without this, an
    // ImGui hook breaks on every alt-tab/resize.
    Signature {
        name: "CSwapChainDx11_ResizeBuffers",
        module: "rendersystemdx11.dll",
        needle: "48 8B C4 55 53 56 57 41 54 48 8B EC 48 83 EC 70 4C 89 68 10 4D 8B E0 4C 89 70 18 4C 8B EA 4C 89",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // Thread_RenderSceneDrawList â€” scenesystem!sub_1800EDA30. Refs
    // "Thread_RenderSceneDrawList" job name (single hit). Per-view
    // scene draw-list submission. Useful as a per-view render hook
    // (e.g. inject world-space chams pass before submission).
    Signature {
        name: "SceneSystem_Thread_RenderSceneDrawList",
        module: "scenesystem.dll",
        needle: "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1 48 81 EC D8 00 00 00 4C 8B 71 28 48 8B D9",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CSceneSystem RenderViewLayer â€” scenesystem!sub_1800EDD80
    // (~0xEE6 bytes). One of two functions referencing the
    // "Thread_RenderViewLayer" job name string. The big per-layer
    // dispatcher that walks scene objects and submits draw work.
    // Hook for layered overlay injection / draw-call replacement.
    Signature {
        name: "CSceneSystem_RenderViewLayer_Dispatch",
        module: "scenesystem.dll",
        needle: "48 8B C4 48 89 48 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D A8 B8 FE FF FF 48 81 EC 08 02 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ====================================================================
    // NUVORA APR-26-2026 EXPANSION v7 (build 14155 â€” material/net/damage)
    // ====================================================================

    // CMaterialSystem2::FrameUpdate â€” materialsystem2!sub_18003BAC0.
    // Refs the unique "CMaterialSystem2::FrameUpdate" job-name
    // string. Per-frame material state advance â€” fires before every
    // scene render, useful as an alternate render-pacing hook for
    // material patches (chams refresh, override-mode reset).
    Signature {
        name: "CMaterialSystem2_FrameUpdate",
        module: "materialsystem2.dll",
        needle: "48 89 4C 24 08 55 53 56 57 41 54 41 56 48 8B EC 48 83 EC 68 48 8D 05 ? ? ? ? 48 C7 45 C0",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18003BAC0(__int64 *a1)",
    },

    // CNetChan::ProcessMessages â€” networksystem!sub_1800BB280. Refs
    // the literal "CNetChan::ProcessMessages" string + two timing
    // log-format strings (single function). Where every received
    // network message dispatches to its handler. PRIME hook for
    // packet inspection / message logging / fakelag analysis.
    Signature {
        name: "CNetChan_ProcessMessages",
        module: "networksystem.dll",
        needle: "48 8B C4 53 57 41 54 41 56 48 81 EC A8 00 00 00 48 89 70 D0 45 33 E4 4C 89 68 C8 48 8B D9 48 89",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CNetChan::SendNetMessage â€” networksystem!sub_1800BD670. Refs
    // three "CNetChan::SendNetMessage:" diagnostic strings (invalid
    // category / buffer full / SerializeAbstract). The outbound
    // counterpart â€” every netmessage you send (CMsg, RCON, voice,
    // user-cmd) flows through here. Hook for traffic shaping /
    // pre-send mutation / packet drop.
    Signature {
        name: "CNetChan_SendNetMessage",
        module: "networksystem.dll",
        needle: "48 89 5C 24 10 48 89 6C 24 18 56 57 41 56 48 83 EC 40 41 0F B6 F0 48 8D 99 F8 73 00 00 4C 8B F2",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ====================================================================
    // NUVORA APR-26-2026 EXPANSION v7 (build 14155 â€” client gameplay)
    // ====================================================================

    // CBaseEntity::TakeDamageOld â€” client!sub_180223C70. Refs both
    // "CBaseEntity::TakeDamageOld: damagetype %d with info.
    // GetDamageForce() == Vector::vZero" and the ...vector::vZero
    // counterpart. The legacy (still-used) damage-application
    // entry â€” hook for damage-indicator, hit-marker, mini-aimbot
    // damage-prediction, and god-mode patches.
    Signature {
        name: "CBaseEntity_TakeDamageOld",
        module: "client.dll",
        needle: "40 55 53 56 57 41 54 48 8D 6C 24 E0 48 81 EC 20 01 00 00 4D 8B E0 48 8B FA 48 8B F1 E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "unsigned __int64 __fastcall sub_180223D20(__int64 a1, __int64 a2, __int64 **a3)",
    },

    // CGameTrace dispatcher â€” client!sub_18098D340. Refs the unique
    // "Physics/TraceShape (Client)" profile-zone string. Wraps
    // every client-side trace (TraceLine / TraceHull) into the
    // physics system. Hook for visibility checks, autowall, head-
    // shot eligibility, custom no-trace sources.
    Signature {
        name: "CGameTrace_TraceShape_Client",
        module: "client.dll",
        needle: "48 89 5C 24 20 48 89 4C 24 08 55 57 41 54 41 55 41 56 48 8D AC 24 10 E0 FF FF B8 F0 20 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "bool __fastcall sub_18098EAA0(_QWORD *a1, __int64 a2, __int64 a3, __int64 a4, _BYTE *a5, __int64 a6)",
    },

    // ====================================================================
    // NUVORA APR-26-2026 EXPANSION v7 (build 14155 â€” entity factory)
    // ====================================================================

    // DispatchSpawn entry â€” client!sub_1814D32A0. Single string-
    // ref "DispatchSpawn". Spawns / re-initialises any entity on
    // the client (called in waves on round-start, map-load,
    // late-create). Hook to intercept new entities (auto-tag
    // weapons, attach overrides, log spawns).
    Signature {
        name: "Client_DispatchSpawn",
        module: "client.dll",
        needle: "4C 8B DC 55 56 48 83 EC 78 49 8B 68 08 48 8B F1 48 85 ED 0F 84 72 01 00 00 49 89 5B 08 49 8D 4B",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1814D5B10(_QWORD *a1, __int64 a2, __int64 a3, __int64 a4)",
    },

    // ====================================================================
    // NUVORA APR-26-2026 EXPANSION v8 (build 14155 â€” resources / hoststate)
    // ====================================================================

    // CResourceSystem::FindOrRegisterResourceByName_Internal â€”
    // resourcesystem!sub_180016D80. Refs the unique
    // "CResourceSystem::FindOrRegisterResourceByName_Internal"
    // string. Every model / material / sound / particle path
    // resolves through here. Hook for resource-load logging,
    // path overrides, asset replacement (custom skins/models).
    Signature {
        name: "ResourceSystem_FindOrRegisterResourceByName",
        module: "resourcesystem.dll",
        needle: "48 89 5C 24 18 48 89 74 24 20 57 48 81 EC A0 00 00 00 F7 02 FF FF FF 3F 41 0F B6 F8 48 8B DA 48",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CResourceSystem::BlockingLoadResourceByNameIntoJustInTimeManifest â€”
    // resourcesystem!sub_180017360. Refs that string. Synchronous
    // resource-load entry. Hook to detect or block on-demand asset
    // streaming, prefetch overrides, custom asset injection.
    Signature {
        name: "ResourceSystem_BlockingLoadResourceByName",
        module: "resourcesystem.dll",
        needle: "40 53 55 57 48 81 EC 80 00 00 00 48 8B 01 49 8B E8 48 8B FA 48 8B D9 FF 90 98 01 00 00 83 F8 03",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CResourceSystem::FrameUpdate â€” resourcesystem!sub_18001C010.
    // Refs both the unique "ResourceSystemWaitingForFutureWork"
    // tracing string and "Idle (ResourceSystemSleep)" inside the
    // same ~0xC83 byte function. Per-frame resource-system tick.
    // Hook to inject custom resource bookkeeping or measure load
    // pressure.
    Signature {
        name: "ResourceSystem_FrameUpdate",
        module: "resourcesystem.dll",
        needle: "44 88 4C 24 20 44 89 44 24 18 89 54 24 10 55 56 41 54 41 55 41 56 48 8D 6C 24 A0 48 81 EC 60 01",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CHostStateMgr::QueueNewRequest â€” engine2!sub_18021AFC0. Refs
    // the unique "CHostStateMgr::QueueNewRequest( %s, %u )" log
    // string. The engine's host-state transition queue (map
    // change, disconnect, demo playback, restart). Hook to
    // intercept / log every map-state change and reset hooks
    // safely between maps.
    Signature {
        name: "Engine_HostStateMgr_QueueNewRequest",
        module: "engine2.dll",
        needle: "48 89 6C 24 18 48 89 7C 24 20 41 56 48 83 EC 30 48 8B EA 48 8B F9 8B 0D ? ? ? ? BA 02 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18021AFC0(__int64 a1, __int64 a2)",
    },

    // ====================================================================
    // NUVORA APR-26-2026 EXPANSION v9 (build 14155 â€” chams / glow / skin)
    //
    // Notes for "real metal / gold / silver" chams looking like a real
    // PBR material instead of a flat colour swap:
    //
    //   The Source 2 path for an entity-bound model is:
    //     C_BaseModelEntity (m_clrRender / m_nRenderMode / m_nRenderFX)
    //         -> CSkeletonInstance (m_materialGroup / m_MeshGroupMask)
    //              -> CMaterial2 (the actual shader: csgo_character.vfx
    //                 with PBR slots: g_flMetalness, g_flRoughness,
    //                 MetalnessTexture, NormalMap, AmbientOcclusion).
    //
    //   To produce a believable "gold" chams you do NOT just override
    //   `m_clrRender` â€” that only multiplies vertex colour. You need
    //   to swap `m_materialGroup` (CSkeletonInstance::SetMaterialGroup
    //   below) onto a custom `csgo_character` material whose shader
    //   params are set to:
    //       g_flMetalness        = 1.0     (full metal)
    //       g_flRoughness        = 0.05    (mirror polish for gold)
    //       g_vReflectanceColor  = (1.0, 0.766, 0.336)  // gold F0
    //       g_flAOStrength       = 0.0
    //       Selfillum            = 0       (kill emissive haze)
    //       NormalMap            = preserved from original (keeps cloth weave)
    //
    //   Then drive that override every frame inside a hook on
    //   CGameSceneNode::SetMaterialGroup so it survives net-state
    //   resets.  For a depth-test "x-ray" pass, draw the same model
    //   a second time with depth-test disabled inside the
    //   SceneSystem_Thread_RenderSceneDrawList layer hook (already
    //   exposed in v1.11.0).
    //
    //   The CGlowProperty path (m_glowColor / m_iGlowType) drives the
    //   outline post-process â€” useful as an outline-only mode but
    //   NOT what produces the metal-look itself.
    // ====================================================================

    // CSkeletonInstance::SetMaterialGroup â€” client!sub_180A2B0D0
    // (~0x2C bytes â€” small fast setter). Verified via decomp:
    //   if ( a2 != *(_DWORD *)(a1 + 0x3C4) ) {
    //       *(_DWORD *)(a1 + 0x3C4) = a2;            // m_materialGroup
    //       v2 = *(_QWORD *)(a1 + 0x228);            // scene-object
    //       if ( v2 ) sub_1803B9E90(qword_1821C2EB8, v2, a2);
    //   }
    // Writes `m_materialGroup` (CUtlStringToken hash) at offset
    // +0x3C4 and notifies the scene system so the swap is visible
    // immediately. THE primary hook for proper chams: pass a hash
    // pointing at your custom csgo_character.vfx variant
    // (gold/silver/etc.) here every frame.
    //
    // NOTE v1.14.0 mistakenly anchored this at sub_1801BC0B0 â€” that
    // address is `CBodyComponent::RegisterScriptDescriptor`, a
    // one-shot script-binding registrar that contains the literal
    // "SetMaterialGroup" symbol but is NOT the runtime setter.
    // The wrapper chain is:
    //   Script_SetMaterialGroup (sub_1801D5890)
    //     -> vtable[+0x58] (CBodyComponent::GetSkeletonInstance)
    //     -> CSkeletonInstance::SetMaterialGroup (sub_180A2B0D0) â† real
    Signature {
        name: "CSkeletonInstance_SetMaterialGroup",
        module: "client.dll",
        needle: "3B 91 C4 03 00 00 74 24 89 91 C4 03 00 00 48 8B 81 28 02 00 00 48 85 C0 74 12",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180A2C830(__int64 a1, unsigned int a2)",
    },

    // CSkeletonInstance::SetMeshGroupMask (skeletonMeshGroupMaskChanged
    // network-var change handler) â€” client!sub_180A23D20.  Verified
    // via the CModelState change-handler registrar sub_18049BBF0 which
    // wires "skeletonMeshGroupMaskChanged" -> sub_180A23D20.  Sets
    // `m_MeshGroupMask` at +0x1C8 and notifies scene system.
    // Pair with SetMaterialGroup above to mask off mesh parts (vest /
    // helmet / scope) in the chams pass for a cleaner silhouette.
    Signature {
        name: "CSkeletonInstance_SetMeshGroupMask",
        module: "client.dll",
        needle: "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B 00 49 8B F8 48 8B F2 48 8B D9 48 39 81 C8 01",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180A25480(__int64 a1, __int64 a2, _QWORD *a3)",
    },

    // CSkeletonInstance::OnBodyGroupChoiceChanged â€” client!sub_180A23BB0.
    // Wired via CModelState registrar as the "bodyGroupChoiceChanged"
    // handler. Lets you control per-bodygroup mesh selection at the
    // skeleton level (without going through CBaseModelEntity).
    Signature {
        name: "CSkeletonInstance_OnBodyGroupChoiceChanged",
        module: "client.dll",
        needle: "48 89 5C 24 08 57 48 83 EC 20 49 63 D8 49 8B F9 45 85 C0 78 20 3B 99 18 02 00 00 7D 18",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180A25310(__int64 a1, __int64 a2, int a3, _DWORD *a4)",
    },

    // CSkeletonInstance::OnSkeletonModelChanged â€” client!sub_180A23DC0
    // (tiny, 18 bytes). Wired as "skeletonModelChanged" handler.
    // Fires whenever a model swap is netted to the client â€” perfect
    // place to (a) re-resolve your override material for the new
    // model, (b) reset cached bone counts, (c) recompute bodygroup
    // override masks.
    Signature {
        name: "CSkeletonInstance_OnSkeletonModelChanged",
        module: "client.dll",
        needle: "49 8B 00 48 89 81 B8 00 00 00 C6 81 B0 00 00 00 01 C3",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180A25520(__int64 a1, __int64 a2, __int64 *a3)",
    },

    // CSkeletonInstance::PostDataUpdate â€” client!sub_180A24D50
    // (~0xDFB).  Fires after every server net-state update for a
    // skeleton-bound entity (player / weapon / hostage). Refs
    // "CSkeletonInstance::PostDataUpdate".  Best place to re-apply
    // material-group / mesh-group / skin overrides after the server
    // resets them â€” without this hook your chams flicker on every
    // entity update.
    Signature {
        name: "CSkeletonInstance_PostDataUpdate",
        module: "client.dll",
        needle: "48 8B C4 4C 89 40 18 89 50 10 55 57 48 8D A8 68 FE FF FF 48 81 EC 88 02 00 00 48 89 70 E0 48 8B",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_180A264B0(__int64 a1, __int64 a2, __int64 a3)",
    },

    // CLoopModeGame::OnPostDataUpdate â€” client!sub_1809AB920. Top-of-frame
    // dispatcher invoked once per net-snapshot, after every entity has
    // finished its individual PostDataUpdate. Single chokepoint to react
    // to "all entities for this tick are now in their final networked
    // state" â€” ideal for prediction-aware caches, lag-comp record
    // sampling, and post-snapshot ESP rebuilds without hooking N
    // per-entity PostDataUpdates. Refs unique "CLoopModeGame::
    // OnPostDataUpdate" string. 1 hit on 14160.
    Signature { name: "CLoopModeGame_OnPostDataUpdate",       module: "client.dll", needle: "48 89 5C 24 08 48 89 74 24 18 55 57 41 56 48 8B EC 48 83 EC 50 45 8B F1 48 8B FA 48 8B F1 45 85", resolve: NONE, extra_off: 0, prototype: "" },

    // CEntitySystem::QueuePostDataUpdates â€” client!sub_1814AE590. The
    // engine-side queuer that batches per-entity PostDataUpdate calls
    // (only enqueued for entities that flipped state this tick). Hook
    // here to learn exactly which entities the engine deems "changed"
    // for the upcoming frame â€” cheap dirty-set anchor for incremental
    // ESP / prediction caches. Refs unique "CEntitySystem::
    // QueuePostDataUpdates" string. 1 hit on 14160.
    Signature { name: "CEntitySystem_QueuePostDataUpdates",   module: "client.dll", needle: "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 40 80 B9 DA 0B 00 00 00 49 8B D8 8B FA 48 8B F1 74 61", resolve: NONE, extra_off: 0, prototype: "" },

    // CSkeletonInstance::GetTransformsForHitboxList â€” client!
    // sub_180A18F60. Refs the unique "CSkeletonInstance::
    // GetTransformsForHitboxList" string. Per-hitbox bone
    // transform fetch â€” the canonical source for hitbox ESP /
    // skeleton ESP / aimbot bone targets, and the matching
    // bone-space frame for chams (so per-hitbox material masks
    // stay aligned to limbs).
    Signature {
        name: "CSkeletonInstance_GetTransformsForHitboxList",
        module: "client.dll",
        needle: "48 89 5C 24 18 55 56 57 41 55 41 57 48 81 EC A0 00 00 00 49 63 28 4D 8B F8 48 8B FA 48 8B D9 85",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_180A1A6C0(__int64 a1, __int64 a2, int *a3)",
    },

    // CGlowProperty::OnGlowTypeChanged â€” client!sub_180B0B630 (~0xE7).
    // Verified via the registrar sub_1802E10F0 which wires
    // "OnGlowTypeChanged" -> sub_180B0B630 and "OnGlowColorChanged"
    // -> sub_180B0B620.  Fires every time `m_iGlowType` (or
    // `m_glowColor`) changes; touches `m_flGlowStartTime` (+0x4C),
    // `m_flGlowTime` (+0x48), and registers/unregisters the entity
    // with `g_pGlowObjectManager` (qword_182325D30).  Hook here to
    // force `m_bGlowing = true` and override the colour for every
    // entity you want outlined regardless of network state.
    //
    // NOTE v1.14.0 mistakenly anchored this at sub_1802E10F0 â€” that
    // address is the prediction-field registrar (a one-shot init
    // function), not the runtime handler.  Sig collided with two
    // other registrars (3 matches in find_bytes); the real handler
    // sig below is unique.
    Signature {
        name: "CGlowProperty_OnGlowTypeChanged",
        module: "client.dll",
        needle: "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B 05 ? ? ? ? 48 8B D9 F3 0F 10 41 4C",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180B0CD90(__int64 a1)",
    },

    // GlowObjectManager_GetInstance â€” client!sub_180B09570 (8 bytes,
    // `mov rax, [g_pGlowObjectManager]; ret`).  Resolves the global
    // CGlowObjectManager singleton â€” the actual outline-renderer
    // that owns the per-entity outline list & materials.  Direct
    // alternative to hooking CGlowProperty: register/unregister
    // entities for outline yourself, set their colours, alpha, and
    // depth-test mode at will.
    Signature {
        name: "GlowObjectManager_GetInstance",
        module: "client.dll",
        needle: "48 8B 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 8B 41 38 C3",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_180B0ACD0()",
    },

    // CBaseModelEntity::SetBodygroup â€” client!sub_1808D87F0 (~0x1D4).
    // Refs "CBaseModelEntity::SetBodygroup(%d,%d) failed:
    // CBaseModelEntity has no model!". Lets you mask off mesh
    // parts (e.g. drop the player's vest mesh so chams shows the
    // base body silhouette only, or hide weapon scope mesh for
    // clearer x-ray).  Useful complement to material-group swap.
    Signature {
        name: "CBaseModelEntity_SetBodygroup",
        module: "client.dll",
        needle: "85 D2 0F 88 CB 01 00 00 55 53 56 41 56 48 8B EC 48 83 EC 78 45 8B F0 8B DA 48 8B F1 E8 ? ? ?",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_1808D9E70(__int64 a1, int a2, int a3)",
    },

    // ====================================================================
    // NUVORA MAY-01-2026 EXPANSION v10 (build 14155 â€” VMAT / shader pipeline)
    //
    // The "real PBR chams" recipe documented in v9 needs a *real* CMaterial2
    // to point CSkeletonInstance::SetMaterialGroup at. These six anchors
    // expose every entry on the CMaterialSystem2 / CMaterial2 / CVfxProgramData
    // pipeline you need to LOAD, COMPILE, and SWAP a custom .vmat_c at
    // runtime â€” without round-tripping through the resource system from the
    // file system.
    //
    // Pipeline (all on materialsystem2.dll, build 14155):
    //   1. CMaterialSystem2::Init                 (sub_180036E40)
    //         constructs g_pMaterialSystem2, the type-manager, the shader
    //         cache, and the error-material fallback. Hook to inject your
    //         own material-type allocator before any vmat is parsed.
    //   2. CMaterialSystem2::GetErrorMaterial     (sub_180016D10)
    //         the fallback CMaterial2*. Useful to force-return YOUR custom
    //         gold/silver chams material from here for a quick global swap
    //         without touching every entity.
    //   3. CMaterial2::LoadShadersAndSetupModes   (sub_180010040)
    //         every CMaterial2 finishing parse routes through here to
    //         load + bind shader passes. Hook to substitute the shader
    //         entry (e.g. force csgo_character.vfx) or rewrite param
    //         tables (g_flMetalness=1.0, g_flRoughness=0.05, etc.)
    //         BEFORE the static combo is compiled.
    //   4. CMaterial2::CompileComboAndGetVariables_DynamicShaderCompile
    //                                             (sub_180013FA0)
    //         dynamic shader-permutation compile path. Hook to log every
    //         combo a custom material asks for, or to short-circuit a slow
    //         compile by returning a pre-warmed permutation.
    //   5. CVfxProgramData::FindOrCreateStaticComboDataInCache
    //                                             (sub_1800AE220)
    //         the lower-level shader-cache lookup that 3 & 4 funnel into.
    //         Hook to share static combos across runtime-injected materials
    //         (cheap chams across many entities = one combo).
    //   6. CMaterialSystem2::DynamicShaderCompile_UnloadAllMaterials
    //                                             (sub_180039AA0)
    //         called by `mat_reloadshaders` ConCommand. Hook to also
    //         re-upload your custom chams material on a hot-reload so
    //         devs iterating on shaders don't lose the override.
    //
    // All six are STRREF-anchored on log strings with exactly ONE xref each
    // (verified via mcp_ida-pro-mcp_xref_query). The strings are literal
    // C source-file LOG_ERROR / Plat_FatalError messages and are extremely
    // stable across patches â€” they have not changed since at least 14154.
    //
    // RTTI strings `.?AVIMaterial2@@` @ 0x180146F98 and `.?AVCMaterial2@@`
    // @ 0x1801473C0 are also present in materialsystem2.dll â€” keep these
    // in mind for future ResolveKind::Vftable work to expose
    // IMaterial2::SetParam / Bind / GetShaderName slots directly.
    // ====================================================================

    // CMaterialSystem2::Init â€” materialsystem2!sub_180036E40 (~0x132B).
    // Refs the literal "MaterialSystem2" subsystem-name string.
    // First-touch hook for installing your own CMaterialResource
    // type-manager or pre-seeding the shader cache with custom
    // permutations BEFORE the engine loads any .vmat_c.
    Signature {
        name: "CMaterialSystem2_Init",
        module: "materialsystem2.dll",
        needle: "MaterialSystem2",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180036E40(__int64 a1)",
    },

    // CMaterialSystem2::GetErrorMaterial â€” materialsystem2!sub_180016D10
    // (~0x9B9). Refs the unique fatal-spew string
    // "CMaterialSystem2::GetErrorMaterial(529): GetErrorMaterial()
    // called when m_pMaterialTypeManager == NULL!". Returns the
    // engine-wide fallback CMaterial2*. Hook to substitute YOUR
    // custom gold/silver csgo_character chams material as the
    // global error fallback for a one-line "everything missing
    // becomes chams" trick.
    Signature {
        name: "CMaterialSystem2_GetErrorMaterial",
        module: "materialsystem2.dll",
        needle: "CMaterialSystem2::GetErrorMaterial(529): GetErrorMaterial() called when m_pMaterialTypeManager == NULL!\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180016D10(__int64 a1, __int64 a2, __int64 a3, _QWORD *a4, char a5)",
    },

    // (NOTE: CMaterial2::LoadShadersAndSetupModes is already shipped
    // earlier as a raw byte signature anchored on its prologue and
    // resolves correctly to the function start. Adding a duplicate
    // STRREF entry was redundant and resolved to the lea instruction
    // mid-function instead of the prologue, so it is omitted here.
    // The string anchor "\nCMaterial2::LoadShadersAndSetupModes(1543):
    // Error! Material \"%s\" is already loaded!\n" remains the unique
    // STRREF anchor for that function on build 14155 if a future raw
    // pattern goes stale.)

    // CMaterial2::CompileComboAndGetVariables_DynamicShaderCompile â€”
    // materialsystem2!sub_180013FA0 (~0x95E). Refs the unique source
    // path string "CompileComboAndGetVariables_DynamicShaderCompile(),
    // C:\\buildworker\\csgo_rel_win64\\build\\src\\materialsystem2\\
    // material2.cpp:2786" (1 xref). Dynamic shader-permutation compile
    // path â€” every novel combo (e.g. your gold chams running with a
    // never-seen-before lighting/skinning combo) lands here. Hook to:
    //   - log permutation requests for warmup baking
    //   - short-circuit slow compiles by serving a pre-built combo
    //   - measure compile-stall hitches on first-frame-with-chams
    Signature {
        name: "CMaterial2_CompileComboAndGetVariables_DynamicShaderCompile",
        module: "materialsystem2.dll",
        needle: "CompileComboAndGetVariables_DynamicShaderCompile(), C:\\buildworker\\csgo_rel_win64\\build\\src\\materialsystem2\\material2.cpp:2786",
        resolve: STRREF,
        extra_off: 0,
        prototype: "char __fastcall sub_180013FA0(__int64 a1, __int64 a2)",
    },

    // Dynamic shader compile batch driver â€” materialsystem2!sub_18003A200
    // (~0x1053). Emits the compile-batch status lines
    // "Compiling %i shaders:" and "Compiled %i shaders (%i cached) in %.1fs".
    // This function fans into CMaterial2_CompileComboAndGetVariables_
    // DynamicShaderCompile for each queued permutation and is the best
    // high-level timing hook for compile stalls / warmup effectiveness.
    Signature {
        name: "CMaterialSystem2_DynamicShaderCompile_ProcessQueue",
        module: "materialsystem2.dll",
        needle: "Compiling %i shaders:",
        resolve: STRREF,
        extra_off: 0,
        prototype: "void __fastcall sub_18003A200(__int64 a1)",
    },

    // CMaterial2::GetVertexShaderInputSignature â€” materialsystem2!
    // sub_18000C8C0 (~0x2AF). Emits unique GetVertexShaderInputSignature
    // validation errors and can trigger dynamic compile queue processing
    // through sub_18003A200 when VS input signature data is missing/stale.
    // Useful for diagnosing shader-input mismatches in custom material paths.
    Signature {
        name: "CMaterial2_GetVertexShaderInputSignature",
        module: "materialsystem2.dll",
        needle: "CMaterial2::GetVertexShaderInputSignature(767): Error! Material \"%s\" doesn't have any valid layers to get the CVsInputSignatureVector from!\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18000C8C0(__int64 a1)",
    },

    // Dynamic shader compile reload orchestrator â€” materialsystem2!
    // sub_1800355C0 (~0x79). Calls
    // CMaterialSystem2_DynamicShaderCompile_UnloadAllMaterials and then
    // CMaterialSystem2_DynamicShaderCompile_ProcessQueue, followed by SRW
    // lock-protected sync over a fixed block. Compact entry for observing
    // full reload+recompile cycles.
    Signature {
        name: "CMaterialSystem2_DynamicShaderCompile_ReloadAndSync",
        module: "materialsystem2.dll",
        needle: "48 83 EC 20 48 8B 35 ? ? ? ? 48 8B CE E8 ? ? ? ? 48 8B CE E8 ? ? ? ? 80 BE A0 03 00 00 00 74 ?",
        resolve: NONE,
        extra_off: -1,
        prototype: "void sub_1800355C0()",
    },

    // CVfxProgramData::FindOrCreateStaticComboDataInCache â€”
    // materialsystem2!sub_1800AE220 (~0x726). Refs the unique log
    // "CVfxProgramData::FindOrCreateStaticComboDataInCache(4448):
    // Error! Ref count !=0 for static combo data cache entry!"
    // (1 xref). The actual shader-static-combo cache lookup that
    // CompileComboAndGetVariables funnels into. Hook here to share
    // a single compiled static combo across many runtime-injected
    // chams materials (e.g. all five enemies wearing your gold
    // material -> one cache entry, not five).
    Signature {
        name: "CVfxProgramData_FindOrCreateStaticComboDataInCache",
        module: "materialsystem2.dll",
        needle: "CVfxProgramData::FindOrCreateStaticComboDataInCache(4448): Error! Ref count !=0 for static combo data cache entry!\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1800AE0E0(__int64 a1, __int64 a2)",
    },

    // CMaterialSystem2::DynamicShaderCompile_UnloadAllMaterials â€”
    // materialsystem2!sub_180039AA0 (~0x757). Refs the unique log
    // "CMaterialSystem2::DynamicShaderCompile_UnloadAllMaterials
    // (1084): ERROR!!! Shaders not freed before shader reload!"
    // (1 xref). Driven by the `mat_reloadshaders` /
    // `mat_forcereloadshaders` ConCommands. Hook to:
    //   - re-upload your custom chams CMaterial2 after the engine
    //     wipes its compiled-shader cache
    //   - detect when a dev fires `mat_reloadshaders` so chams
    //     overrides survive iterative shader work
    Signature {
        name: "CMaterialSystem2_DynamicShaderCompile_UnloadAllMaterials",
        module: "materialsystem2.dll",
        needle: "CMaterialSystem2::DynamicShaderCompile_UnloadAllMaterials(1084): ERROR!!! Shaders not freed before shader reload! (See spew above)\n\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180039AA0(__int64 a1)",
    },

    // ====================================================================
    // NUVORA MAY-02-2026 EXPANSION v11 (build 14155 â€” GPU-pipeline / drawcall layer)
    //
    // v10 covered material PARSE / LOAD / COMPILE. v11 covers the layer
    // BELOW that â€” the per-pass GPU command-buffer recording, per-draw
    // render-state setup, scene-graph cull, and D3D11 constant-buffer
    // creation. This is the layer where a graphics engineer would hook
    // to:
    //
    //   - Intercept the actual shader / texture / cbuf bindings for a
    //     specific material at submit time (chams without owning a
    //     custom .vmat â€” just rewrite the bind table).
    //   - Re-add culled entities back to the visible set for true x-ray
    //     wallhack (vs. the post-process outline trick).
    //   - Track every D3D11 constant buffer the engine creates so a
    //     PBR-param patch (g_flMetalness/g_flRoughness/g_vReflectance)
    //     can be written directly into the matching cbuf upload.
    //   - Inject custom geometry into a real engine display-list batch
    //     instead of running a parallel ImGui pass.
    //
    // Pipeline (build 14155):
    //
    //   CSceneSystem::Thread_CullView  (scenesystem!sub_1800E92F0)
    //     -> CSceneSystem::Thread_RenderSceneDrawList (already shipped v1.11.0)
    //         -> CMaterialLayer::CreateCommandBuffer (materialsystem2!sub_180019820)
    //              -> CMaterialLayer::ComputeWorkItemsToSetupStaticCombosForMode
    //                                                 (materialsystem2!sub_180015BC0)
    //                  -> CMaterial::SetVariableAndRenderState (materialsystem2!sub_18002F9B0)
    //                       -> CRenderDeviceDx11::BeginSubmittingDisplayLists
    //                                                 (rendersystemdx11!sub_18003C4E0)
    //                            -> CRenderDeviceBase::CreateConstantBuffer
    //                                                 (rendersystemdx11!sub_18002F500)
    //                                 -> CMaterialSystem2::BindIdentityInstanceIDBufferAndSetRenderState
    //                                                 (materialsystem2!sub_180070000)
    //
    // All 7 are STRREF-anchored on log strings with EXACTLY ONE xref each
    // (verified via mcp_ida-pro-mcp_xref_query across instances 13338,
    // 13341, 13344). Strings are extremely stable across patches.
    // ====================================================================

    // CMaterialLayer::CreateCommandBuffer â€” materialsystem2!sub_180019820
    // (~0x1DD9 â€” large per-pass GPU command-buffer recorder).  Refs the
    // unique error string "CMaterialLayer::CreateCommandBuffer(4446):
    // Find a graphics programmer! Trying to bind a \"%s\" shader that
    // doesn't exist! for %s" (1 xref).  The function CS2 calls when a
    // CMaterialLayer needs to materialise its bound shader/texture/
    // constant-buffer state into a recordable D3D command sequence.
    // THE hook for "intercept the actual shader binds and rewrite
    // PBR slots before the GPU sees them" â€” perfect for swapping in
    // gold/silver chams without owning a custom .vmat.
    Signature {
        name: "CMaterialLayer_CreateCommandBuffer",
        module: "materialsystem2.dll",
        needle: "\nCMaterialLayer::CreateCommandBuffer(4446): Find a graphics programmer! Trying to bind a \"%s\" shader that doesn't exist! for %s\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180019820(__int64 a1, __int64 a2, int a3, int a4, _DWORD *a5)",
    },

    // CMaterialLayer::ComputeWorkItemsToSetupStaticCombosForMode â€”
    // materialsystem2!sub_180015BC0 (~0x632).  Refs the unique
    // "CMaterialLayer::ComputeWorkItemsToSetupStaticCombosForMode(3154):
    // Failed call to FindOrLoadStaticComboData()!" log (1 xref).
    // Schedules the work-items required to materialise every static
    // shader combo a CMaterialLayer needs for a given render mode.
    // Sits one level above CVfxProgramData::FindOrCreateStaticComboDataInCache
    // (already shipped v1.16.0). Hook to inspect / pre-warm shader
    // permutation work for runtime-injected chams materials.
    Signature {
        name: "CMaterialLayer_ComputeWorkItemsToSetupStaticCombosForMode",
        module: "materialsystem2.dll",
        needle: "CMaterialLayer::ComputeWorkItemsToSetupStaticCombosForMode(3154): Failed call to FindOrLoadStaticComboData()!\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "char __fastcall sub_180015BC0(unsigned __int16 *a1, unsigned int a2, int *a3)",
    },

    // Static combo merge/validation worker â€” materialsystem2!sub_1800BDAE0
    // (~0x1B89). Called by ComputeWorkItemsToSetupStaticCombosForMode and
    // funnels through sub_1800AE950 (cache gate wrapper) for combo fetch.
    // The unique warning below fires when shader attributes diverge across
    // shaders in one feature combo, making this a high-value observability
    // hook for custom VFX/VCS compatibility debugging.
    Signature {
        name: "CVfxProgramData_FindOrLoadStaticComboData",
        module: "materialsystem2.dll",
        needle: "Shader %s attribute \"%s\" has inconsistent value or type across multiple shaders of a feature combo! [",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1800BDAE0(__int64 a1, __int64 a2, __int64 a3, __int64 a4, char a5)",
    },

    // Static combo cache gate wrapper â€” materialsystem2!sub_1800AE950
    // (~0x1F6). Called by sub_1800BDAE0 and dispatches to
    // CVfxProgramData_FindOrCreateStaticComboDataInCache (sub_1800AE220)
    // on cache miss / invalid-state paths. This gives a compact hook to
    // observe cache hit/miss behavior without instrumenting the full merge
    // worker. Raw prologue pattern validated as unique in module.
    Signature {
        name: "CVfxProgramData_FindOrCreateStaticComboData_CacheGate",
        module: "materialsystem2.dll",
        needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 57 48 83 EC 60 80 39 00 45 8B D9",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1800AE950(__int64 a1, unsigned __int64 a2, __int64 a3, int a4, __int64 a5, int a6, char a7)",
    },

    // CMaterial::SetVariableAndRenderState â€” materialsystem2!sub_18002F9B0
    // (~0x8A4).  Refs the unique
    // "SetRenderStateValueFromVariable(1172): Unsupported render state
    // type in material \"%s\"!" log (1 xref). Decompile shows it ALSO
    // contains the unique "SetVariable(1346): Could not bind constant
    // buffer..." and "SetVariable(1363): Error setting constant for
    // REGISTER_FLOAT4..." spew strings, confirming this is the
    // dispatch hub that, for every CMaterialVariable, picks the right
    // setter:
    //   - REGISTER_FLOAT4 -> writes into per-material cbuf upload
    //   - REGISTER_TEX_*   -> shader-resource-view binding
    //   - render-state     -> blend / depth / stencil / colour-write
    // THIS is where you literally write g_flMetalness / g_flRoughness /
    // g_vReflectanceColor into the D3D constant-buffer slot for a
    // gold-chams material. Single most useful hook for live PBR
    // param injection.
    Signature {
        name: "CMaterial_SetVariableAndRenderState",
        module: "materialsystem2.dll",
        needle: "SetRenderStateValueFromVariable(1172): Unsupported render state type in material \"%s\"!\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },

    // CMaterialSystem2::BindIdentityInstanceIDBufferAndSetRenderState â€”
    // materialsystem2!sub_180070000 (~0x677).  Refs the unique
    // "BindIdentityInstanceIDBufferAndSetRenderState: GetMode == NULL?
    // Can't Render" log (1 xref).  Decompile confirms it builds an
    // identity per-instance vertex layout (`VertexUVPosColorNormalAnd
    // Tangent_t`) and dispatches through the render-context vtable
    // (qword_18014EE78, slot +320) to set up render state for a
    // single-instance draw.  Hook to inject custom geometry into a
    // real engine batch instead of running a parallel ImGui pass â€”
    // gives free depth-buffer integration for chams x-ray.
    Signature {
        name: "CMaterialSystem2_BindIdentityInstanceIDBufferAndSetRenderState",
        module: "materialsystem2.dll",
        needle: "BindIdentityInstanceIDBufferAndSetRenderState: GetMode == NULL? Can't Render\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "char __fastcall sub_180070000(__int64 *a1, __int64 a2, __int64 a3, __int64 a4)",
    },

    // CSceneSystem::Thread_CullView â€” scenesystem!sub_1800E92F0
    // (~0x7BF).  Refs the unique source-path string
    // "CSceneSystem::Thread_CullView(), C:\\buildworker\\csgo_rel_win64\\
    // build\\src\\scenesystem\\scenesystem.cpp:3312" (1 xref).  Per-
    // worker-thread frustum + occlusion cull for a single scene view
    // (one of the parallel jobs that feed Thread_RenderSceneDrawList,
    // already shipped v1.11.0).  Hook target for TRUE x-ray wallhack:
    // re-add the player scene-objects that the cull just rejected so
    // they get drawn behind the world (with depth-test override in the
    // RenderSceneDrawList layer hook). This is what an actual
    // graphics-programmer wallhack looks like â€” not a 2D ImGui line
    // overlay.
    Signature {
        name: "CSceneSystem_Thread_CullView",
        module: "scenesystem.dll",
        needle: "CSceneSystem::Thread_CullView(), C:\\buildworker\\csgo_rel_win64\\build\\src\\scenesystem\\scenesystem.cpp:3312",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },

    // CRenderDeviceBase::CreateConstantBuffer â€” rendersystemdx11!sub_18002F500
    // (~0x1D2).  Refs the unique source-line string
    // "CRenderDeviceBase::CreateConstantBuffer(1571):" (1 xref). Every
    // ID3D11Buffer (D3D11_BIND_CONSTANT_BUFFER) the renderer ever
    // creates routes through here. Hook to:
    //   - Build a runtime map [cbuf-handle -> { shader-name, slot,
    //     param-name list }] so you can locate the gold-chams cbuf
    //     by name (g_flMetalness / g_flRoughness / etc.).
    //   - Detect when a custom material is granted its cbuf so you
    //     can keep its slot pinned across hot-reloads.
    Signature {
        name: "CRenderDeviceBase_CreateConstantBuffer",
        module: "rendersystemdx11.dll",
        needle: "CRenderDeviceBase::CreateConstantBuffer(1571): ",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },

    // CRenderDeviceDx11::BeginSubmittingDisplayLists â€” rendersystemdx11!
    // sub_18003C4E0 (~0x147).  Refs the unique source-line string
    // "CRenderDeviceDx11::BeginSubmittingDisplayLists(1162):" (1 xref).
    // Per-frame display-list submission boundary (the engine batches
    // all materialised D3D commands into display lists, then submits
    // them here).  Useful to:
    //   - Time GPU submit latency on the chams pass.
    //   - Inject extra display lists for custom passes without paying
    //     the full per-draw vtable cost.
    Signature {
        name: "CRenderDeviceDx11_BeginSubmittingDisplayLists",
        module: "rendersystemdx11.dll",
        needle: "CRenderDeviceDx11::BeginSubmittingDisplayLists(1162): ",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },

    // ====================================================================
    // NUVORA APR-25-2026 EXPANSION v12 (build 14155 â€” WEAPON PAINT KIT /
    // CCompositeMaterialKit pipeline â€” "Galaxy-camo" custom-skin reversing)
    //
    // GOAL: trace the full code path that turns a `paint kit id + seed +
    // wear` triple on a `C_EconItemView` into a runtime-composited PBR
    // material that gets bound to the weapon viewmodel â€” so we can
    // INJECT a custom `.vcompmat` (or override the input shader-vars
    // directly) and ship a fully custom Galaxy-style camo on any weapon.
    //
    // CS2's weapon-skin system is a layered shader-compositing engine
    // (functionally identical to Fortnite skin-compositing, Valve just
    // calls it `CCompositeMaterialKit`). The runtime recipe:
    //
    //   .vcompmat (kit definition)        -- e.g. weapons/paints/legacy/
    //                                        missing_paintkit.vcompmat
    //     |
    //     +-- list of `CompositeMaterialAssemblyProcedure_t`
    //     |       (each = "take input vmat A, blend into output vmat B
    //     |        using mask M and shader-vars V")
    //     +-- final output material  (the one bound to the model)
    //
    //   CompositeMaterialInputContainer_t  (per-instance)
    //     +-- g_flWearAmount  (scratch / scuff intensity)
    //     +-- g_nRandomSeed   (per-pattern offset)
    //     +-- g_vColor*       (4 colour slots â€” what we override for
    //                          a Galaxy purple-blue gradient)
    //     +-- g_tNormalMap, g_tPattern, g_tMaskWear, g_flMetalness,
    //         g_flRoughness, g_vReflectanceColor (PBR slots)
    //
    // The legacy-weapons pipeline (these sigs target the LEGACY path,
    // because that is the one CS2 still uses for every weapon shipped
    // before the workshop-2.0 era â€” i.e. ALL of them currently):
    //
    //   1. game tick: viewmodel becomes visible
    //   2. sub_18011C6D0  registers `cl_paintkit_override` ConVar
    //      (already-shipped earlier â€” paintkit override hot-swap entry)
    //   3. C_EconWearable_OnNewCustomMaterials (sub_1810B67D0)
    //        --> "[Wearables] Creating new wearable (%d)" log
    //        --> calls sub_180A4CE30 with sub_180164704 callback
    //            = the per-wearable composite-material build kickoff
    //   4. C_EconEntity_BuildLegacyWeaponSkinMaterial (sub_18078C050)
    //        --> reads paintkit name from off_182013BB0[(seed + N) % 34]
    //            (the 34-entry legacy paintkit name table)
    //        --> calls sub_180789A00 to push every shader-variable into
    //            a CompositeMaterialInputContainer_t with key strings
    //            "g_flWearAmount" then "g_nRandomSeed"
    //        --> sets the .vcompmat resource path to
    //            "weapons/paints/legacy/missing_paintkit.vcompmat" as
    //            the FALLBACK if no kit was matched
    //        --> tags the request "low-res weapon" or "workshop
    //            preview weapon" depending on render scope
    //        --> dispatches via vtable+8 of the composite-material
    //            manager
    //   5. CompositeMaterialPanoramaPanel_Init (sub_180B8FB00) /
    //      CCompositeMaterialManager_AddNewPanoramaPanelRenderRequest
    //      (called from sub_1813B8DD0) â€” feed the kit through the
    //      panorama-render path so the inventory thumbnail rebuilds
    //      whenever the user previews a skin
    //   6. CMaterialLayer::CreateCommandBuffer (already shipped v1.17.0)
    //      records the actual GPU bind sequence
    //   7. CMaterial::SetVariableAndRenderState (already shipped v1.17.0)
    //      writes our g_vColor / g_flMetalness into the cbuf upload
    //
    // CUSTOM-CAMO HOOK STRATEGY (for future feature impl):
    //   A. Hook (4) C_EconEntity_BuildLegacyWeaponSkinMaterial:
    //      - replace the .vcompmat path with our own bundled kit
    //      - add extra `sub_180789A00(...)` calls injecting per-channel
    //        Galaxy colours (e.g. g_vColor1=(0.31,0.18,0.85), g_vColor2=
    //        (0.85,0.30,0.95), g_flMetalness=1.0, g_flRoughness=0.15,
    //        g_tPattern -> our custom .vtex)
    //   B. Or hook (7) CMaterial::SetVariableAndRenderState directly
    //      and rewrite the cbuf upload at draw-time (no resource files
    //      needed â€” pure in-memory swap, but per-draw cost).
    //
    // All 7 sigs below are STRREF-anchored on log / resource strings
    // each with EXACTLY ONE xref to its target function (verified via
    // mcp_ida-pro-mcp_xref_query on instance 13337 / client.dll).
    // ====================================================================

    // C_EconWearable::OnNewCustomMaterials â€” client.dll!sub_1810B67D0
    // (~0xF5).  Refs the unique error string "Invalid EconItemView --
    // Can't create custom materials for wearable, debug this." (1 xref).
    // The per-wearable composite-material build kickoff. Schedules the
    // per-frame composite-material recipe build (calls sub_180A4CE30
    // with sub_180164704 callback). Hook here to gate which weapons
    // receive a custom kit.
    Signature {
        name: "C_EconWearable_OnNewCustomMaterials",
        module: "client.dll",
        needle: "Invalid EconItemView -- Can't create custom materials for wearable, debug this.\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1810B9090(__int64 a1, char a2)",
    },

    // CPaintKitDefinitions::FindOrCreateByName â€” client.dll!sub_181057DD0
    // (~0x328).  Refs the unique error string "Kit \"[%s]\" specified,
    // but doesn't exist!! You're probably missing an entry in
    // items_paintkits.txt or items_stickerkits.txt or need to run with
    // -use_local_item_data" (1 xref). Translates a paint-kit name (or
    // m_nFallbackPaintKit id) into a `CPaintKit*` definition. Hook to
    // inject our custom kit name -> custom CPaintKit (which can in
    // turn point at a custom .vcompmat).
    Signature {
        name: "CPaintKitDefinitions_FindOrCreateByName",
        module: "client.dll",
        needle: "Kit \"[%s]\" specified, but doesn't exist!! You're probably missing an entry in items_paintkits.txt or items_stickerkits.txt or need to run with -use_local_item_data\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "char __fastcall sub_18105A690(__int64 a1, __int64 a2, char *a3, __int64 a4)",
    },

    // CPaintKitDefinitions::LoadDefaultKit â€” client.dll!sub_181029EA0
    // (~0x37D).  Refs the unique error string "Unable to find \"default\"
    // paint kit in \"paint_kits_rarity\"" (1 xref).  One-shot loader
    // run during econ-schema init that establishes the rarity-bucketed
    // default paintkit table. Hook to inject custom-rarity-bucket entries.
    Signature {
        name: "CPaintKitDefinitions_LoadDefaultKit",
        module: "client.dll",
        needle: "Unable to find \"default\" paint kit in \"paint_kits_rarity\"",
        resolve: STRREF,
        extra_off: 0,
        prototype: "char __fastcall sub_18102C760(__int64 a1, KeyValues *a2, _DWORD *a3)",
    },

    // C_EconEntity::BuildLegacyWeaponSkinMaterial â€” client.dll!sub_18078C050
    // (~0x810).  â˜… THE GOLD-MINE FUNCTION FOR CUSTOM CAMO â˜…
    // Refs the unique scope-tag string "workshop preview weapon"
    // (1 xref). Decompile reveals the full per-weapon kit-build
    // recipe: reads paintkit name from off_182013BB0[(seed+N) % 34]
    // (the 34-entry legacy-paintkit name table â€” NOTE: pattern offset
    // also appears in `*((_DWORD*)off_1820496A0 + 17)`); pushes
    // CompositeMaterialInputContainer_t entries via sub_180789A00
    // (`AddCompositeMaterialInput`) with keys "g_flWearAmount" and
    // "g_nRandomSeed"; sets the .vcompmat resource path (default
    // fallback `weapons/paints/legacy/missing_paintkit.vcompmat`);
    // tags scope "low-res weapon" (512) or "workshop preview weapon"
    // (2048); dispatches via composite-material-manager vtable +8.
    // Hook to swap the .vcompmat path for our custom Galaxy kit AND
    // inject extra g_vColor*/g_flMetalness/g_tPattern entries into the
    // input container before dispatch.
    Signature {
        name: "C_EconEntity_BuildLegacyWeaponSkinMaterial",
        module: "client.dll",
        needle: "workshop preview weapon",
        resolve: STRREF,
        extra_off: 0,
        prototype: "void __fastcall sub_18078C2A0(__int64 a1, char a2)",
    },

    // C_EconEntity::BuildModernWeaponSkinMaterial â€” client.dll!sub_180D828E0
    // (~0x13BD â€” large).  Modern (post-workshop-2.0) sibling of the
    // legacy builder above.  Anchored via raw prologue bytes because
    // it shares the `g_flWearAmount` / `missing_paintkit.vcompmat`
    // strings with sub_18078C050 (no STRREF uniqueness possible
    // without decompiling for a sub-region anchor).  Prologue:
    //   48 85 C9              test  rcx, rcx
    //   0F 84 60 13 00 00     jz    +0x1360                (early-out
    //                                                       to function
    //                                                       end â€” note
    //                                                       0x1360 is
    //                                                       fragile vs
    //                                                       future patch)
    //   48 8B C4              mov   rax, rsp
    //   48 89 50 10 / 48 8D A8 B8 FA  unique stack frame
    Signature {
        name: "C_EconEntity_BuildModernWeaponSkinMaterial",
        module: "client.dll",
        needle: "48 85 C9 0F 84 ? ? 00 00 48 8B C4 48 89 50 10 48 89 48 08 55 41 54 41 56 41 57 48 8D A8 B8 FA",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180D84F90(__int64 a1, _QWORD *a2, __int64 a3, int a4, char a5, char a6, __int64 a7)",
    },

    // CompositeMaterialPanoramaPanel_t::Init â€” client.dll!sub_180B8FB00
    // (~0x4DC).  Refs the unique RTTI/log string
    // "CompositeMaterialPanoramaPanel_t::Init" (1 xref). Initialiser
    // that wires a Panorama UI panel to a composite-material render
    // request â€” used for inventory previews, store thumbnails, weapon-
    // inspect screens. Hook to drive a Panorama-rendered preview of
    // our custom kit before the user equips it.
    Signature {
        name: "CompositeMaterialPanoramaPanel_Init",
        module: "client.dll",
        needle: "CompositeMaterialPanoramaPanel_t::Init",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180B91260(__int64 a1, __int64 a2, __int64 a3)",
    },

    // CCompositeMaterialManager::AddNewPanoramaPanelRenderRequest_Caller â€”
    // client.dll!sub_1813B8DD0 (~0x388). Refs the unique log string
    // "CCompositeMaterialManager::AddNewPanoramaPanelRenderRequest"
    // (1 xref).  The caller-side wrapper around the manager's
    // render-request enqueue. Hook to log every kit-build request
    // (great for runtime kit discovery / dumping the live paintkit
    // table during a match).
    Signature {
        name: "CCompositeMaterialManager_AddPanoramaPanelRenderRequest_Caller",
        module: "client.dll",
        needle: "CCompositeMaterialManager::AddNewPanoramaPanelRenderRequest",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1813BB640(__int64 a1, const char *a2, __int64 a3, __int64 a4)",
    },

    // ====================================================================
    // NUVORA APR-25-2026 EXPANSION v13 (build 14155 â€” composite-material
    // DEEP DIVE â€” completes the Galaxy-camo recipe started in v12 by
    // pinning the central shader-var injector, ALL three variant builders
    // (weapon / glove / nametag), the schema-callback registrars that
    // describe CCompositeMaterialKit + CompositeMaterial_t at runtime,
    // and the CS2ItemEditor template-material parser â€” i.e. every door
    // a graphics engineer needs to OWN the kit pipeline end-to-end).
    //
    // Why this round matters (success-rate vs. v12 surface):
    //
    //   * v12 anchored 7 entry points scattered around the Galaxy-camo
    //     code path.  v13 adds the choke-point: AddCompositeMaterialInput
    //     funnels EVERY shader-variable the engine ever pushes into a
    //     kit (g_flWearAmount / g_nRandomSeed / g_vColor* / g_tPattern
    //     ...).  Hook it once and you trivially observe AND mutate the
    //     full per-instance kit recipe â€” for ALL variants (weapon,
    //     glove, nametag, sticker, agent) simultaneously.
    //
    //   * v13 also exposes the SCHEMA layer: the type-manager callbacks
    //     for `InfoForResourceTypeCCompositeMaterialKit` and
    //     `InfoForResourceTypeCCompositeMaterial` enumerate every
    //     CUtlVector field the kit/material structs contain at runtime,
    //     so a runtime kit-dump tool can crawl the entire object tree
    //     without hard-coded offsets â€” survives every CS2 patch.
    //
    //   * The template-material parser (CS2ItemEditor) is the OFFICIAL
    //     KV-driven param exposer Valve themselves use to describe what
    //     a shader exposes to the kit system (g_v* / g_fl* / g_b* /
    //     Texture).  Knowing its layout = knowing exactly how to author
    //     a custom .vcompmat that the engine will accept.
    //
    // Schema sizes confirmed via the type-manager registrars:
    //
    //   CompositeMaterialMatchFilter_t        =  32 B
    //   CompositeMaterialAssemblyProcedure_t  =  96 B   (160 B incl. wrap)
    //   CompositeMaterial_t                   = 160 B
    //   CompositeMaterialInputContainer_t     = 312 B   (reflected POD)
    //                                         = 648 B   (full runtime
    //                                                    container, the
    //                                                    delta = scratch
    //                                                    + render state)
    //   CompMatPropertyMutator_t              = 912 B   (per-property
    //                                                    runtime mutator)
    //   CResourceNameTyped<CWeakHandle<...>>  = 224 B   (resource handle
    //                                                    wrapper)
    //
    // Glove-asymmetry note:  the glove builder pushes BOTH
    // `g_nRandomSeed` and `g_nRandomSeedAlt` (alt = seed+1) so left- and
    // right-hand glove patterns are deterministically offset â€” a detail
    // a custom glove kit MUST reproduce or both gloves will look
    // identical.
    //
    // Variant scope tags (the string set in `a1[28]`):
    //   "low-res weapon"          â€” viewmodel / world-model PBR
    //   "low-res gloves"          â€” viewmodel gloves
    //   "low-res nametag"         â€” engraved nametag overlay (512x32)
    //   "workshop preview weapon" â€” full-quality preview (loadout)
    //
    // ====================================================================

    // CUtlVector<CompositeMaterialInput_t>::AddToTail â€” client.dll!
    // sub_180789A00 (~0x158).  Has NO unique string of its own (it is a
    // small templated container helper) so anchored by its 28-byte
    // function prologue. 11 code xrefs from the kit-build path
    // (BuildLegacyWeaponSkinMaterial x2, BuildModernWeaponSkinMaterial
    // x5, BuildLegacyGloveSkinMaterial x3, BuildNametagOverlayMaterial
    // x1).  Element size in the push = 648 bytes (full runtime
    // CompositeMaterialInputContainer_t).
    //
    // SINGLE MOST IMPACTFUL HOOK in the entire pipeline: every shader-
    // variable the engine ever injects (g_flWearAmount, g_nRandomSeed,
    // g_nRandomSeedAlt, g_vColor*, g_tPattern, g_tNormalMap, ...) for
    // EVERY variant flows through here.
    //   - LOG mode:  dump (kit_path, key, value_type, value) on every
    //                call to enumerate the live paintkit recipe at
    //                runtime â€” fully patch-proof kit dumper.
    //   - INTERCEPT: rewrite g_vColor1..4 in-place to ship a Galaxy
    //                purple-blue gradient on top of any base kit
    //                without ever touching disk.
    Signature {
        name: "CUtlVector_CompositeMaterialInput_AddToTail",
        module: "client.dll",
        // Generic AddToTail<T> prologue collides with 20+ other CUtlVector
        // template instantiations.  Anchor instead by the mid-body
        // sequence that hard-codes the element size 0x288 (=648 B = full
        // CompositeMaterialInputContainer_t) followed by the UtlMemory
        // 0x3FFFFFFF mask â€” unique to this single instantiation. We then
        // back up by -0x52 to land on the function start.
        needle: "41 B9 88 02 00 00 8B 57 14 81 E2 FF FF FF 3F 8D 71 01 44 8B C6 FF 15",
        resolve: NONE,
        extra_off: -0x52,
        prototype: "__int64 __fastcall sub_180789C50(int *a1, __int64 a2)",
    },

    // C_EconEntity::BuildLegacyGloveSkinMaterial â€” client.dll!sub_180BBFB00
    // (~0x9E7).  Refs the unique string "MapPlayerPreview gloves"
    // (1 xref).  The glove-specific sibling of BuildLegacyWeaponSkinMaterial
    // (already shipped v12).  Reads the prefix "gloves/paints/" from the
    // econ item, builds a CompositeMaterialKit request scoped
    // "low-res gloves" (512x512), then pushes via AddCompositeMaterialInput:
    //   - g_flWearAmount
    //   - g_nRandomSeed     (= econ seed)
    //   - g_nRandomSeedAlt  (= econ seed + 1, drives left/right asymmetry)
    // The "econ_instance" KV is then handed to sub_18071A140 which feeds
    // the C_WorldModelGloves entity.  Hook this to ship a custom glove
    // kit (CCompositeMaterialKit override) onto the player's hands with
    // independent left/right pattern offsets.
    Signature {
        name: "C_EconEntity_BuildLegacyGloveSkinMaterial",
        module: "client.dll",
        needle: "MapPlayerPreview gloves",
        resolve: STRREF,
        extra_off: 0,
        prototype: "void __fastcall sub_180BC1460(int *a1)",
    },

    // C_EconEntity::BuildNametagOverlayMaterial â€” client.dll!sub_18078AE20
    // (~0x969).  Refs the unique scope tag "low-res nametag" (1 xref).
    // Builds a 512x32 composite material from the .vcompmat
    // "weapons/models/shared/nametag/nametag_default.vcompmat" with the
    // user-supplied nametag string pushed as the "label" input â€” the
    // engraved-text overlay you see on stickered weapons.  Hook to ship
    // a custom nametag font / pattern, or to inject a multi-line
    // animated overlay (the underlying material supports any param the
    // shader exposes; nametag_default.vcompmat just happens to expose a
    // single string slot today).
    Signature {
        name: "C_EconEntity_BuildNametagOverlayMaterial",
        module: "client.dll",
        needle: "low-res nametag",
        resolve: STRREF,
        extra_off: 0,
        prototype: "char __fastcall sub_18078B070(__int64 a1, __int64 a2)",
    },

    // InfoForResourceTypeCCompositeMaterialKit::TypeManagerCallback â€”
    // client.dll!sub_1813D6840 (~0x370). Refs the unique RTTI string
    // "InfoForResourceTypeCCompositeMaterialKit" (1 xref).  Vftable-style
    // dispatch (cases 0/2/3/4/5/6 = Init/Construct/Destruct/Reset/
    // Cleanup/RTTI) registered with the resource system as the
    // CCompositeMaterialKit type manager.  The case-0 branch declares
    // every CUtlVector field of the kit struct via the schema reflector,
    // revealing exact runtime layout:
    //
    //   +08  CUtlVector<CResourceNameTyped<CWeakHandle<CompositeMaterialKit>>>
    //                                                        elem 224 B
    //   +xx  CUtlVector<CompositeMaterialMatchFilter_t>      elem  32 B
    //   +xx  CUtlVector<CompositeMaterialInputContainer_t>   elem 312 B
    //   +xx  CUtlVector<CompMatPropertyMutator_t>            elem 912 B
    //
    // Hook for runtime kit-tree introspection that survives patches.
    Signature {
        name: "InfoForResourceTypeCCompositeMaterialKit_TypeManager",
        module: "client.dll",
        needle: "InfoForResourceTypeCCompositeMaterialKit",
        resolve: STRREF,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1813D90B0(int a1, __int64 a2)",
    },

    // InfoForResourceTypeCCompositeMaterial::TypeManagerCallback â€”
    // client.dll!sub_1813D6D90 (~0x2F0).  No unique 1-xref string of
    // its own (uses "InfoForResourceTypeCModel" + "CompositeMaterial_t"
    // + "CompositeMaterialAssemblyProcedure_t" â€” none singletons), so
    // anchored by 20-byte function prologue.  Sibling of the kit
    // type-manager: declares the FINAL CompositeMaterial_t struct
    // schema:
    //
    //   +08  CResourceNameTyped<CWeakHandle<CModel>>         224 B
    //   +xx  CResourceNameTyped<CWeakHandle<CModel>>         224 B
    //   +xx  CUtlVector<CompositeMaterialAssemblyProcedure_t> elem  96 B
    //   +xx  CUtlVector<CompositeMaterial_t>                  elem 160 B
    //
    // Hook to enumerate the assembly-procedure list of every materialised
    // composite (= the "recipe" Valve actually ran to bake the final
    // PBR material the GPU will sample).
    Signature {
        name: "InfoForResourceTypeCCompositeMaterial_TypeManager",
        module: "client.dll",
        needle: "40 55 41 56 48 83 EC 68 48 8B EA 83 F9 06 0F 87 B4 02 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1813D9600(int a1, __int64 a2)",
    },

    // CS2ItemEditor::BuildTemplateMaterialFromFile â€” client.dll!sub_1813BA1E0
    // (~0x1445).  No 1-xref string anchor (uses generic logging strings
    // and the literal "CS2ItemEditor" 4x as a KV-dict key), so anchored
    // by 32-byte function prologue.  This is the OFFICIAL .vmt template
    // -material parser Valve ships in client.dll: it loads a KV file
    // via IFileSystem ("CONTENT" search path), iterates the `Attributes`
    // block, and for each `exposed_param_*` key classifies the var by
    // name prefix:
    //
    //   "g_b*"        -> bool      (type 0)
    //   "g_fl*" "g_f*" -> float    (type 5)
    //   "g_v*"        -> vec3      (type 6)
    //   "g_vColor*"   -> color/vec4 (type 9)
    //   "Texture*"    -> resource  (type 13)
    //
    // and emits a KV3 `template_material` block tagged "CS2ItemEditor"
    // with each var's (path, name, friendlyname, group, alert_when_true,
    // alert_helpid, type, typename, value, range_min, range_max).
    //
    // = the GROUND TRUTH for "what can a custom .vcompmat expose?".  To
    // ship a Galaxy gradient we author a template_material that exposes
    // 4 g_vColor slots + a Texture for the noise pattern, then drive
    // them via CompositeMaterialInputContainer_t at runtime.
    Signature {
        name: "CS2ItemEditor_BuildTemplateMaterialFromFile",
        module: "client.dll",
        needle: "48 89 54 24 10 55 53 41 55 41 57 48 8D AC 24 18 F9 FF FF 48 81 EC E8 07 00 00 4C 8B FA 48 85 D2",
        resolve: NONE,
        extra_off: 0,
        prototype: "CKeyValues_Data *__fastcall sub_1813BCA50(__int64 a1, const char *a2)",
    },

    // ====================================================================
    // NUVORA APR-25-2026 EXPANSION v20 (build 14155 â€” GLOBAL material /
    // shader injection path: not weapon-only)
    //
    // v12/v13 locked the econ/composite side. This block pins the broader
    // renderer/material path used by anything that has a material state:
    // world geometry, player models, skybox layers, props, particles.
    //
    // Practical model:
    //   - Valve VMAT/VFX path (materialsystem2/scenesystem): stable and
    //     semantically rich (material vars + render states + pass context)
    //   - Direct D3D path (rendersystemdx11): strongest for arbitrary HLSL
    //     replacement and custom bytecode injection.
    //
    // With these anchors we can bridge both worlds and target "anything
    // with a material" instead of only econ paintkit entities.
    // ====================================================================

    // CMaterialLayer::ApplyMaterialVarsForBatch â€” materialsystem2!
    // sub_180018B80 (~0x24C).  Raw prologue anchor.  Mid-level per-batch
    // dispatcher that iterates draw surfaces/material entries and calls
    // CMaterial::SetVariableAndRenderState (sub_18002F9B0) for each
    // relevant var binding.  This is where material vars stop being
    // "definition data" and start becoming per-draw GPU state.
    Signature {
        name: "CMaterialLayer_ApplyMaterialVarsForBatch",
        module: "materialsystem2.dll",
        needle: "4C 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 53 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 78",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CMaterialLayer::BuildPassCommandData â€” materialsystem2!sub_180018F80
    // (~0x89C).  Raw prologue anchor.  Higher-level pass builder that
    // allocates/records per-surface command data and repeatedly invokes
    // CMaterialLayer::CreateCommandBuffer (sub_180019820).  Good global
    // interception point for "all materialized surfaces this frame",
    // regardless of whether they are player, world, prop, or FX.
    Signature {
        name: "CMaterialLayer_BuildPassCommandData",
        module: "materialsystem2.dll",
        needle: "89 54 24 10 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 58 FE FF FF 48 81 EC A8 02 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "int __fastcall sub_180018F80(__int64 a1, int a2, __int64 a3)",
    },

    // CSceneSkyBoxObject::DrawSkyboxArray â€” scenesystem!sub_18014FB90
    // (~0x6F9).  Raw prologue (already production-proven in project hook).
    // Render-time sky pass used by map sky/cubemap flow. Hook here for
    // global sky material/tint changes without touching entity netvars.
    Signature {
        name: "CSceneSkyBoxObject_DrawSkyboxArray",
        module: "scenesystem.dll",
        needle: "45 85 C9 0F 8E ? ? ? ? 4C 8B DC 55 41 56 49 8D AB 58 FC FF FF 48 81 EC 98 04 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // CRenderDeviceDx11::CompileShaderSourceMain â€” rendersystemdx11!
    // sub_18003FAF0 (~0x171). Refs the unique compile-failure string
    // "Shader compilation failed! Reported no errors." (1 xref).
    // This wrapper calls D3DCompile(source, size, ..., "main", profile,
    // 0x1200, ...) and returns a shader blob object.
    //
    // Critical implication: in-process custom HLSL compilation is real
    // and not limited to Valve's precompiled blobs. Combined with draw/
    // material interception, this is the practical anchor for custom
    // pixel-shader injection on any materialized surface.
    Signature {
        name: "CRenderDeviceDx11_CompileShaderSourceMain",
        module: "rendersystemdx11.dll",
        needle: "Shader compilation failed! Reported no errors.\n",
        resolve: STRREF,
        extra_off: 0,
        prototype: "",
    },

    // ---------- INTERNAL FINDINGS (build 14158) -----------------------
    // Signatures sourced from the live internal cheat (`core/signatures.h`)
    // and re-validated against cs2.exe pid 1556. See git log for the
    // verification cmds.
    Signature {
        name: "ThirdPersonOnHandler",
        module: "client.dll",
        needle: "48 83 EC 38 48 8B 0D ? ? ? ? 48 8D 54 24 ? 48 8B 01 FF 90 08 03 00 00 83 7C 24 ? 00 0F 85 ? ? ? ? 4C 8B 05 ? ? ? ? 41 8B 80 50 0B 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_180ACA390()",
    },
    Signature {
        name: "ThirdPersonOffHandler",
        module: "client.dll",
        needle: "48 83 EC 28 48 8B 0D ? ? ? ? 48 8D 54 24 ? 48 8B 01 FF 90 08 03 00 00 83 7C 24 ? 00 75 ? 48 8B 05 ? ? ? ? C6 80 29 02 00 00 00 C7 80 A8 06 00 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_180ACA2B0()",
    },

    // ---------- world / scene visuals ---------------------------------
    // CGlobalLightBase::UpdateState â€” sun-light per-frame copy. Hooked
    // by the visuals module to dim the sun for the night-mode toggle.
    Signature {
        name: "GlobalLightUpdateState",
        module: "client.dll",
        needle: "40 57 48 81 EC C0 00 00 00 48 8B F9 BA FF FF FF FF 48 8D 0D ? ? ? ? E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "_BYTE *__fastcall sub_180A8B5A0(__int64 a1)",
    },
    // CSceneSystem::DrawAggregateSceneObjectArray â€” distinct from the
    // existing `DrawAggregateSceneObject` (singular) sig in this file;
    // this is the per-frame batched array dispatcher. Forcing the fade
    // alpha at a3[1]+8 to 1.0f keeps far aggregates fully opaque.
    Signature {
        name: "DrawAggregateSceneObjectArray",
        module: "scenesystem.dll",
        needle: "48 8B C4 48 89 50 ? 48 89 48 ? 55 53 56 57 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 70",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    // BuildSceneInfoGpu â€” sub_180084FF0, fires ONCE per map load. Writes
    // sky_color / sky_bounce / sun_light_min_brightness into the GPU
    // scene-info struct. Authoritative atmosphere-modulation entry.
    Signature {
        name: "BuildSceneInfoGpu",
        module: "scenesystem.dll",
        needle: "4C 89 4C 24 20 4C 89 44 24 18 48 89 4C 24 08 55 48 8D AC 24 00 E3 FF FF B8 00 1E 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    // PVS / visibility-singleton accessor â€” lea rcx,[g_visMgr]; xor edx,
    // edx; call [rax+30h]. Calling vtable[6] with edx=1 (instead of 0)
    // marks every leaf visible â€” chams render through any wall.
    Signature {
        name: "DisablePvsAccessor",
        module: "engine2.dll",
        needle: "48 8D 0D ? ? ? ? 33 D2 FF 50",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18023D2A0(_DWORD *a1, __int64 a2, int a3, char a4)",
    },
    // CSceneAnimatableObject::GeneratePrimitives â€” primary chams hook.
    // Per-renderable mesh-submit virtual; gives access to the actual
    // scene-object so we can swap material per-entity (friend/enemy
    // colour separation). Already aliased as the chams target in
    // features/visuals/chams.h.
    Signature {
        name: "CSceneAnimatableObject_GeneratePrimitives",
        module: "scenesystem.dll",
        needle: "48 8B C4 48 89 58 08 48 89 50 10 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ? ? ? ?",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ---------- EngineTrace bullet-trace pipeline (client.dll) --------
    // Six functions Valve uses to do a bullet trace from start->end,
    // collect surface hits and run penetration. Used by vischeck (no
    // fake-tick gate), autowall, edge-jump trace, seeded-triggerbot
    // ground-truth validation. RVAs (build 14158) recorded for drift
    // tracking: 0x800580 / 0x15FC2A0 / 0x32BBF0 / 0x804900 / 0x806F50 /
    // 0x8211F0.
    Signature {
        name: "TraceInitData",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8D 79 ? 33 F6 C7 47",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180800580(__int64 a1)",
    },
    Signature {
        name: "TraceInitInfo",
        module: "client.dll",
        needle: "40 55 41 55 41 57 48 83 EC 30",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1815FC2A0(__int64 a1)",
    },
    Signature {
        name: "TraceInitFilter",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 0F B6 41 ? 33 FF 24",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18032BBF0(__int64 a1, _DWORD *a2, __int64 a3, char a4, char a5)",
    },
    Signature {
        name: "TraceCreate",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 50 F2 0F 10 02",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_180804900(__int64 a1, __int64 a2, int a3, __int64 a4, int a5, char a6)",
    },
    Signature {
        name: "TraceGetInfo",
        module: "client.dll",
        needle: "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 60 48 8B E9 0F 29 74 24",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180806F50(__int64 a1, __int64 a2, float a3, unsigned __int64 *a4)",
    },
    // 14158 prologue â€” the older 9-byte UC stub matched zero sites; the
    // full prologue includes the arg-spill (mov [rsp+20],r9d ; mov
    // [rsp+10],rdx ; mov [rsp+8],rcx) before push rbp/push rdi/push r15.
    Signature {
        name: "TraceHandleBulletPen",
        module: "client.dll",
        needle: "48 8B C4 44 89 48 20 48 89 50 10 48 89 48 08 55 57 41 57",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_1808211F0(__int64 a1, float *a2, __int64 a3, int a4, __int64 a5)",
    },

    // ---------- kill / damage feedback + sound dispatch ---------------
    // KillFeedbackEmitter â€” emits Player.Death*.AttackerFeedback events.
    // The iconic CS2 "headshot ding" call site (and body-kill thud).
    // Most reliable kill-detection point in the game â€” fires from the
    // engine's damage flow, not aimbot lock state. Hooked by
    // features/misc/kill_sound.h to suppress the Valve ack and play our
    // own custom sound on confirmed kills.
    Signature {
        name: "KillFeedbackEmitter",
        module: "client.dll",
        needle: "48 89 5C 24 08 48 89 74 24 18 48 89 7C 24 20 55 41 56 41 57 48 8B EC 48 81 EC 80 00 00 00 44 8B",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18084B0F0(__int64 a1, __int64 a2)",
    },
    // DamageFeedbackEmitter â€” sub_18081ED00, per-HIT damage feedback.
    // Fires on every successful damaging hit â€” produces the high-pitch
    // headshot chirp on non-fatal HS too. Suppressed independently of
    // KillFeedbackEmitter.
    Signature {
        name: "DamageFeedbackEmitter",
        module: "client.dll",
        needle: "48 89 4C 24 08 55 53 41 54 41 55 41 57 48 8D AC 24 E0 FE FF FF 48 81 EC 20 02 00 00 48 83 79 38",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_18081FB40(__int64 a1, _QWORD *a2, __int64 a3)",
    },
    // GetHitGroup â€” sub_180A163A0 helper called from
    // DamageFeedbackEmitter. Returns 1 for HEAD; lets the cheat
    // selectively skip the HS dink without disturbing body hit-marker
    // sounds.
    Signature {
        name: "GetHitGroup",
        module: "client.dll",
        needle: "40 53 48 83 EC 20 48 83 79 10 00 48 8B D9 74 16 E8 ?? ?? ?? ?? 84 C0 75 0D 48 8B 43 10 8B 40 38",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180A17C40(__int64 a1)",
    },
    // EmitSoundByHandle â€” sub_180B62270, universal sound emit dispatcher
    // used by EVERY in-game sound path (damage, death, killfeed, weapon
    // fire, footsteps, voice, music). a4[0] is the event-name C-string
    // ptr â€” name-filter to drop just the HS chirp variants regardless
    // of which subsystem emitted them.
    Signature {
        name: "EmitSoundByHandle",
        module: "client.dll",
        needle: "40 53 48 83 EC 30 4C 89 4C 24 20 48 8B D9 45 8B C8 4C 8B C2 48 8B D1 48 8D 0D ?? ?? ?? ?? E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180B63B10(__int64 a1, int a2, int a3, __int64 a4)",
    },
    // CSosOperatorSystem::StartSoundEvent â€” soundsystem!sub_1801B7AD0.
    // The single convergence point for every named, by-handle, AND
    // by-hash sound-event start in CS2. Vtable slots 11 / 12 / 13 all
    // tail-call here. Hooking this catches the HS dink that takes the
    // by-handle path (which never enters the by-name overload).
    Signature {
        name: "CSosOperatorSystem_StartSoundEvent",
        module: "soundsystem.dll",
        needle: "40 53 55 56 48 83 EC 20 83 B9 ?? ?? ?? ?? 00 49 8B D8 48 8B F2 48 8B E9 74 ?? C7 02 00 00 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },

    // ---------- skin / paint application ------------------------------
    // Modern paint-apply path: sub_1807A8A00 â†’ sub_181079790 â†’
    // sub_18105AAF0 (consumes m_nFallbackPaintKit/Seed/Wear, queues
    // "clientside_reload_custom_econ" delayed think). RegenerateWeaponSkin
    // alone DOES NOT trigger this â€” it only handles the legacy static
    // paint table.
    Signature {
        name: "ApplyEconCustomization",
        module: "client.dll",
        needle: "48 89 5C 24 ? 57 48 83 EC ? 8B FA 48 8B D9 E8 ? ? ? ? 48 8B CB E8 ? ? ? ? 48 85 C0 74",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1807A8A90(__int64 a1, char a2)",
    },
    // CAnimGraphController force-rebuild â€” sub_1808AD5F0 (build 14155;
    // 14158: 0x8AEC70). Called with mode=2 to tear down and re-create
    // the CNmGraphInstance after a knife model swap so animations bind
    // to the NEW subclass's animgraph (fixes inspect playing default
    // anim on swapped knives).
    Signature {
        name: "AnimGraphRebuild",
        module: "client.dll",
        needle: "40 55 56 48 83 EC 28 4C 89 74 24 58 48 8B F1 80 FA FF 75 04 0F B6 51 18",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1808AEC70(__int64 a1, char a2)",
    },

    // ---------- triggerbot internals ----------------------------------
    // Spread-seed generator + per-shot spread compute. The triggerbot
    // re-runs both client-side with the predicted next-fire seed to
    // know exactly where the bullet would land before pulling the
    // trigger. NoSpread1 / CalcSpread already exist above as the hook
    // entrypoints; these are the inner math functions.
    Signature {
        name: "SpreadSeedGen",
        module: "client.dll",
        needle: "48 89 5C 24 08 57 48 81 EC F0 00 00 00 F3 0F 10 0A 48 8D 8C 24 10 01 00 00 41 8B D8 48 8B FA E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180C7E2D0(__int64 a1, __int64 a2, int a3)",
    },

    // ---------- particle manager (particles.dll) ----------------------
    // GetParticleManager â€” 1-line accessor:
    //     mov rax, [rip+rel32_to_g_pParticleMgr]
    //     ret
    // RipRel resolution with rel_off=3 walks the disp32 to the
    // singleton ptr-to-ptr slot. Trailing `48 83 EC 28 8B 0D` anchors
    // the next function's prologue (build 14158 â€” was `48 89 5C 24 ?
    // 57 B8` on earlier builds; compiler reshuffled the neighbour
    // function), making the pattern unique inside particles.dll.
    Signature {
        name: "GetParticleManager",
        module: "particles.dll",
        needle: "48 8B 05 ? ? ? ? C3 ? ? ? ? ? ? ? ? 48 83 EC 28 8B 0D",
        resolve: RIPREL_3,
        extra_off: 0,
        prototype: "",
    },

    // ---------- cspatterns.dev cross-reference (build 14158) ----------
    // Patterns sourced from the public cspatterns.dev/cpp catalogue,
    // each independently re-validated in IDA Pro against the live
    // build (single-match in their owning module). Names mirror the
    // upstream catalogue so consumers familiar with that source see
    // identical symbols. Resolution kind is `NONE` (pattern starts at
    // the function prologue) unless noted.

    // CBaseEntity::ChangeModel â€” single dispatch used by the model
    // pipeline; we hook it in the skin/knife model swap path.
    Signature {
        name: "CBaseEntity_ChangeModel",
        module: "client.dll",
        needle: "40 53 48 83 EC ? 48 8B D9 4C 8B C2 48 8B 0D ? ? ? ? 48 8D 54 24",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1808DB1C0(__int64 a1, __int64 a2)",
    },
    // gpGlobals copy-out: mov rcx,[g_pCVar?] / lea r8,[g_global_vars].
    // Useful for resolving the global timing struct without walking
    // the engine interface table.
    Signature {
        name: "UpdateGlobalVars",
        module: "client.dll",
        needle: "48 8B 0D ? ? ? ? 4C 8D 05 ? ? ? ? 48 85 D2",
        resolve: NONE,
        extra_off: 0,
        prototype: "void *__fastcall sub_180AE4730(__int64 a1, void *a2)",
    },
    // CCSPlayer_WeaponServices::ComputeRandomSeed â€” direct cousin of
    // SpreadSeedGen; consumed by the seeded-triggerbot path for
    // server-RNG synchronisation experiments.
    Signature {
        name: "ComputeRandomSeed",
        module: "client.dll",
        needle: "48 89 5C 24 ? 57 48 81 EC ? ? ? ? ? ? ? ? 48 8D 8C 24",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180C7E2D0(__int64 a1, __int64 a2, int a3)",
    },
    // UI::ShowMessageBox â€” popup dispatcher; stubbing it out silences
    // VAC nag dialogs and other modal interruptions during testing.
    Signature {
        name: "ShowMessageBox",
        module: "client.dll",
        needle: "44 88 4C 24 ? 53 41 56",
        resolve: NONE,
        extra_off: 0,
        prototype: "",
    },
    // CCSPlayerController::SetPlayerReady â€” match-ready toggle. Cheap
    // hook target for queue-state automation.
    Signature {
        name: "SetPlayerReady",
        module: "client.dll",
        needle: "40 53 48 83 EC ? 48 8B DA 48 8D 15 ? ? ? ? 48 8B CB FF 15",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_180F1DD90(__int64 a1, __int64 a2)",
    },
    // Popup-event dispatcher (achievements, MM popups, etc.). Useful
    // for menu-driven UI suppression. (Currently dormant on this build
    // â€” IDA db lags live image; re-validate before relying on it.)
    // Signature {
    //     name: "PopupEventHandle",
    //     module: "client.dll",
    //     needle: "40 56 57 41 57 48 83 EC ? 48 8B 3D ? ? ? ? 4D 85 C0",
    //     resolve: NONE,
    //     extra_off: 0,
    // },
    // CEngineClient::IsInGame â€” predicates a global state byte; we
    // gate per-frame hooks on it to avoid menu-time work.
    Signature {
        name: "IsInGame",
        module: "engine2.dll",
        needle: "48 8B 05 ? ? ? ? 48 85 C0 74 ? 80 B8 ? ? ? ? 00 75 ? 83 B8 ? ? ? ? ? 7C",
        resolve: NONE,
        extra_off: 0,
        prototype: "bool sub_180076450()",
    },
    // CCSGOPlayerAnimGraphController::DrawLegs â€” first-person leg
    // renderer; togglable to remove the FP leg geometry.
    Signature {
        name: "DrawLegs",
        module: "client.dll",
        needle: "40 55 53 56 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? F2 0F 10 42",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_1810F0410(__int64 *a1, __int64 *a2, __int64 a3, __int64 a4, __int64 a5)",
    },
    // CUserCmd::ValidateInput â€” server-side-style sanity check on the
    // local user-cmd. Currently dormant on this build (IDA db lags live
    // image; re-validate before relying on it).
    // Signature {
    //     name: "ValidateInput",
    //     module: "client.dll",
    //     needle: "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 33 C0 C6 83 ? ? ? ? 00",
    //     resolve: NONE,
    //     extra_off: 0,
    // },
    // HUD::DrawCrosshair â€” already covered above (line ~260). Skipped
    // here to avoid duplicate scanning.
    // PostProcessing per-frame update â€” useful entry point for
    // disabling fades, color-correction lookups, etc.
    Signature {
        name: "UpdatePostProcessing",
        module: "client.dll",
        needle: "48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 57 48 83 EC ? ? ? 00 48 8B DA 48 8B F9 0F 84 ? ? ? ? 48 8D 15",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180F21F20(__int64 a1, _BYTE *a2)",
    },
    // Skybox per-frame update (counterpart to scenesystem's draw).
    Signature {
        name: "UpdateSkybox",
        module: "client.dll",
        needle: "48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 E8 ? ? ? ? 48 8B 47",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_18025A850(__int64 a1)",
    },
    // CGameEntitySystem::GetEntityByIndex â€” short, distinctive
    // 6-byte head; the canonical entity-list lookup helper.
    Signature {
        name: "GetEntityByIndex",
        module: "client.dll",
        needle: "4C 8D 49 ? 81 FA",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180967600(__int64 a1, int a2)",
    },
    // Local-pawn accessor; mirrors the existing GetLocalControllerById
    // entry but returns the player-pawn pointer instead.
    Signature {
        name: "GetLocalPawn",
        module: "client.dll",
        needle: "48 83 EC ? 83 F9 ? 75 ? 48 8B 0D ? ? ? ? 48 8D 54 24 ? ? ? ? FF 90 ? ? ? ? ? ? 48 63 C1 4C 8D 05",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1808E1070(int a1)",
    },

    // ==================================================================
    // NUVORA MAY-05-2026 EXPANSION (build 14158, port-13338 IDA pass)
    // ------------------------------------------------------------------
    // Two more cheat-relevant unique anchors mined live:
    //   * CCSPlayer_MovementServices::CheckJumpButton   (bhop / autostrafe)
    //   * CSGOInput::CreateMove                         (per-tick aim/move hook)
    // Both verified single-match on client.dll 14158 via IDA-MCP
    // find_bytes against the live IDB.
    // ==================================================================

    // CCSPlayer_MovementServices::CheckJumpButton â€” sub_180ACF410.
    // Stamina + jump-impulse logic; refs the
    // "stamina: %.1f, jump impulse mul: %.3f" log string. This is THE
    // function to hook for perfect bunnyhop (force-jump on landing
    // tick) and autostrafe (overwrite m_vecVelocity right after the
    // stamina-penalty multiplier is applied). Replaces the older
    // create-move-side jump emulation with the exact same write the
    // engine does internally â€” no more "first jump miss" desync.
    Signature {
        name: "CCSPlayer_MovementServices_CheckJumpButton",
        module: "client.dll",
        needle: "4C 89 44 24 18 55 56 41 56 48 8D AC 24 70 EC FF FF B8 90 14 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180ACF410(__int64 a1, __int64 a2, __int64 a3)",
    },

    // CSGOInput::CreateMove â€” sub_180C5E7F0. The actual createmove the
    // existing `create_move_v2` short-form sig was missing. Refs
    // "cl: CreateMove - Frame %d, cmd %d, cmd client tick %d, ..."
    // log string. Wraps the per-subtick CUserCmd assembly (mouse
    // delta â†’ view angles â†’ shoot angles â†’ buttons). Hook this
    // instead of patching individual subtick writers when you want
    // a single chokepoint for aim/anti-aim/triggerbot.

    // ==================================================================
    // NUVORA MAY-05-2026 EXPANSION v2 (build 14158, ports 13338+13339)
    // ------------------------------------------------------------------
    // 4 client.dll + 2 engine2.dll anchors, all single-match verified.
    // Mined from VProf scope strings, assert-fatal logs, and FCVAR_CHEAT
    // gating logic. Every entry below is a primary chokepoint for a
    // distinct cheat capability and is NOT in any public dumper.
    // ==================================================================

    // C_CSWeaponBase::GetEconWpnData â€” sub_180795180. Returns the
    // CCSWeaponBaseVData* for a weapon by walking
    // weapon->m_AttributeManager->m_Item->ItemDefinition. Refs the
    // unique "C_CSWeaponBase::GetEconWpnData" assert-fatal string from
    // weapon_csbase.cpp:3135. Hook to override damage / range /
    // accuracy parameters per-shot without touching the live VData
    // pointer (return a thread-local override struct instead).
    Signature {
        name: "C_CSWeaponBase_GetEconWpnData",
        module: "client.dll",
        needle: "40 53 48 83 EC 40 48 8B D9 E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 85 C0 75 ? 48 8B 43 10",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180795180(__int64 a1)",
    },

    // C_BaseEntity::ProcessInterpolatedList â€” sub_180A6BDD0. Refs
    // unique VProf scope name "OnLatchInterpolatedVariablesHelper".
    // Walks every interpolated-var on the entity each tick and calls
    // its NoteChanged vfunc; the chokepoint where ALL interpolation
    // (origin, angles, view-offset, etc) is committed per-frame.
    // Hook for visual-only desync / fake interpolation / extrapolated
    // ESP without writing m_flSimulationTime directly.
    Signature {
        name: "C_BaseEntity_ProcessInterpolatedList",
        module: "client.dll",
        needle: "4C 8B DC 49 89 5B 10 49 89 6B 18 49 89 73 20 57 41 54 41 57 48 83 EC 60 49 C7 43 B0 E1 07 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180A6BDD0(__int64 a1, unsigned int a2, int a3, unsigned int a4)",
    },

    // C_BaseEntity::CheckPredictionForceReLatch â€” sub_180B47910. Refs
    // unique log "prediction forced re-latch of %s due to prediction
    // error for field marked FTYPEDESC_INTERPOLATEDVAR". Runs after
    // a prediction-error rollback to force-relatch interpolated state.
    // Hook to suppress engine-side prediction corrections (no rollback
    // jitter on local pawn for visual smoothness during high-ping play).
    Signature {
        name: "C_BaseEntity_CheckPredictionForceReLatch",
        module: "client.dll",
        needle: "48 8B C4 48 89 50 10 53 55 56 48 81 EC 00 01 00 00 0F 29 78 98 48 8B F2 8B 91 04 01 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180B47910(__int64 a1, __int64 a2)",
    },

    // CServerSideClient::ExecuteStringCommand â€” engine2!sub_1800BE120.
    // Server-side path that filters incoming client console commands
    // against FCVAR_CHEAT / FCVAR_CLIENT_CAN_EXECUTE. Refs unique log
    // "SV: Cheat command '%s' ignored. Set sv_cheats to 1 enable
    // cheats." On a listen server (or a self-hosted SDK environment)
    // hooking this and clearing the cheat-flag check before it returns
    // false unlocks every server-only ConCommand without sv_cheats.
    Signature {
        name: "CServerSideClient_ExecuteStringCommand",
        module: "engine2.dll",
        needle: "40 55 53 56 48 8D AC 24 50 FA FF FF 48 81 EC B0 06 00 00 48 8B D9 48 8B F2 48 8B 4A 48",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1800BE120(__int64 a1, __int64 a2)",
    },

    // sv_cheats change-callback â€” engine2!sub_18009C1F0. Refs unique
    // log "FCVAR_CHEAT cvars reverted to defaults (sv_cheats disabled)."
    // Fires every time sv_cheats flips state and walks the cvar
    // registry, snapping every FCVAR_CHEAT cvar back to its default.
    // Hook + early-return preserves any cheat-flag cvar values
    // (host_thread_mode, mat_fullbright, cl_drawhud, etc) that the
    // user previously customized through console.
    Signature {
        name: "Cvar_RevertFlaggedCvars_OnSvCheatsChange",
        module: "engine2.dll",
        needle: "40 53 48 83 EC 20 48 8B 41 08 48 8B D9 8B 50 30 48 C1 EA 0C F6 C2 01 0F 85",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_18009C1F0(__int64 a1, __int64 a2, _BYTE *a3, char *a4)",
    },

    // CNetworkGameClient::ProcessTick â€” engine2!sub_18006AAF0. Refs the
    // log "CNetworkGameClient::ProcessTick( -1 ), ignoring during demo
    // playback". Per-tick client-side network frame driver: dispatches
    // the tick to the simulation, applies prediction, and orders demo
    // recording. Anchor for tick-rate / fake-lag observability and a
    // safe pre-prediction insertion point for client mods.
    Signature {
        name: "CNetworkGameClient_ProcessTick",
        module: "engine2.dll",
        needle: "48 89 5C 24 20 55 57 41 57 48 81 EC F0 00 00 00 8B 7A 50 45 33 FF 44 38 3D ? ? ? ? 48 8B EA",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_18006AAF0(__int64 a1, __int64 a2)",
    },

    // CNetworkGameClientBase::ForceDemoRecordingFullUpdateAfterNextDeltaPacket
    // â€” engine2!sub_1800292B0. Refs unique log "CDemoRecorder::
    // StartRecording( %s ) calling ForceDemoRecordingFullUpdate
    // AfterNextDeltaPacket to await next delta update before forcing a
    // full update". Sets the flag that makes the next demo segment
    // contain a full snapshot. Useful for demo tools that need clean
    // restart points and for forcing a deterministic resync after a
    // mid-match attach.
    Signature {
        name: "CNetworkGameClientBase_ForceDemoRecordingFullUpdateAfterNextDeltaPacket",
        module: "engine2.dll",
        needle: "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B 1D ? ? ? ? 48 8B FA 48 8B F1 48 85 DB",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_1800292B0(__int64 a1, const char *a2)",
    },

    // C_BaseEntity::SaveData â€” client!sub_180A71820. Refs the unique
    // formats "SaveData   :%32.32s [orig]" and "SaveData   :%32.32s
    // [%4d]" used by the cl_predictioncopy_print machinery. Captures a
    // per-field snapshot of an entity's predicted state before the
    // engine runs the next prediction phase. Hook target for prediction
    // observability, replay/rewind tools, and prediction-divergence
    // forensics.
    Signature {
        name: "C_BaseEntity_SaveData",
        module: "client.dll",
        needle: "48 8B C4 55 56 57 41 56 41 57 48 8D A8 E8 FD FF FF 48 81 EC F0 02 00 00 48 83 B9 A0 05 00 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180A71820(_QWORD *a1, const char *a2, __int64 a3, int a4, int a5, unsigned int a6, __int64 a7)",
    },

    // C_BaseEntity::RestoreData â€” client!sub_180A71610. Refs the unique
    // formats "RestoreData:%32.32s [orig]" and "RestoreData:%32.32s
    // [%4d]". Mirror of SaveData: copies a previously stashed
    // prediction snapshot back into an entity, called when prediction
    // is rewound or when a server packet arrives mid-prediction. Pair
    // with C_BaseEntity_SaveData for end-to-end prediction tracing.
    Signature {
        name: "C_BaseEntity_RestoreData",
        module: "client.dll",
        needle: "40 55 53 56 41 54 41 57 48 8D AC 24 20 FF FF FF 48 81 EC E0 01 00 00 48 8B D9 45 8B E1 48 8B 89",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180A71610(__int64 a1, const char *a2, unsigned int a3, int a4)",
    },

    // CSource2Client::Shutdown â€” client!sub_180AE5B90. The function
    // referenced by the unique log "CSource2Client::Shutdown\n". Top-
    // level teardown for the client: unregisters game systems, closes
    // panel UI, releases prediction state, and tears down all client-
    // side managers. Hook this to gracefully unload an internal cheat
    // when the client unloads/restarts without leaking game state.
    Signature {
        name: "CSource2Client_Shutdown",
        module: "client.dll",
        needle: "48 89 5C 24 08 55 56 57 41 54 41 55 41 56 41 57 48 81 EC 40 02 00 00 8B 0D ? ? ? ? BA 02 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 sub_180AE5B90()",
    },

    // ---------- v1.21.7 additions (build 14158) -----------------------
    // CInputSystem_AttachToWindow - inputsystem!sub_? - SDL window attach
    // hook. Sets HWND, attaches SDL2 input subsystem, registers message
    // pump. Hook to inject custom WndProc / sniff raw input messages.
    Signature {
        name: "CInputSystem_AttachToWindow",
        module: "inputsystem.dll",
        needle: "48 89 5C 24 20 55 48 83 EC 20 48 63 41 30 48 8B EA 33 D2 48 8B D9 85 C0 7E 20 4C 8B C0 8B CA",
        resolve: NONE,
        extra_off: 0,
        prototype: "int __fastcall sub_1800039F0(__int64 a1, HWND a2)",
    },

    // CMatchSessionOfflineCustom_InitializeGameSettings - matchmaking!sub_?
    // Builds the game-settings KV for offline custom match (lobby/practice).
    // Hook to spoof map / mode / convars at session creation.
    Signature {
        name: "CMatchSessionOfflineCustom_InitializeGameSettings",
        module: "matchmaking.dll",
        needle: "40 53 48 81 EC 40 01 00 00 48 89 BC 24 58 01 00 00 48 8D 15 ? ? ? ? 48 8B F9 41 B0 01 48 8B 49 10 FF 15 ? ? ? ? 48 8B D8 48 85 C0 74 59",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_1800EE6A0(__int64 a1)",
    },

    // CMatchSessionOnlineHost_InitializeGameSettings - matchmaking!sub_?
    // Online-host equivalent: writes settings KV when locally hosting an
    // online match. Anchor for community-server / lobby manipulation.
    Signature {
        name: "CMatchSessionOnlineHost_InitializeGameSettings",
        module: "matchmaking.dll",
        needle: "48 8B C4 53 48 81 EC 80 01 00 00 48 89 70 10 48 8D 15 ? ? ? ? 48 89 78 18 4C 89 60 F0",
        resolve: NONE,
        extra_off: 0,
        prototype: "char __fastcall sub_1800F0460(__int64 a1)",
    },

    // CAnimationSystem_FrameUpdate - animationsystem!sub_? - per-tick driver
    // for the new Source2 animgraph: ticks all active animation contexts,
    // schedules sample jobs. Hook to inject pose-blends / time-warp.
    Signature {
        name: "CAnimationSystem_FrameUpdate",
        module: "animationsystem.dll",
        needle: "48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 C8 EB FF FF B8 38 15 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_18008B530(__int64 a1)",
    },



    // CUIEngine_RunFrame - panorama!sub_1800A95F0 - per-frame Panorama UI
    // tick: runs scheduled delegates, repaints, processes script tasks.
    // Anchor to inject menu render hooks or sniff Panorama events.
    Signature {
        name: "CUIEngine_RunFrame",
        module: "panorama.dll",
        needle: "48 89 5C 24 10 48 89 6C 24 18 56 57 41 54 41 56 41 57 48 81 EC 80 00 00 00 45 33 F6 48 8B F1",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1800A95F0(_QWORD *a1)",
    },

    // CUIEngine_DispatchEvent - panorama!sub_180098320 - synchronous event
    // dispatch into the Panorama panel tree (validates event name, walks
    // listeners). Hook to capture every UI event for scripting/automation.
    Signature {
        name: "CUIEngine_DispatchEvent",
        module: "panorama.dll",
        needle: "48 8B C4 48 89 58 18 88 50 10 55 56 57 41 54 41 55 41 56 41 57 48 8D A8 78 F7 FF FF 48 81 EC 50",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall sub_180098320(int *a1, unsigned __int8 a2, __int64 a3)",
    },

    // CCSGameRules_FrameUpdatePreEntityThink - server!sub_1808A9B50 - early
    // per-frame gamerules tick before entity Think pass. Wraps real worker
    // sub_1802729B0 in a VProf scope. Anchor for game-state pre-step.
    Signature {
        // NOTE: DEAD on build 14160 (0 hits, dumper-verified). Pattern/string
        // is stale on current CS2 retail. Kept so the dumper diff still surfaces
        // 0/N hits as a regression signal if a future build resurrects it.
        name: "CCSGameRules_FrameUpdatePreEntityThink",
        module: "server.dll",
        needle: "48 89 5C 24 08 57 48 83 EC 60 48 8D 05 ? ? ? ? 48 C7 44 24 28 01 13 00 00 48 89 44 24 20",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_1808A9B50(__int64 a1, __int64 a2)",
    },

    // CCSGameRules_Think - server!sub_1808D80F0 - main per-tick game-rules
    // think (round timers, halftime swap, GMR_EndRound dispatch). Top-level
    // anchor for round-state manipulation / freezetime / score hacks.
    Signature {
        name: "CCSGameRules_Think",
        module: "server.dll",
        needle: "40 55 53 41 55 41 57 48 8D 6C 24 C1 48 81 EC A8 00 00 00 80 79 48 00 4C 8B F9 4C 8B 2D",
        resolve: NONE,
        extra_off: 0,
        prototype: "double __fastcall sub_1808D80F0(__int64 a1)",
    },

    // CCSGameRules_TerminateRound - server!sub_1808EFA50 - round terminator
    // (sets winner team, plays end-round sound, kicks state machine to
    // post-round). Anchor for forcing arbitrary round-end conditions.
    Signature {
        name: "CCSGameRules_TerminateRound",
        module: "server.dll",
        needle: "48 8B C4 4C 89 48 20 48 89 48 08 55 56 41 56 41 57 48 8D 68 A1 48 81 EC E8 00 00 00 4C 8D B1",
        resolve: NONE,
        extra_off: 0,
        prototype: "_BYTE *__fastcall sub_1808EFA50(__int64 a1, __int64 a2, unsigned int a3, __int64 a4)",
    },

    // CCSPlayerPawn_GiveNamedItem - server!sub_180A2AC60 - resolves classname
    // alias, finds entity factory, spawns the weapon/item entity, equips it
    // on the pawn. Anchor for server-side give-weapon implementations.
    Signature {
        name: "CCSPlayerPawn_GiveNamedItem",
        module: "server.dll",
        needle: "48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 20 44 89 44 24 18 55 41 54 41 55 41 56 41 57 48 8D AC 24 40 FF FF FF 48 81 EC C0 01 00 00 4D 8B E1 45 8B E8",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180A2AC60(__int64 a1, const char *a2, int a3, __int64 a4, char a5, unsigned __int64 *a6)",
    },

    // CCSPlayerPawnBase_SwitchTeam - server!sub_180A0D380 - team-change entry
    // (validates team idx, fires team-change event, updates pending-team,
    // schedules respawn). Anchor for forced team-swap utilities.
    Signature {
        name: "CCSPlayerPawnBase_SwitchTeam",
        module: "server.dll",
        needle: "40 53 57 48 81 EC 88 00 00 00 48 8B D9 8B FA 8B CA E8 ? ? ? ? 48 85 C0 0F 84 3A 02 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "__int64 __fastcall sub_180A0D380(__int64 a1, unsigned int a2)",
    },
    Signature {
        name: "SDL_EventHandler",
        module: "inputsystem.dll",
        needle: "53 48 81 EC ? ? ? ? 8B 02 48 8B DA 2D 00 04 00 00",
        resolve: NONE,
        extra_off: 0,
        prototype: "void __fastcall SDL_EventHandler(__int64 a1, SDL_Event* event)",
    },

    // ---------- Additional ports (danielkrupinski/Osiris) ----------------
    // ----- client.dll -----
    Signature { name: "MainMenuPanelPointer", module: "client.dll", needle: "EC ? 48 8B 05 ? ? ? ? 48 8D 15 ? ? ? ? 48", resolve: ResolveKind::RipRel { rel_off: 5 }, extra_off: 0, prototype: "" },
    Signature { name: "HudPanelPointer", module: "client.dll", needle: "48 89 35 ? ? ? ? E8 ? ? ? ? 48 85", resolve: ResolveKind::RipRel { rel_off: 3 }, extra_off: 0, prototype: "" },
    Signature { name: "GlobalVarsPointer", module: "client.dll", needle: "48 8B 05 ? ? ? ? 0F 57 C0 8B 48", resolve: ResolveKind::RipRel { rel_off: 3 }, extra_off: 0, prototype: "" },
    Signature { name: "TransformTranslate3dVMT", module: "client.dll", needle: "00 00 80 00 48 8D 05 ? ? ? ? 48 C7 42 ? 00", resolve: ResolveKind::RipRel { rel_off: 7 }, extra_off: 0, prototype: "" },
    Signature { name: "TransformScale3dVMT", module: "client.dll", needle: "48 8D 0D ? ? ? ? F3 0F 10 4B ? F3 0F 10 43", resolve: ResolveKind::RipRel { rel_off: 3 }, extra_off: 0, prototype: "" },
    Signature { name: "WorldToProjectionMatrixPointer", module: "client.dll", needle: "48 8D 0D ? ? ? ? 48 C1 E0 06", resolve: ResolveKind::RipRel { rel_off: 3 }, extra_off: 0, prototype: "" },
    Signature { name: "ViewToProjectionMatrixPointer", module: "client.dll", needle: "48 89 4C 24 ? 4C 8D 0D ? ? ? ? 48 8B 0D", resolve: ResolveKind::RipRel { rel_off: 8 }, extra_off: 0, prototype: "" },
    Signature { name: "ManageGlowSceneObjectPointer", module: "client.dll", needle: "E8 ? ? ? ? 48 8B 4F ? 0F 28 7C", resolve: ResolveKind::RipRel { rel_off: 1 }, extra_off: 0, prototype: "" },
    Signature { name: "SetSceneObjectAttributeFloat4", module: "client.dll", needle: "E8 ? ? ? ? FF C6 48 83 C3 ? 49 3B", resolve: ResolveKind::RipRel { rel_off: 1 }, extra_off: 0, prototype: "" },
    Signature { name: "PointerToClientMode", module: "client.dll", needle: "57 48 83 EC ? 33 DB 48 8D 3D ? ? ? ? 48 8D", resolve: ResolveKind::RipRel { rel_off: 10 }, extra_off: 0, prototype: "" },
    Signature { name: "CvarPointer", module: "client.dll", needle: "48 83 EC ? ? 8B ? ? ? ? ? 48 8D 54 ? ? 4C", resolve: ResolveKind::RipRel { rel_off: 7 }, extra_off: 0, prototype: "" },
    Signature { name: "GetAbsOriginFunction", module: "client.dll", needle: "F8 ? 75 ? E8 ? ? ? ? F3", resolve: ResolveKind::RipRel { rel_off: 5 }, extra_off: 0, prototype: "" },
    Signature { name: "EntitySystemPointer", module: "client.dll", needle: "48 89 ? ? ? ? ? 4C 63 ? ? ? ? ? 44 3B ? ? ? ? ? 0F", resolve: ResolveKind::RipRel { rel_off: 3 }, extra_off: 0, prototype: "" },
    Signature { name: "GameRulesPointer", module: "client.dll", needle: "F6 ? ? 0F 85 ? ? ? ? ? 8B ? ? ? ? ? ? 85 ? 0F", resolve: ResolveKind::RipRel { rel_off: 12 }, extra_off: 0, prototype: "" },
    Signature { name: "PanelConstructorPointer", module: "client.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B F1 48 8B FA B9 ? ? ? ? E8 ? ? ? ? 48 8B D8 48 85 C0 74 ? 48", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "SetSelectedIndexFunctionPointer", module: "client.dll", needle: "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F1 8B DA 48 83", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "SetImageFunctionPointer", module: "client.dll", needle: "CF E8 ? ? ? ? 41 0F B6 C5", resolve: ResolveKind::RipRel { rel_off: 2 }, extra_off: 0, prototype: "" },
    Signature { name: "ImagePanelConstructorPointer", module: "client.dll", needle: "? ? ? ? 48 8B C8 EB 03 49 8B ? 48 89", resolve: ResolveKind::RipRel { rel_off: 0 }, extra_off: 0, prototype: "" },
    Signature { name: "LabelPanelConstructorPointer", module: "client.dll", needle: "C8 E8 ? ? ? ? 48 8B F0 48 8B 57", resolve: ResolveKind::RipRel { rel_off: 2 }, extra_off: 0, prototype: "" },
    Signature { name: "SetLabelTextFunctionPointer", module: "client.dll", needle: "41 B1 01 41 B8 ? ? ? ? E9 ? ? ? ?", resolve: ResolveKind::RipRel { rel_off: 10 }, extra_off: 0, prototype: "" },
    Signature { name: "UiEnginePointer", module: "client.dll", needle: "48 89 78 ? 48 89 0D ? ? ? ?", resolve: ResolveKind::RipRel { rel_off: 7 }, extra_off: 0, prototype: "" },
    Signature { name: "PlantedC4sPointer", module: "client.dll", needle: "0F ? ? ? ? ? 39 ? ? ? ? ? 7E ? 48 8B 0D", resolve: ResolveKind::RipRel { rel_off: 8 }, extra_off: 0, prototype: "" },
    Signature { name: "GetBombsiteACenter", module: "client.dll", needle: "54 24 ? E8 ? ? ? ? EB 0A", resolve: ResolveKind::RipRel { rel_off: 4 }, extra_off: 0, prototype: "" },
    Signature { name: "GetBombsiteBCenter", module: "client.dll", needle: "EB 0A 48 8D 54 24 ? E8 ? ? ? ? F2", resolve: ResolveKind::RipRel { rel_off: 8 }, extra_off: 0, prototype: "" },
    Signature { name: "SliderSetValueFunction", module: "client.dll", needle: "CF E8 ? ? ? ? 0F 28 74 24 ? 48 8B 74", resolve: ResolveKind::RipRel { rel_off: 2 }, extra_off: 0, prototype: "" },
    Signature { name: "TextEntrySetTextFunction", module: "client.dll", needle: "8B 89 ? ? ? ? E8 ? ? ? ? B0", resolve: ResolveKind::RipRel { rel_off: 7 }, extra_off: 0, prototype: "" },
    Signature { name: "SetItemItemIdFunction", module: "client.dll", needle: "CF 48 8B D0 48 8B 5C 24 ? 48 83 C4 ? 5F E9 ? ? ? ?", resolve: ResolveKind::RipRel { rel_off: 15 }, extra_off: 0, prototype: "" },
    Signature { name: "PointerToGetInaccuracyFunction", module: "client.dll", needle: "48 89 5C 24 ? 55 56 57 48 81 EC ? ? ? ? 44", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "PointerToGetSpreadFunction", module: "client.dll", needle: "48 83 EC ? 48 63 91", resolve: NONE, extra_off: 0, prototype: "" },
    // ----- panorama.dll -----
    Signature { name: "SetPanelStylePropertyFunctionPointer", module: "panorama.dll", needle: "E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 45 ? EB ? 0F", resolve: ResolveKind::RipRel { rel_off: 1 }, extra_off: 0, prototype: "" },
    Signature { name: "GetPanelPointerFunctionPointer", module: "panorama.dll", needle: "4C 63 0A 4C 8B DA", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "RunScriptFunctionPointer", module: "panorama.dll", needle: "48 89 5C 24 ? 4C 89 4C 24 ? 48 89 54 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "MakeSymbolFunctionPointer", module: "panorama.dll", needle: "40 55 56 48 83 EC ? 48 63", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "OnDeletePanelFunctionPointer", module: "panorama.dll", needle: "48 85 D2 0F 84 ? ? ? ? 48 89 ? 24 ? 57 48 83 EC ? 48", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "RegisterEventHandlerFunctionPointer", module: "panorama.dll", needle: "48 89 5C 24 ? 66 89 54 24 ? 55 56 57 41 56 41 57 48 83 EC ? 48 8D 05 ? ? ? ? 48 C7 44 24 28 ? ? ? ? 48 89 44 24 ? 4D", resolve: NONE, extra_off: 0, prototype: "" },
    // ----- scenesystem.dll -----
    Signature { name: "SceneSystemPointer", module: "scenesystem.dll", needle: "72 ? ? 8B ? ? ? ? ? 48 8D 0D ? ? ? ? 48", resolve: ResolveKind::RipRel { rel_off: 12 }, extra_off: 0, prototype: "" },
    Signature { name: "DeleteSceneObjectFunctionPointer", module: "scenesystem.dll", needle: "48 85 D2 0F 84 ? ? ? ? 48 8B C4 48 89 50", resolve: NONE, extra_off: 0, prototype: "" },
    Signature { name: "AllocateAttributeListFunctionPointer", module: "scenesystem.dll", needle: "40 55 48 83 EC ? 48 83 BA", resolve: NONE, extra_off: 0, prototype: "" },
    // ----- soundsystem.dll -----
    Signature { name: "SoundChannelsPointer", module: "soundsystem.dll", needle: "8B 3D ? ? ? ? 48 89 58", resolve: ResolveKind::RipRel { rel_off: 2 }, extra_off: 0, prototype: "" },

];
