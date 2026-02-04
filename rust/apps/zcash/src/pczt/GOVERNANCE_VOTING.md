# Zcash Governance Voting - Keystone Hardware Wallet PoC

## Overview

This document describes a mechanism for Zcash governance voting using Keystone hardware wallets without firmware modifications. The approach leverages an asymmetry in Keystone's PCZT validation to sign governance transactions with non-standard nullifier derivation.

---

## The Account Index Trick

### How It Works

Keystone's firmware has an asymmetry between its **check** and **sign** phases:

| Phase | Account Index Source | Behavior |
|-------|---------------------|----------|
| **Check** | Hardcoded to `0` | Only verifies nullifier/rk if path matches account 0 |
| **Sign** | From PCZT's derivation path | Signs using whatever account is specified |

```
Keystone check: expects m/32'/133'/0' (account 0)
PCZT contains:  m/32'/133'/1' (account 1)
Result:         Path mismatch → nullifier verification SKIPPED
Sign:           Uses PCZT path → signs with account 1's key
```

### Why This Helps Governance Voting

Governance voting uses a **modified nullifier derivation** (Poseidon-based, includes proposal_id). Keystone's standard check would reject this because `verify_nullifier()` expects standard Orchard derivation.

By using account 1's path:
1. Check sees path mismatch → skips `verify_nullifier()` → no rejection
2. Sign derives account 1's key → signs successfully

---

## The Decoupled Signature Model

This approach requires a **decoupled** model in the governance ZKP:

**Standard Orchard (coupled):**
```
Account 0's FVK = (ak, nk, rivk)
                   ↓       ↓
                  rk    nullifier
                   ↓       ↓
              signature  circuit
                   └──────┘
            Both tied to SAME account
```

**Governance with Account Trick (decoupled):**
```
Account 0's nk → governance nullifier (circuit proves note ownership)
Account 1's ak → rk → signature (out-of-circuit verification)

Circuit does NOT require nk and ak from same account
```

---

## Security Model: Viewing Authority vs Spend Authority

### Orchard Key Hierarchy

```
SpendingKey (sk)
    ├── SpendAuthorizingKey (ask) → ak → can sign spends
    └── NullifierDerivingKey (nk) → can derive nullifiers

Full Viewing Key (FVK) = (ak, nk, rivk)
```

- **FVK can be shared** without sharing the spending key
- Anyone with FVK has `nk` but not `ask`
- `nk` allows deriving nullifiers; `ask` allows signing spends

### What This Means for Governance

The governance circuit proves knowledge of `nk` (from account 0), while the signature comes from account 1's `ask`. These are cryptographically unrelated.

**Voting authority in this model = viewing authority (nk knowledge), not spend authority (ask knowledge).**

| Scenario | Has nk? | Has ask? | Can vote? |
|----------|---------|----------|-----------|
| User with spending key | ✅ | ✅ | ✅ |
| Watch-only wallet (has FVK) | ✅ | ❌ | ✅ |
| Custodian with viewing access | ✅ | ❌ | ✅ |

### Tradeoffs

| Consideration | Implication |
|---------------|-------------|
| **Simpler implementation** | No firmware changes needed |
| **Weaker security model** | Viewing authority = voting authority |
| **User still signs on device** | Physical consent is captured |
| **FVK sharing is uncommon** | In practice, most users don't share FVK |
| **Custodial edge cases** | Could allow custodians with viewing access to vote |

---

## Technical Details

### PCZT Construction Requirements

Zashi must construct a fresh governance PCZT (not modify an existing one):

```
Governance PCZT:
  spend:
    nullifier: governance_nullifier (Poseidon-based)
    rk: account 1's randomized key (ak1 + alpha * G)
    zip32_derivation: m/32'/133'/1' (account 1)
  output:
    cmx: computed with rho = governance_nullifier
```

**Why fresh construction?** The output note's `rho` equals the nullifier bytes. Changing the nullifier without recomputing `cmx` breaks consistency and fails verification.

### Sign Enforces rk Match

Keystone's sign phase verifies the derived key matches the `rk` in the PCZT:
- Path = account 1 → derives account 1's ask
- PCZT must contain account 1's rk
- Mismatch → `WrongSpendAuthorizingKey` error

---

## What's Proven

| Test | Status | What it proves |
|------|--------|----------------|
| `test_account1_path_bypasses_check` | ✅ | Account 1 path skips nullifier verification |
| `test_signing_succeeds_with_governance_nullifier` | ✅ | Sign accepts governance nullifier |
| `test_sign_requires_matching_rk` | ✅ | Sign enforces rk matches derived key |
| `test_check_fails_with_governance_nullifier` | ✅ | Account 0 path rejects governance nullifier |
| **Fresh governance PCZT e2e** | ⏳ | Requires PCZT construction in Zashi |

All 18 governance tests pass. The mechanism works at the code-path level.

---

## Options Going Forward

### Option A: Accept Viewing Authority Model

Proceed with the account index trick. Document explicitly:
> "Voting authority is defined as the ability to derive nullifiers (nk knowledge), not the ability to sign spends."

**Pros:** No firmware changes, simpler implementation
**Cons:** Weaker than spend-authority model

### Option B: Require Spend Authority (Firmware Change)

Modify Keystone firmware to add governance mode:
- Skip nullifier verification for account 0 when governance flag is set
- Keep signature tied to account 0
- Circuit proves `ask` knowledge

**Pros:** Stronger security model (spend authority = voting authority)
**Cons:** Requires firmware changes

### Option C: Different Hardware Wallet

Find a hardware wallet that doesn't verify nullifier derivation, avoiding the need for the account trick entirely.

---

## Next Steps

1. **Decide:** Is viewing-authority voting acceptable for Zcash governance?
2. **If yes:** Build e2e test in Zashi with fresh PCZT construction
3. **If no:** Explore firmware modification or alternative approaches

---

## Code References

- Check logic: `rust/apps/zcash/src/pczt/check.rs:336-366`
- Sign logic: `rust/apps/zcash/src/pczt/sign.rs:78-103`
- Key derivation: `rust/keystore/src/algorithms/zcash/mod.rs:73-104`
- Tests: `rust/apps/zcash/src/pczt/governance_test.rs`
