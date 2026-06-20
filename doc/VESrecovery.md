# VESrecovery — design & threat model

*How VES lets you recover encryption keys without giving anyone a backdoor.*

> **Status.** This is a design explainer for developers and security reviewers,
> written against the reference implementation (see [Source map](#source-map)). It
> describes what the system does; it is not, by itself, a formal cryptographic proof of
> `RDX1.2` — for that, see VES's canonical cryptographic documentation. Canonical
> documentation lives at <https://ves.host>.

## The problem

End-to-end encryption has one notorious failure mode: **lose the key and the data is
gone forever.** There is no "forgot password" link for a private key. This is the main
reason most products quietly fall back to server-side encryption, where the provider
holds the keys and can read everything.

VES is built to give real end-to-end encryption *and* a realistic way back in after a
lost device — **without the VESvault service ever being able to read your keys or your
data.** This document explains how, and is explicit about the trade-offs, because
"recoverable end-to-end encryption" sounds like a contradiction (or a backdoor) until
you see the mechanism.

## Goals and non-goals

**Goals**

- The VESvault service stores and routes only ciphertext it cannot decrypt.
- A user who loses every device can regain access through a recovery path *they* set up
  in advance.
- No single party — not the server, not any one recovery contact — can unilaterally
  recover a user's keys.
- The user chooses who participates in recovery and how many of them are required.

**Non-goals**

- VES does not protect a user who deliberately hands their unlocked key or VESkey to an
  attacker.
- VES does not offer a *cryptographic* guarantee against a *threshold-sized coalition* of
  the user's own chosen recovery contacts who collude, impersonate the user, and **keep the
  user locked out of their own email for the entire Security Time Delay**. That last
  condition is the crux: the delay, the email-gated stop path, and the alert sent to *every*
  recovery friend make this a detection-and-response boundary — if the user reaches their
  email at any point in the window they get the alert and can stop the recovery, so the
  coalition must *deny* that access for the whole delay, not merely seize the mailbox once.
  A coalition that sustains all of this is the inherent, consented trade-off of social
  recovery; see [Is this a backdoor?](#is-this-a-backdoor). The very same structure can be
  entirely *legitimate* — an organization recovering a departing employee's corporate vault
  once it controls that employee's email by prior agreement; see
  [organizational key custody](org-key-custody.md).

## Architecture primitives

A few building blocks are enough to follow the rest:

- **Vault Key** — an asymmetric key pair that represents an identity or device (types
  include `current`, `secondary`, `temp`, `shadow`, `recovery`, `lost`; see
  `libVES/VaultKey.h`). The private key is encrypted at rest under a **VESkey** (a
  secret the user controls) and is only ever decrypted client-side.
- **Vault Item** — a piece of data encrypted to one or more Vault Keys. Each recipient
  Vault Key gets its own encrypted copy of the item's content key ("vault entry"). To
  share an item with someone is to add a vault entry encrypted to *their* Vault Key.
- **The server is a zero-knowledge store and router.** It holds public keys, encrypted
  private keys, and encrypted vault entries. It never receives a VESkey or a decrypted
  private key. Every decrypt happens on the client.
- **VESlocker** — a layer *orthogonal* to VES and **agnostic of credentials**: a small
  **encrypted store** for a secret (VES uses it to stash a VESkey), *not* part of the VES
  key model and *not* a source of VES keys. A value is kept as AES-256-GCM ciphertext (the
  `VESlocker_entry`: service URL, `id`, `seed`, ciphertext). The GCM key is **derived by
  the VESlocker service** from an `(id, challenge)` pair, with the **number of attempts
  capped per `id`**: the client sends `id` plus `challenge = SHA-256(seed ‖ pin)`, the
  server returns the derived key (from server-held material) or, once the cap is hit,
  `403` / `VESLOCKER_E_RETRY` with a `Refresh:` backoff (`lib/VESlocker.*`), and the client
  then decrypts the stored ciphertext locally. A wrong PIN is never *rejected* — it derives
  a *different* key and the GCM auth simply fails. That is what lets a low-entropy PIN
  safely guard a high-entropy secret: the derivation happens only server-side behind the
  rate limit, so there is **nothing to brute-force offline**, and the per-`id` cap exhausts
  online guessing after a few tries. VES uses VESlocker to hold a device's VESkey behind a
  PIN — **both** a freshly bootstrapped recovery key *and* a key imported/synced from
  another device (the everyday "add another browser/app" path); the two are independent
  layers.

Because sharing is "add a vault entry encrypted to another key," **re-sharing a key to a
new key is the single primitive** behind both everyday multi-device access and
catastrophic recovery.

## Everyday continuity (the common case)

Most "recovery" is mundane — a new phone, a second laptop. VES handles this without any
threshold ceremony:

- A user identity can hold several active Vault Keys (one per device). Items shared with
  the identity are re-encrypted to each active device key, so any authorized device can
  decrypt them.
- Authorizing a new device **imports (syncs) the VESkey** to it (the "add another
  browser/app" path), where it is held in that device's own VESlocker store under a
  device-local PIN — the same store mechanism the recovery bootstrap key uses.
- When a user changes their VESkey, `setVESkey(veskey, lost, …)` mints a new `current`
  Vault Key and disposes of the previous one per the `lost` flag:
  - **Rotation of a still-usable key** (`lost` false): the old key is unlocked and the
    user's items are **rekeyed** from it to the new key (`rekeyFrom`); the old key is
    simply superseded — *not* marked lost.
  - **Key loss** (`lost` true): the old VESkey is gone, so there is nothing to rekey from
    — the old key is marked **`lost`** (its items become reachable again only via a found
    key or VESrecovery) and the new key starts fresh.

In all of these, access moves between keys the user already controls. Nothing here lets
a third party in.

> **Aside — what propagator keys actually are.** It is tempting to assume *propagator
> keys* (`domain = .propagate`) are how an identity moves between a user's own devices.
> They are not. A propagator key is the channel for delivering a **provisional `temp`
> key** to a *new recipient who does not yet have a VES identity*: when you share a secret
> with someone before they have an account, VES mints a `temp` key for them and propagates
> it to their real key once they finish setting up (`libVES_attn`, `libVES_getPropagators`,
> `VaultKey.propagate`). It is orthogonal to multi-device continuity and to recovery.

## VESrecovery: social threshold recovery

The hard case is total loss: every device and the active VESkey are gone. VESrecovery
solves it with **threshold secret sharing among recovery contacts the user picks in
advance.** The user's recovery secret is split into shares; each share is stored as a
Vault Item **encrypted to a contact's own Vault Key**. Recovery requires a threshold of
those contacts to actively help.

### Setup

1. The recovery secret `s` (what is needed to unlock the user's recovery key) is split
   with VES's threshold scheme, algorithm tag **`RDX1.2`** (`libVES.Scramble.RDX`).
   - `toVector(s)` expands `s` into a length-`n` vector whose first element is `s` and
     whose remaining elements are random, then chains the elements with AES-CTR so the
     whole vector must be reconstructed to recover `s` (`fromVector` reverses it).
   - `explode(s, m, {t})` evaluates that vector as a degree-`(n−1)` polynomial at `m`
     distinct points, producing **`m` shares** ("tokens"). Each token carries metadata
     `{v: "RDX1.2", n, b, t}` — the algorithm tag, the threshold `n`, that token's
     evaluation point `b`, and `t`, the **Security Time Delay** in seconds (see below).
2. Each token is written as a Vault Item **shared (encrypted) only to one recovery
   contact's Vault Key.** The owner cannot read the tokens; any single contact holds
   only one share.

The result: an **(`n`, `m`) threshold** — `n` of the `m` chosen contacts are required to
reconstruct, and fewer than `n` shares reveal nothing usable.

At setup the user also picks the **Security Time Delay** `t` (`setShadow(friends, {n, t})`;
recommended 12–24 h, or `0` for none). It is recorded in every token's metadata and does
nothing during setup — it governs how long a *future* recovery must wait before it can
finalize. See [Recovery](#recovery) and [Is this a backdoor?](#is-this-a-backdoor).

### Recovery

1. After total loss, the user re-establishes a fresh `current` Vault Key under a new PIN;
   the new VESkey is stashed in a VESlocker encrypted store keyed to that PIN (per-`id`
   attempt-capped — see [Architecture primitives](#architecture-primitives) and
   `lib/VESlocker.*`).
2. Each recovery contact **assists** by re-sharing their recovery token back to the
   user's new `current` key (`Recovery.assist` → `VaultItem.shareWith`). `revoke()`
   withdraws assistance. The owner can see progress: `getFriendsRequired()` (= `n`),
   `getFriendsAssisted()`, `getFriendsToGo()`.
3. Once at least `n` contacts have assisted, the owner reconstructs the secret entirely
   client-side: `Recovery.unlock()` collects the now-readable token values and calls
   `Scramble.implode()`, which reduces the Vandermonde system
   (`libVES.Math.matrixReduce` + `div`) and reverses the AES-CTR chaining to recover `s`.
4. The **Security Time Delay** gates the final step. When a recovery is initiated VES
   emails an alert to the account owner, and the **server withholds the recovered
   keychains until the user-configured delay `t` has elapsed** — so completing recovery is
   not instant even once the threshold is met. During that window the owner can **stop the
   recovery** (the "VESrecovery in Progress" flow), reverting the account before any keys
   change hands. Stopping is itself **gated by an emailed OTP** *plus* the former PIN (or a
   saved VESkey), so it requires email access: an owner who controls — or regains — the
   email can always stop an unwanted recovery, while a party who has *lost* the email
   cannot (see [Is this a backdoor?](#is-this-a-backdoor) and
   [organizational key custody](org-key-custody.md)).
5. `Recovery.recover()` then verifies the caller is the vault owner (`requireOwner()`),
   unlocks the recovery key with `s`, and **rekeys** the vault to the user's new key —
   restoring access to all previously encrypted items.

A **`shadow`** key variant supports user-held self-recovery (a backup the user keeps),
using the same splitting machinery; the friend-assisted flow above is key type
`recovery`.

## Is this a backdoor?

No. The useful way to answer is to enumerate what each party can do.

| Party | Can they recover the user's keys? |
|---|---|
| **VESvault (the server)** | **No.** It stores only ciphertext: public keys, encrypted private keys, and recovery tokens encrypted to contacts. It never sees a VESkey, a decrypted private key, or a reconstructed secret. |
| **A single recovery contact** | **No.** One share is below threshold and reveals nothing usable. |
| **Fewer than `n` contacts** | **No.** Below threshold. |
| **The user** | **Yes** — by design — after `n` contacts they chose assist and they re-establish a current key. |
| **`n` colluding contacts who *also* seize the user's email** | **Only under compounding conditions** — they must hold the email for the entire Security Time Delay *and* escape notice by every honest friend (see below). |

The last row is the honest cost of any social-recovery scheme, and VES does not hide it —
but it is not the unconditional "yes" it first appears. For a coalition to actually take
the vault, **all of these must hold at once**:

- **A threshold colludes.** `n` of the `m` contacts the user chose must each actively
  assist and not revoke. The user picks both the contacts and `n`, so a high enough
  threshold among trustworthy contacts makes this implausible to begin with.
- **They also seize the user's email.** Recovery is initiated against the identity's email
  and is OTP-gated to it, so the coalition needs control of that mailbox — not just the
  shares.
- **They sustain it through the entire Security Time Delay.** The server withholds the
  recovered keychains until the user-set delay `t` elapses (the user picks it, typically
  12–24 h), and the owner can **stop** the recovery at any point before then — also
  OTP-gated to the email. The attacker must therefore hold *both* the email and the
  threshold, uninterrupted, for the whole window; if the owner regains the email and stops
  it in time, the attempt fails.
- **No honest friend warns the user.** Initiating a recovery **alerts every recovery
  friend**, not only the colluding ones — so each non-colluding contact is an independent
  detection channel that can reach the user out of band, *even if the attacker controls the
  user's own email*.

Put together, a would-be impersonator must defeat the bootstrap credential, marshal a
threshold of independent humans, hold the victim's email for the full delay, *and* evade
every honest friend — strictly harder than compromising the single provider-held key that
server-side encryption exposes.

Crucially, the comparison is not "VES vs. perfect E2E." It is "VES vs. the server-side
encryption most products fall back to *because* perfect E2E loses data." Against that
baseline, VES removes the provider's ability to read your data while keeping a recovery
path that no single party controls.

## Adjacent case: email squatting

A VES identity is bootstrapped from an email address, so whoever controls the email
controls the ability to establish that identity. If someone with **illegitimate access to
an email** creates a VES account on it *before the rightful owner does*, they are
**squatting** — but on an **empty** vault. There is no prior ciphertext of the rightful
owner to read, and anything the owner encrypts later is keyed to keys they establish
*after* reclaiming the address.

The resolution follows the normal model: once the rightful owner **secures the email and
resets the vault**, they re-establish their own `current` key on the identity and the
squatter is displaced, having never held anything of the owner's. Because acting on an
identity is OTP-gated to its email, control follows the email — so the displaced squatter,
having lost the address, cannot reverse the reset or stop a recovery.

(The *legitimate* mirror image — an organization taking over a departing employee's
address to recover corporate data under a pre-agreed policy — is a different topic; see
the [organizational key-custody document](org-key-custody.md).)

## What the server can and cannot see

- **Cannot see:** VESkeys, decrypted private keys, plaintext item content, reconstructed
  recovery secrets. All decryption is client-side.
- **Can see (metadata):** which Vault Keys exist, which items are shared with which keys,
  timing of shares/assists, and the recovery token metadata (`n`, evaluation points, and
  the Security Time Delay `t` — which the server must see, since it enforces it).
  Recovery topology is therefore not secret even though the shares are.

## Limitations & caveats

- Recovery only works if it was **set up beforehand** with enough live contacts; lose
  your devices before configuring recovery and there is no path back. This is intended.
- Metadata is not hidden (see above).
- The bootstrap secret (the VESkey stashed in VESlocker) used to re-establish a `current`
  key during recovery is part of the trust story. When it is guarded by a low-entropy PIN,
  safety rests on VESlocker's per-`id` attempt cap rather than on the PIN's entropy: the
  store's key is derived server-side from `(id, challenge)`, so there is nothing to
  brute-force offline, and online guesses are capped per `id`.
- The Security Time Delay is a *detection-and-response* control, not a cryptographic
  guarantee. Stopping a recovery is gated by an emailed OTP, so it protects an owner who is
  reachable and **still controls (or can regain) the email** within the window; it does not
  by itself stop a threshold-plus-impersonation coalition that holds the email for the
  whole delay and that the owner never overrides. The same delay also blocks a *legitimate*
  recovery for its full duration, so an excessively long value locks the user out of their
  own content while it elapses — and, symmetrically, an owner who cannot regain the email in
  time cannot stop an unwanted one.
- `RDX1.2` is a VES-specific construction. This document describes *what it does*; its
  formal cryptographic analysis is out of scope here and should be cited from VES's
  cryptographic documentation rather than inferred from this overview.

## Source map

| Concern | File / symbol |
|---|---|
| Recovery orchestration (tokens, assist, unlock, recover) | `libVES.Recovery.js` |
| Threshold scheme `RDX1.2` (explode/implode, scramble) | `libVES.Scramble.js` |
| Big-integer / matrix arithmetic | `libVES.Math.js` |
| Vault Key types & rekey | `lib/libVES/VaultKey.{c,h}` |
| Key-loss / VESkey reset path | `setVESkey()` in `libVES-base.js` |
| Bootstrap secret store — credential-agnostic AES-GCM store; per-`id` attempt-capped `(id, challenge)` key derivation | `lib/VESlocker.{c,h}` (`VESlocker_encrypt`/`_decrypt`, `VESlocker_getkey_n`) |
| Temp-key propagation to new (account-less) recipients | `libVES_getPropagators`, `libVES_attn`, `VaultKey.propagate` |
| Security Time Delay `t` — set in token metadata (enforced server-side) | `Scramble.explode(…, {t})`, `setShadow(friends, {n, t})` |
