# Organizational key custody & offboarding — design & policy

*How an organization keeps lawful access to corporate encrypted data under VES's
end-to-end model — without a backdoor, and without being able to read employees' data at
will.*

> **Status.** This is a design & policy explainer for IT/compliance owners and security
> reviewers. It describes VES's continuity model and service policy — not a contract or
> legal advice. Operational details (notably data-retention windows) reflect **service
> policy** rather than properties of the recovery code, and are governed by VES's canonical
> policy and terms. Companion document:
> [VESrecovery — design & threat model](VESrecovery.md). Canonical documentation lives at
> <https://ves.host>.

## The problem

Organizations that adopt end-to-end encryption face a continuity obligation: when an
employee leaves, is incapacitated, or simply becomes unavailable, the organization still
needs access to the **corporate** encrypted data that employee held. The naive fix — give
the provider or the employer a master key — is exactly the backdoor that end-to-end
encryption exists to remove.

VES resolves this the same way it resolves personal recovery: through **social threshold
recovery the employee sets up in advance** (see [VESrecovery](VESrecovery.md)), constrained
by **organizational policy** rather than by a technical master key.

## Why it can't be forced (and why that's the point)

Because VES is end-to-end, recovery is configured **client-side, under the user's control**.
The organization:

- cannot mint, seize, or read the employee's keys;
- cannot silently set or alter the employee's recovery configuration;
- cannot compel the VES service to hand over plaintext — the service only ever holds
  ciphertext.

So the organizational control is **policy + verification**, not compulsion. This is a
feature, not a gap: it means even the employer cannot unilaterally read an employee's
vault.

## The pattern

1. **Policy-mandated recovery friends.** Corporate policy requires each employee to
   configure VESrecovery with a set of **organization-designated recovery friends** —
   e.g. a custodian / security-team identity, or a quorum of officers — at a threshold the
   policy specifies.
2. **Verifiable compliance.** Recovery topology is **visible metadata** — which identities
   hold shares, the threshold `n`, etc. (see
   [VESrecovery → What the server can and cannot see](VESrecovery.md#what-the-server-can-and-cannot-see)).
   The designated friends — and the organization — can therefore **verify** that an
   employee actually configured recovery with the required friends and threshold, *without
   being able to read the employee's data*. End-to-end encryption prevents *forcing* the
   configuration; it does not prevent *confirming* it.
3. **Corporate-controlled identity.** The employee's VES identity is bound to a **corporate
   email address** the organization administers.

## Offboarding / hand-over

When an employee departs:

1. The organization takes over the corporate **email address** that bootstraps the
   identity.
2. Using that address, it **initiates VESrecovery** on the identity.
3. The **designated recovery friends assist** — the same active, consented threshold step
   as personal recovery.
4. The organization reconstructs the recovery secret and **rekeys the vault to an
   organization-controlled key**, regaining access to the corporate items.

This is **not** a backdoor: it works only because (a) the organization owns the
email/identity by prior agreement, (b) the employee consented, via policy, to
organization-designated recovery friends, and (c) those friends **actively assist**. No
single party — not VES, not the employer alone — can read the data without that threshold.

### Data-retention safety net

A departing employee might try to destroy corporate data on the way out by overwriting or
deleting items. VES's per-owner **ciphertext retention** is the safety net: the service
retains the item owner's ciphertexts for **at least 30 days**, so the organization can
recover the prior ciphertexts within the retention window even if the user purposely
overwrote or erased them before leaving. (The exact retention scope — deleted vs.
overwritten items, expunged vaults — and how it interacts with data-erasure / GDPR-style
obligations are governed by VES's canonical retention policy and terms.)

## Interaction with the Security Time Delay

The [Security Time Delay](VESrecovery.md#recovery) applies to an organizational recovery
too, and the way it is gated works *in the organization's favor*:

- The delay's **alert email** goes to the identity's email address — which, in offboarding,
  the **organization now controls** — so the org both sees the alert and can satisfy any
  email verification the flow requires.
- The delay's **stop path is itself gated by an emailed OTP** (plus the former PIN or a
  saved VESkey), so stopping a recovery requires control of the identity's email. A
  departing employee who **retained their old VESkey still cannot stop or reverse** the
  recovery: they no longer hold the corporate email and cannot pass the OTP. The OTP gate
  therefore *closes* the interference window rather than leaving it open. (The delay does
  still impose a wait before the org's own recovery finalizes — choose `t` with that in
  mind.)

## What this is and isn't

- **It is** consented, policy-driven continuity: pre-agreed recovery friends + an
  organization-owned identity + active threshold assistance.
- **It is not** a master key or provider backdoor: VES never holds plaintext, the employer
  cannot read at will, and recovery requires the designated friends to act.
- **It does not** let an organization read a *personal* identity it does not own, or
  override an employee who declined to configure the mandated friends — that
  non-compliance is *detectable* (step 2) but not *preventable*, by design.
