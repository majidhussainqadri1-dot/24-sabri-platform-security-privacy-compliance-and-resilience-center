# File 24 — Review and Correction Cycle 41

**Defect:** F24-D075 — Privacy verification accepted any existing user ID as a manual verifier.

The evidence validator checked that `verified_by_user_id` existed, but manual document review returned confirmed without proving that the authenticated actor owned that verifier identity or had privacy-request authority.

## Correction

Manual review now requires the verifying user to equal the current authenticated actor and to hold `spcrc_manage_privacy_requests`. Authenticated-session verification remains strictly self-bound. Other methods require either the same capable operator or an explicit fail-closed native verifier-authorization adapter, in addition to method-specific proof confirmation.

## Verification

`tests/cycle41-privacy-verifier-authority.php` proves rejection of verifier impersonation, rejection without capability, preservation of self-session verification and separation between verifier authorization and native proof confirmation.
