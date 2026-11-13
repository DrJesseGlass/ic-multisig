---
name: Bug report
about: Something ic-multisig does wrong. Security problems go to the private form instead (SECURITY.md).
title: ''
labels: bug
assignees: ''
---

<!-- If this is a security problem, stop: report it privately at
     https://github.com/DrJesseGlass/ic-multisig/security/advisories/new
     A tally that counts what it should not, or a signature that verifies
     when it should not, is a security problem. -->

## Version

The `ic-multisig` version (`cargo tree -p ic-multisig`), the features
enabled (`candid`, `ed25519`), the target (host or
`wasm32-unknown-unknown`) and `rustc --version`.

## What you did

The smallest code that shows it: the policy, the subject, the approvals,
and the call (`record`, `tally`, `tally_checked`, `ed25519::verify`). A
failing test is ideal.

## What happened

The tally or error you got, or the compiler output. Paste text as text.

## What you expected

## Anything else

Never paste a signing key. Test keys like `SigningKey::from_bytes(&[1u8; 32])`
reproduce everything this crate does.
