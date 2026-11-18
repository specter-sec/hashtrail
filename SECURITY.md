# Security policy

## Supported code

The current 1.x line is maintained on a best-effort basis. HashTrail is an educational local integrity utility, not a sandbox, malware detector, backup service or evidence certification system.

## Report privately

Use GitHub's private vulnerability reporting option if it is available for this repository. Otherwise use a contact channel shown on the `specter-sec` profile. Do not disclose sensitive filenames, manifests, live credentials or private file contents in public issues. Use a minimal synthetic example for ordinary bugs.

Useful reports identify the affected revision, reproduction steps, expected and actual behavior and impact. There is no guaranteed response time.

## Trust model

The reference manifest must be trusted separately. An attacker who can replace both files and manifest can make verification match. HashTrail provides no digital signature, authentication, trusted timestamp or tamper-proof storage. Content hashes can identify or enable guessing of known files; they are not encryption.

The local filesystem must be stable and not under active adversarial modification. No-follow opens and before/after descriptor checks reduce some races but do not protect against hostile directory-tree mutation or guarantee an atomic snapshot. Use operating-system snapshots or stop writers when consistency matters.

Manifests and reports expose metadata even though source bytes are not included. Store them appropriately. A complete result can still omit excluded paths, symlinks and special objects. Permissions, ownership and other filesystem metadata are outside the comparison policy.
