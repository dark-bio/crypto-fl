# Security policy

This plugin wraps the Rust cryptographic library crypto-rs for Flutter. It is
part of the foundation of the Dark Bio ecosystem, so reports are taken
seriously and handled quickly.

## Reporting a vulnerability

Please do not open a public issue for anything that looks like a security
problem. Send a private email to peter@dark.bio instead, with a description of
the issue, the affected version and, if you have one, a way to reproduce it.
You will get an acknowledgement within a few days, and updates as the fix
progresses.

Findings in the underlying libraries belong with their own maintainers, but a
report here is still welcome. We track the RustSec and OSV advisory databases
daily and ship dependency fixes as new releases.

## Supported versions

Only the latest release on pub.dev receives fixes. Versions are 0.x and every
minor bump may change the API, so fixes ship as new versions rather than
backports. Consumers should track the latest release.

## Disclosure

Fixes are released first and disclosed afterwards. Once a fixed version is on
pub.dev, an advisory is filed with the GitHub Advisory Database, which pub.dev
shows to users. The report is credited unless you prefer otherwise.

The Rust, Go and TypeScript siblings of this plugin share its design and
version numbers. A report affecting the design is coordinated across all of
them before disclosure.
