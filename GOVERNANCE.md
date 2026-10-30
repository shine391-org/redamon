# RedAmon Governance

This document explains who makes decisions in RedAmon, how they are made, and how
the project is funded. It applies to this repository; the
[redamon-plugins](https://github.com/samugit83/redamon-plugins) repository follows
the same rules.

## Model

RedAmon is a young project led by its creator. The lead maintainer has the final say,
and decisions are taken in the open: in issues, discussions, pull requests and the
project board. As the community grows, more of these decisions will move to the
maintainers and Core contributors as a group.

## Roles

| Role | Who | What they can do |
|---|---|---|
| **Lead maintainer** | Samuele Giampieri ([@samugit83](https://github.com/samugit83)), creator and owner | Sets the roadmap and scope, merges, tags releases, publishes security advisories, appoints maintainers, owns the name and logo. Final say on any decision. |
| **Co-maintainer** | Ritesh Gohil ([@L4stPL4Y3R](https://github.com/L4stPL4Y3R)), lead security researcher | Reviews and merges pull requests, triages issues and security reports, and stands in for the lead maintainer (see [Continuity](#continuity)). |
| **Core contributors** | By invitation | Push access to non-protected branches, merge pull requests, vote on roadmap priorities. |
| **Contributors** | Anyone | Open issues, pull requests, test reports and discussions. Earn ranks as described in [CONTRIBUTING.md](CONTRIBUTING.md#contributor-ranks). |
| **Plugin administrators** | Appointed by the lead maintainer | Review, merge, release and sign plugins in `redamon-plugins`. Only they can publish a plugin to the catalog. |

The lead maintainer invites Core contributors and appoints maintainers, based on
sustained contribution, knowledge of the codebase and trust. Access that has not been
used for 12 months is removed, and can be restored on request.

## How decisions are made

- **Pull requests** need the approval of a maintainer or Core contributor before they
  are merged into `master`. Contributors follow [CONTRIBUTING.md](CONTRIBUTING.md).
- **Roadmap.** Priorities live on the GitHub project board. Core contributors vote on
  them; the lead maintainer decides the final order.
- **Disagreements** are discussed in the issue or pull request. Maintainers look for
  agreement first; when there is none, the lead maintainer decides and explains why.
- **Releases** follow [Semantic Versioning](https://semver.org/) and are recorded in
  [CHANGELOG.md](CHANGELOG.md). The lead maintainer tags each release.

## Scope: authorized testing only

RedAmon is built for authorized security testing. Maintainers decline any contribution
designed for malicious use, detection evasion or unauthorized access, whatever its
technical quality. The rules for users are in [DISCLAIMER.md](DISCLAIMER.md); the rules
for contributors are in
[CONTRIBUTING.md](CONTRIBUTING.md#legal-and-ethical-responsibilities).

## Security

Vulnerabilities in RedAmon are reported privately, as described in
[SECURITY.md](SECURITY.md). The maintainers triage each report, prepare the fix in
private, release it, and then publish a GitHub security advisory crediting the reporter.
Security decisions are made by the maintainers alone; sponsors and funders have no part
in them.

## Funding and sponsors

- **The project stays complete and free.** RedAmon is MIT licensed. No feature or
  security update is held back for sponsors or paying users.
- **Who receives the money.** Grants for RedAmon are shared equally between the lead
  maintainer and the co-maintainer, and paid to each directly where the funder allows
  it; otherwise they are paid to the lead maintainer, who pays the co-maintainer's share.
  Sponsorships are paid to the lead maintainer. Receiving money changes no one's rights
  over the code or the licence.
- **Sponsors buy visibility, never influence.** A sponsor may get its logo and name shown
  and a seat on roadmap calls. A sponsor never decides product defaults, findings, scores,
  benchmark results or security decisions, and never gets access to users' data.
- **Every sponsorship is public**, in the README and in release notes.
- **Who is not accepted as a sponsor:** parties under EU sanctions, vendors of spyware
  or surveillance aimed at civil society, and anyone whose use of RedAmon would break
  [DISCLAIMER.md](DISCLAIMER.md).
- The project's funding needs are published in [funding.json](funding.json). To sponsor
  RedAmon, write to **samuele@redamon.org**.

## Name and logo

The code is MIT licensed, so anyone may use, copy and fork it. The RedAmon name and logo
are trademarks of the lead maintainer, and their use is governed by
[TRADEMARKS.md](TRADEMARKS.md). A fork that is distributed must use a different name.

## Code of conduct

Everyone in the project follows the
[code of conduct](CONTRIBUTING.md#code-of-conduct). Maintainers enforce it: they may
edit or remove content, and warn or block anyone who breaks it.

## Contributions and licence

Contributions are accepted under the MIT licence of this repository. Contributors keep
the copyright on their own work.

## Continuity

If the lead maintainer is unreachable for more than 30 days, the co-maintainer may
merge and release security fixes, so that users are not left exposed. Decisions on
scope, the roadmap, the name and funding wait for the lead maintainer.

## Changes to this document

The lead maintainer changes this document through a public pull request. The version
in this repository is the current one.
