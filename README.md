# config-schemas

JSON Schemas (draft 2020-12) for every Vulnetix config-as-code kind: the documents `vulnetix config apply` reads from `.vulnetix/config/`, the Terraform provider manages, and the console's "Download as code" writes. This repository is the source of truth; the config engine, the CLI and the provider import it pinned to a release.

Reference documentation for every kind is at https://docs.vulnetix.com (the Platform IaC segment).

## Kinds

| Kind | Since | What it declares |
|---|---|---|
| `QualityGate` | v1.0.0 | The checks every `vulnetix scan` in CI must pass. One per tenant. |
| `JailPolicy` | v1.1.0 | The ordered jail rules for the tenant default or one repository. |
| `JailExemption` | v1.1.0 | A time-boxed waiver of a jail rule for one repository. |
| `LicensePolicy` | v1.1.0 | Licence categories, severities, scopes and per-project overrides. Also valid as the flat `.vulnetix/license-policy.yaml`. |
| `PackageFirewallPolicy` | v1.1.0 | Package firewall thresholds, blocks, mode, per-ecosystem modes and mirrors. One per tenant. |
| `PackageList` | v1.1.0 | Allow or deny list entries, as purls, including namespace entries such as `pkg:npm/@acme/*`. |
| `AiFirewallPolicy` | v1.1.0 | Providers, models, guardrails, capability lists and hold for review. The `.vulnetix/ai-firewall.yaml` document. One per tenant. |
| `AiProvider` | v1.1.0 | A custom AI Firewall provider. |
| `AiGovernanceList` | v1.1.0 | A tool, MCP server, skill or client allow or deny list. |
| `RiskStrategy` | v1.1.0 | An ordered risk prioritisation strategy. |
| `RemediationPolicy` | v1.1.0 | Remediation windows per severity band, or a published standard. One per tenant. |
| `Suppression` | v1.1.0 | A suppression rule with its scope, OpenVEX justification and expiry. |
| `VexSource` | v1.1.0 | VEX documents read back as suppression rules, from TEA, S3, git, a path or URLs. |
| `MalwareIoc` | v1.1.0 | An indicator of compromise the tenant manages. |
| `ApiSpecSource` | v1.2.0 | Where Vulnetix finds an organisation's OpenAPI and Swagger descriptions. |
| `LicenseExceptions` | v1.3.0 | Attributed, expiring exceptions to the licence policy, blanket or per package. Also valid as the flat `.vulnetix/license-exceptions.yaml`. Validate only: the server does not store it yet. |
| `SavedSearch` | v1.3.0 | A Guardian saved search, in the Guardian search language or Sigma. |
| `DetectionRule` | v1.3.0 | A Guardian alert rule: your own Sigma, a saved search, a countermeasure, a SigmaHQ rule or a built-in indicator rule, with its tuning. |
| `AlertTrigger` | v1.3.0 | Run a saved search or rule on a schedule and start a workflow, post a message or send an email when it returns rows. |
| `ScheduledReport` | v1.3.0 | Send a saved search's rows on a calendar, to messaging connections or email. |
| `LogSource` | v1.3.0 | A way logs reach Guardian: the AWS stack's token, Cloudflare Logpush jobs, or the events API. |
| `AwsConnection` | v1.3.0 | How Vulnetix reaches the AWS estate: IAM Identity Center or an access key. One per tenant. |
| `AwsAccount` | v1.3.0 | One connected AWS account, whether it is swept, and its stack deploy. |
| `CloudSensors` | v1.3.0 | Which AWS-native sources and Vulnetix passes are read, for every account or one. |
| `DetectionRuleFeed` | v1.3.0 | A published feed of virtual patches, countermeasures and catalogue rules in one format. |
| `RuntimeSensorPolicy` | v1.3.0 | The configuration runtime sensors enroll with: mode, hold, feeds, forwarding and tamper protection. |
| `Organization` | v1.5.0 | The organisation's display name and company email domains. One per tenant. |
| `Member` | v1.5.0 | A person in the organisation by email, with their role. A new member is invited and reports `Pending` until they accept. |
| `ServiceAccount` | v1.5.0 | A CI credential that is not a person. Its API key is returned once, by the apply that creates it. |
| `NotificationDefaults` | v1.5.0 | Which events are pushed to people who have not chosen for themselves. One per tenant. |
| `VaultEntry` | v1.5.0 | A secret in the tenant's vault (provider key, environment variable or management key) with its grants per surface. The value is sent once and never exported. |
| `GitHubInstallation` | v1.5.0 | Adopts an installation of the Vulnetix GitHub App by its installation id. The App is installed on GitHub; deleting the document does not uninstall it. |
| `ForgeConnection` | v1.5.0 | How the Software Factory reaches GitLab, Gitea, Forgejo or GitHub Enterprise Server: a bot token or a GHES App, and an optional OAuth application for members' own sign-in. |
| `WizConnection` | v1.5.0 | The Wiz service account, verified from inside the connected AWS account. One per tenant; a change replaces it. |
| `MessagingConnection` | v1.5.0 | A messaging destination: Slack (authorized in a browser), Teams, Discord, Google Chat, Jira or a signed webhook. Its credential is kept in the secrets vault. |
| `MessagingRoute` | v1.5.0 | Which events go to which messaging connections, with filters, mentions, template, digest and rate limit. |
| `MessagingTemplate` | v1.5.0 | An organisation's own message template, compiled at plan and versioned on every change. |
| `FactorySettings` | v1.6.0 | The Software Factory settings document: autonomy, System One, crews, forge, Pix, budgets, schedules, defaults and delivery settings. One per tenant. |
| `ScannerProfile` | v1.6.0 | The factory's scanners, minimum SLSA level and build evidence. One per tenant. |
| `FactoryManagedOrg` | v1.6.0 | An organisation or account the Software Factory manages. Which repositories the GitHub App reaches stays on GitHub. |
| `RepositorySettings` | v1.6.0 | The factory's autonomy, kanban mode, token cap, branch protection, TEA publishing and default workflow opt-outs for one repository. Since v1.7.0 it also carries the repository's asset labels, owner and criticality, which are CEL `finding` variables. |
| `FactoryWorkflow` | v1.6.0 | A Software Factory workflow graph, saved as a new version on every change and published with `publish: true`. |
| `FactoryTrigger` | v1.6.0 | A trigger node of a workflow: a webhook event with typed conditions, a finding, a label, a kanban move, a firewall sighting or a manual run. |
| `FactorySchedule` | v1.6.0 | A cron schedule that starts a workflow, with its time zone and timer. |
| `FactoryBudget` | v1.6.0 | A token or call budget for the factory, an organisation, a repository, a workflow or one step, with alerts and the action at the limit. |
| `AgentProfile` | v1.6.0 | A Belai agent definition and the files beside it, by the id in its front matter. Versioned on every change. |
| `Crew` | v1.6.0 | A named set of Belai worker agents a host runs together. |
| `LibraryItem` | v1.6.0 | A skill, prompt, command, process, MCP server, repo, budget, provider, rewrite table, hook bundle or launch configuration of the Belai library, checked by the library's own validator. |
| `SandboxLaunchProfile` | v1.6.0 | What the next launch of a Pix sandbox installs and how Belai runs on it. |
| `SandboxEgressPolicy` | v1.6.0 | A Pix sandbox's egress mode and the hostnames it may or may not reach. |
| `TeaProduct` | v1.6.0 | A product published through the Transparency Exchange API. Its releases and artifacts are published by CI, not declared. |
| `TeaComponent` | v1.6.0 | A component published through the Transparency Exchange API. |
| `TeaCollection` | v1.6.0 | The collection of a release CI has published, so an access policy can name it. |
| `TeaAccessPolicy` | v1.6.0 | Who may read a TEA product, component or collection: private, shared with named organisations, or public. |
| `TeaPublicationTarget` | v1.6.0 | A remote TEA server registered for mirroring, with its credential. |
| `Campaign` | v1.6.0 | A remediation campaign: its scope, done criteria, timing, deadline and contributors. Removing it archives the campaign. |
| `SsvcPolicy` | v1.8.0 | How the tenant makes its CISA SSVC decision (Track, Track*, Attend, Act): how signals become the decision points, table cells read differently, rules that decide by finding or repository, and what each outcome asks. One per tenant. |
| `RegistryConnection` | v1.10.0 | A private npm, PyPI, Maven or OCI registry that scans may read, with its scope. The credential is kept in the secrets vault. |

A field or kind whose description says "Not stored yet" (`CloudSensors` for one account), and the whole of `VexSource`, is ahead of the server: it validates today, and applying it needs the backend change the description names.

## Schema URLs

Each release publishes every schema as a release asset. The asset URL is the schema's `$id`.

| Use | URL |
|---|---|
| A pinned version | `https://github.com/Vulnetix/config-schemas/releases/download/v1.0.0/QualityGate.schema.json` |
| The newest release | `https://github.com/Vulnetix/config-schemas/releases/latest/download/QualityGate.schema.json` |
| Any kind, by its `kind` field | `.../vulnetix-config.schema.json` |
| The kinds in a release | `.../index.json` |

Every asset has a Sigstore bundle beside it (`<file>.sigstore.json`, keyless, signed by this repository's release workflow), and `SHA256SUMS` lists them all:

```sh
cosign verify-blob QualityGate.schema.json \
  --bundle QualityGate.schema.json.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Vulnetix/config-schemas/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

To validate as you type in an editor with the YAML language server, start a file with:

```yaml
# yaml-language-server: $schema=https://github.com/Vulnetix/config-schemas/releases/latest/download/vulnetix-config.schema.json
```

## A document

```yaml
apiVersion: vulnetix.com/v1
kind: QualityGate
metadata:
  name: default
spec:
  severity: high
  blockMalware: true
```

`apiVersion` is the document format and stays `vulnetix.com/v1`. The release version moves on its own: additive changes are a minor release, and anything that could reject a document an earlier release accepted needs a major release.

## Kind metadata (`x-vulnetix`)

Every schema carries an `x-vulnetix` object at its root. Validators ignore it; generators and clients read it instead of keeping their own tables. Each release's `index.json` repeats it per kind as `meta`, and Go code reads it with `configschemas.KindMeta(kind)`.

| Field | Meaning |
|---|---|
| `validateOnly` | The CLI validates the kind and never sends it: nothing on the server stores it yet. Plan notes it; apply skips it. |
| `singleton` | One per tenant, named `default`. |
| `dependsOn` | Kinds this kind refers to by `metadata.name`, which apply creates first. A kind listed may be newer than the release. |
| `secrets` | Field paths that take a `valueFrom`. The value is read on the client, sent once, and never exported or shown. |
| `celFields` | Field paths that take a CEL expression, each with the `env` (the [cel](cel/README.md) context) it is compiled and evaluated in. |

Paths are dotted from the document root, and `[]` means every item of an array: `spec.rules[].when`. A test derives `singleton`, `secrets` and `celFields` from the schema itself and fails when the annotation disagrees.

## Use from Go

```go
v, err := configschemas.NewValidator()
docs, err := configschemas.Decode(file) // multi-document YAML or JSON
for _, d := range docs {
	if err := v.Validate(d); err != nil { ... }
}
```

Validation never fetches anything: `$ref`s resolve against the embedded copy.

## Layout

| Path | What |
|---|---|
| `schemas/<Kind>.schema.json` | One schema per kind. `$id` uses `v0.0.0-dev`; the release rewrites it to the tag. |
| `schemas/common.schema.json` | Shared definitions: metadata, `valueFrom` secrets, CEL expressions, purl, severities, VEX justifications. |
| `examples/<Kind>/minimal.yaml` | One document with only the required fields. |
| `examples/<Kind>/advanced.yaml` | Every field, a CEL rule where the kind takes one, and secrets as `valueFrom.env`. Several documents when the kind has mutually exclusive forms. The Terraform provider and the docs render both files; a test holds them to this shape. |
| `examples/<Kind>/unsupported-features.yaml` | Fields the schema accepts that a server cannot honour yet, so they are kept out of `advanced.yaml`, which is applied. Validated, and counted with `advanced.yaml` toward setting every field. Only VexSource has one. |
| `examples/<Kind>/*.yaml` | Other valid documents. |
| `testdata/invalid/<Kind>/*.yaml` | Documents that must be rejected; the first line says why. |
| `cmd/schemacheck` | `release` builds the release files; `compat` fails a release that breaks the previous one without a major bump. |
| `cel/` | The CEL environments for rule expressions, with golden vectors. See [cel/README.md](cel/README.md). |
| `cmd/celdoc` | Prints the CEL variable reference as Markdown for the docs site. |
| `ssvc/` | The CISA SSVC decision (Coordinator table 2.0.3) and the SsvcPolicy that configures it, shared by every runtime that decides. |

## Develop

```sh
go test ./...
go run ./cmd/schemacheck release --version v0.0.0 --out /tmp/dist
```

## Release

```sh
git tag v1.1.0 && git push origin v1.1.0
```

`.github/workflows/release.yml` tests, checks compatibility against the previous tag, builds, signs and publishes. If the job fails after the tag exists, run the workflow by hand with that tag; every step is safe to repeat.

## License

Apache-2.0.
