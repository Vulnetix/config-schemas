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

A field or kind whose description says "Not stored yet" (`DetectionRuleFeed.spec.selector`, `CloudSensors` for one account), and the whole of `VexSource`, is ahead of the server: it validates today, and applying it needs the backend change the description names.

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
| `examples/<Kind>/*.yaml` | Other valid documents. |
| `testdata/invalid/<Kind>/*.yaml` | Documents that must be rejected; the first line says why. |
| `cmd/schemacheck` | `release` builds the release files; `compat` fails a release that breaks the previous one without a major bump. |
| `cel/` | The CEL environments for rule expressions, with golden vectors. See [cel/README.md](cel/README.md). |
| `cmd/celdoc` | Prints the CEL variable reference as Markdown for the docs site. |

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
