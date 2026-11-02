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

A field whose description says "Not stored yet", and the whole of `VexSource`, is ahead of the server: it validates today, and applying it needs the backend change the description names.

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
| `examples/<Kind>/*.yaml` | Valid documents. Every kind needs at least one. |
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
