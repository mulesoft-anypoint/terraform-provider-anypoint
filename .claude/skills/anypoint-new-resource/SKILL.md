---
name: anypoint-new-resource
description: End-to-end pipeline for delivering a new Anypoint resource or data source. TRIGGER when the user asks to "add resource", "add data source", "implement issue", "wire up <Anypoint service>", "scaffold <service>", "new TGW/VPC/DLB/etc.", or references a GitHub issue that requires creating a Terraform resource/data source against Anypoint Platform. Covers OAS3 spec authoring in the sibling client-generator repo, client regeneration via `go mod replace`, provider scaffolding per AGENTS.md, docs/examples, playground verification, and the release dance (generator PR → client module tag → provider `dropreplace` + go get → provider PR). SKIP when the user is only asking to fix a bug in an existing resource, edit docs, or do small tweaks.
---

# Anypoint new resource pipeline

End-to-end recipe for shipping a Terraform resource or data source against MuleSoft Anypoint Platform. Spans two repos:

- **Generator repo** (sibling, path: `../anypoint-automation-client-generator`) — owns the OAS3 specs that drive `anypoint-client-go/*` module generation.
- **Provider repo** (this repo, `terraform-provider-anypoint`) — Terraform plugin consuming those generated clients.

Read `AGENTS.md` in both repos before doing anything mechanical. This skill is the **workflow on top**; AGENTS.md is the style guide.

## Decision tree

Before starting, decide which kind of change:

| Situation | Skip to |
|---|---|
| Client lib exists & API surface known | Phase B (provider scaffolding) |
| Client lib exists but new endpoint needs OAS patching | Phase A2 (spec patch only) then B |
| New Anypoint service, no client lib yet | Phase A (full discovery) |
| Bug fix in existing resource | EXIT — this skill is overkill |

## Phase A — API discovery & spec authoring

### A1. HAR capture (when API is undocumented)

Anypoint public docs are sparse. Most CRUD shapes only exist in the Runtime Manager browser flow. Workflow:

1. Ask the user to perform the action in the Anypoint UI with browser DevTools open, then save the recording as `recordings/cloudhub2/<resource>-attemptN.har` in `Anypoint-Devops-Collective/`.
2. Extract:
   ```bash
   jq -r '.log.entries[] | select(.request.method=="POST" or .request.method=="PATCH" or .request.method=="DELETE") | "=== \(.request.method) \(.request.url)\nREQ: \(.request.postData.text // "")\nRES: \(.response.content.text // "")"' <har>
   ```
3. Document findings in `docs/ISSUE_<N>_<SLUG>.md` (gitignored working notes). Always note:
   - exact path templates (look for `{orgId}`, `{psId}`, etc.)
   - request body schema
   - response shape **incl. status codes**
   - whether array-wrapped, truncated vs full
   - whether PATCH semantics is **replace** or **delta-merge** (huge difference for provider Update logic)
   - state-machine transitions (`refreshing → available`, etc.)
4. Capture multiple attempts: POST, every PATCH variant, DELETE. Lifecycle = `POST → PATCH → DELETE → list shows []`.

### A2. Spec patch

Edit `../anypoint-automation-client-generator/spec/<service>.yml` per the generator repo's `AGENTS.md` rules. Key reminders (full list in generator's AGENTS.md):

- OAS 3.0.0; objects in `#/components/schemas` with `title` on every schema/attribute (camelCase).
- Path-scoped responses go in `#/components/responses`.
- `operationId` is what becomes the Go method name — pick a stable, verb-prefixed name (`CreatePrivateSpaceTransitGateway`, `GetPrivateSpaceTransitGateways`, etc.).
- Avoid `oneOf` / `anyOf`. Generator can't pick a Go type.
- For raw-string responses (e.g. account id endpoint) declare `schema: { type: string }`.

Validate:
```bash
cd ../anypoint-automation-client-generator
npx openapi-generator-cli validate -i spec/<service>.yml
```

### A3. Regenerate locally

```bash
cd ../anypoint-automation-client-generator && make generate
```

Output lands in `dest/<service>/`. Switch the provider's `go.mod` to the local module:
```bash
cd ../terraform-provider-anypoint
go mod edit -replace github.com/mulesoft-anypoint/anypoint-client-go/<service>=../anypoint-automation-client-generator/dest/<service>
go mod tidy
```

**Watch for generator-version bumps.** Newer openapi-generator-cli renames `DefaultApi` → `DefaultAPI`. If the regenerated module uses the new name, scoped-rename only the files that consume this module (do NOT global-replace — other still-old client modules will break).

## Phase B — Provider scaffolding

### B1. Register client

In `anypoint/provider_clients.go`:
- Add import alias matching the submodule directory name.
- Add `<service>client *<service>.APIClient` field on `ProviderConfOutput`.
- Instantiate in `newProviderConfOutput`.

### B2. Resource / data source files

Follow `AGENTS.md` skeletons exactly. Per file:

- `anypoint/resource_<name>.go` — `CreateContext / ReadContext / UpdateContext / DeleteContext`. Define `get<Name>AuthCtx` locally. Mark immutable fields `ForceNew: true`. Composite IDs via `COMPOSITE_ID_SEPARATOR`. Errors as structured `diag.Diagnostic` — never `diag.FromErr`.
- `anypoint/data_source_<name>.go` (singular) — `ReadContext` only. Often pairs with a `*_xxxs.go` plural variant.
- Helpers go into the resource file (e.g. `split<Name>Id`, `flatten<X>List`). Reuse `util.go` (`ListInterface2ListStrings`, `ComposeResourceId`, `DecomposeResourceId`).

**Read semantics gotcha:** Don't blindly trust the field name. The `status` block often contains observed-state (route table view, attachment state). The user-declared input is sometimes nested elsewhere or in `spec`. **Cross-check Read source against PATCH response shape** so updates don't loop. See ISSUE_74_TGW.md for an example of `status.routes` being PS route table, not declared TGW routes.

### B3. Register in maps

- `anypoint/provider_resources.go` → `RESOURCES_MAP`
- `anypoint/provider_datasources.go` → `DATASOURCES_MAP`

Keys: snake_case `anypoint_<name>`.

### B4. Examples

Always one example per resource AND per data source. Layout:
```
examples/resources/anypoint_<name>/
  resource.tf
  import.sh
examples/data-sources/anypoint_<name>/
  data-source.tf
```

`import.sh` must show the composite-id format with a comment block.

### B5. Docs

```bash
$(go env GOPATH)/bin/tfplugindocs generate
```

If not installed: `go install github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@latest`. Commit the generated `docs/<resources|data-sources>/<name>.md`.

## Phase C — Verify end-to-end

1. `make install` (edit `VERSION` and `OS_ARCH` in Makefile first if needed; defaults `1.8.5-SNAPSHOT`, `darwin_arm64`).
2. Playground at `../../playground/anypoint_terraform_playground/` (path is machine-specific; see gitignored `docs/MULTIREPO.md`).
3. Add a `case_<N>.tf` for the issue. Wire prereqs (AWS, networking, etc.).
4. Cycle:
   ```bash
   cd <playground>
   rm -f .terraform.lock.hcl   # only if checksum mismatch
   terraform init -upgrade
   terraform plan -var-file=params.tfvars.json
   terraform apply -var-file=params.tfvars.json
   ```
5. **Test all CRUD paths**:
   - Create → state matches API (verify via `terraform state show` + raw `curl` against API).
   - Update → tweak each updatable field separately. Confirm PATCH dispatches correctly when only some fields change (`d.HasChange("...")` guards).
   - Read drift → run `terraform plan` again with no changes; expect "No changes."
   - Destroy → `terraform destroy`, then `curl` the list endpoint to confirm `[]`.
6. **Never claim done on `apply` alone.** Update + destroy are the failure-prone paths.

## Phase D — Release

Strict ordering. **Each step blocks the next.**

### D1. Generator PR (dev → master)
- Push your spec branch to `anypoint-automation-client-generator`, target `dev`.
- Use the generator's PR template (see `.github/PULL_REQUEST_TEMPLATE.md` there).
- After dev merge, open PR from `dev` to `master`.
- Pipeline on master-merge generates clients and pushes them to `github.com/mulesoft-anypoint/anypoint-client-go`.

### D2. User releases the client module
**You cannot do this — only the user can.** They tag the affected module (e.g. `private_space/vX.Y.Z`) on `anypoint-client-go`. Wait for confirmation with the new version string.

### D3. Provider switch-back
Once user gives the version:
```bash
go mod edit -dropreplace github.com/mulesoft-anypoint/anypoint-client-go/<service>
go get github.com/mulesoft-anypoint/anypoint-client-go/<service>@<vX.Y.Z>
go mod tidy
```

**Sanity check before committing:**
```bash
grep -n "replace " go.mod   # expect no anypoint-client-go entries
```

### D4. Provider PR (feature branch → dev → master)
- Use this repo's `.github/PULL_REQUEST_TEMPLATE.md`.
- Reference the GitHub issue.
- Link the generator PR + the client module release tag in the description.

## Gates / checklist (run before declaring done)

- [ ] Spec validates: `npx openapi-generator-cli validate -i spec/<service>.yml`
- [ ] Local regen succeeds: `make generate` in generator repo
- [ ] `make build` in provider passes
- [ ] `RESOURCES_MAP` / `DATASOURCES_MAP` entries present
- [ ] `examples/resources/...` and `examples/data-sources/...` files exist
- [ ] `docs/` regenerated and committed
- [ ] Playground apply + update + destroy all clean
- [ ] `go.mod` has NO `replace` directive for `anypoint-client-go/*` (only true at final commit time)
- [ ] PR description references issue + generator PR + client module tag

## Common failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `DefaultApi undefined` after regen | Generator version bumped to `DefaultAPI` casing | Scoped rename per file |
| Terraform plan loops forever showing same diff | Read pulls from wrong field (e.g. status vs spec) | Audit `setXxxAttrs` source fields against PATCH/POST response shape |
| `Invalid Request` 400 with no detail | Pre-condition not met (RAM share unaccepted, CIDR overlap, region mismatch) | Capture HAR of working manual flow, diff |
| `terraform.lock.hcl` checksum mismatch after rebuild | Plugin binary changed but lock pins old hash | Delete the lock file, `init` again |
| `goimports` not in PATH | Not installed by default | `go install golang.org/x/tools/cmd/goimports@latest` |
| Resource cannot be imported | `Importer` block missing | Add `Importer: &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext}` |

## Reference paths

- Provider AGENTS.md: `/Users/souf/Workspaces/cat/Anypoint-Devops-Collective/terraform-provider-anypoint/AGENTS.md`
- Generator AGENTS.md: `/Users/souf/Workspaces/cat/Anypoint-Devops-Collective/anypoint-automation-client-generator/AGENTS.md`
- Multirepo notes (gitignored, maintainer-specific): `docs/MULTIREPO.md`
- HAR recordings: `../recordings/cloudhub2/`
- Playground: `../../playground/anypoint_terraform_playground/`
