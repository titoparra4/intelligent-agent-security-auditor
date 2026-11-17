# Tool permissions, identities and least privilege (MODULE 05)

## The matrix

`Tool | Identity | Permissions | Data Access | Operations | Risk | Required Approval` — plus
**provenance** for every permission: `declared` (manifest), `code`/`configured` (requested in
code/config, e.g. `scopes=[...]`), `inferred` (names only), `verified` (observed in a sandbox).

## Scope catalog (excerpt)

| Scope / role | Grants | Narrower alternative |
|---|---|---|
| `https://mail.google.com/` | read, write, delete, send all mail | `gmail.readonly` / `gmail.send` |
| `…/auth/gmail.modify` | read, write, send | `gmail.readonly` |
| `…/auth/drive` | read, write, delete, share all files | `drive.file` or `drive.readonly` |
| `…/auth/cloud-platform` | broad GCP admin | service-specific roles |
| `Mail.ReadWrite`, `Files.ReadWrite.All`, `Sites.FullControl.All`, `Directory.ReadWrite.All` | broad Microsoft Graph | `Mail.Read`, `Files.Read`, `Sites.Selected` |
| GitHub `repo`, `admin:org`, `delete_repo` | broad repo/org | fine-grained token per repository |
| `*`, `admin`, `owner`, `root`, `db_owner`, `rds_superuser`, `ALL PRIVILEGES` | administrative | task-specific role |

PERM-001 fires when a broad scope grants operations the tool does not perform; PERM-002 for
administrative/wildcard grants (CRITICAL). Unknown scopes are not guessed: they produce no
finding, and CTRL-PERM-01 stays NOT_VERIFIED unless every tool's permissions are known.

## Enforcement must be outside the prompt

- Authorization is evaluated by the tool or backend using the **end-user identity**
  (on-behalf-of tokens, row-level security), not by the model.
- One identity per tool (PERM-003): attributable audit logs, contained compromise.
- Approval for privileged actions is a runtime gate (see autonomous-actions.md).
- Policy conformance (PERM-004/005): authorized tool list, forbidden operations per profile.

## Declaring permissions

```yaml
tools:
  - name: drive_search
    operations: [read]
    data_access: [documents]
    data_classification: [confidential]
    identity: svc-drive-reader
    permissions: ["https://www.googleapis.com/auth/drive.readonly"]
```
Declarations are accepted as evidence only when the policy sets `evidence.accept_declared: true`
(the high-risk profile does not).
