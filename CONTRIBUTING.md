# Contributing to dingdawg-governance

## Run locally

```bash
git clone https://github.com/dingdawg/governance-sdk
cd governance-sdk
npm install
npm run build          # compiles TypeScript → dist/
node dist/index.js     # starts the MCP server on stdio
```

Test a live `govern_action` call:

```bash
node examples/01-basic-governance.js
```

TypeScript compile check (no emit):

```bash
npx tsc --noEmit
```

## Submit a governed agent to the marketplace

Built something on top of this SDK? Submit it at:
**https://dingdawg.com/marketplace/submit**

Submissions should include:
- The agent's `@handle` identity
- Which regulated use case it targets (healthcare, fintech, employment, etc.)
- A link to a public repo or working demo
- At least one example showing a governance receipt

The DingDawg team reviews submissions within 3 business days.

## Code style

- **TypeScript strict mode** — `"strict": true` is enforced in `tsconfig.json`. No `any`, no implicit returns, no unused variables.
- Keep functions pure where possible. Side effects (filesystem, network) belong in clearly named helpers.
- All async paths must handle errors explicitly — no silent swallows (`catch {}`).
- No hardcoded credentials, URLs, or machine-specific paths in source.

## PR requirements

Every pull request must include:

1. **An example** — add or update a file in `examples/` showing the new behavior with expected output in comments.
2. **A test** — the CI smoke test in `.github/workflows/ci.yml` must stay green. If you add a new tool, add a corresponding smoke test call.
3. **Passing compile check** — `npx tsc --noEmit` must exit 0.
4. **No new `any` types** — use proper interfaces or `unknown` with narrowing.

Open a PR against `main`. The CI badge must be green before merge.
