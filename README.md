# ScamSafe Alliance Frontline AI Assistant

React + TypeScript + Node.js prototype for authorised frontline workers. The three-page Case Intake → AI Analysis → Recommended Actions workflow remains employee-controlled. Nothing is sent, referred, frozen, or executed.

## Effective decision policy

`docs/ScamSafe_AI_Decision_Policy_中文版.md` version 1.0 is the sole active business policy. The server loads this file at startup, includes its full contents in the AI extraction instructions, and returns `policyVersion` with analysis responses. The matching synthetic acceptance cases are in `docs/ScamSafe_Acceptance_Cases.json`.

Legacy Rules v4.1/v4.2 documents and the older workflow/build prompts are historical reference material only; they are not loaded by the application and must not be treated as active business policy.

## Start

```powershell
cd 'D:\5706 Codex'
pnpm install
pnpm run dev
```

Open `http://localhost:5173`.

## Real AI mode

Gemini is the default provider. Set the key only in the server environment; never put it in browser code or commit a `.env` file.

```powershell
$env:AI_PROVIDER = 'gemini'
$env:GEMINI_API_KEY = 'your-key'
$env:GEMINI_MODEL = 'gemini-3.8-flash'
pnpm run dev
```

OpenAI Responses API is optional (`AI_PROVIDER=openai`, `OPENAI_API_KEY`, `OPENAI_MODEL`). The UI reports Real AI Mode only after a successful, schema-valid API response for that analysis. API or validation failure is shown explicitly and uses clearly labelled **Limited Demo Mode**; Demo Mode does not provide full semantic AI analysis and flags unresolved safety cues for urgent human review.

## Demo and verification

Choose **Immediate safety concern**, analyse it, confirm P1 and Designated Safety Contact, then review the recommendation and generate a Not Sent report.

```powershell
pnpm run test
pnpm run typecheck
pnpm run build
```

Tests include the acceptance cases plus mocked provider success/failure paths. Mocked Real AI tests verify the application contract; they do not substitute for a live Gemini or OpenAI service call.

