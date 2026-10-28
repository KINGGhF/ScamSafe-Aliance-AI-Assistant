# ScamSafe Alliance Frontline AI Assistant

React + TypeScript + Vite prototype for authorised frontline workers. Gemini extracts narrative facts and uncertainty by default; a deterministic ScamSafe rules engine applies priorities, routing, and recommendations. It supports per-recommendation human review and assembles an unsent case report. It does not send messages, create referrals, freeze funds, modify accounts, or contact real institutions.

## Start

```powershell
cd 'D:\5706 Codex'
pnpm install
pnpm run dev
```

Open `http://localhost:5173`.

## Real AI mode

Rules v4.2 uses Gemini for structured semantic extraction. Keep the key server-side:

```powershell
$env:AI_PROVIDER = 'gemini'
$env:GEMINI_API_KEY = 'your-key'
$env:GEMINI_MODEL = 'gemini-3.8-flash'
pnpm run dev
```

The server asks Gemini for schema-constrained facts and a context-aware safety assessment, then validates the response before applying deterministic ScamSafe rules. An optional OpenAI Responses API provider is available with `AI_PROVIDER=openai`, `OPENAI_API_KEY`, and `OPENAI_MODEL`. Without a configured provider or valid response, the interface shows **Limited Demo Mode**. Demo Mode does not provide full semantic AI analysis; ambiguous safety cues require human review instead of silently defaulting to P3.

## Demo

Choose **Suspicious store + card debit**, analyse it, review the P1 card-dispute action and the additional Community Support action, then accept/modify/reject them independently and generate the report. The report includes every decision and remains marked **Synthetic Case Report — Not Sent**.

## Checks

```powershell
pnpm run test
pnpm run typecheck
pnpm run build
```

