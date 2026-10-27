# ScamSafe Alliance Frontline AI Assistant

React + TypeScript + Vite prototype for authorised frontline workers. It accepts synthetic fictional narratives, performs dynamic local policy analysis or server-side model analysis, supports per-recommendation human review, and assembles an unsent case report. It does not send messages, create referrals, freeze funds, modify accounts, or contact real institutions.

## Start

```powershell
cd 'D:\5706 Codex'
pnpm install
pnpm run dev
```

Open `http://localhost:5173`.

## Real AI mode

The server exposes `POST /api/analyze`. Keep the key server-side:

```powershell
$env:OPENAI_API_KEY = 'your-key'
$env:OPENAI_MODEL = 'gpt-4.1-mini'
pnpm run dev
```

The server asks for structured JSON, rejects provider failures, and the UI falls back to the clearly labelled **Local Rule-Based Demo Mode** when no key or valid response is available. No browser-exposed key is used.

## Demo

Choose **Suspicious store + card debit**, analyse it, review the P1 card-dispute action and the additional Community Support action, then accept/modify/reject them independently and generate the report. The report includes every decision and remains marked **Synthetic Case Report — Not Sent**.

## Checks

```powershell
pnpm run test
pnpm run typecheck
pnpm run build
```

The requested `docs/*.md` files were absent from the project directory. The available `ScamSafe_Codex_Build_Prompt.md`, `AI_Assistant_Workflow_Chinese.md`, and the available v4.1 Word rules document were used as references.
