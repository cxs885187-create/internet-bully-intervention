# Internet Bully Intervention API

Vercel-first FastAPI service for:

- receiving Feishu event subscriptions
- classifying text with GLM-4-Plus
- warning the group when content is risky
- reserving a future recall path for severe messages

## Routes

- `GET /api/healthz`
- `POST /api/feishu/events`
- `POST /api/internal/replay`

## Runtime modes

- `SHADOW`: log only
- `WARN_ONLY`: send warnings for level 1 and 2
- `ENFORCE`: warn for level 1 and 2, and try recall for level 2 when `FEISHU_RECALL_ENABLED=true`

## Environment variables

Copy values from `.env.example` into Vercel Project Settings.

Required for v1:

- `FEISHU_APP_ID`
- `FEISHU_APP_SECRET`
- `FEISHU_ENCRYPT_KEY`
- `FEISHU_VERIFICATION_TOKEN`
- `GLM_API_KEY`

Recommended defaults:

- `GLM_BASE_URL=https://open.bigmodel.cn/api/paas/v4`
- `GLM_MODEL=glm-4-plus`
- `RUNTIME_MODE=SHADOW`
- `FEISHU_RECALL_ENABLED=false`

## Local run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn api.index:app --reload
```

The routes will then be:

- `http://127.0.0.1:8000/api/healthz`
- `http://127.0.0.1:8000/api/feishu/events`
- `http://127.0.0.1:8000/api/internal/replay`

## Deploy to Vercel

1. Import the project into Vercel
2. Add environment variables from `.env.example`
3. Deploy
4. After deployment, your webhook URL should look like:

```text
https://your-project.vercel.app/api/feishu/events
```

5. Put that URL into the Feishu event subscription settings

## Replay test

Use this payload to test the moderation pipeline without Feishu:

```json
{
  "message_text": "You are worthless and everyone hates you.",
  "chat_id": "oc_xxx"
}
```

## Current limitations

- text messages only
- no database
- recall path is implemented but disabled by default
- deduplication uses Vercel Runtime Cache when available, with in-memory fallback
