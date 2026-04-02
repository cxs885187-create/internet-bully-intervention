import base64
import json
import logging
import os
import time
from typing import Any

import httpx
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

try:
    from vercel.functions import RuntimeCache
except Exception:  # pragma: no cover
    RuntimeCache = None


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("internet-bully")

SYSTEM_PROMPT = """
You are Internet_Bully_helper. Classify the user's text for cyberbullying intervention.
Return strict JSON only. No markdown, no code fences, no explanation outside JSON.
Allowed schema:
{
  "level": 0,
  "category": "safe|insult|threat|humiliation|pua|other",
  "reason": "short reason",
  "evidence": ["quoted snippet 1"],
  "confidence": 0.0,
  "warn_text": "warning to send back to the chat"
}
Rules:
- level 0: safe or ambiguous
- level 1: harmful but should only warn
- level 2: severe harassment, threats, humiliation, or manipulative abuse that should be escalated for recall
- Keep warn_text polite, short, and suitable for a group chat
- confidence must be between 0 and 1
""".strip()


class ReplayRequest(BaseModel):
    message_text: str = Field(min_length=1)
    chat_id: str | None = None
    sender_name: str | None = "manual-replay"
    sender_open_id: str | None = "manual-replay"


class Settings:
    def __init__(self) -> None:
        self.feishu_app_id = os.getenv("FEISHU_APP_ID", "")
        self.feishu_app_secret = os.getenv("FEISHU_APP_SECRET", "")
        self.feishu_encrypt_key = os.getenv("FEISHU_ENCRYPT_KEY", "")
        self.feishu_verification_token = os.getenv("FEISHU_VERIFICATION_TOKEN", "")
        self.feishu_admin_chat_id = os.getenv("FEISHU_ADMIN_CHAT_ID", "")
        self.feishu_admin_open_id = os.getenv("FEISHU_ADMIN_OPEN_ID", "")
        self.glm_api_key = os.getenv("GLM_API_KEY", "")
        self.glm_base_url = os.getenv("GLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4").rstrip("/")
        self.glm_model = os.getenv("GLM_MODEL", "glm-4-plus")
        self.runtime_mode = os.getenv("RUNTIME_MODE", "SHADOW").upper()
        self.recall_enabled = os.getenv("FEISHU_RECALL_ENABLED", "false").lower() == "true"
        self.moderation_timeout_seconds = float(os.getenv("MODERATION_TIMEOUT_SECONDS", "12"))


settings = Settings()
app = FastAPI(title="Internet Bully Intervention API", version="1.0.0")

_http_client = httpx.AsyncClient(timeout=settings.moderation_timeout_seconds)
_tenant_token: dict[str, Any] = {"value": None, "expires_at": 0.0}
_memory_dedupe: dict[str, float] = {}
_runtime_cache = RuntimeCache(namespace="internet_bully") if RuntimeCache else None


def _json_log(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    logger.info(json.dumps(payload, ensure_ascii=False))


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.replace("json\n", "", 1).strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON object found in model output")
    return json.loads(cleaned[start : end + 1])


def _normalize_result(data: dict[str, Any]) -> dict[str, Any]:
    level = int(data.get("level", 0))
    level = max(0, min(level, 2))
    category = str(data.get("category", "other")).strip() or "other"
    reason = str(data.get("reason", "")).strip() or "No reason provided"
    evidence = data.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = [str(evidence)]
    evidence = [str(item).strip() for item in evidence if str(item).strip()]
    confidence = data.get("confidence", 0.0)
    try:
        confidence = max(0.0, min(float(confidence), 1.0))
    except (TypeError, ValueError):
        confidence = 0.0
    warn_text = str(data.get("warn_text", "")).strip()
    if not warn_text:
        warn_text = "Please keep the conversation respectful and avoid harmful language."
    return {
        "level": level,
        "category": category,
        "reason": reason,
        "evidence": evidence,
        "confidence": confidence,
        "warn_text": warn_text,
    }


def _decrypt_feishu_body(encrypted_value: str) -> dict[str, Any]:
    key = SHA256.new(settings.feishu_encrypt_key.encode("utf-8")).digest()
    cipher = AES.new(key, AES.MODE_CBC, key[:16])
    decrypted = cipher.decrypt(base64.b64decode(encrypted_value))
    plaintext = unpad(decrypted, AES.block_size).decode("utf-8")
    return json.loads(plaintext)


def _should_warn(level: int, runtime_mode: str) -> bool:
    return level >= 1 and runtime_mode in {"WARN_ONLY", "ENFORCE"}


def _should_recall(level: int, runtime_mode: str) -> bool:
    return level == 2 and runtime_mode == "ENFORCE" and settings.recall_enabled


def _parse_text_content(content: Any) -> str:
    if isinstance(content, dict):
        return str(content.get("text", "")).strip()
    if isinstance(content, str):
        stripped = content.strip()
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
        if isinstance(parsed, dict):
            return str(parsed.get("text", "")).strip()
    return ""


def _cache_seen(event_id: str) -> bool:
    now = time.time()
    for key, expires_at in list(_memory_dedupe.items()):
        if expires_at <= now:
            _memory_dedupe.pop(key, None)
    if event_id in _memory_dedupe:
        return True
    if _runtime_cache:
        cached = _runtime_cache.get(f"event:{event_id}")
        if cached is not None:
            return True
    return False


def _cache_mark(event_id: str) -> None:
    ttl_seconds = 3600
    _memory_dedupe[event_id] = time.time() + ttl_seconds
    if _runtime_cache:
        _runtime_cache.set(f"event:{event_id}", True, {"ttl": ttl_seconds, "tags": ["events"]})


async def _get_feishu_tenant_access_token() -> str:
    if _tenant_token["value"] and _tenant_token["expires_at"] > time.time() + 30:
        return str(_tenant_token["value"])
    if not settings.feishu_app_id or not settings.feishu_app_secret:
        raise HTTPException(status_code=500, detail="Missing Feishu credentials")
    response = await _http_client.post(
        "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
        json={"app_id": settings.feishu_app_id, "app_secret": settings.feishu_app_secret},
    )
    data = response.json()
    if response.status_code >= 400 or data.get("code") not in (0, None):
        raise HTTPException(status_code=502, detail=f"Feishu token failed: {data}")
    token = data["tenant_access_token"]
    expire = int(data.get("expire", 7200))
    _tenant_token["value"] = token
    _tenant_token["expires_at"] = time.time() + expire
    return token


async def _send_feishu_text(chat_id: str, text: str) -> dict[str, Any]:
    access_token = await _get_feishu_tenant_access_token()
    response = await _http_client.post(
        "https://open.feishu.cn/open-apis/im/v1/messages",
        params={"receive_id_type": "chat_id"},
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "receive_id": chat_id,
            "msg_type": "text",
            "content": json.dumps({"text": text}, ensure_ascii=False),
        },
    )
    data = response.json()
    if response.status_code >= 400 or data.get("code") not in (0, None):
        raise HTTPException(status_code=502, detail=f"Feishu send failed: {data}")
    return data


async def _recall_feishu_message(message_id: str) -> dict[str, Any]:
    access_token = await _get_feishu_tenant_access_token()
    response = await _http_client.delete(
        f"https://open.feishu.cn/open-apis/im/v1/messages/{message_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    data = response.json() if response.content else {}
    if response.status_code >= 400 or data.get("code") not in (0, None):
        raise HTTPException(status_code=502, detail=f"Feishu recall failed: {data}")
    return data


async def _moderate_text(message_text: str) -> dict[str, Any]:
    if not settings.glm_api_key:
        raise HTTPException(status_code=500, detail="Missing GLM API key")
    response = await _http_client.post(
        f"{settings.glm_base_url}/chat/completions",
        headers={"Authorization": f"Bearer {settings.glm_api_key}"},
        json={
            "model": settings.glm_model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"Analyze this message only:\n{message_text}",
                },
            ],
        },
    )
    data = response.json()
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"GLM request failed: {data}")
    message = data["choices"][0]["message"]["content"]
    if isinstance(message, list):
        message = "".join(part.get("text", "") for part in message if isinstance(part, dict))
    parsed = _extract_json_object(str(message))
    return _normalize_result(parsed)


async def _handle_intervention(
    *,
    source: str,
    message_text: str,
    chat_id: str | None,
    message_id: str | None,
    sender_name: str | None,
    sender_open_id: str | None,
    event_id: str | None,
) -> dict[str, Any]:
    runtime_mode = settings.runtime_mode
    try:
        result = await _moderate_text(message_text)
    except Exception as exc:
        _json_log("moderation_failed", source=source, event_id=event_id, error=str(exc))
        return {"status": "shadow_due_to_moderation_failure", "runtime_mode": "SHADOW"}

    action_taken = "logged_only"
    send_error = None
    recall_error = None

    if chat_id and _should_warn(result["level"], runtime_mode):
        try:
            await _send_feishu_text(chat_id, result["warn_text"])
            action_taken = "warned"
        except Exception as exc:
            runtime_mode = "SHADOW"
            send_error = str(exc)

    if message_id and _should_recall(result["level"], runtime_mode):
        try:
            await _recall_feishu_message(message_id)
            action_taken = "warned_and_recall_attempted"
        except Exception as exc:
            recall_error = str(exc)

    payload = {
        "status": "ok",
        "source": source,
        "runtime_mode": runtime_mode,
        "action_taken": action_taken,
        "result": result,
        "chat_id": chat_id,
        "message_id": message_id,
        "sender_name": sender_name,
        "sender_open_id": sender_open_id,
        "event_id": event_id,
        "suggested_recall": result["level"] == 2,
        "send_error": send_error,
        "recall_error": recall_error,
    }
    _json_log("intervention_completed", **payload)
    return payload


def _unwrap_feishu_payload(body: dict[str, Any]) -> dict[str, Any]:
    payload = body
    if "encrypt" in body:
        payload = _decrypt_feishu_body(body["encrypt"])
    header = payload.get("header", {})
    token = payload.get("token") or header.get("token")
    if settings.feishu_verification_token and token and token != settings.feishu_verification_token:
        raise HTTPException(status_code=403, detail="Invalid verification token")
    return payload


@app.get("/api/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "internet-bully-intervention",
        "runtime_mode": settings.runtime_mode,
        "glm_model": settings.glm_model,
    }


@app.post("/api/internal/replay")
async def replay(body: ReplayRequest) -> dict[str, Any]:
    return await _handle_intervention(
        source="manual_replay",
        message_text=body.message_text,
        chat_id=body.chat_id,
        message_id=None,
        sender_name=body.sender_name,
        sender_open_id=body.sender_open_id,
        event_id=None,
    )


@app.post("/api/feishu/events")
async def feishu_events(request: Request) -> dict[str, Any]:
    body = await request.json()
    payload = _unwrap_feishu_payload(body)

    if payload.get("type") == "url_verification":
        _json_log("url_verification", challenge_received=True)
        return {"challenge": payload["challenge"]}

    header = payload.get("header", {})
    event = payload.get("event", {})
    event_id = header.get("event_id") or payload.get("uuid")
    event_type = header.get("event_type") or payload.get("type")

    if event_id and _cache_seen(event_id):
        return {"ok": True, "deduplicated": True}

    if event_id:
        _cache_mark(event_id)

    if event_type != "im.message.receive_v1":
        _json_log("ignored_event", event_type=event_type, event_id=event_id)
        return {"ok": True, "ignored": True, "event_type": event_type}

    sender = event.get("sender", {})
    if sender.get("sender_type") == "app":
        return {"ok": True, "ignored": True, "reason": "self_message"}

    message = event.get("message", {})
    message_type = message.get("message_type")
    if message_type != "text":
        _json_log("ignored_non_text_message", event_id=event_id, message_type=message_type)
        return {"ok": True, "ignored": True, "reason": "non_text"}

    text = _parse_text_content(message.get("content"))
    if not text:
        return {"ok": True, "ignored": True, "reason": "empty_text"}

    sender_id = sender.get("sender_id", {})
    sender_open_id = sender_id.get("open_id") if isinstance(sender_id, dict) else None

    result = await _handle_intervention(
        source="feishu_event",
        message_text=text,
        chat_id=message.get("chat_id"),
        message_id=message.get("message_id"),
        sender_name=sender.get("sender_name"),
        sender_open_id=sender_open_id,
        event_id=event_id,
    )
    return {"ok": True, "handled": True, "result": result}
