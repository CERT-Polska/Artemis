import hashlib
import json
import logging
from typing import Any, Optional, Tuple

from redis import Redis, RedisError

logger = logging.getLogger(__name__)

PENDING_TTL_MS = 60_000
DONE_TTL_MS = 24 * 60 * 60 * 1000


def _body_hash(body: Any) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def _key(token: str, idem: str) -> str:
    token_ns = hashlib.sha256(token.encode()).hexdigest()[:16]
    return f"idem:{token_ns}:{idem}"


class IdempotencyStore:
    """Redis-backed store implementing the Idempotency-Key contract for POST /add.

    States held under each key:
      {"state": "pending", "body": <hash>}            - claimed, handler running
      {"state": "done",    "body": <hash>, "response": <json>}
    """

    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    def begin(self, token: str, idem: str, body: Any) -> Tuple[str, Optional[dict]]:
        """Atomically claim the key. Returns one of:
        ("new", None)                - caller should execute the handler
        ("replay", cached_response)  - caller should return cached_response verbatim
        ("in_flight", None)          - another request with the same key+body is running
        ("conflict", None)           - key reused with a different body
        """
        k = _key(token, idem)
        bh = _body_hash(body)
        claim = json.dumps({"state": "pending", "body": bh})
        if self.redis.set(k, claim, nx=True, px=PENDING_TTL_MS):
            return "new", None

        raw = self.redis.get(k)
        if not raw:
            # TTL expired between SET NX and GET; retry the claim once.
            if self.redis.set(k, claim, nx=True, px=PENDING_TTL_MS):
                return "new", None
            raw = self.redis.get(k) or b"{}"

        existing = json.loads(raw)
        if existing.get("body") != bh:
            return "conflict", None
        if existing.get("state") == "pending":
            return "in_flight", None
        return "replay", existing.get("response")

    def finalize(self, token: str, idem: str, body: Any, response: dict) -> None:
        k = _key(token, idem)
        payload = json.dumps({"state": "done", "body": _body_hash(body), "response": response})
        self.redis.set(k, payload, px=DONE_TTL_MS)

    def abort(self, token: str, idem: str) -> None:
        try:
            self.redis.delete(_key(token, idem))
        except RedisError as e:
            logger.warning("idempotency abort failed: %s", e)
