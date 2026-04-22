import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class AuditEvent:
    timestamp: datetime
    user_id: str
    action: str  # CREATE, READ, UPDATE, DELETE, LOGIN, LOGOUT
    resource_type: str  # USER, DASHBOARD, THREAT, CONFIG
    resource_id: str
    previous_state: Optional[Dict[str, Any]]
    new_state: Optional[Dict[str, Any]]
    ip_address: str
    user_agent: str
    status_code: int
    error_message: Optional[str]


class ImmutableAuditLog:
    """Hash-chained audit log for tamper evidence."""
    def __init__(self):
        self._last_hash = "GENESIS"
        self._logs = []

    def log_event(self, event: AuditEvent) -> dict:
        payload = {
            "timestamp": event.timestamp.isoformat(),
            "action": event.action,
            "user": event.user_id,
            "ip": event.ip_address,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "status": event.status_code,
            "before": event.previous_state or {},
            "after": event.new_state or {},
            "prev_hash": self._last_hash
        }
        
        payload_str = json.dumps(payload, sort_keys=True)
        current_hash = hashlib.sha256(payload_str.encode()).hexdigest()
        
        payload["hash"] = current_hash
        self._last_hash = current_hash
        self._logs.append(payload)
        
        try:
            from backend.main import db
            import asyncio
            if db:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    loop.create_task(db.save_audit_log(payload))
        except Exception:
            pass

        # Log it to stdout with structlog and maintain in-memory chain.
        logger.info(f"security_audit_event: {event.action} by {event.user_id} hash: {current_hash}")
        return payload

    def verify_chain(self) -> bool:
        """Validate the audit chain integrity."""
        current_prev = "GENESIS"
        
        logs_to_verify = self._logs
        
        try:
            from backend.main import db
            import asyncio
            if db:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    # We can't await easily in sync function, so we'll just check memory
                    # Unless we use run_until_complete which might conflict.
                    pass
        except Exception:
            pass
            
        for log in logs_to_verify:
            if log["prev_hash"] != current_prev:
                logger.critical(f"audit_chain_broken: expected {current_prev} actual {log['prev_hash']}")
                return False
                
            payload_copy = log.copy()
            if "id" in payload_copy:
                del payload_copy["id"]
            del payload_copy["hash"]
            expected_hash = hashlib.sha256(json.dumps(payload_copy, sort_keys=True).encode()).hexdigest()
            
            if log["hash"] != expected_hash:
                logger.critical(f"audit_hash_mismatch: expected {expected_hash} actual {log['hash']}")
                return False
                
            current_prev = log["hash"]
            
        return True

audit_logger = ImmutableAuditLog()
