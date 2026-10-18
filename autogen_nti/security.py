"""
NTI Security Wrapper for AutoGen / Microsoft Agent Framework.
Enforces all 5 pillars of NTI on agent message exchanges and tool calls.
"""

import json
import logging
import uuid
from typing import Any, Dict, Optional, Sequence
from autogen_core import CancellationToken

logger = logging.getLogger("autogen_nti")


class NTISecurityWrapper:
    """
    NTI Security Wrapper for AutoGen / MAF.

    Enforces all 5 pillars of NTI (Neutral Trust Infrastructure) on every
    message exchange:
      Pillar 1 - Zero-Trust Capability Enforcement
      Pillar 2 - NIST Post-Quantum Cryptography (Dilithium5 / Kyber1024)
      Pillar 3 - BFT Multi-Agent Consensus
      Pillar 4 - Merkle-Chained Audit Trails
      Pillar 5 - P2P Agent Mesh & State Persistence
    """

    def __init__(self, agent_id: str, strict: bool = True, require_signature: bool = True) -> None:
        from ube_foundation import PqcKeyPair, TrustEngine

        self.agent_id = agent_id
        self.strict = strict
        self.require_signature = require_signature
        self.engine = TrustEngine()
        self.pqc_key = PqcKeyPair()

    def grant_capability(self, capability: str) -> None:
        self.engine.grant(self.agent_id, capability)

    def revoke_token(self, token_id: str) -> None:
        self.engine.revoke_token(token_id)

    def public_key_hex(self) -> str:
        return self.pqc_key.public_key_hex()

    def kyber_public_key_bytes(self) -> bytes:
        raw = self.pqc_key.get_kyber_public_key_bytes()
        return bytes(raw) if isinstance(raw, (list, tuple)) else raw

    def sign(self, message: bytes) -> str:
        return self.pqc_key.sign(message)

    def verify_signature(self, message: bytes, signature: str) -> bool:
        return self.pqc_key.verify(message, signature)

    def register_voter_key(self, voter_id: str, public_key_bytes: bytes) -> None:
        self.engine.register_voter_key(voter_id, public_key_bytes)

    def verify_message(
        self,
        capability: str,
        message: Dict[str, Any],
        signature: Optional[str] = None,
    ) -> bool:
        """
        Verify an incoming or outgoing message exchange against capability policy and PQC signature.
        Fails closed if capability is not granted, message is unsigned (when require_signature=True),
        or signature verification fails.
        """
        # Determine signature to verify
        sig_to_verify = (
            signature
            or message.get("signature")
            or message.get("pqc_signature")
        )

        if sig_to_verify is None and self.require_signature:
            logger.warning("NTI Security Event: Unsigned message blocked for agent '%s'", self.agent_id)
            if self.strict:
                raise PermissionError("NTI Security Denied Action: Unsigned message blocked")
            return False

        if sig_to_verify is not None:
            # Exclude signature keys when serializing payload for verification
            clean_msg = {k: v for k, v in message.items() if k not in ("signature", "pqc_signature")}
            msg_bytes = json.dumps(clean_msg, sort_keys=True).encode("utf-8")

            if not isinstance(sig_to_verify, str) or not self.pqc_key.verify(msg_bytes, sig_to_verify):
                logger.warning("NTI Security Event: Invalid signature or tampered message for agent '%s'", self.agent_id)
                if self.strict:
                    raise PermissionError("NTI Security Denied Action: Invalid PQC signature or tampered message")
                return False

        # Build ActionRequest for TrustEngine capability evaluation
        req = {
            "id": f"req-{uuid.uuid4()}",
            "actor": self.agent_id,
            "capability": capability,
            "action": "message_exchange",
            "input": message,
            "signature": None,
            "pqc_signature": None,
            "public_key": None,
            "pqc_public_key": None,
            "token": None,
            "identity_claim": None,
        }

        decision_raw = self.engine.evaluate(json.dumps(req))
        decision = json.loads(decision_raw)

        if decision.get("decision") != "Allow":
            reason = decision.get("reason", "Unknown reason")
            logger.warning("NTI Security Event: Action denied for agent '%s': %s", self.agent_id, reason)
            if self.strict:
                raise PermissionError(f"NTI Security Denied Action: {reason}")
            return False

        return True

    def wrap_agent(self, agent: Any, capability: str) -> "NTIAgentWrapper":
        """
        Wrap an AutoGen / MAF ChatAgent to intercept incoming and outgoing conversational messages.
        """
        return NTIAgentWrapper(agent=agent, capability=capability, security_wrapper=self)


class NTIAgentWrapper:
    """
    Agent Wrapper that intercepts AutoGen / MAF messages and applies NTI security verification.
    """

    def __init__(self, agent: Any, capability: str, security_wrapper: NTISecurityWrapper) -> None:
        self.agent = agent
        self.capability = capability
        self.security_wrapper = security_wrapper

    @property
    def name(self) -> str:
        return getattr(self.agent, "name", self.security_wrapper.agent_id)

    @property
    def description(self) -> str:
        return getattr(self.agent, "description", "")

    async def on_messages(
        self,
        messages: Sequence[Any],
        cancellation_token: CancellationToken,
    ) -> Any:
        for msg in messages:
            content = getattr(msg, "content", str(msg))
            source = getattr(msg, "source", "unknown")
            msg_dict = {"source": source, "content": content}
            sig = getattr(msg, "pqc_signature", None)
            self.security_wrapper.verify_message(self.capability, msg_dict, signature=sig)

        return await self.agent.on_messages(messages, cancellation_token)
