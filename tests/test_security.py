import json
import pytest
from autogen_agentchat.agents import UserProxyAgent
from autogen_agentchat.messages import TextMessage
from autogen_core import CancellationToken
from autogen_nti import NTISecurityWrapper


def test_grant_capability_and_verify_message():
    wrapper = NTISecurityWrapper(agent_id="finance_agent", strict=True, require_signature=False)
    wrapper.grant_capability("execute_transfer")

    msg = {"action": "transfer", "amount": 100}
    assert wrapper.verify_message(capability="execute_transfer", message=msg) is True


def test_unsigned_message_blocked_when_signature_required():
    wrapper = NTISecurityWrapper(agent_id="finance_agent", strict=True, require_signature=True)
    wrapper.grant_capability("execute_transfer")

    msg = {"action": "transfer", "amount": 100}
    with pytest.raises(PermissionError) as exc_info:
        wrapper.verify_message(capability="execute_transfer", message=msg)
    assert "Unsigned message blocked" in str(exc_info.value)


def test_ungranted_capability_raises_in_strict_mode():
    wrapper = NTISecurityWrapper(agent_id="finance_agent", strict=True, require_signature=False)
    msg = {"action": "transfer", "amount": 100}

    with pytest.raises(PermissionError) as exc_info:
        wrapper.verify_message(capability="execute_transfer", message=msg)
    assert "NTI Security Denied Action" in str(exc_info.value)


def test_ungranted_capability_returns_false_in_non_strict_mode():
    wrapper = NTISecurityWrapper(agent_id="finance_agent", strict=False, require_signature=False)
    msg = {"action": "transfer", "amount": 100}

    assert wrapper.verify_message(capability="execute_transfer", message=msg) is False


def test_valid_pqc_signature_verification():
    wrapper = NTISecurityWrapper(agent_id="finance_agent", strict=True, require_signature=True)
    wrapper.grant_capability("execute_transfer")

    msg = {"action": "transfer", "amount": 100}
    msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
    signature = wrapper.sign(msg_bytes)

    assert wrapper.verify_message(capability="execute_transfer", message=msg, signature=signature) is True


def test_tampered_message_signature_rejection():
    wrapper = NTISecurityWrapper(agent_id="finance_agent", strict=True, require_signature=True)
    wrapper.grant_capability("execute_transfer")

    msg = {"action": "transfer", "amount": 100}
    msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
    signature = wrapper.sign(msg_bytes)

    tampered_msg = {"action": "transfer", "amount": 999999}

    with pytest.raises(PermissionError) as exc_info:
        wrapper.verify_message(capability="execute_transfer", message=tampered_msg, signature=signature)
    assert "Invalid PQC signature or tampered message" in str(exc_info.value)


def test_invalid_signature_rejection():
    wrapper = NTISecurityWrapper(agent_id="finance_agent", strict=True, require_signature=True)
    wrapper.grant_capability("execute_transfer")

    msg = {"action": "transfer", "amount": 100}

    with pytest.raises(PermissionError) as exc_info:
        wrapper.verify_message(capability="execute_transfer", message=msg, signature="invalid_hex_signature")
    assert "Invalid PQC signature or tampered message" in str(exc_info.value)


def test_embedded_signature_in_message():
    wrapper = NTISecurityWrapper(agent_id="finance_agent", strict=True, require_signature=True)
    wrapper.grant_capability("execute_transfer")

    msg = {"action": "transfer", "amount": 100}
    msg_bytes = json.dumps(msg, sort_keys=True).encode("utf-8")
    signature = wrapper.sign(msg_bytes)

    msg_with_sig = dict(msg, pqc_signature=signature)
    assert wrapper.verify_message(capability="execute_transfer", message=msg_with_sig) is True


def test_public_key_and_kyber_bytes():
    wrapper = NTISecurityWrapper(agent_id="agent_1")
    pub_hex = wrapper.public_key_hex()
    assert isinstance(pub_hex, str)
    assert len(pub_hex) > 0

    kyber_bytes = wrapper.kyber_public_key_bytes()
    assert isinstance(kyber_bytes, bytes)
    assert len(kyber_bytes) > 0


def test_voter_key_registration_and_token_revocation():
    wrapper = NTISecurityWrapper(agent_id="consensus_agent")
    wrapper.register_voter_key("voter_1", b"dummy_voter_public_key")
    wrapper.revoke_token("token_123")


@pytest.mark.asyncio
async def test_autogen_real_agent_interception_granted():
    wrapper = NTISecurityWrapper(agent_id="user_proxy", strict=True, require_signature=False)
    wrapper.grant_capability("chat_response")

    def fixed_input_func(prompt: str) -> str:
        return "Fixed User Input"

    real_agent = UserProxyAgent(name="user_proxy", input_func=fixed_input_func)
    wrapped_agent = wrapper.wrap_agent(real_agent, capability="chat_response")

    msg = TextMessage(content="Hello agent", source="user")
    response = await wrapped_agent.on_messages([msg], CancellationToken())
    assert response is not None


@pytest.mark.asyncio
async def test_autogen_real_agent_interception_denied():
    wrapper = NTISecurityWrapper(agent_id="user_proxy", strict=True, require_signature=False)

    def fixed_input_func(prompt: str) -> str:
        return "Fixed User Input"

    real_agent = UserProxyAgent(name="user_proxy", input_func=fixed_input_func)
    wrapped_agent = wrapper.wrap_agent(real_agent, capability="chat_response")

    msg = TextMessage(content="Hello agent", source="user")

    with pytest.raises(PermissionError) as exc_info:
        await wrapped_agent.on_messages([msg], CancellationToken())
    assert "NTI Security Denied Action" in str(exc_info.value)
