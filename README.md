# autogen-nti

[![License](https://img.shields.io/badge/License-Apache%202.0-blue)](https://www.apache.org/licenses/LICENSE-2.0)

Drop-in post-quantum security for AutoGen and Microsoft Agent Framework, powered by NTI (Neutral Trust Infrastructure).

## Install

pip install autogen-nti

## Usage

from autogen_nti import NTISecurityWrapper

wrapper = NTISecurityWrapper(agent_id="finance_agent")
wrapper.grant_capability("execute_transfer")

# Verify an incoming message before processing
is_allowed = wrapper.verify_message(
    capability="execute_transfer",
    message={"action": "transfer", "amount": 100}
)

## What it enforces (all 5 pillars)

1. Zero-Trust Capability Enforcement
2. NIST Post-Quantum Cryptography (Dilithium5 / Kyber1024)
3. BFT Multi-Agent Consensus
4. Merkle-Chained Audit Trails
5. P2P Agent Mesh & State Persistence

## License

Apache License 2.0. See LICENSE.

## Links

- Core SDK: https://pypi.org/project/ube-foundation/
- Homepage: https://abisheakp197.github.io/Neutral-Trust-Infrastructure/

## Architecture

```mermaid
graph TD
    subgraph AutoGen["AutoGen Framework"]
        Sender["Sender Agent (ConversableAgent)"]
        MsgLoop["GroupChat / Message Loop"]
        Receiver["Receiver Agent (ConversableAgent)"]
    end

    subgraph NTILayer["NTI Security Layer"]
        Interceptor["Message Interceptor (NTIAgentWrapper)"]
        Wrapper["NTISecurityWrapper"]
        PolicyCheck["Signature & Capability Evaluation"]
        FailClosed["Fail-Closed Logic & Security Logger"]
    end

    subgraph CryptoEngine["Crypto Engine"]
        PQCKey["PqcKeyPair (Dilithium5 / Kyber1024)"]
        TrustEng["TrustEngine (Capability Policy Engine)"]
    end

    %% Flow
    Sender -->|"1. Sign message payload"| PQCKey
    Sender -->|"2. Send message into loop"| MsgLoop
    MsgLoop -->|"3. Intercept on_messages()"| Interceptor
    Interceptor -->|"4. Pass message to verification"| Wrapper

    Wrapper -->|"5. Verify Dilithium5 signature"| PQCKey
    Wrapper -->|"6. Evaluate capability request"| TrustEng
    TrustEng --> PolicyCheck

    PolicyCheck -->|"7a. Valid & Authorized"| Receiver
    PolicyCheck -->|"7b. Unsigned / Spoofed / Unauthorized"| FailClosed
    FailClosed -->|"Block Message & Log Security Event"| MsgLoop
```
