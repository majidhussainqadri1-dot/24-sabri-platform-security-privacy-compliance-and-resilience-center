# File 24 0.99.0 — API and Event Contracts

Private REST namespace: `sabri-security/v1`.

Repository APIs expose bounded governance types, artifact lists/saves, traceability, status and Trust Center data with capability callbacks and private no-store/noindex headers where applicable. REST cookie authentication still requires WordPress nonce behavior; application capability and object authorization remain mandatory.

Security events are past-tense evidence facts with UUID, type, native module, actor when permitted, approved result, risk level, correlation reference, redacted bounded context and UTC time. Events are not commands and cannot grant authority. Webhook ingress requires HTTPS policy, secret resolution, HMAC, timestamp tolerance and replay blocking.
