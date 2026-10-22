"""用 A 的 ReceiptVerifier 复核 Go Broker 签发的 Execution Receipt（`make interop` 的最后一步）。

用法：.venv/bin/python credential-broker/scripts/verify-a-receipt.py <目录>

目录中需有 Go 联调测试写出的 receipt.json、result_envelope.json、broker-keys.json。
检查：A 的严格模型能解析回执；SM2 签名有效；result_hash = SM3(ZTCANON(result_envelope))；
篡改 outcome 或 envelope 后验证失败。
"""

from __future__ import annotations

import sys
from pathlib import Path

from agent_aa.canonical import canonical_json, strict_json_loads
from agent_aa.crypto import sm3_hex
from agent_aa.errors import VerificationError
from agent_aa.keys import KeyRegistry
from agent_aa.models import ResultEnvelope, SignedReceipt
from agent_aa.receipt import ReceiptVerifier


def main(directory: Path) -> None:
    registry = KeyRegistry.from_path(directory / "broker-keys.json")
    receipt = SignedReceipt.model_validate(strict_json_loads((directory / "receipt.json").read_bytes()))
    envelope_bytes = (directory / "result_envelope.json").read_bytes()
    broker_id = receipt.body.broker_id
    verifier = ReceiptVerifier(registry)

    verifier.verify(receipt, expected_broker_id=broker_id)
    if canonical_json(strict_json_loads(envelope_bytes)) != envelope_bytes:
        sys.exit("result_envelope is not ZTCANON-JSON-v1 canonical bytes")
    if sm3_hex(envelope_bytes) != receipt.body.result_hash:
        sys.exit("result_hash does not match SM3(result_envelope)")
    # result_envelope 必须符合 shared/schemas/result-envelope.schema.json，且与回执绑定一致
    verifier.verify_result(
        receipt, ResultEnvelope.model_validate(strict_json_loads(envelope_bytes)), expected_broker_id=broker_id
    )

    tampered = receipt.model_copy(update={"body": receipt.body.model_copy(update={"outcome": "DENIED"})})
    try:
        verifier.verify(tampered, expected_broker_id=broker_id)
    except VerificationError:
        pass
    else:
        sys.exit("tampered receipt was accepted")
    try:
        verifier.verify(receipt, expected_broker_id="broker-evil")
    except VerificationError:
        pass
    else:
        sys.exit("receipt accepted for the wrong broker")

    print(f"A ReceiptVerifier accepted Go receipt {receipt.body.receipt_id} "
          f"(outcome={receipt.body.outcome}, epoch={receipt.body.credential_epoch}); tampered copies rejected")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: verify-a-receipt.py <directory>")
    main(Path(sys.argv[1]))
