"""Agent/issuer/broker public-key identity registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import strict_json_loads
from .crypto import load_public_key_pem, public_key_to_pem
from .errors import VerificationError
from .models import KeyRegistryDocument, PublicKeyRecord


class KeyRegistry:
    def __init__(self, records: list[PublicKeyRecord] | None = None) -> None:
        self._records: dict[str, PublicKeyRecord] = {}
        for record in records or []:
            self.register(record)

    def register(self, record: PublicKeyRecord) -> None:
        load_public_key_pem(record.public_key_pem)
        if record.key_id in self._records:
            raise VerificationError("DUPLICATE_KEY_ID", f"duplicate key id: {record.key_id}")
        self._records[record.key_id] = record

    def get_record(
        self,
        key_id: str,
        *,
        purpose: str,
        subject_id: str | None = None,
        at_time: int | None = None,
    ) -> PublicKeyRecord:
        record = self._records.get(key_id)
        if record is None:
            raise VerificationError("UNKNOWN_KEY", f"unknown key id: {key_id}")
        if record.status != "ACTIVE":
            raise VerificationError("KEY_REVOKED", f"key is not active: {key_id}")
        if record.purpose != purpose:
            raise VerificationError("WRONG_KEY_PURPOSE", f"key {key_id} is not for {purpose}")
        if subject_id is not None and record.subject_id != subject_id:
            raise VerificationError("KEY_SUBJECT_MISMATCH", "key is bound to a different subject")
        if at_time is not None and not (record.not_before <= at_time < record.not_after):
            raise VerificationError("KEY_OUTSIDE_VALIDITY", "key is outside its validity window")
        return record

    def find(self, key_id: str) -> PublicKeyRecord:
        record = self._records.get(key_id)
        if record is None:
            raise VerificationError("UNKNOWN_KEY", f"unknown key id: {key_id}")
        return record

    def get_public_key(self, *args: Any, **kwargs: Any) -> Any:
        return load_public_key_pem(self.get_record(*args, **kwargs).public_key_pem)

    def document(self) -> KeyRegistryDocument:
        return KeyRegistryDocument(keys=list(self._records.values()))

    @classmethod
    def from_path(cls, path: Path) -> "KeyRegistry":
        document = KeyRegistryDocument.model_validate(strict_json_loads(path.read_bytes()))
        return cls(document.keys)


def make_public_key_record(
    *,
    key_id: str,
    subject_id: str,
    purpose: str,
    public_key: Any,
    not_before: int,
    not_after: int,
) -> PublicKeyRecord:
    return PublicKeyRecord(
        key_id=key_id,
        subject_id=subject_id,
        purpose=purpose,
        public_key_pem=public_key_to_pem(public_key).decode("ascii"),
        not_before=not_before,
        not_after=not_after,
    )
