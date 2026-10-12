"""Trusted task store and deterministic authorization policy."""

from __future__ import annotations

from pathlib import Path

from .canonical import canonical_json, strict_json_loads
from .errors import AuthorizationDenied
from .models import AgentRequest, AllowedAction, TaskContext, TaskStoreDocument


class TrustedTaskStore:
    """Server-owned contexts; Agent input can only reference a task_id."""

    def __init__(self, tasks: list[TaskContext] | None = None) -> None:
        self._tasks: dict[str, TaskContext] = {}
        for task in tasks or []:
            if task.task_id in self._tasks:
                raise AuthorizationDenied("DUPLICATE_TASK", f"duplicate trusted task: {task.task_id}")
            self._tasks[task.task_id] = task

    def get(self, task_id: str) -> TaskContext:
        task = self._tasks.get(task_id)
        if task is None:
            raise AuthorizationDenied("UNKNOWN_TASK", "task is not present in the trusted task store")
        return task

    def document(self) -> TaskStoreDocument:
        return TaskStoreDocument(tasks=list(self._tasks.values()))

    @classmethod
    def from_path(cls, path: Path) -> "TrustedTaskStore":
        document = TaskStoreDocument.model_validate(strict_json_loads(path.read_bytes()))
        return cls(document.tasks)


def _matches(action: AllowedAction, request: AgentRequest) -> bool:
    return (
        action.service == request.service
        and action.resource == request.resource
        and action.operation == request.operation
        and action.method == request.method
        and action.path == request.path
        and canonical_json(action.query) == canonical_json(request.query)
        and canonical_json(action.body) == canonical_json(request.body)
        and action.credential_id == request.credential_id
    )


class AuthorizationPolicy:
    def __init__(self, task_store: TrustedTaskStore) -> None:
        self.task_store = task_store

    def authorize(self, request: AgentRequest, *, ttl_seconds: int, now: int) -> AllowedAction:
        task = self.task_store.get(request.task_id)
        if task.status != "ACTIVE":
            raise AuthorizationDenied("TASK_NOT_ACTIVE", "trusted task is not active")
        if not (task.valid_from <= now < task.expires_at):
            raise AuthorizationDenied("TASK_OUTSIDE_VALIDITY", "trusted task is outside its validity window")
        if task.agent_id != request.agent_id or task.agent_key_id != request.agent_key_id:
            raise AuthorizationDenied("AGENT_TASK_MISMATCH", "Agent identity is not assigned to this task")
        matches = [action for action in task.allowed_actions if _matches(action, request)]
        if len(matches) != 1:
            raise AuthorizationDenied(
                "REQUEST_NOT_AUTHORIZED",
                "request does not exactly match one trusted action",
            )
        action = matches[0]
        if ttl_seconds > action.max_ttl_seconds:
            raise AuthorizationDenied("TTL_EXCEEDS_POLICY", "requested TTL exceeds the trusted policy limit")
        if now + ttl_seconds > task.expires_at:
            raise AuthorizationDenied("TTL_EXCEEDS_TASK", "capability would outlive its trusted task")
        return action
