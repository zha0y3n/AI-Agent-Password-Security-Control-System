"""Reliable fixed-task Agent; an LLM planner is deliberately not required."""

from __future__ import annotations

from .canonical import canonical_json
from .crypto import sm3_hex
from .models import AgentRequest, TaskContext


class DeterministicAgent:
    def __init__(self, *, agent_id: str, agent_key_id: str) -> None:
        self.agent_id = agent_id
        self.agent_key_id = agent_key_id

    def request_for(self, task: TaskContext, *, action_index: int = 0) -> AgentRequest:
        if task.agent_id != self.agent_id or task.agent_key_id != self.agent_key_id:
            raise ValueError("task is assigned to a different Agent identity")
        action = task.allowed_actions[action_index]
        request_seed = canonical_json(
            {
                "task_id": task.task_id,
                "agent_id": self.agent_id,
                "agent_key_id": self.agent_key_id,
                "action_index": action_index,
            }
        )
        return AgentRequest(
            request_id=f"req_{sm3_hex(request_seed)[:24]}",
            agent_id=self.agent_id,
            agent_key_id=self.agent_key_id,
            task_id=task.task_id,
            service=action.service,
            resource=action.resource,
            operation=action.operation,
            method=action.method,
            path=action.path,
            query=action.query,
            body=action.body,
            credential_id=action.credential_id,
        )
