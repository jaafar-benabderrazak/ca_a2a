import asyncio
import json
import os
import socket

import pytest

from base_agent import BaseAgent
from agent_card import AgentSkill


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class EchoAgent(BaseAgent):
    def __init__(self, port: int):
        super().__init__("Echo", "127.0.0.1", port, description="test agent")

    def _register_handlers(self):
        async def echo(params):
            return {"echo": params}

        self.protocol.register_handler("echo", echo)

    def _define_skills(self):
        return [
            AgentSkill(
                skill_id="echo",
                name="Echo",
                description="Echo params",
                method="echo",
                input_schema={"type": "object"},
                output_schema={"type": "object"},
            )
        ]

    async def initialize(self):
        return None

    async def cleanup(self):
        return None


@pytest.mark.asyncio
async def test_message_requires_api_key_when_enabled(monkeypatch: pytest.MonkeyPatch):
    # Enable auth; configure API key and RBAC
    monkeypatch.setenv("A2A_REQUIRE_AUTH", "true")
    monkeypatch.setenv("A2A_ENABLE_RATE_LIMIT", "false")
    monkeypatch.setenv("A2A_ENABLE_REPLAY_PROTECTION", "false")
    monkeypatch.setenv("A2A_API_KEYS_JSON", json.dumps({"external_client": "k"}))
    monkeypatch.setenv("A2A_RBAC_POLICY_JSON", json.dumps({"allow": {"external_client": ["echo"]}, "deny": {}}))

    port = _free_port()
    agent = EchoAgent(port=port)
    await agent.start()

    try:
        import aiohttp

        url = f"http://127.0.0.1:{port}/message"
        payload = {"jsonrpc": "2.0", "method": "echo", "params": {"x": 1}, "id": "1"}

        async with aiohttp.ClientSession() as session:
            # Missing auth -> 401
            async with session.post(url, json=payload) as r:
                assert r.status == 401

            # Bad key -> 401
            async with session.post(url, json=payload, headers={"X-API-Key": "bad"}) as r:
                assert r.status == 401

            # Good key -> 200
            async with session.post(url, json=payload, headers={"X-API-Key": "k"}) as r:
                assert r.status == 200
                body = await r.json()
                assert body["result"]["echo"] == {"x": 1}
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_rbac_denies_unknown_method(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("A2A_REQUIRE_AUTH", "true")
    monkeypatch.setenv("A2A_ENABLE_RATE_LIMIT", "false")
    monkeypatch.setenv("A2A_ENABLE_REPLAY_PROTECTION", "false")
    monkeypatch.setenv("A2A_API_KEYS_JSON", json.dumps({"external_client": "k"}))
    monkeypatch.setenv("A2A_RBAC_POLICY_JSON", json.dumps({"allow": {"external_client": ["echo"]}, "deny": {}}))

    port = _free_port()
    agent = EchoAgent(port=port)
    await agent.start()
    try:
        import aiohttp

        url = f"http://127.0.0.1:{port}/message"
        payload = {"jsonrpc": "2.0", "method": "not_allowed", "params": {}, "id": "1"}
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers={"X-API-Key": "k"}) as r:
                assert r.status == 403
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_request_size_limit(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("A2A_REQUIRE_AUTH", "false")
    monkeypatch.setenv("A2A_MAX_REQUEST_BYTES", "200")

    port = _free_port()
    agent = EchoAgent(port=port)
    await agent.start()

    try:
        import aiohttp

        url = f"http://127.0.0.1:{port}/message"
        big = {"jsonrpc": "2.0", "method": "echo", "params": {"x": "a" * 1000}, "id": "1"}
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=json.dumps(big), headers={"Content-Type": "application/json"}) as r:
                # aiohttp returns 413 Payload Too Large when client_max_size exceeded
                assert r.status in (413, 400)
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_card_and_skills_visibility_filtered_by_rbac(monkeypatch: pytest.MonkeyPatch):
    # Require auth and require auth for /card,/skills; allow only echo for this principal.
    monkeypatch.setenv("A2A_REQUIRE_AUTH", "true")
    monkeypatch.setenv("A2A_CARD_REQUIRE_AUTH", "true")
    monkeypatch.setenv("A2A_CARD_VISIBILITY_MODE", "rbac")
    monkeypatch.setenv("A2A_ENABLE_RATE_LIMIT", "false")
    monkeypatch.setenv("A2A_ENABLE_REPLAY_PROTECTION", "false")
    monkeypatch.setenv("A2A_API_KEYS_JSON", json.dumps({"external_client": "k"}))
    monkeypatch.setenv("A2A_RBAC_POLICY_JSON", json.dumps({"allow": {"external_client": ["echo"]}, "deny": {}}))

    port = _free_port()
    agent = EchoAgent(port=port)
    await agent.start()

    try:
        import aiohttp

        async with aiohttp.ClientSession() as session:
            card_url = f"http://127.0.0.1:{port}/card"
            skills_url = f"http://127.0.0.1:{port}/skills"

            # Without auth -> 401
            async with session.get(card_url) as r:
                assert r.status == 401
            async with session.get(skills_url) as r:
                assert r.status == 401

            # With auth -> skill list filtered to allowed methods
            async with session.get(card_url, headers={"X-API-Key": "k"}) as r:
                assert r.status == 200
                body = await r.json()
                methods = sorted([s["method"] for s in body.get("skills", [])])
                assert methods == ["echo"]

            async with session.get(skills_url, headers={"X-API-Key": "k"}) as r:
                assert r.status == 200
                body = await r.json()
                methods = sorted([s["method"] for s in body.get("skills", [])])
                assert methods == ["echo"]
    finally:
        await agent.stop()

