import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_scan_rejects_empty_text():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/scan", json={"text": "", "channel": "chat"})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_scan_rejects_invalid_channel():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/v1/scan", json={"text": "hello", "channel": "fax"})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_rules_requires_api_key():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/rules")
    assert r.status_code == 422  # missing X-API-Key header


@pytest.mark.asyncio
async def test_rules_rejects_wrong_key():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/v1/rules", headers={"X-API-Key": "wrong"})
    assert r.status_code == 403
