"""Native Wazuh HTTP intake on the actual common in-process core; no live manager."""

from fastapi.testclient import TestClient

from responseforge.api import create_app
from tests.rf07a.helpers import Clock, auth, encoded, settings


def test_native_authenticated_intake_creates_atomic_case_provenance_and_two_evidence(tmp_path):
    clock = Clock()
    configured = settings(tmp_path / "native.sqlite3")
    app = create_app(configured, clock=clock)
    client = TestClient(app)
    response = client.post("/v1/integrations/wazuh/alerts", content=encoded(), headers=auth())
    assert response.status_code == 201
    identifier = response.json()["incident_id"]
    with app.state.store.transaction() as tx:
        assert len(tx.list("incidents")) == len(tx.list("alerts")) == len(tx.list("metrics")) == 1
        assert len(tx.list("evidence")) == 2
        assert tx.get("callbacks", "wazuh-source:" + identifier) is not None
        assert not tx.list("executions") and not tx.list("proposals")


def test_authentication_and_exact_source_actor_precede_native_body_processing(tmp_path):
    client = TestClient(create_app(settings(tmp_path / "auth.sqlite3"), clock=Clock()))
    for headers in (
        {},
        {"Authorization": "Bearer synthetic-wrong-secret"},
        {"Authorization": "Basic synthetic-wrong-secret"},
    ):
        response = client.post(
            "/v1/integrations/wazuh/alerts", content=b"malformed-secret", headers=headers
        )
        assert response.status_code == 401
        assert (
            "synthetic-wrong-secret" not in response.text
            and "malformed-secret" not in response.text
        )
    for role in ("analyst", "approver", "executor", "workflow", "other-source"):
        response = client.post(
            "/v1/integrations/wazuh/alerts", content=encoded(), headers=auth(role)
        )
        assert response.status_code == 403
    assert client.get("/v1/incidents", headers=auth("analyst")).json() == []


def test_disabled_native_intake_does_not_enable_live_features(tmp_path):
    client = TestClient(
        create_app(settings(tmp_path / "disabled.sqlite3", wazuh=None), clock=Clock())
    )
    response = client.post("/v1/integrations/wazuh/alerts", content=encoded(), headers=auth())
    assert response.status_code == 404


def test_exact_duplicate_and_restart_preserve_original_server_receipt_and_acceptance(tmp_path):
    clock = Clock()
    configured = settings(tmp_path / "repeat.sqlite3")
    app = create_app(configured, clock=clock)
    client = TestClient(app)
    first = client.post("/v1/integrations/wazuh/alerts", content=encoded(), headers=auth())
    assert first.status_code == 201
    case = first.json()["incident_id"]
    with app.state.store.transaction() as tx:
        original = {
            name: tx.list(name)
            for name in (
                "alerts",
                "incidents",
                "case_meta",
                "evidence",
                "metrics",
                "callbacks",
                "audit",
            )
        }
    clock.advance(hours=2)
    again_app = create_app(configured, clock=clock)
    again = TestClient(again_app)
    repeated = again.post("/v1/integrations/wazuh/alerts", content=encoded(), headers=auth())
    assert repeated.status_code == 200 and repeated.json()["duplicate"] is True
    assert (
        repeated.json()["incident_id"] == case
        and repeated.json()["correlation_id"] == first.json()["correlation_id"]
    )
    with again_app.state.store.transaction() as tx:
        assert {name: tx.list(name) for name in original} == original
    original_alert = original["alerts"][0]
    assert original_alert["ingested_at"] == "2026-11-19T17:00:00Z"
    assert original_alert["event_time"] == "2026-02-03T12:15:16.123000Z"


def test_generic_normalized_api_cannot_bypass_reserved_native_source(tmp_path):
    from responseforge.integrations.wazuh.mapping import project_alert
    from tests.rf07a.helpers import NOW, config

    client = TestClient(create_app(settings(tmp_path / "reserved.sqlite3"), clock=Clock()))
    alert = project_alert(encoded(), config()).to_alert(NOW).model_dump(mode="json")
    response = client.post("/v1/alerts", json=alert, headers=auth())
    assert response.status_code == 403
    assert client.get("/v1/incidents", headers=auth("analyst")).json() == []


def test_source_payload_cannot_forge_endpoint_mode_approval_or_provider(tmp_path):
    from tests.rf07a.helpers import ENDPOINT, payload

    app = create_app(settings(tmp_path / "inert.sqlite3"), clock=Clock())
    client = TestClient(app)
    raw = encoded(
        payload(
            mode="replay",
            endpoint_id="developer-host",
            provider="mock-edr",
            approved=True,
            approver_id="fake-human",
            command="SYNTHETIC-DO-NOT-RUN",
            hook_url="https://invalid.example/secret",
        )
    )
    response = client.post("/v1/integrations/wazuh/alerts", content=raw, headers=auth())
    assert response.status_code == 201
    with app.state.store.transaction() as tx:
        alert = tx.list("alerts")[0]
        assert alert["mode"] == "live" and alert["endpoint"] == ENDPOINT.model_dump(mode="json")
        assert not tx.list("proposals") and not tx.list("approvals") and not tx.list("executions")
        assert len(tx.list("metrics")) == 1 and tx.list("metrics")[0]["kind"] == "alert_accepted"


def test_unmapped_agent_or_wrong_name_rejects_without_case_or_raw_echo(tmp_path):
    from tests.rf07a.helpers import payload

    client = TestClient(create_app(settings(tmp_path / "agent.sqlite3"), clock=Clock()))
    for agent in (
        {"id": "999", "name": "SYNTHETIC-PRIVATE-HOST"},
        {"id": "001", "name": "SYNTHETIC-PRIVATE-HOST"},
    ):
        response = client.post(
            "/v1/integrations/wazuh/alerts", content=encoded(payload(agent=agent)), headers=auth()
        )
        assert response.status_code == 403
        assert "SYNTHETIC-PRIVATE-HOST" not in response.text
    assert client.get("/v1/incidents", headers=auth("analyst")).json() == []


def test_http_json_representation_and_stream_size_are_explicit(tmp_path):
    client = TestClient(create_app(settings(tmp_path / "representation.sqlite3"), clock=Clock()))
    for headers in (auth(**{"Content-Type": "text/plain"}), auth(**{"Content-Encoding": "gzip"})):
        response = client.post("/v1/integrations/wazuh/alerts", content=encoded(), headers=headers)
        assert response.status_code in {415, 422}
    oversized = encoded() + b" " * 262144
    assert (
        client.post("/v1/integrations/wazuh/alerts", content=oversized, headers=auth()).status_code
        == 413
    )
    invalid = client.post(
        "/v1/integrations/wazuh/alerts", content=b'{"source-secret":', headers=auth()
    )
    assert invalid.status_code == 422 and "source-secret" not in invalid.text
    assert client.get("/v1/incidents", headers=auth("analyst")).json() == []


def test_bounded_asgi_stream_stops_reading_after_first_oversized_chunk(tmp_path):
    import asyncio

    app = create_app(settings(tmp_path / "stream.sqlite3"), clock=Clock())
    seen = []
    sent = []

    async def receive():
        seen.append(1)
        assert len(seen) == 1, "Native route drained beyond the declared maximum"
        return {"type": "http.request", "body": encoded() + b" " * 262144, "more_body": True}

    async def send(message):
        sent.append(message)

    headers = [(key.lower().encode(), value.encode()) for key, value in auth().items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/integrations/wazuh/alerts",
        "raw_path": b"/v1/integrations/wazuh/alerts",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 8443),
    }
    asyncio.run(app(scope, receive, send))
    assert next(m["status"] for m in sent if m["type"] == "http.response.start") == 413
    assert len(seen) == 1
    with app.state.store.transaction() as tx:
        assert not tx.list("incidents") and not tx.list("callbacks")


def test_rate_limit_retains_current_sixty_per_actor_and_restart_state(tmp_path):
    clock = Clock()
    configured = settings(tmp_path / "rate.sqlite3")
    client = TestClient(create_app(configured, clock=clock))
    for index in range(60):
        result = client.post("/v1/integrations/wazuh/alerts", content=encoded(), headers=auth())
        assert result.status_code == (201 if index == 0 else 200)
    restarted = TestClient(create_app(configured, clock=clock))
    assert (
        restarted.post(
            "/v1/integrations/wazuh/alerts", content=encoded(), headers=auth()
        ).status_code
        == 429
    )
    clock.advance(minutes=1)
    assert (
        restarted.post(
            "/v1/integrations/wazuh/alerts", content=encoded(), headers=auth()
        ).status_code
        == 200
    )


def test_generated_openapi_keeps_native_bearer_and_no_private_configuration(tmp_path):
    import json

    from tests.rf07a.helpers import TOKENS

    schema = create_app(settings(tmp_path / "schema.sqlite3"), clock=Clock()).openapi()
    native = schema["paths"]["/v1/integrations/wazuh/alerts"]["post"]
    assert native.get("security")
    assert all(token not in json.dumps(schema) for token in TOKENS.values())


def test_unauthorized_request_never_consumes_body_stream(tmp_path):
    import asyncio

    app = create_app(settings(tmp_path / "no-body.sqlite3"), clock=Clock())
    for headers, expected in (({}, 401), (auth("analyst"), 403)):
        messages = []

        async def receive():
            raise AssertionError("Unauthorized native intake consumed private body")

        async def send(message):
            messages.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/v1/integrations/wazuh/alerts",
            "raw_path": b"/v1/integrations/wazuh/alerts",
            "query_string": b"",
            "root_path": "",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "client": ("127.0.0.1", 1234),
            "server": ("127.0.0.1", 8443),
        }
        asyncio.run(app(scope, receive, send))
        assert next(m["status"] for m in messages if m["type"] == "http.response.start") == expected


def test_non_utf8_declared_json_charset_is_rejected(tmp_path):
    client = TestClient(create_app(settings(tmp_path / "charset.sqlite3"), clock=Clock()))
    refused = client.post(
        "/v1/integrations/wazuh/alerts",
        content=encoded(),
        headers=auth(**{"Content-Type": "application/json;charset=latin-1"}),
    )
    assert refused.status_code == 415
    assert (
        client.post(
            "/v1/integrations/wazuh/alerts",
            content=encoded(),
            headers=auth(**{"Content-Type": "application/json; charset=UTF-8"}),
        ).status_code
        == 201
    )
