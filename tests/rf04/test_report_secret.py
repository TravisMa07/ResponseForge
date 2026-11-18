"""Review regression: configured vendor secrets join default report redaction."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from responseforge.api import create_app
from tests.rf02.helpers import TOKENS
from tests.rf04.helpers import KEY
from tests.rf04.test_coordinator import case_world


@pytest.mark.parametrize("format", ["json", "html"])
def test_configured_shuffle_key_is_redacted_even_inside_retained_identifier(
    tmp_path: Path, format: str
) -> None:
    def no_vendor_call(request):
        raise AssertionError("Report export must not connect to vendor")

    v = case_world(tmp_path, no_vendor_call)
    with v.service.store.transaction() as tx:
        alert = tx.get("alerts", v.incident_id)
        assert alert is not None
        alert["rule_id"] = KEY
        tx.replace("alerts", v.incident_id, alert)
    client = TestClient(
        create_app(v.service.settings, clock=v.w.clock, shuffle_transport=v.transport)
    )
    response = client.get(
        f"/v1/incidents/{v.incident_id}/report?format={format}",
        headers={"Authorization": "Bearer " + TOKENS["analyst"]},
    )
    assert response.status_code == 200
    assert KEY not in response.text
