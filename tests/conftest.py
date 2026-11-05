import pytest


@pytest.fixture(autouse=True)
def _no_live_provider(monkeypatch):
    """Tests never call a real model, whatever keys are set on the machine running them."""
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
