import pytest

from agent_guard.cli import initialize, trust_arguments


@pytest.fixture
def setup(tmp_path):
    gateway, token, trust = initialize(tmp_path / "state")
    return gateway, token, trust_arguments(trust)
