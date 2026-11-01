import pytest
from blacktool.dashboard import serve

def test_dashboard_refuses_public_bind():
    with pytest.raises(ValueError):
        serve("0.0.0.0",8765)
