# Copyright 2023 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from unittest.mock import Mock, call

import ops
import ops.testing
import pytest
from charm import MagpieCharm
from magpie_tools import status_for_speed_check


@pytest.fixture
def harness():
    harness = ops.testing.Harness(MagpieCharm)
    harness.begin()
    yield harness
    harness.cleanup()


@pytest.fixture
def os_system_mock(monkeypatch):
    mock = Mock()
    monkeypatch.setattr("charm.os.system", mock)
    return mock


def test_example(harness, os_system_mock):
    harness.charm.on.install.emit()
    assert os_system_mock.call_count == 2
    os_system_mock.assert_has_calls([call("apt update"), call("apt install -y iperf")])


def test_status_for_speed_check():
    assert status_for_speed_check("0", 123, 150) == {"message": "min-speed disabled", "ok": True}
    assert status_for_speed_check("0%", 123, 150) == {"message": "min-speed disabled", "ok": True}
    assert status_for_speed_check(":P", 123, 150) == {
        "message": "invalid min_speed: :P",
        "ok": False,
    }
    assert status_for_speed_check("1", 10, 400) == {"message": "10 >= 1 mbit/s", "ok": True}
    assert status_for_speed_check("12", 10, 400) == {
        "message": "failed: 10 < 12 mbit/s",
        "ok": False,
    }
    assert status_for_speed_check("50%", 100, 400) == {
        "message": "failed: 100 < 200 mbit/s",
        "ok": False,
    }
    assert status_for_speed_check("50%", 200, 400) == {"message": "200 >= 200 mbit/s", "ok": True}
    assert status_for_speed_check("50%", 300, 400) == {"message": "300 >= 200 mbit/s", "ok": True}
    assert status_for_speed_check("50%", 300, -1) == {
        "message": "unknown, link speed undefined",
        "ok": False,
    }
