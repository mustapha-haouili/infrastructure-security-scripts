import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "monitoring" / "service-health-check.py"

spec = importlib.util.spec_from_file_location("service_health_check", MODULE_PATH)
service_health_check = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = service_health_check
spec.loader.exec_module(service_health_check)


class DummyContextManager:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class ServiceHealthCheckTests(unittest.TestCase):
    def test_http_timeout_override_accepts_zero(self):
        service = {
            "name": "local",
            "type": "http",
            "url": "https://example.test",
            "timeout": 9,
            "expected_status": [200],
        }

        with mock.patch.object(service_health_check, "urlopen", return_value=DummyContextManager()) as urlopen:
            result = service_health_check.check_http(service, timeout_override=0)

        self.assertTrue(result.ok)
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 0.0)

    def test_tcp_timeout_override_accepts_zero(self):
        service = {
            "name": "local",
            "type": "tcp",
            "host": "127.0.0.1",
            "port": 443,
            "timeout": 9,
        }

        with mock.patch.object(
            service_health_check.socket,
            "create_connection",
            return_value=DummyContextManager(),
        ) as create_connection:
            result = service_health_check.check_tcp(service, timeout_override=0)

        self.assertTrue(result.ok)
        create_connection.assert_called_once_with(("127.0.0.1", 443), timeout=0.0)


if __name__ == "__main__":
    unittest.main()
