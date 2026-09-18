"""Unit tests for http_request's header/form handling -- the only pure
logic added by the vuln-testing expansion. Everything else (container
management, live probes) needs Docker/a real target and is verified by an
actual run, not a mock."""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import tools


def _fake_response(status=200, headers=None, text="{}"):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {"Content-Type": "application/json"}
    resp.text = text
    return resp


class HttpRequestTests(unittest.TestCase):
    def test_auth_token_sets_authorization_header(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "GET", "path": "/rest/basket/1", "auth_token": "abc123"
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer abc123")

    def test_explicit_authorization_header_overrides_auth_token(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "GET", "path": "/rest/basket/1", "auth_token": "abc123",
                "headers": {"Authorization": "Bearer override"}
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer override")

    def test_custom_header_passed_through_for_cors_testing(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "GET", "path": "/rest/basket/1",
                "headers": {"Origin": "https://evil-attacker.example"}
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["headers"]["Origin"], "https://evil-attacker.example")

    def test_form_true_sends_data_not_json(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "POST", "path": "/login.php",
                "body": {"username": "admin", "password": "password"}, "form": True
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["data"], {"username": "admin", "password": "password"})
        self.assertNotIn("json", kwargs)

    def test_form_false_default_sends_json(self):
        with patch.object(tools._HTTP_SESSION, "request", return_value=_fake_response()) as mock_req:
            tools.http_request.invoke({
                "method": "POST", "path": "/rest/user/login",
                "body": {"email": "a@b.com", "password": "x"}
            })
        _, kwargs = mock_req.call_args
        self.assertEqual(kwargs["json"], {"email": "a@b.com", "password": "x"})
        self.assertNotIn("data", kwargs)

    def test_response_includes_all_headers_not_just_content_type(self):
        headers = {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "https://evil-attacker.example",
            "Access-Control-Allow-Credentials": "true",
        }
        with patch.object(tools._HTTP_SESSION, "request",
                           return_value=_fake_response(headers=headers, text='{"ok":true}')):
            result = tools.http_request.invoke({"method": "GET", "path": "/rest/basket/1"})
        self.assertIn("Access-Control-Allow-Origin: https://evil-attacker.example", result)
        self.assertIn("Access-Control-Allow-Credentials: true", result)


if __name__ == "__main__":
    unittest.main()
