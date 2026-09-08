import json
import threading
import urllib.request

from http.server import ThreadingHTTPServer

from dashboard import DashboardHandler


def test_dashboard_serves_page_and_checks_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        with urllib.request.urlopen(base_url) as response:
            assert response.status == 200
            assert "Signal Desk" in response.read().decode()

        request = urllib.request.Request(
            f"{base_url}/api/check",
            data=json.dumps({"mode": "url", "url": "http://bit.ly/abc123"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            payload = json.loads(response.read())
        assert payload["input_type"] == "url"
        assert 0 <= payload["score"] <= 100
        assert payload["reasons"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()