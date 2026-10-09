import http.client
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server  # noqa: E402


@pytest.fixture
def running_server(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ROOT", tmp_path)
    monkeypatch.setattr(server, "DB", tmp_path / "conversations.sqlite3")
    web = tmp_path / "web"
    assets = web / "assets"
    assets.mkdir(parents=True)
    (web / "index.html").write_text('<script src="/assets/orbit.js"></script>', encoding="utf-8")
    (assets / "orbit.js").write_text("window.orbit = true;", encoding="utf-8")
    server.initialize()
    with server.database() as db:
        db.execute("INSERT INTO sessions VALUES (?)", ("test-session",))
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_port
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=3)


def request(port, method, path, payload=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Cookie": "orbit_session=test-session"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    result = response.status, response.read().decode()
    connection.close()
    return result


def test_regeneration_replaces_latest_reply_without_duplicating_user(running_server, monkeypatch):
    original = [
        {"role": "user", "content": "Explain this log"},
        {"role": "assistant", "content": "Old answer"},
    ]
    with server.database() as db:
        db.execute(
            "INSERT INTO conversations VALUES (?,?,?,?,?)",
            ("chat-1", "test-session", "Explain this log", json.dumps(original), 1),
        )

    captured = {}

    def inspect(stage, payload):
        if stage == "input":
            captured["input"] = payload
            return {"approved": True, "text": payload["message"], "stored_text": payload["message"],
                    "action": "allow", "score": 0, "request_id": "test-request"}
        return {"approved": True, "text": payload["text"], "action": "allow"}

    class ModelResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "New answer"}}

    def model_post(url, **kwargs):
        captured["model_messages"] = kwargs["json"]["messages"]
        return ModelResponse()

    monkeypatch.setattr(server, "inspect", inspect)
    monkeypatch.setattr(server, "models", lambda: ["phi3"])
    monkeypatch.setattr(server.httpx, "post", model_post)

    status, body = request(running_server, "POST", "/api/chat",
                           {"conversation_id": "chat-1", "regenerate": True, "model": "phi3"})

    assert status == 200
    assert "event: done" in body
    assert '"text": "New answer"' in body
    assert captured["input"]["history"] == []
    assert [item["role"] for item in captured["model_messages"]] == ["system", "user"]
    with server.database() as db:
        row = db.execute("SELECT messages FROM conversations WHERE id=?", ("chat-1",)).fetchone()
    turns = json.loads(row["messages"])
    assert len(turns) == 2
    assert turns[0]["content"] == "Explain this log"
    assert turns[1]["content"] == "New answer"


def test_compiled_assets_are_served_without_exposing_other_files(running_server):
    status, html = request(running_server, "GET", "/")
    assert status == 200
    assert '/assets/orbit.js' in html
    status, script = request(running_server, "GET", "/assets/orbit.js")
    assert status == 200
    assert "window.orbit" in script
    status, _ = request(running_server, "GET", "/assets/../server.py")
    assert status == 404
