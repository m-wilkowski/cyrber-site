"""Tests for new evilginx_phishing functions: credentials, lures, status."""

import json
import os
import sqlite3
import time

import pytest
import yaml

import modules.evilginx_phishing as eg


# ── Fixtures (reuse pattern from test_evilginx_phishing.py) ──

@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    """Create a temporary Evilginx data directory and patch module paths."""
    db_path = str(tmp_path / "data.db")
    config_path = str(tmp_path / "config.json")
    phishlets_dir = str(tmp_path / "phishlets")
    os.makedirs(phishlets_dir)

    monkeypatch.setattr(eg, "_DB_PATH", db_path)
    monkeypatch.setattr(eg, "_CONFIG_PATH", config_path)
    monkeypatch.setattr(eg, "_PHISHLETS_DIR", phishlets_dir)

    return tmp_path


@pytest.fixture()
def db(data_dir):
    """Create an empty sessions database with the Evilginx schema."""
    db_path = str(data_dir / "data.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phishlet TEXT,
            landing_url TEXT,
            username TEXT,
            password TEXT,
            custom TEXT,
            body_tokens TEXT,
            http_tokens TEXT,
            tokens TEXT,
            session_id TEXT UNIQUE,
            useragent TEXT,
            remote_addr TEXT,
            create_time INTEGER,
            update_time INTEGER
        )
    """)
    conn.commit()
    conn.close()
    return db_path


def _insert_session(db_path, **overrides):
    """Helper: insert a session row."""
    now = int(time.time())
    defaults = {
        "phishlet": "office365",
        "landing_url": "https://login.example.com",
        "username": "",
        "password": "",
        "custom": "{}",
        "body_tokens": "{}",
        "http_tokens": "{}",
        "tokens": "{}",
        "session_id": f"sess_{now}_{id(overrides)}",
        "useragent": "Mozilla/5.0",
        "remote_addr": "10.0.0.1",
        "create_time": now,
        "update_time": now,
    }
    defaults.update(overrides)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """INSERT INTO sessions
           (phishlet, landing_url, username, password, custom, body_tokens,
            http_tokens, tokens, session_id, useragent, remote_addr,
            create_time, update_time)
           VALUES (:phishlet, :landing_url, :username, :password, :custom,
                   :body_tokens, :http_tokens, :tokens, :session_id,
                   :useragent, :remote_addr, :create_time, :update_time)""",
        defaults,
    )
    conn.commit()
    conn.close()
    return defaults["session_id"]


# ═══════════════════════════════════════════════════════════════
#  get_credentials
# ═══════════════════════════════════════════════════════════════


class TestGetCredentials:

    def test_empty_db(self, db):
        assert eg.get_credentials() == []

    def test_filters_sessions_with_credentials(self, db):
        _insert_session(db, session_id="s1", username="alice", password="pass1")
        _insert_session(db, session_id="s2", username="bob", password="")
        _insert_session(db, session_id="s3", username="", password="")
        result = eg.get_credentials()
        assert len(result) == 2
        usernames = {c["username"] for c in result}
        assert usernames == {"alice", "bob"}

    def test_fields_present(self, db):
        _insert_session(
            db, session_id="s1", username="victim", password="secret",
            tokens=json.dumps({"auth": {"sid": "x"}, "cookie": {"val": "y"}}),
            remote_addr="192.168.1.1",
        )
        result = eg.get_credentials()
        assert len(result) == 1
        cred = result[0]
        expected_keys = {
            "session_id", "phishlet", "username", "password",
            "tokens_count", "remote_addr", "landing_url", "create_time",
        }
        assert set(cred.keys()) == expected_keys
        assert cred["username"] == "victim"
        assert cred["password"] == "secret"
        assert cred["tokens_count"] == 2
        assert cred["remote_addr"] == "192.168.1.1"

    def test_unavailable(self, data_dir):
        assert eg.get_credentials() == []


# ═══════════════════════════════════════════════════════════════
#  get_lures
# ═══════════════════════════════════════════════════════════════


class TestGetLures:

    def test_no_config(self, data_dir):
        assert eg.get_lures() == []

    def test_config_without_lures_key(self, data_dir):
        (data_dir / "config.json").write_text(json.dumps({"domain": "evil.com"}))
        assert eg.get_lures() == []

    def test_returns_lures_list(self, data_dir):
        lures = [
            {"id": 1, "phishlet": "office365", "path": "/login", "redirect_url": "https://real.com"},
            {"id": 2, "phishlet": "github", "path": "/auth", "redirect_url": ""},
        ]
        (data_dir / "config.json").write_text(json.dumps({"lures": lures}))
        result = eg.get_lures()
        assert len(result) == 2
        assert result[0]["phishlet"] == "office365"
        assert result[1]["phishlet"] == "github"


# ═══════════════════════════════════════════════════════════════
#  create_lure
# ═══════════════════════════════════════════════════════════════


class TestCreateLure:

    def test_success(self, data_dir):
        # Create phishlet and config
        (data_dir / "phishlets" / "office365.yaml").write_text(
            yaml.dump({"author": "kgretzky"})
        )
        (data_dir / "config.json").write_text(json.dumps({"domain": "evil.com", "lures": []}))

        lure = eg.create_lure("office365", redirect_url="https://real.com", path="/login")
        assert lure["id"] == 1
        assert lure["phishlet"] == "office365"
        assert lure["redirect_url"] == "https://real.com"
        assert lure["path"] == "/login"
        assert lure["paused"] is False

        # Verify persisted
        config = json.loads((data_dir / "config.json").read_text())
        assert len(config["lures"]) == 1
        assert config["lures"][0]["id"] == 1

    def test_invalid_phishlet(self, data_dir):
        (data_dir / "config.json").write_text(json.dumps({"domain": "evil.com"}))
        with pytest.raises(ValueError, match="not found"):
            eg.create_lure("nonexistent")

    def test_no_config_file(self, data_dir):
        with pytest.raises(FileNotFoundError):
            eg.create_lure("office365")

    def test_increments_id(self, data_dir):
        (data_dir / "phishlets" / "office365.yaml").write_text(yaml.dump({"author": "x"}))
        existing = [{"id": 5, "phishlet": "office365", "path": ""}]
        (data_dir / "config.json").write_text(json.dumps({"lures": existing}))

        lure = eg.create_lure("office365")
        assert lure["id"] == 6


# ═══════════════════════════════════════════════════════════════
#  delete_lure
# ═══════════════════════════════════════════════════════════════


class TestDeleteLure:

    def test_success(self, data_dir):
        lures = [{"id": 1, "phishlet": "office365"}, {"id": 2, "phishlet": "github"}]
        (data_dir / "config.json").write_text(json.dumps({"lures": lures}))

        assert eg.delete_lure(1) is True

        config = json.loads((data_dir / "config.json").read_text())
        assert len(config["lures"]) == 1
        assert config["lures"][0]["id"] == 2

    def test_nonexistent_id(self, data_dir):
        lures = [{"id": 1, "phishlet": "office365"}]
        (data_dir / "config.json").write_text(json.dumps({"lures": lures}))
        assert eg.delete_lure(999) is False

    def test_no_config(self, data_dir):
        assert eg.delete_lure(1) is False


# ═══════════════════════════════════════════════════════════════
#  get_status
# ═══════════════════════════════════════════════════════════════


class TestGetStatus:

    def test_available(self, db, data_dir):
        _insert_session(db, session_id="s1", username="alice", password="pass")
        config = {
            "domain": "evil.com",
            "ip": "1.2.3.4",
            "phishlets": {"office365": "enabled", "github": "disabled"},
            "lures": [{"id": 1, "phishlet": "office365"}],
        }
        (data_dir / "config.json").write_text(json.dumps(config))
        (data_dir / "phishlets" / "office365.yaml").write_text(yaml.dump({"author": "x"}))

        status = eg.get_status()
        assert status["available"] is True
        assert status["domain"] == "evil.com"
        assert status["ip"] == "1.2.3.4"
        assert status["active_phishlets"] == ["office365"]
        assert status["total_sessions"] == 1
        assert status["credentials_captured"] == 1
        assert status["phishlets_count"] == 1
        assert status["lures_count"] == 1

    def test_unavailable(self, data_dir):
        status = eg.get_status()
        assert status["available"] is False
        assert status["total_sessions"] == 0
        assert status["credentials_captured"] == 0
        assert status["tokens_captured"] == 0
        assert status["phishlets_count"] == 0
        assert status["lures_count"] == 0
        assert status["domain"] == ""
        assert status["ip"] == ""
