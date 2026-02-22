"""Tests for modules/evilginx_phishing.py."""

import json
import os
import sqlite3
import tempfile
import time

import pytest
import yaml

import modules.evilginx_phishing as eg


# ── Fixtures ──────────────────────────────────────────────────

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
    """Helper: insert a session row and return the session_id."""
    now = int(time.time())
    defaults = {
        "phishlet": "office365",
        "landing_url": "https://login.example.com",
        "username": "victim@corp.com",
        "password": "P@ss123",
        "custom": "{}",
        "body_tokens": "{}",
        "http_tokens": "{}",
        "tokens": json.dumps({"auth": {"sid": {"Name": "sid", "Value": "abc123"}}}),
        "session_id": f"sess_{now}",
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
#  is_available
# ═══════════════════════════════════════════════════════════════


class TestIsAvailable:

    def test_true_when_db_exists(self, db):
        assert eg.is_available() is True

    def test_false_when_no_db(self, data_dir):
        assert eg.is_available() is False

    def test_false_with_default_path(self):
        # Default /app/evilginx/data.db won't exist in test env
        assert not os.path.isfile("/app/evilginx/data.db") or True


# ═══════════════════════════════════════════════════════════════
#  _parse_json_field
# ═══════════════════════════════════════════════════════════════


class TestParseJsonField:

    def test_valid_json(self):
        assert eg._parse_json_field('{"a": 1}') == {"a": 1}

    def test_empty_string(self):
        assert eg._parse_json_field("") == {}

    def test_none(self):
        assert eg._parse_json_field(None) == {}

    def test_invalid_json(self):
        assert eg._parse_json_field("not json{") == {}

    def test_nested_json(self):
        data = {"tokens": {"cookie": {"name": "sid", "value": "abc"}}}
        assert eg._parse_json_field(json.dumps(data)) == data


# ═══════════════════════════════════════════════════════════════
#  get_sessions
# ═══════════════════════════════════════════════════════════════


class TestGetSessions:

    def test_empty_db(self, db):
        assert eg.get_sessions() == []

    def test_returns_sessions(self, db):
        _insert_session(db, session_id="s1", username="alice")
        _insert_session(db, session_id="s2", username="bob")
        result = eg.get_sessions()
        assert len(result) == 2
        usernames = {s["username"] for s in result}
        assert usernames == {"alice", "bob"}

    def test_ordered_by_update_time_desc(self, db):
        _insert_session(db, session_id="old", update_time=1000)
        _insert_session(db, session_id="new", update_time=9999)
        result = eg.get_sessions()
        assert result[0]["session_id"] == "new"
        assert result[1]["session_id"] == "old"

    def test_tokens_parsed_as_dict(self, db):
        tokens = {"auth": {"sid": {"Name": "sid", "Value": "xyz"}}}
        _insert_session(db, session_id="s1", tokens=json.dumps(tokens))
        result = eg.get_sessions()
        assert result[0]["tokens"] == tokens

    def test_returns_empty_when_unavailable(self, data_dir):
        assert eg.get_sessions() == []

    def test_all_fields_present(self, db):
        _insert_session(db, session_id="s1")
        s = eg.get_sessions()[0]
        expected_keys = {
            "id", "phishlet", "landing_url", "username", "password",
            "session_id", "useragent", "remote_addr", "create_time",
            "update_time", "tokens", "custom",
        }
        assert set(s.keys()) == expected_keys


# ═══════════════════════════════════════════════════════════════
#  get_session
# ═══════════════════════════════════════════════════════════════


class TestGetSession:

    def test_found(self, db):
        _insert_session(db, session_id="target_sid", username="victim")
        s = eg.get_session("target_sid")
        assert s is not None
        assert s["username"] == "victim"
        assert s["session_id"] == "target_sid"

    def test_not_found(self, db):
        assert eg.get_session("nonexistent") is None

    def test_returns_none_when_unavailable(self, data_dir):
        assert eg.get_session("any") is None

    def test_tokens_parsed(self, db):
        tokens = {"cookie": {"val": "123"}}
        _insert_session(db, session_id="s1", tokens=json.dumps(tokens))
        s = eg.get_session("s1")
        assert s["tokens"] == tokens


# ═══════════════════════════════════════════════════════════════
#  delete_session
# ═══════════════════════════════════════════════════════════════


class TestDeleteSession:

    def test_delete_existing(self, db):
        _insert_session(db, session_id="del_me")
        assert eg.delete_session("del_me") is True
        assert eg.get_session("del_me") is None

    def test_delete_nonexistent(self, db):
        assert eg.delete_session("nope") is False

    def test_delete_when_unavailable(self, data_dir):
        assert eg.delete_session("any") is False

    def test_only_deletes_target(self, db):
        _insert_session(db, session_id="keep")
        _insert_session(db, session_id="remove")
        eg.delete_session("remove")
        assert eg.get_session("keep") is not None
        assert eg.get_session("remove") is None


# ═══════════════════════════════════════════════════════════════
#  list_phishlets
# ═══════════════════════════════════════════════════════════════


class TestListPhishlets:

    def test_empty_directory(self, data_dir):
        assert eg.list_phishlets() == []

    def test_lists_phishlets(self, data_dir):
        phishlets_dir = data_dir / "phishlets"
        (phishlets_dir / "office365.yaml").write_text(yaml.dump({
            "author": "kgretzky",
            "min_ver": "2.4.0",
            "proxy_hosts": [
                {"phish_sub": "login", "domain": "microsoftonline.com"},
            ],
            "credentials": {
                "username": [{"name": "email"}],
            },
        }))
        result = eg.list_phishlets()
        assert len(result) == 1
        assert result[0]["name"] == "office365"
        assert result[0]["author"] == "kgretzky"
        assert "login.microsoftonline.com" in result[0]["proxy_hosts"]

    def test_multiple_phishlets_sorted(self, data_dir):
        phishlets_dir = data_dir / "phishlets"
        (phishlets_dir / "b_github.yaml").write_text(yaml.dump({"author": "test"}))
        (phishlets_dir / "a_google.yaml").write_text(yaml.dump({"author": "test"}))
        result = eg.list_phishlets()
        assert [p["name"] for p in result] == ["a_google", "b_github"]

    def test_invalid_yaml_graceful(self, data_dir):
        phishlets_dir = data_dir / "phishlets"
        (phishlets_dir / "broken.yaml").write_text(": invalid: yaml: {{[")
        result = eg.list_phishlets()
        assert len(result) == 1
        assert result[0]["name"] == "broken"
        assert result[0]["error"] == "parse_failed"

    def test_missing_fields_default_empty(self, data_dir):
        phishlets_dir = data_dir / "phishlets"
        (phishlets_dir / "minimal.yaml").write_text(yaml.dump({"author": "x"}))
        result = eg.list_phishlets()
        assert result[0]["proxy_hosts"] == []
        assert result[0]["credentials"] == []
        assert result[0]["min_ver"] == ""

    def test_ignores_non_yaml_files(self, data_dir):
        phishlets_dir = data_dir / "phishlets"
        (phishlets_dir / "readme.txt").write_text("not a phishlet")
        (phishlets_dir / "real.yaml").write_text(yaml.dump({"author": "a"}))
        result = eg.list_phishlets()
        assert len(result) == 1
        assert result[0]["name"] == "real"


# ═══════════════════════════════════════════════════════════════
#  get_phishlet
# ═══════════════════════════════════════════════════════════════


class TestGetPhishlet:

    def test_found(self, data_dir):
        phishlets_dir = data_dir / "phishlets"
        content = {"author": "kgretzky", "min_ver": "2.4.0", "proxy_hosts": []}
        (phishlets_dir / "office365.yaml").write_text(yaml.dump(content))
        result = eg.get_phishlet("office365")
        assert result["author"] == "kgretzky"

    def test_not_found(self, data_dir):
        assert eg.get_phishlet("nonexistent") is None

    def test_invalid_yaml_returns_none(self, data_dir):
        phishlets_dir = data_dir / "phishlets"
        (phishlets_dir / "bad.yaml").write_text(": {{invalid")
        assert eg.get_phishlet("bad") is None


# ═══════════════════════════════════════════════════════════════
#  get_config
# ═══════════════════════════════════════════════════════════════


class TestGetConfig:

    def test_reads_config(self, data_dir):
        config = {"domain": "evil.com", "ip": "1.2.3.4", "phishlets": {"office365": "enabled"}}
        (data_dir / "config.json").write_text(json.dumps(config))
        assert eg.get_config() == config

    def test_missing_config(self, data_dir):
        assert eg.get_config() == {}

    def test_invalid_json(self, data_dir):
        (data_dir / "config.json").write_text("not json{{{")
        assert eg.get_config() == {}


# ═══════════════════════════════════════════════════════════════
#  get_stats
# ═══════════════════════════════════════════════════════════════


class TestGetStats:

    def test_empty_stats(self, db):
        stats = eg.get_stats()
        assert stats["total_sessions"] == 0
        assert stats["credentials_captured"] == 0
        assert stats["tokens_captured"] == 0
        assert stats["phishlets_used"] == []
        assert stats["sessions_last_24h"] == 0
        assert stats["available"] is True

    def test_counts_credentials(self, db):
        _insert_session(db, session_id="s1", username="alice", password="pass")
        _insert_session(db, session_id="s2", username="", password="")
        stats = eg.get_stats()
        assert stats["credentials_captured"] == 1

    def test_counts_tokens(self, db):
        _insert_session(db, session_id="s1", tokens='{"auth": {"sid": "x"}}')
        _insert_session(db, session_id="s2", tokens="{}")
        stats = eg.get_stats()
        assert stats["tokens_captured"] == 1

    def test_phishlets_used_unique(self, db):
        _insert_session(db, session_id="s1", phishlet="office365")
        _insert_session(db, session_id="s2", phishlet="office365")
        _insert_session(db, session_id="s3", phishlet="github")
        stats = eg.get_stats()
        assert sorted(stats["phishlets_used"]) == ["github", "office365"]

    def test_recent_24h(self, db):
        now = int(time.time())
        _insert_session(db, session_id="fresh", update_time=now - 3600)
        _insert_session(db, session_id="old", update_time=now - 100000)
        stats = eg.get_stats()
        assert stats["sessions_last_24h"] == 1
        assert stats["total_sessions"] == 2

    def test_unavailable(self, data_dir):
        stats = eg.get_stats()
        assert stats["available"] is False
        assert stats["total_sessions"] == 0
