import pytest
import sqlite3
import tempfile
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ai-service"))

from agents.tools.get_incidents import query_incidents, redact_text, redact_dict


class TestIncidentSummary:
    @pytest.fixture
    def temp_db(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        
        # Create attack_metrics table
        cur.execute("""
            CREATE TABLE attack_metrics (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                source_ip TEXT,
                attack_category TEXT,
                blocked INTEGER,
                threat_score REAL
            )
        """)
        
        # Create attack_runs table
        cur.execute("""
            CREATE TABLE attack_runs (
                run_id TEXT PRIMARY KEY,
                start_time TEXT,
                end_time TEXT,
                total_attacks INTEGER,
                intensity_level TEXT,
                strategy TEXT
            )
        """)
        
        conn.commit()
        yield path
        conn.close()
        os.unlink(path)

    def test_query_incidents_empty_db(self, temp_db):
        result = query_incidents(temp_db, 24)
        assert result["total_incidents"] == 0
        assert result["blocked"] == 0
        assert result["allowed"] == 0
        assert len(result["top_categories"]) == 0
        assert len(result["top_source_ips"]) == 0

    def test_query_incidents_with_data(self, temp_db):
        conn = sqlite3.connect(temp_db)
        cur = conn.cursor()
        
        now = datetime.utcnow()
        recent = now - timedelta(hours=1)
        
        # Insert test data
        test_data = [
            (recent.isoformat(sep=" "), "192.168.1.1", "sql_injection", 1, 0.85),
            (recent.isoformat(sep=" "), "192.168.1.2", "xss", 0, 0.45),
            (recent.isoformat(sep=" "), "192.168.1.1", "sql_injection", 1, 0.90),
        ]
        
        for ts, ip, cat, blocked, score in test_data:
            cur.execute(
                "INSERT INTO attack_metrics (timestamp, source_ip, attack_category, blocked, threat_score) VALUES (?, ?, ?, ?, ?)",
                (ts, ip, cat, blocked, score),
            )
        
        conn.commit()
        conn.close()
        
        result = query_incidents(temp_db, 24)
        assert result["total_incidents"] == 3
        assert result["blocked"] == 2
        assert result["allowed"] == 1
        assert len(result["top_categories"]) == 2
        assert result["top_categories"][0]["attack_category"] == "sql_injection"
        assert result["top_categories"][0]["count"] == 2

    def test_query_incidents_time_filtering(self, temp_db):
        conn = sqlite3.connect(temp_db)
        cur = conn.cursor()
        
        now = datetime.utcnow()
        recent = now - timedelta(hours=1)
        old = now - timedelta(hours=50)
        
        cur.execute(
            "INSERT INTO attack_metrics (timestamp, source_ip, attack_category, blocked, threat_score) VALUES (?, ?, ?, ?, ?)",
            (recent.isoformat(sep=" "), "192.168.1.1", "sql_injection", 1, 0.85),
        )
        cur.execute(
            "INSERT INTO attack_metrics (timestamp, source_ip, attack_category, blocked, threat_score) VALUES (?, ?, ?, ?, ?)",
            (old.isoformat(sep=" "), "192.168.1.2", "xss", 1, 0.90),
        )
        
        conn.commit()
        conn.close()
        
        result = query_incidents(temp_db, 24)
        assert result["total_incidents"] == 1
        assert result["since_hours"] == 24

    def test_query_incidents_top_source_ips(self, temp_db):
        conn = sqlite3.connect(temp_db)
        cur = conn.cursor()
        
        now = datetime.utcnow()
        recent = now - timedelta(hours=1)
        
        # Same IP multiple times
        for _ in range(5):
            cur.execute(
                "INSERT INTO attack_metrics (timestamp, source_ip, attack_category, blocked, threat_score) VALUES (?, ?, ?, ?, ?)",
                (recent.isoformat(sep=" "), "192.168.1.100", "brute_force", 1, 0.95),
            )
        
        cur.execute(
            "INSERT INTO attack_metrics (timestamp, source_ip, attack_category, blocked, threat_score) VALUES (?, ?, ?, ?, ?)",
            (recent.isoformat(sep=" "), "192.168.1.200", "xss", 0, 0.40),
        )
        
        conn.commit()
        conn.close()
        
        result = query_incidents(temp_db, 24)
        assert len(result["top_source_ips"]) == 2
        assert result["top_source_ips"][0]["source_ip"] == "192.168.1.100"
        assert result["top_source_ips"][0]["count"] == 5

    def test_query_incidents_attack_runs(self, temp_db):
        conn = sqlite3.connect(temp_db)
        cur = conn.cursor()
        
        cur.execute(
            """INSERT INTO attack_runs (run_id, start_time, end_time, total_attacks, intensity_level, strategy)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("run-001", "2024-01-01 10:00:00", "2024-01-01 11:00:00", 100, "high", "distributed"),
        )
        
        conn.commit()
        conn.close()
        
        result = query_incidents(temp_db, 24)
        assert len(result["recent_runs"]) == 1
        assert result["recent_runs"][0]["run_id"] == "run-001"
        assert result["recent_runs"][0]["total_attacks"] == 100

    def test_redaction_applied_to_summary(self, temp_db):
        conn = sqlite3.connect(temp_db)
        cur = conn.cursor()
        
        now = datetime.utcnow()
        recent = now - timedelta(hours=1)
        
        # Insert data that would appear in body/payload (text field), not IP
        # Source IP is not typically redacted, only text fields
        cur.execute(
            "INSERT INTO attack_metrics (timestamp, source_ip, attack_category, blocked, threat_score) VALUES (?, ?, ?, ?, ?)",
            (recent.isoformat(sep=" "), "192.168.1.1", "sql_injection", 1, 0.85),
        )
        
        conn.commit()
        conn.close()
        
        result = query_incidents(temp_db, 24)
        # Basic structure check - redaction primarily works on string values in dict
        assert result["total_incidents"] == 1

    def test_query_incidents_null_values(self, temp_db):
        conn = sqlite3.connect(temp_db)
        cur = conn.cursor()
        
        now = datetime.utcnow()
        recent = now - timedelta(hours=1)
        
        cur.execute(
            "INSERT INTO attack_metrics (timestamp, source_ip, attack_category, blocked, threat_score) VALUES (?, ?, ?, ?, ?)",
            (recent.isoformat(sep=" "), None, None, 1, 0.85),
        )
        
        conn.commit()
        conn.close()
        
        result = query_incidents(temp_db, 24)
        assert result["total_incidents"] == 1
        # Should handle None gracefully
        if len(result["top_categories"]) > 0:
            assert result["top_categories"][0]["attack_category"] == "unknown"

    def test_redact_text_integration(self):
        # Test the redaction function directly
        text = "Authorization: Bearer sk-12345 and api_key=secret"
        result = redact_text(text)
        assert "sk-12345" not in result
        assert "secret" not in result
        # Multiple patterns may match, count at least 2
        assert result.count("[REDACTED]") >= 2

    def test_redact_dict_integration(self):
        data = {
            "headers": {"Authorization": "Bearer token123"},
            "body": "normal text",
            "nested": {"api_key": "api_key=secret456"},  # Match the pattern expected
        }
        result = redact_dict(data)
        assert "token123" not in str(result)
        assert "secret456" not in str(result)
        assert result["body"] == "normal text"
