"""
CAPSTONE-1 Database Access Layer
Runtime database is PostgreSQL. SQLite remains available only for local reference/testing.
Strict privacy protection: no passwords, tokens, or secret values are stored.
"""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg
from dotenv import load_dotenv
from psycopg.rows import dict_row

load_dotenv()

DB_FILE_PATH = Path(__file__).resolve().parent / "capstone.db"
SCHEMA_FILE_PATH = Path(__file__).resolve().parent / "schema.sql"


class Database:
    database_engine = "postgresql"

    def __init__(self):
        self.db_host = os.getenv("DB_HOST", "localhost")
        self.db_port = int(os.getenv("DB_PORT", "5432"))
        self.db_name = os.getenv("DB_NAME", "capstone1")
        self.db_user = os.getenv("DB_USER", "postgres")
        self.db_password = os.getenv("DB_PASSWORD", "")
        self._is_connected = False
        self.init_db()

    def get_connection(self):
        conn = psycopg.connect(
            host=self.db_host,
            port=self.db_port,
            dbname=self.db_name,
            user=self.db_user,
            password=self.db_password,
            connect_timeout=10,
        )
        return conn

    def init_db(self) -> None:
        try:
            with self.get_connection() as conn:
                if SCHEMA_FILE_PATH.exists():
                    schema_sql = SCHEMA_FILE_PATH.read_text(encoding="utf-8")
                    with conn.cursor() as cursor:
                        cursor.execute(schema_sql)

                with conn.cursor() as cursor:
                    cursor.execute("SELECT COUNT(*) FROM model_versions")
                    if cursor.fetchone()[0] == 0:
                        cursor.execute(
                            "INSERT INTO model_versions (model_id, version, model_type, sha256_hash, is_active) "
                            "VALUES (%s, %s, %s, %s, %s)",
                            ("model-onnx-v1.1", "1.1.0", "ONNX / LogisticRegression", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", True),
                        )

                    event_model = Path(__file__).resolve().parents[1] / 'browser-extension/assets/event-model.json'
                    if event_model.exists():
                        cursor.execute("UPDATE model_versions SET is_active = false WHERE model_id <> %s", ('controlled-event-lr-1',))
                        cursor.execute("INSERT INTO model_versions (model_id, version, model_type, sha256_hash, is_active) "
                                       "VALUES (%s, %s, %s, %s, true) ON CONFLICT (model_id) DO UPDATE SET "
                                       "sha256_hash=EXCLUDED.sha256_hash, model_type=EXCLUDED.model_type, is_active=true",
                                       ('controlled-event-lr-1', 'event-features-1', 'LogisticRegression CONTROLLED uncalibrated', hashlib.sha256(event_model.read_bytes()).hexdigest()))

                    cursor.execute("SELECT COUNT(*) FROM policy_versions")
                    if cursor.fetchone()[0] == 0:
                        cursor.execute(
                            "INSERT INTO policy_versions (policy_id, version, description, is_active) "
                            "VALUES (%s, %s, %s, %s)",
                            ("policy-v1.1", "1.1.0", "Standard Threat Policy (Allow/Warn/Contain/Block)", True),
                        )

                    cursor.execute("SELECT COUNT(*) FROM service_profiles")
                    if cursor.fetchone()[0] == 0:
                        cursor.execute(
                            "INSERT INTO service_profiles (service_id, service_name, category, declared_behavior) "
                            "VALUES (%s, %s, %s, %s)",
                            ("google", "Google Account Services", "identity_provider", json.dumps({"declared_auth": ["password", "otp"], "primary_domain": "google.com"})),
                        )
                        cursor.execute(
                            "INSERT INTO service_domains (service_id, domain, is_primary) VALUES (%s, %s, %s)",
                            ("google", "accounts.google.com", True),
                        )
                        cursor.execute(
                            "INSERT INTO service_domains (service_id, domain, is_primary) VALUES (%s, %s, %s)",
                            ("google", "google.com", False),
                        )

                conn.commit()
                self._is_connected = True
        except Exception as e:
            print(f"[CAPSTONE-1 DB Warning] DB init error: {type(e).__name__}")
            self._is_connected = False

    def is_healthy(self) -> bool:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    return cursor.fetchone()[0] == 1
        except Exception:
            return False

    def get_active_model(self) -> Optional[Dict[str, Any]]:
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cursor:
                    cursor.execute(
                        "SELECT model_id, version, model_type, sha256_hash, is_active, created_at "
                        "FROM model_versions WHERE is_active = true LIMIT 1"
                    )
                    row = cursor.fetchone()
                    return dict(row) if row else None
        except Exception as e:
            print(f"[CAPSTONE-1 DB] Error fetching active model: {type(e).__name__}")
            return None

    def get_service_profile(self, service_id: str) -> Optional[Dict[str, Any]]:
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cursor:
                    cursor.execute(
                        "SELECT service_id, service_name, category, declared_behavior, created_at "
                        "FROM service_profiles WHERE service_id = %s",
                        (service_id,),
                    )
                    row = cursor.fetchone()
                    if not row:
                        return None
                    profile = dict(row)
                    cursor.execute(
                        "SELECT domain, is_primary FROM service_domains WHERE service_id = %s",
                        (service_id,),
                    )
                    profile["domains"] = [dict(d) for d in cursor.fetchall()]
                    if profile.get("declared_behavior"):
                        try:
                            profile["declared_behavior"] = json.loads(profile["declared_behavior"])
                        except Exception:
                            pass
                    return profile
        except Exception as e:
            print(f"[CAPSTONE-1 DB] Error fetching service profile: {type(e).__name__}")
            return None

    def list_observations(self, limit: int = 20) -> List[Dict[str, Any]]:
        try:
            with self.get_connection() as conn:
                with conn.cursor(row_factory=dict_row) as cursor:
                    cursor.execute(
                        "SELECT observation_id, collection_id, device_id, device_platform, page_domain, page_url_sanitized, is_https, "
                        "form_count, input_count, script_count, requested_data_types, privacy_policy_url, terms_url, threat_level, model_score, policy_action, observed_at "
                        "FROM observations ORDER BY observed_at DESC LIMIT %s",
                        (limit,),
                    )
                    rows = cursor.fetchall()
                    return [dict(row) for row in rows]
        except Exception as e:
            print(f"[CAPSTONE-1 DB] Error listing observations: {type(e).__name__}")
            return []

    def store_observation(
        self,
        observation_id: str,
        collection_id: str,
        device_id: str,
        device_platform: str,
        page_domain: str,
        page_url_sanitized: str,
        is_https: bool,
        form_count: int,
        input_count: int,
        script_count: int,
        requested_data_types: List[str],
        privacy_policy_url: str = "",
        terms_url: str = "",
        threat_level: Optional[str] = None,
        model_score: Optional[float] = None,
        policy_action: Optional[str] = None,
    ) -> bool:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO observations ("
                        "  observation_id, collection_id, device_id, device_platform, page_domain, page_url_sanitized, is_https, "
                        "  form_count, input_count, script_count, requested_data_types, privacy_policy_url, terms_url, threat_level, model_score, policy_action"
                        ") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            observation_id,
                            collection_id,
                            device_id,
                            device_platform,
                            page_domain,
                            page_url_sanitized,
                            is_https,
                            form_count,
                            input_count,
                            script_count,
                            json.dumps(requested_data_types),
                            privacy_policy_url,
                            terms_url,
                            threat_level,
                            model_score,
                            policy_action,
                        ),
                    )
                conn.commit()
                return True
        except Exception as e:
            print(f"[CAPSTONE-1 DB] Error storing observation: {type(e).__name__}")
            return False


db_instance = Database()
