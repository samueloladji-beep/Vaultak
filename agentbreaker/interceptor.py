import builtins
import threading
import urllib.request
import subprocess
import os
import fnmatch
from typing import Optional

_local = threading.local()

def _get_monitor():
    return getattr(_local, "monitor", None)

def _set_monitor(monitor):
    _local.monitor = monitor

def _clear_monitor():
    _local.monitor = None


# ── File Interceptor ─────────────────────────────────────────────────────────

class FileInterceptor:
    def __init__(self):
        self._original_open = builtins.open
        self._active = False

    def install(self, monitor):
        if self._active:
            return
        self._active = True
        original = self._original_open

        def patched_open(file, mode="r", *args, **kwargs):
            m = _get_monitor()
            if m and isinstance(file, str) and not file.startswith("/proc"):
                if "w" in mode or "a" in mode or "x" in mode:
                    snapshot = None
                    if os.path.exists(file):
                        try:
                            with original(file, "rb") as f:
                                snapshot = f.read()
                        except Exception:
                            snapshot = None
                    decision = m._intercept("file_write", file, {"mode": mode})
                    if decision == "BLOCK":
                        from .exceptions import BehaviorViolationError
                        raise BehaviorViolationError(
                            agent_id=m.agent_id,
                            violation=f"File write blocked by policy: {file}",
                            action_type="file_write"
                        )
                    if snapshot is not None:
                        m._register_file_snapshot(file, snapshot)
                    else:
                        m._register_file_snapshot(file, None)
                elif "r" in mode:
                    m._intercept("file_read", file, {"mode": mode})
            return original(file, mode, *args, **kwargs)

        builtins.open = patched_open

    def uninstall(self):
        if self._active:
            builtins.open = self._original_open
            self._active = False


# ── HTTP Interceptor ─────────────────────────────────────────────────────────

class HttpInterceptor:
    def __init__(self):
        self._original_urlopen = urllib.request.urlopen
        self._active = False

    def install(self, monitor):
        if self._active:
            return
        self._active = True
        original = self._original_urlopen

        def patched_urlopen(url, *args, **kwargs):
            m = _get_monitor()
            if m:
                resource = url if isinstance(url, str) else getattr(url, "full_url", str(url))
                if "vaultak.com" not in resource:
                    decision = m._intercept("api_call", resource, {"method": "HTTP"})
                    if decision == "BLOCK":
                        from .exceptions import BehaviorViolationError
                        raise BehaviorViolationError(
                            agent_id=m.agent_id,
                            violation=f"HTTP call blocked by policy: {resource}",
                            action_type="api_call"
                        )
            return original(url, *args, **kwargs)

        urllib.request.urlopen = patched_urlopen

    def uninstall(self):
        if self._active:
            urllib.request.urlopen = self._original_urlopen
            self._active = False


# ── Subprocess Interceptor ───────────────────────────────────────────────────

class SubprocessInterceptor:
    def __init__(self):
        self._original_run = subprocess.run
        self._original_popen = subprocess.Popen
        self._active = False

    def install(self, monitor):
        if self._active:
            return
        self._active = True
        orig_run = self._original_run
        orig_popen = self._original_popen

        def patched_run(args, *a, **kw):
            m = _get_monitor()
            if m:
                cmd = args[0] if isinstance(args, (list, tuple)) else args
                decision = m._intercept("execute", str(cmd), {"args": str(args)})
                if decision == "BLOCK":
                    from .exceptions import BehaviorViolationError
                    raise BehaviorViolationError(
                        agent_id=m.agent_id,
                        violation=f"Subprocess blocked by policy: {cmd}",
                        action_type="execute"
                    )
            return orig_run(args, *a, **kw)

        def patched_popen(args, *a, **kw):
            m = _get_monitor()
            if m:
                cmd = args[0] if isinstance(args, (list, tuple)) else args
                m._intercept("execute", str(cmd), {"args": str(args)})
            return orig_popen(args, *a, **kw)

        subprocess.run = patched_run
        subprocess.Popen = patched_popen

    def uninstall(self):
        if self._active:
            subprocess.run = self._original_run
            subprocess.Popen = self._original_popen
            self._active = False


# ── Requests Interceptor ─────────────────────────────────────────────────────

class RequestsInterceptor:
    def __init__(self):
        self._active = False
        self._original_send = None

    def install(self, monitor):
        try:
            import requests
            from requests import Session
            original_send = Session.send

            def patched_send(self_session, request, **kwargs):
                m = _get_monitor()
                if m and "vaultak.com" not in request.url:
                    decision = m._intercept("api_call", request.url, {"method": request.method})
                    if decision == "BLOCK":
                        from .exceptions import BehaviorViolationError
                        raise BehaviorViolationError(
                            agent_id=m.agent_id,
                            violation=f"HTTP request blocked: {request.url}",
                            action_type="api_call"
                        )
                return original_send(self_session, request, **kwargs)

            Session.send = patched_send
            self._original_send = original_send
            self._Session = Session
            self._active = True
        except ImportError:
            pass

    def uninstall(self):
        if self._active and self._original_send:
            self._Session.send = self._original_send
            self._active = False


# ── Database Interceptor ─────────────────────────────────────────────────────

class _WrappedSQLiteCursor:
    """Proxy for sqlite3 cursor that intercepts execute calls."""
    def __init__(self, cursor, database, conn):
        self._cursor = cursor
        self._database = database
        self._conn = conn

    def execute(self, sql, parameters=None):
        m = _get_monitor()
        if m:
            sql_upper = sql.strip().upper()
            is_write = any(sql_upper.startswith(kw) for kw in
                          ["INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE"])
            action_type = "database_write" if is_write else "database_read"
            if is_write:
                m._register_db_snapshot(self._database, sql, self._conn)
            decision = m._intercept(action_type, f"{self._database}:{sql[:100]}", {"sql": sql[:100]})
            if decision == "BLOCK":
                from .exceptions import BehaviorViolationError
                raise BehaviorViolationError(
                    agent_id=m.agent_id,
                    violation=f"Database operation blocked: {sql[:100]}",
                    action_type=action_type
                )
        if parameters is not None:
            return self._cursor.execute(sql, parameters)
        return self._cursor.execute(sql)

    def executemany(self, sql, seq):
        m = _get_monitor()
        if m:
            m._intercept("database_write", f"{self._database}:{sql[:100]}", {"sql": sql[:100]})
        return self._cursor.executemany(sql, seq)

    def fetchone(self): return self._cursor.fetchone()
    def fetchall(self): return self._cursor.fetchall()
    def fetchmany(self, size=None): return self._cursor.fetchmany(size)
    def __iter__(self): return iter(self._cursor)
    def __getattr__(self, name): return getattr(self._cursor, name)


def _wrap_sqlite_cursor(cursor, database, conn):
    return _WrappedSQLiteCursor(cursor, database, conn)


class _WrappedSQLiteConnection:
    """Proxy for sqlite3 connection that intercepts cursor calls."""
    def __init__(self, conn, database):
        self._conn = conn
        self._database = database

    def cursor(self, *args, **kwargs):
        cursor = self._conn.cursor(*args, **kwargs)
        return _wrap_sqlite_cursor(cursor, self._database, self._conn)

    def execute(self, sql, parameters=None):
        cursor = self._conn.cursor()
        c = _wrap_sqlite_cursor(cursor, self._database, self._conn)
        if parameters is not None:
            return c.execute(sql, parameters)
        return c.execute(sql)

    def executemany(self, sql, seq):
        cursor = self._conn.cursor()
        c = _wrap_sqlite_cursor(cursor, self._database, self._conn)
        return c.executemany(sql, seq)

    def commit(self): return self._conn.commit()
    def rollback(self): return self._conn.rollback()
    def close(self): return self._conn.close()
    def __getattr__(self, name): return getattr(self._conn, name)
    def __enter__(self): return self
    def __exit__(self, *a): return self._conn.__exit__(*a)


def _wrap_sqlite_connection(conn, database):
    return _WrappedSQLiteConnection(conn, database)


def _wrap_pg_cursor(cursor, dsn, conn):
    original_execute = cursor.execute

    def patched_execute(sql, vars=None):
        m = _get_monitor()
        if m:
            sql_str = str(sql)
            sql_upper = sql_str.strip().upper()
            is_write = any(sql_upper.startswith(kw) for kw in
                          ["INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER"])
            action_type = "database_write" if is_write else "database_read"
            if is_write:
                m._register_db_snapshot(dsn, sql_str, conn)
            decision = m._intercept(action_type, f"{dsn}:{sql_str[:100]}", {"sql": sql_str[:100]})
            if decision == "BLOCK":
                from .exceptions import BehaviorViolationError
                raise BehaviorViolationError(
                    agent_id=m.agent_id,
                    violation=f"Database write blocked: {sql_str[:100]}",
                    action_type=action_type
                )
        if vars is not None:
            return original_execute(sql, vars)
        return original_execute(sql)

    cursor.execute = patched_execute
    return cursor


def _wrap_pg_connection(conn, dsn):
    original_cursor = conn.cursor

    def patched_cursor(*args, **kwargs):
        cursor = original_cursor(*args, **kwargs)
        return _wrap_pg_cursor(cursor, dsn, conn)

    conn.cursor = patched_cursor
    return conn


class DatabaseInterceptor:
    def __init__(self):
        self._active = False
        self._orig_sqlite_connect = None
        self._orig_pg_connect = None

    def install(self, monitor):
        if self._active:
            return
        self._active = True

        # sqlite3
        try:
            import sqlite3
            orig = sqlite3.connect

            def patched_sqlite_connect(database, *args, **kwargs):
                conn = orig(database, *args, **kwargs)
                if _get_monitor():
                    return _wrap_sqlite_connection(conn, database)
                return conn

            sqlite3.connect = patched_sqlite_connect
            self._orig_sqlite_connect = orig
            self._sqlite3 = sqlite3
        except Exception:
            pass

        # psycopg2
        try:
            import psycopg2
            orig_pg = psycopg2.connect

            def patched_pg_connect(*args, **kwargs):
                conn = orig_pg(*args, **kwargs)
                if _get_monitor():
                    dsn = str(kwargs.get("dsn", kwargs.get("database", "postgres")))
                    return _wrap_pg_connection(conn, dsn)
                return conn

            psycopg2.connect = patched_pg_connect
            self._orig_pg_connect = orig_pg
            self._psycopg2 = psycopg2
        except ImportError:
            pass

        # sqlalchemy
        try:
            from sqlalchemy import event
            from sqlalchemy.engine import Engine

            @event.listens_for(Engine, "before_execute")
            def before_execute(conn, clauseelement, multiparams, params, execution_options):
                m = _get_monitor()
                if m:
                    sql = str(clauseelement)
                    is_write = any(kw in sql.upper() for kw in
                                  ["INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE"])
                    action_type = "database_write" if is_write else "database_read"
                    decision = m._intercept(action_type, sql[:200], {"sql": sql[:200]})
                    if decision == "BLOCK":
                        from .exceptions import BehaviorViolationError
                        raise BehaviorViolationError(
                            agent_id=m.agent_id,
                            violation=f"Database operation blocked",
                            action_type=action_type
                        )
        except ImportError:
            pass

    def uninstall(self):
        if not self._active:
            return
        try:
            if self._orig_sqlite_connect:
                self._sqlite3.connect = self._orig_sqlite_connect
        except Exception:
            pass
        try:
            if self._orig_pg_connect:
                self._psycopg2.connect = self._orig_pg_connect
        except Exception:
            pass
        self._active = False


# ── Global instances ─────────────────────────────────────────────────────────

_file_interceptor = FileInterceptor()
_http_interceptor = HttpInterceptor()
_subprocess_interceptor = SubprocessInterceptor()
_requests_interceptor = RequestsInterceptor()
_database_interceptor = DatabaseInterceptor()


def install_all(monitor):
    _set_monitor(monitor)
    _file_interceptor.install(monitor)
    _http_interceptor.install(monitor)
    _subprocess_interceptor.install(monitor)
    _requests_interceptor.install(monitor)
    _database_interceptor.install(monitor)


def uninstall_all():
    _clear_monitor()
    _file_interceptor.uninstall()
    _http_interceptor.uninstall()
    _subprocess_interceptor.uninstall()
    _requests_interceptor.uninstall()
    _database_interceptor.uninstall()
