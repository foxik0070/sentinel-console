"""Modaly se musi skutecne vykreslit, ne jen naimportovat.

Puvodni verze mela DEFAULT_CSS jako @property. Modul se importoval, klavesy
sedely a vsechny testy nad daty prochazely — ale Textual cte DEFAULT_CSS
z TRIDY, kde dostal objekt property, a prvni otevreni okna skoncilo na
'StylesheetError: property object has no attribute splitlines'. Tyhle testy
proto okna opravdu otevrou.
"""
import os
import sys
import asyncio
import unittest

import httpx
from textual.app import App
from textual.widgets import Static, DataTable

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import sentinel_client as sc  # noqa: E402

ROUTES = {
    "/api/ai_sessions": [
        {"host": "h1", "user": "u1", "tool": "Claude Code", "category": "cli",
         "model": "ANTHROPIC_MODEL=opus", "pid": 101, "cwd": "/srv",
         "started_at": "2026-11-12T09:00:00+00:00", "is_active": True},
        {"host": "h1", "user": "u2", "tool": "Ollama", "category": "runtime",
         "pid": 102, "started_at": "2026-11-01T09:00:00+00:00",
         "ended_at": "2026-11-02T09:00:00+00:00", "is_active": False},
    ],
    "/api/root_audit": [
        {"server": "s1", "cluster": "C", "ip": "10.0.0.1", "tty": "pts/0",
         "connected_at": "2026-11-12T09:00:00+00:00", "is_active": True},
    ],
    "/api/agents/health": {"agents": [
        {"hostname": "h1", "status": "ONLINE", "agent_version": "abc", "os_name": "Debian",
         "alerts_24h": 1, "alerts_7d": 3, "alerts_total": 9, "last_data_lag_ms": 12,
         "last_seen": "2026-11-12T09:00:00+00:00"},
        {"hostname": "h2", "status": "OFFLINE", "last_seen": "2026-11-01T09:00:00+00:00"},
    ]},
    "/api/incidents": {
        "incidents": [{"id": "INC-1", "severity": "WARNING", "issue_count": 3,
                       "started_at": "2026-11-12T09:00:00+00:00",
                       "ended_at": "2026-11-12T09:05:00+00:00", "span_min": 5,
                       "hosts": ["h1"], "plugins": ["p1"]}],
        "total_issues": 5, "grouped_issues": 3, "standalone_issues": 2},
    "/api/analytics/slo": {"days": 7, "slo": [
        {"host": "h1", "target_pct": 99.9, "uptime_pct": 99.95, "downtime_min": 5,
         "budget_min": 10, "budget_remaining_min": 5, "budget_used_pct": 50, "status": "ok"}]},
}

TABLE_MODALS = [
    ("AiSessionsModal", 2),
    ("RootAuditModal", 1),
    ("FleetHealthModal", 2),
    ("SloModal", 1),
]


class _Harness(App):
    def compose(self):
        yield Static("")


def _api(routes=ROUTES):
    api = sc.APIClient.__new__(sc.APIClient)
    api._http = httpx.AsyncClient(
        base_url="http://test",
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json=routes.get(r.url.path, []))))
    return api


def _open(modal_cls, routes=ROUTES):
    """Otevre modal v headless aplikaci a vrati pocet radku jeho tabulky."""
    async def run():
        app = _Harness()
        async with app.run_test() as pilot:
            await app.push_screen(modal_cls(_api(routes)))
            for _ in range(4):
                await pilot.pause()
            tables = app.screen.query(DataTable)
            return len(tables.first().rows) if tables else None
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(run())


class TestMount(unittest.TestCase):
    def test_table_modals_render_rows(self):
        for name, expected in TABLE_MODALS:
            with self.subTest(modal=name):
                self.assertEqual(_open(getattr(sc, name)), expected)

    def test_incidents_modal_opens(self):
        # Nema DataTable, staci ze se vykresli bez vyjimky.
        self.assertIsNone(_open(sc.IncidentsModal))

    def test_default_css_is_a_string_on_every_class(self):
        # Textual ho cte z tridy; cokoliv jineho nez str parser neprekousne.
        for name in [n for n, _ in TABLE_MODALS] + ["IncidentsModal", "_TableModal"]:
            with self.subTest(modal=name):
                self.assertIsInstance(getattr(sc, name).DEFAULT_CSS, str)

    def test_modals_survive_empty_responses(self):
        empty = {k: ([] if isinstance(v, list) else {}) for k, v in ROUTES.items()}
        for name, _ in TABLE_MODALS:
            with self.subTest(modal=name):
                self.assertEqual(_open(getattr(sc, name), empty), 0)
        self.assertIsNone(_open(sc.IncidentsModal, empty))


if __name__ == "__main__":
    unittest.main()
