"""Prehledy pribyle v Sentinelu v2026.09-10 (AI uzivatele, root audit, flotila,
incidenty, SLO).

Konzole se proti Sentinelu neoveruje nicim jinym nez temito volanimi, takze
testy drzi dve veci: ze klient cte odpovedi ve tvaru, v jakem je server posila,
a ze kazda klavesa ma skutecne existujici akci — preklep v Binding() se jinak
projevi az tim, ze klavesa v provozu tise nic nedela.
"""
import os
import sys
import asyncio
import unittest

import httpx

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import sentinel_client as sc  # noqa: E402


def _api(routes):
    """SentinelAPI s podvrzenym transportem; routes = {cesta: json}."""
    def handler(request: httpx.Request) -> httpx.Response:
        body = routes.get(request.url.path)
        if body is None:
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json=body)

    api = sc.APIClient.__new__(sc.APIClient)
    api._http = httpx.AsyncClient(base_url="http://test",
                                  transport=httpx.MockTransport(handler))
    return api


def _run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


class TestHelpers(unittest.TestCase):
    def test_short_dt(self):
        self.assertEqual(sc._short_dt("2026-10-23T15:33:19.123+00:00"), "23.10. 15:33")
        self.assertEqual(sc._short_dt(None), "-")
        self.assertEqual(sc._short_dt("necas"), "necas")

    def test_age_units(self):
        base = "2026-10-23T10:00:00+00:00"
        self.assertEqual(sc._age(base, "2026-10-23T10:30:00+00:00"), "30m")
        self.assertEqual(sc._age(base, "2026-10-23T14:00:00+00:00"), "4h")
        self.assertEqual(sc._age(base, "2026-10-26T10:00:00+00:00"), "3d")

    def test_age_survives_garbage(self):
        self.assertEqual(sc._age(None), "-")
        self.assertEqual(sc._age("necas", "taky ne"), "-")

    def test_age_never_negative(self):
        # Rozjete hodiny mezi strojem a serverem nesmi vyrobit zaporny cas.
        self.assertEqual(sc._age("2026-10-23T12:00:00+00:00", "2026-10-23T10:00:00+00:00"), "0m")


class TestApiClient(unittest.TestCase):
    def test_ai_sessions_returns_list(self):
        api = _api({"/api/ai_sessions": [{"host": "h", "user": "u", "tool": "Claude Code",
                                          "is_active": True}]})
        rows = _run(api.get_ai_sessions())
        self.assertEqual(rows[0]["tool"], "Claude Code")

    def test_root_audit_returns_list(self):
        api = _api({"/api/root_audit": [{"server": "s", "ip": "10.0.0.1", "is_active": True}]})
        self.assertEqual(len(_run(api.get_root_audit())), 1)

    def test_agent_health_unwraps_agents(self):
        api = _api({"/api/agents/health": {"agents": [{"hostname": "h", "status": "ONLINE"}]}})
        self.assertEqual(_run(api.get_agent_health())[0]["hostname"], "h")

    def test_incidents_returns_envelope(self):
        api = _api({"/api/incidents": {"incidents": [{"id": "INC-1"}], "total_issues": 3,
                                       "grouped_issues": 2, "standalone_issues": 1}})
        d = _run(api.get_incidents())
        self.assertEqual(d["incidents"][0]["id"], "INC-1")
        self.assertEqual(d["total_issues"], 3)

    def test_slo_unwraps_list(self):
        api = _api({"/api/analytics/slo": {"days": 7, "slo": [{"host": "h", "uptime_pct": 99.9}]}})
        self.assertEqual(_run(api.get_slo())[0]["uptime_pct"], 99.9)

    def test_server_error_does_not_raise(self):
        # Starsi Sentinel endpoint nezna -> 404. Konzole musi zustat pouzitelna.
        api = _api({})
        self.assertEqual(_run(api.get_ai_sessions()), [])
        self.assertEqual(_run(api.get_agent_health()), [])
        self.assertEqual(_run(api.get_incidents()), {})
        self.assertEqual(_run(api.get_slo()), [])


class TestBindings(unittest.TestCase):
    NEW_KEYS = {"u": "open_ai_users", "R": "open_root_audit", "h": "open_fleet",
                "e": "open_incidents", "b": "open_slo"}

    def test_every_binding_has_an_action(self):
        missing = []
        for b in sc.SentinelConsole.BINDINGS:
            for key in str(b.action).split(","):
                if not hasattr(sc.SentinelConsole, f"action_{key.strip()}"):
                    missing.append(b.action)
        self.assertEqual(missing, [], f"Binding bez akce: {missing}")

    def test_new_views_are_bound(self):
        bound = {str(b.key): str(b.action) for b in sc.SentinelConsole.BINDINGS}
        for key, action in self.NEW_KEYS.items():
            self.assertEqual(bound.get(key), action, f"klavesa {key} nevede na {action}")

    def test_new_keys_do_not_collide(self):
        keys = [str(b.key) for b in sc.SentinelConsole.BINDINGS]
        for key in self.NEW_KEYS:
            self.assertEqual(keys.count(key), 1, f"klavesa {key} je navazana vickrat")

    def test_modal_classes_exist(self):
        for cls in ("AiSessionsModal", "RootAuditModal", "FleetHealthModal",
                    "IncidentsModal", "SloModal"):
            self.assertTrue(hasattr(sc, cls), f"chybi {cls}")

    def test_help_mentions_new_views(self):
        for key in self.NEW_KEYS:
            self.assertIn(f"[yellow]{key}[/]", sc.HELP_TEXT, f"napoveda neuvadi {key}")


if __name__ == "__main__":
    unittest.main()
