import asyncio
import unittest

from main import run_analyzer_with_heartbeat


class SlowAnalyzer:
    async def analyze(self):
        await asyncio.sleep(0.03)
        return {"score": 100, "risk_level": "LOW", "summary": "ok", "findings": [], "metrics": {}}


class FailingAnalyzer:
    async def analyze(self):
        await asyncio.sleep(0.01)
        raise RuntimeError("boom")


class SseHeartbeatTests(unittest.IsolatedAsyncioTestCase):
    async def test_emits_heartbeat_before_slow_analyzer_result(self):
        events = []
        async for event in run_analyzer_with_heartbeat("skill", "Skill", SlowAnalyzer(), "en", heartbeat_interval=0.01):
            events.append(event)

        self.assertEqual(events[0]["type"], "heartbeat")
        self.assertEqual(events[0]["phase"], "skill")
        self.assertEqual(events[0]["name"], "Skill")
        self.assertEqual(events[0]["status"], "running")
        self.assertEqual(events[-1]["event"], "result")
        self.assertEqual(events[-1]["result"]["summary"], "ok")

    async def test_analyzer_exception_becomes_result_payload(self):
        events = []
        async for event in run_analyzer_with_heartbeat("skill", "Skill", FailingAnalyzer(), "en", heartbeat_interval=0.01):
            events.append(event)

        self.assertEqual(events[-1]["event"], "result")
        self.assertEqual(events[-1]["result"]["risk_level"], "UNKNOWN")
        self.assertIn("Analysis failed", events[-1]["result"]["summary"])


class StreamHeartbeatTests(unittest.IsolatedAsyncioTestCase):
    async def test_stream_analysis_yields_heartbeat_events(self):
        events = []
        async for event in run_analyzer_with_heartbeat("code", "Code", SlowAnalyzer(), "en", heartbeat_interval=0.01):
            events.append(event)
        self.assertTrue(any(event.get("type") == "heartbeat" for event in events))
