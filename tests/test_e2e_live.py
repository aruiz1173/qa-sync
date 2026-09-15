"""Opt-in, non-writing E2E checks against dedicated QA infrastructure and real devices."""

from __future__ import annotations

import os
import time
import unittest

from qasync.config import Config
from qasync.recorder import RecorderManager
from qasync.service import QASyncService


LIVE = os.getenv("QA_SYNC_E2E", "").lower() in {"1", "true", "yes"}


@unittest.skipUnless(LIVE, "set QA_SYNC_E2E=1 to run dedicated live E2E checks")
class LiveMobileE2ETests(unittest.TestCase):
    def setUp(self):
        self.config = Config.from_env()
        if self.config.write_mode != "review_only":
            self.fail("Live E2E requires QA_SYNC_WRITE_MODE=review_only")
        self.case_id = os.environ["QA_SYNC_E2E_CASE_ID"]
        self.recorder = RecorderManager(
            max_frames=2, max_duration=30, appium_url=self.config.appium_url,
            ios_bundle_id=self.config.ios_bundle_id,
            appium_capabilities_json=self.config.appium_capabilities_json,
            ios_devices_json=self.config.ios_devices_json,
            evidence_key=self.config.evidence_key,
        )

    def _exercise(self, platform: str, device_id: str):
        session = self.recorder.start(platform, device_id, int(self.case_id.lstrip("Cc")))
        deadline = time.time() + 20
        while time.time() < deadline and not self.recorder.status(session["session_id"])["frames"]:
            time.sleep(0.25)
        self.recorder.stop(session["session_id"])
        result = QASyncService(self.config, recorder=self.recorder).analyze_recording({
            "session_id": session["session_id"], "case_id": self.case_id,
            "context": "Dedicated QA Sync E2E smoke test",
        })
        self.assertEqual(result["case_id"], int(self.case_id.lstrip("Cc")))
        self.assertTrue(result["changes"])

    def test_android_emulator_to_testrail_proposal(self):
        device = os.getenv("QA_SYNC_E2E_ANDROID_DEVICE", "")
        if not device:
            self.skipTest("QA_SYNC_E2E_ANDROID_DEVICE is not configured")
        self._exercise("android", device)

    def test_ios_simulator_to_testrail_proposal(self):
        device = os.getenv("QA_SYNC_E2E_IOS_DEVICE", "")
        if not device:
            self.skipTest("QA_SYNC_E2E_IOS_DEVICE is not configured")
        self._exercise("ios", device)
