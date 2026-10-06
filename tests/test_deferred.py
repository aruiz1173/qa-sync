from __future__ import annotations

import tempfile
import subprocess
import sys
import time
import unittest
import base64
import io
from pathlib import Path
from unittest.mock import Mock, patch

from PIL import Image

from qasync.checkpoints import VisionCheckpoints
from qasync.deferred import DeferredQueue
from qasync.errors import ExternalServiceError, UsageLimitError, ValidationError
from qasync.execution import ExecutionStore
from qasync.recorder import RecorderManager, RecordingSession
from qasync.service import DraftStore, Proposal, QASyncService
from qasync.vision import VisionAnalyzer
from tests.test_core import config


class DeferredQueueTests(unittest.TestCase):
    def test_abrupt_capture_exit_recovers_complete_orphan_but_not_partial_frame(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "recovery"
            key = base64.urlsafe_b64encode(b"c" * 32).decode()
            recorder = RecorderManager(recovery_dir=root, evidence_key=key)
            session_id = "c" * 32
            folder = root / session_id
            folder.mkdir(parents=True)
            session = RecordingSession(id=session_id, platform="ios", device_id="sim", directory=folder,
                                       interval=1, max_frames=40, case_id=42)
            recorder._persist(session)
            output = io.BytesIO()
            Image.new("RGB", (2, 2), "white").save(output, format="PNG")
            child = subprocess.run([sys.executable, "-c",
                "import base64,os,sys; from pathlib import Path; from qasync.evidence import EvidenceCipher; "
                "folder=Path(sys.argv[1]); folder.joinpath('frame-001.qasec').write_bytes(EvidenceCipher(sys.argv[2]).encrypt(base64.b64decode(sys.argv[3]))); "
                "folder.joinpath('frame-002.qasec').write_bytes(b'incomplete'); os._exit(17)",
                str(folder), key, base64.b64encode(output.getvalue()).decode()],
                cwd=str(Path(__file__).resolve().parents[1]), check=False)
            self.assertEqual(child.returncode, 17)
            restored = RecorderManager(recovery_dir=root, evidence_key=key)
            self.assertEqual(restored.status(session_id)["frames"], 1)
            images, _, _ = restored.evidence(session_id)
            self.assertEqual(base64.b64decode(images[0]["data"]), output.getvalue())
            self.assertEqual(RecorderManager(recovery_dir=root, evidence_key=key).status(session_id)["frames"], 1)

    def test_abrupt_batch_and_synthesis_exits_reuse_checkpointed_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = """
import base64, json, os, sys
from pathlib import Path
from unittest.mock import patch
from qasync.checkpoints import VisionCheckpoints
from qasync.vision import VisionAnalyzer
from tests.test_core import config
root, phase = Path(sys.argv[1]), sys.argv[2]
key = base64.urlsafe_b64encode(b'x' * 32).decode()
checkpoints = VisionCheckpoints(root / 'checkpoints', key)
images = [{'type':'image/png','data':base64.b64encode(f'frame-{n}'.encode()).decode()} for n in range(8)]
def provider(self, name, images, prompt):
    with (root / 'calls').open('a') as log:
        log.write(str(len(images)) + '\\n')
    return {'title':'Case','preconditions':'','confidence':0.8,'warnings':[],
            'steps':[{'content':'Tap','expected':'Done'}]}
def progress(event):
    if event['stage'] == phase:
        os._exit(17)
with patch.object(VisionAnalyzer, '_call_provider', provider):
    result = VisionAnalyzer(config(vision_quality='economical')).analyze(
        platform='ios', images=images, context='', current_case={'id':1},
        progress=progress,
        checkpoint_get=lambda stage:checkpoints.get('a'*32,'analysis-key',stage),
        checkpoint_put=lambda stage,value:checkpoints.put('a'*32,'analysis-key',stage,value))
print(json.dumps(result['_usage']))
"""
            for phase in ("batch_complete", "synthesis_complete"):
                child = subprocess.run([sys.executable, "-c", script, str(root), phase],
                                       cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True)
                self.assertEqual(child.returncode, 17, child.stderr)
            finished = subprocess.run([sys.executable, "-c", script, str(root), "never"],
                                      cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True)
            self.assertEqual(finished.returncode, 0, finished.stderr)
            self.assertEqual((root / "calls").read_text().splitlines(), ["4", "4", "0"])
            self.assertEqual(__import__("json").loads(finished.stdout)["model_calls_reused"], 3)
            raw = next((root / "checkpoints" / ("a"*32)).glob("*.qacp")).read_bytes()
            self.assertNotIn(b"Tap", raw)

    def test_service_restart_reuses_queued_batch_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)), patch("qasync.service.TestRailClient") as client_type:
            client_type.return_value.get_case.return_value = {"id": 1, "title": "Case", "custom_steps_separated": []}
            key = base64.urlsafe_b64encode(b"s" * 32).decode()
            settings = config(vision_quality="economical", evidence_key=key)
            images = [{"type": "image/png", "data": base64.b64encode(f"frame-{index}".encode()).decode()}
                      for index in range(8)]
            calls = []
            def provider(self, name, frames, prompt):
                calls.append(len(frames))
                return {"title": "Case", "preconditions": "", "confidence": 0.8, "warnings": [],
                        "steps": [{"content": "Tap", "expected": "Done"}]}
            request = {"case_id": 1, "platform": "ios", "images": images}
            first = QASyncService(settings, recorder=Mock())
            first._style_samples = Mock(return_value=[])
            def interrupt(event):
                if event["stage"] == "batch_complete":
                    raise RuntimeError("simulated interruption after durable checkpoint")
            with patch.object(VisionAnalyzer, "_call_provider", provider), self.assertRaisesRegex(RuntimeError, "interruption"):
                first.analyze({**request, "_progress_callback": interrupt}, queue_job_id="e"*32)
            second = QASyncService(settings, recorder=Mock())
            second._style_samples = Mock(return_value=[])
            with patch.object(VisionAnalyzer, "_call_provider", provider):
                result = second.analyze(request, queue_job_id="e"*32)
            self.assertEqual(calls, [4, 4, 0])
            self.assertEqual(result["usage"]["model_calls_reused"], 1)
            with patch.object(VisionAnalyzer, "_call_provider", provider):
                changed = second.analyze({**request, "context": "different flow"}, queue_job_id="e"*32)
            self.assertEqual(calls, [4, 4, 0, 4, 4, 0])
            self.assertEqual(changed["usage"]["model_calls_reused"], 0)

    def test_reviewer_evidence_links_survive_draft_and_cannot_claim_unselected_screen(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            service = QASyncService(config(), recorder=Mock())
            steps_field = service.config.testrail_steps_field
            pre_field = service.config.testrail_preconditions_field
            proposal = Proposal(31, "ios", {"title": "Old", steps_field: []},
                                {"title": "New", pre_field: "", steps_field: [{"content": "Tap", "expected": "Open"}]},
                                time.time(), usage={"selected_frame_indices": [2, 5]},
                                evidence_session_id="b"*32)
            token = service.store.put(proposal)
            payload = {"proposal_token": token, "title": "New", "preconditions": "",
                       "steps": [{"content": "Tap", "expected": "Open"}], "evidence_links": [5]}
            with self.assertRaisesRegex(ValidationError, "selected"):
                service.revise_proposal({**payload, "evidence_links": [4]})
            revised = service.revise_proposal(payload)
            self.assertEqual(revised["evidence_links"], [5])
            saved = service.save_draft({"proposal_token": token, "name": "Evidence-linked"})
            reopened = service.open_draft({"draft_id": saved["draft_id"]})
            self.assertEqual(reopened["evidence_links"], [5])
            self.assertEqual(reopened["evidence_session_id"], "b"*32)
            self.assertEqual(reopened["changes"][steps_field], [{"content": "Tap", "expected": "Open"}])

    def test_per_case_reorder_and_unschedule_preserve_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = DeferredQueue(Path(directory) / "deferred.json")
            rows = [queue.add(session_id=str(index)*32, case_id=index, platform="ios") for index in (1, 2, 3)]
            for index, row in enumerate(rows, 1):
                queue.review(row["id"], [0], False)
                queue.set_state(row["id"], "scheduled", queue_order=index)
            queue.move(rows[2]["id"], "up")
            self.assertEqual([row["case_id"] for row in queue.pending()], [1, 3, 2])
            with self.assertRaises(ValidationError):
                queue.move(rows[0]["id"], "up")
            queue.unschedule(rows[2]["id"])
            self.assertEqual([row["case_id"] for row in queue.pending()], [1, 2])
            self.assertEqual(queue.get(rows[2]["id"])["selected_frames"], [0])
            self.assertEqual(DeferredQueue(Path(directory) / "deferred.json").get(rows[2]["id"])["state"], "ready")

    def test_unscheduled_case_cannot_be_claimed_by_stale_worker_snapshot(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            recorder = Mock()
            service = QASyncService(config(), recorder=recorder)
            item = service.deferred.add(session_id="a"*32, case_id=21, platform="ios")
            service.deferred.review(item["id"], [0], False)
            service.deferred.set_state(item["id"], "scheduled", queue_order=1)
            service.unschedule_deferred({"id": item["id"]})
            service.analyze_recording = Mock()
            service._run_deferred_item(item["id"])
            service.analyze_recording.assert_not_called()
            recorder.unprotect.assert_not_called()
            self.assertEqual(service.deferred.get(item["id"])["selected_frames"], [0])

    def test_abrupt_process_exit_retries_once_in_order_without_losing_capture(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            path = Path(directory) / "deferred.json"
            queue = DeferredQueue(path)
            rows = [queue.add(session_id=str(index)*32, case_id=index, platform="ios") for index in (1, 2)]
            for index, row in enumerate(rows, 1):
                queue.review(row["id"], [0], False)
                queue.set_state(row["id"], "scheduled", queue_order=index)
            queue.pause()
            child = subprocess.run([sys.executable, "-c",
                "import os,sys; from pathlib import Path; from qasync.deferred import DeferredQueue; "
                "DeferredQueue(Path(sys.argv[1])).set_state(sys.argv[2], 'running'); os._exit(17)",
                str(path), rows[0]["id"]], cwd=str(Path(__file__).resolve().parents[1]), check=False)
            self.assertEqual(child.returncode, 17)
            recorder = Mock()
            service = QASyncService(config(), recorder=recorder)
            self.assertEqual(service.deferred.get(rows[0]["id"])["state"], "scheduled")
            seen = []
            service.analyze_recording = lambda request, **kwargs: (seen.append(request["case_id"]) or {"proposal_token": str(request["case_id"])})
            service._save_deferred_draft = lambda token, item: token
            worker = service._deferred_worker
            service.resume_deferred()
            worker.join(timeout=3)
            self.assertEqual(seen, [1, 2])
            self.assertEqual([service.deferred.get(row["id"])["state"] for row in rows], ["completed", "completed"])
            recorder.unprotect.assert_not_called()

    def test_failed_analysis_can_be_requeued_without_repeating_screen_review(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            recorder = Mock()
            service = QASyncService(config(), recorder=recorder)
            item = service.deferred.add(session_id="7" * 32, case_id=7, platform="ios")
            service.deferred.review(item["id"], [0], False)
            service.deferred.set_state(item["id"], "scheduled", queue_order=1)
            service.analyze_recording = Mock(side_effect=ExternalServiceError("temporary failure"))
            service._run_deferred_item(item["id"])
            self.assertEqual(service.deferred.get(item["id"])["state"], "failed")
            with patch.object(service, "_ensure_deferred_worker"):
                service.start_deferred({"ids": [item["id"]], "mode": "sequential"})
            self.assertEqual(service.deferred.get(item["id"])["state"], "scheduled")
            self.assertEqual(service.deferred.get(item["id"])["selected_frames"], [0])

    def test_try_now_only_targets_first_waiting_case(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            service = QASyncService(config(), recorder=Mock())
            first = service.deferred.add(session_id="8" * 32, case_id=8, platform="ios")
            second = service.deferred.add(session_id="9" * 32, case_id=9, platform="ios")
            service.deferred.set_state(first["id"], "waiting_limit", queue_order=1, retry_at=time.time()+3600)
            service.deferred.set_state(second["id"], "waiting_limit", queue_order=2, retry_at=time.time()+3600)
            with self.assertRaisesRegex(ValidationError, "no longer waiting"):
                service.retry_deferred_now({"id": second["id"]})
            with patch.object(service, "_ensure_deferred_worker"):
                result = service.retry_deferred_now({"id": first["id"]})
            self.assertEqual(result["item"]["retry_at"], 0)
            self.assertGreater(service.deferred.get(second["id"])["retry_at"], time.time())

    def test_draft_idempotency_keeps_original_after_repeated_save(self):
        with tempfile.TemporaryDirectory() as directory:
            drafts = DraftStore(Path(directory) / "drafts.json")
            proposal = Proposal(case_id=12, platform="ios", current={}, changes={"title": "first"}, created_at=time.time())
            first = drafts.save("C12", proposal, idempotency_key="queue-job-12")
            proposal.changes["title"] = "second"
            self.assertEqual(drafts.save("C12", proposal, idempotency_key="queue-job-12"), first)
            self.assertEqual(DraftStore(Path(directory) / "drafts.json").get(first)["changes"]["title"], "first")

    def test_restart_recognises_saved_draft_without_another_ai_call(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            root = Path(directory)
            queue = DeferredQueue(root / "deferred.json")
            item = queue.add(session_id="6" * 32, case_id=6, platform="ios")
            queue.review(item["id"], [0], False)
            queue.set_state(item["id"], "running", queue_order=1)
            queue.pause()
            proposal = Proposal(case_id=6, platform="ios", current={}, changes={"title": "saved"}, created_at=time.time())
            draft_id = DraftStore(root / "drafts.json").save("C6", proposal, idempotency_key=item["id"])
            service = QASyncService(config(), recorder=Mock())
            worker = service._deferred_worker
            service.analyze_recording = Mock()
            service.resume_deferred()
            worker.join(timeout=2)
            self.assertEqual(service.deferred.get(item["id"])["draft_id"], draft_id)
            service.analyze_recording.assert_not_called()

    def test_abrupt_exit_after_draft_write_does_not_repeat_analysis_or_duplicate_draft(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            root = Path(directory)
            queue = DeferredQueue(root / "deferred.json")
            item = queue.add(session_id="d" * 32, case_id=77, platform="ios")
            queue.review(item["id"], [0], False)
            queue.set_state(item["id"], "running", queue_order=1)
            queue.pause()
            child = subprocess.run([sys.executable, "-c",
                "import os,sys,time; from pathlib import Path; from qasync.service import DraftStore,Proposal; "
                "root=Path(sys.argv[1]); item=sys.argv[2]; "
                "DraftStore(root/'drafts.json').save('C77', Proposal(77,'ios',{}, {'title':'saved'},time.time()), idempotency_key=item); os._exit(17)",
                str(root), item["id"]], cwd=str(Path(__file__).resolve().parents[1]), check=False)
            self.assertEqual(child.returncode, 17)
            service = QASyncService(config(), recorder=Mock())
            worker = service._deferred_worker
            service.analyze_recording = Mock()
            service.resume_deferred()
            worker.join(timeout=3)
            self.assertEqual(service.deferred.get(item["id"])["state"], "completed")
            self.assertEqual(len(service.drafts.list()), 1)
            service.analyze_recording.assert_not_called()

    def test_pause_resume_and_cancel_keep_evidence(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            recorder = Mock()
            service = QASyncService(config(), recorder=recorder)
            item = service.deferred.add(session_id="4" * 32, case_id=4, platform="ios")
            service.deferred.review(item["id"], [0], False)
            service.analyze_recording = Mock(return_value={"proposal_token": "p"})
            service._save_deferred_draft = Mock(return_value="d")
            with patch.object(service, "_ensure_deferred_worker"):
                service.start_deferred({"ids": [item["id"]], "mode": "sequential",
                                        "retry_minutes": 30, "max_limit_attempts": 3})
            self.assertEqual(service.deferred.status()["retry_minutes"], 30)
            service.pause_deferred()
            service._run_deferred_item(item["id"])
            service.analyze_recording.assert_not_called()
            self.assertTrue(DeferredQueue(Path(directory) / "deferred.json").paused)
            service.cancel_deferred()
            self.assertEqual(service.deferred.get(item["id"])["state"], "ready")
            recorder.unprotect.assert_not_called()
            self.assertFalse(service.deferred.status()["paused"])

    def test_repeated_limits_pause_for_human_review(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            service = QASyncService(config(), recorder=Mock())
            item = service.deferred.add(session_id="5" * 32, case_id=5, platform="ios")
            service.deferred.review(item["id"], [0], False)
            service.deferred.configure(5, 2)
            service.deferred.set_state(item["id"], "scheduled", queue_order=1)
            service.analyze_recording = Mock(side_effect=UsageLimitError("limit"))
            service._run_deferred_item(item["id"])
            self.assertFalse(service.deferred.paused)
            service._run_deferred_item(item["id"])
            self.assertTrue(service.deferred.paused)
            self.assertEqual(service.deferred.paused_reason, "limit_attempts")
            self.assertEqual(service.deferred.get(item["id"])["limit_attempts"], 2)
            self.assertEqual(service.analyze_recording.call_count, 2)
            with self.assertRaisesRegex(ValidationError, "Cancel this pending"):
                service.deferred.review(item["id"], [0], False)

    def test_queue_survives_restart_and_preserves_authorised_work(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deferred.json"
            queue = DeferredQueue(path)
            item = queue.add(session_id="a" * 32, case_id=42, platform="ios",
                             context="password: abc123")
            self.assertEqual(item["state"], "needs_review")
            self.assertNotIn("abc123", item["context"])
            ready = queue.review(item["id"], [1, 3], False)
            self.assertEqual(ready["state"], "ready")
            queue.set_state(item["id"], "running")
            restored = DeferredQueue(path).get(item["id"])
            self.assertEqual(restored["state"], "scheduled")
            self.assertEqual(restored["selected_frames"], [1, 3])
            self.assertIn("retry in queue order", restored["error"])

    def test_restart_during_uncheckpointed_provider_call_pauses_before_repeat(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "deferred.json"
            queue = DeferredQueue(path)
            item = queue.add(session_id="f" * 32, case_id=54, platform="ios")
            queue.review(item["id"], [0], False)
            queue.set_state(item["id"], "scheduled", queue_order=1)
            child = subprocess.run([sys.executable, "-c",
                "import os,sys; from pathlib import Path; from qasync.deferred import DeferredQueue; "
                "DeferredQueue(Path(sys.argv[1])).set_state(sys.argv[2], 'running', "
                "progress={'stage':'synthesis','current':2,'total':2}); os._exit(17)",
                str(path), item["id"]], cwd=str(Path(__file__).resolve().parents[1]), check=False)
            self.assertEqual(child.returncode, 17)
            restored = DeferredQueue(path)
            row = restored.get(item["id"])
            self.assertEqual(row["state"], "failed")
            self.assertEqual(row["error_code"], "uncertain_provider_call")
            self.assertEqual(row["selected_frames"], [0])
            self.assertTrue(restored.paused)
            self.assertEqual(restored.paused_reason, "uncertain_call")

    def test_sequential_queue_pauses_on_limit_then_resumes_in_order(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            recorder = Mock()
            recorder.status.return_value = {"frames": 3}
            service = QASyncService(config(), recorder=recorder)
            first = service.deferred.add(session_id="1" * 32, case_id=1, platform="ios")
            second = service.deferred.add(session_id="2" * 32, case_id=2, platform="ios")
            for item in (first, second):
                service.deferred.review(item["id"], [0], False)
            calls = []

            def analyze(request, **kwargs):
                calls.append(request["case_id"])
                if len(calls) == 1:
                    raise UsageLimitError("provider exhausted")
                return {"proposal_token": str(request["case_id"])}

            service.analyze_recording = analyze
            service._save_deferred_draft = lambda token, item: token
            with patch.object(service, "_ensure_deferred_worker"):
                service.start_deferred({"ids": [first["id"], second["id"]], "mode": "sequential"})
            service._run_deferred_item(first["id"])
            self.assertEqual(calls, [1])
            self.assertEqual(service.deferred.get(first["id"])["state"], "waiting_limit")
            self.assertEqual(service.deferred.get(second["id"])["state"], "scheduled")
            service.deferred.set_state(first["id"], "waiting_limit", retry_at=0)
            service._run_deferred_queue()
            self.assertEqual(calls, [1, 1, 2])
            self.assertEqual(service.deferred.get(first["id"])["draft_id"], "1")
            self.assertEqual(service.deferred.get(second["id"])["draft_id"], "2")

    def test_parallel_queue_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            service = QASyncService(config(), recorder=Mock())
            with self.assertRaisesRegex(ValidationError, "one-at-a-time"):
                service.start_deferred({"ids": ["abc"], "mode": "parallel"})

    def test_authorised_queue_restarts_without_reselection(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            path = Path(directory) / "deferred.json"
            queue = DeferredQueue(path)
            item = queue.add(session_id="3" * 32, case_id=3, platform="android")
            queue.review(item["id"], [0], False)
            queue.set_state(item["id"], "waiting_limit", queue_order=1, retry_at=time.time()+3600)
            recorder = Mock()
            service = QASyncService(config(), recorder=recorder)
            self.assertEqual(service.deferred.get(item["id"])["state"], "waiting_limit")
            worker = service._deferred_worker
            self.assertTrue(worker.is_alive())
            service.analyze_recording = Mock(return_value={"proposal_token": "resumed"})
            service._save_deferred_draft = Mock(return_value="resumed-draft")
            service.deferred.set_state(item["id"], "waiting_limit", retry_at=0)
            service._deferred_wake.set()
            worker.join(timeout=2)
            self.assertEqual(service.deferred.get(item["id"])["draft_id"], "resumed-draft")
            service.analyze_recording.assert_called_once()

    def test_protected_capture_survives_retention_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "recovery"
            recorder = RecorderManager(recovery_dir=root, recovery_ttl_seconds=1)
            session_id = "b" * 32
            folder = root / session_id
            folder.mkdir(parents=True)
            frame = folder / "frame-0.png"
            frame.write_bytes(b"local encrypted frame")
            session = RecordingSession(id=session_id, platform="ios", device_id="sim",
                                       directory=folder, interval=1, max_frames=40,
                                       started_at=time.time()-100, ended_at=time.time()-100,
                                       stopped=True, frames=[frame], case_id=42)
            recorder._sessions[session_id] = session
            recorder._persist(session)
            checkpoint = folder / "checkpoint-step-0-after.qasec"
            checkpoint.write_bytes(b"local encrypted checkpoint")
            self.assertEqual(recorder.include_execution_checkpoints(session_id), 1)
            self.assertEqual(recorder.include_execution_checkpoints(session_id), 0)
            recorder.protect(session_id)
            recorder._cleanup_expired()
            self.assertTrue(folder.exists())
            restored = RecorderManager(recovery_dir=root, recovery_ttl_seconds=1)
            self.assertEqual(restored.status(session_id)["case_id"], 42)
            self.assertEqual(restored.status(session_id)["frames"], 2)
            restored.unprotect(session_id)
            restored._cleanup_expired()
            self.assertFalse(folder.exists())

    def test_capture_enqueue_does_not_call_ai_and_review_is_bound_to_case(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            recorder = Mock()
            recorder.status.return_value = {"case_id": 42, "session_id": "c"*32,
                                            "platform": "android", "frames": 5, "stopped": True}
            service = QASyncService(config(), recorder=recorder)
            service.analyze_recording = Mock()
            with self.assertRaises(ValidationError):
                service.defer_recording({"session_id": "c"*32, "case_id": 43})
            item = service.defer_recording({"session_id": "c"*32, "case_id": 42})["item"]
            recorder.protect.assert_called_once_with("c"*32)
            service.analyze_recording.assert_not_called()
            self.assertEqual(item["state"], "needs_review")
            with self.assertRaises(ValidationError):
                service.review_deferred({"id": item["id"], "selected_frames": [1],
                                         "sensitive_reviewed": False, "include_test_credentials": False})
            ready = service.review_deferred({"id": item["id"], "selected_frames": [1, 4],
                                             "sensitive_reviewed": True,
                                             "include_test_credentials": False})["item"]
            self.assertEqual(ready["state"], "ready")
            service.analyze_recording.return_value = {"proposal_token": "proposal"}
            service._save_deferred_draft = Mock(return_value="draft")
            service.deferred.set_state(item["id"], "scheduled", queue_order=1)
            service._run_deferred_item(item["id"])
            self.assertEqual(service.deferred.get(item["id"])["draft_id"], "draft")
            self.assertEqual(service.analyze_recording.call_args.args[0]["selected_frames"], [1, 4])

    def test_offline_execution_blocks_ai_verification_on_server(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            service = QASyncService(config(), recorder=Mock())
            service.executions = ExecutionStore(Path(directory) / "executions.json")
            run = service.executions.create(recorder_session_id="d"*32, run_id=1, test_id=2,
                                            case_id=3, platform="ios", device_id="sim",
                                            steps=[{"content": "Tap", "expected": "Shown"}], offline=True)
            with self.assertRaisesRegex(ValidationError, "disabled"):
                service.verify_execution_step({"execution_id": run["id"], "step_index": 0})
            service.recorder.checkpoint.assert_not_called()

    def test_finished_execution_retains_capture_in_queue_without_ai(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            recorder = Mock()
            service = QASyncService(config(), recorder=recorder)
            service.executions = ExecutionStore(Path(directory) / "executions.json")
            run = service.executions.create(recorder_session_id="e"*32, run_id=7, test_id=8,
                                            case_id=9, platform="android", device_id="phone",
                                            steps=[{"content": "Tap", "expected": "Shown"}], offline=True)
            service.executions.record(run["id"], 0, "passed", "Shown", source="manual")
            service.analyze_recording = Mock()
            finished = service.finish_execution({"execution_id": run["id"], "publish": False,
                                                 "defer_analysis": True})
            self.assertEqual(finished["deferred"]["state"], "needs_review")
            self.assertEqual(finished["deferred"]["test_id"], 8)
            recorder.stop.assert_called_once_with("e"*32)
            recorder.protect.assert_called_once_with("e"*32)
            recorder.discard.assert_not_called()
            service.analyze_recording.assert_not_called()

    def test_recovery_keeps_queued_capture_out_of_generic_resume(self):
        with tempfile.TemporaryDirectory() as directory, patch("qasync.service.state_root", return_value=Path(directory)):
            recorder = Mock()
            recorder.recovered_sessions.return_value = {"sessions": [
                {"session_id": "f"*32, "case_id": 10},
                {"session_id": "g"*32, "case_id": 11},
            ]}
            service = QASyncService(config(), recorder=recorder)
            service.deferred.add(session_id="f"*32, case_id=10, platform="ios")
            recovered = service.recovery()
            self.assertEqual(recovered["deferred_count"], 1)
            self.assertEqual([row["case_id"] for row in recovered["sessions"]], [11])


if __name__ == "__main__":
    unittest.main()
