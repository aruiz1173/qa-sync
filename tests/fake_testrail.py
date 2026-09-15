"""Servidor de desarrollo para revisar la UI sin tocar una instancia de TestRail."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if "get_case_fields" in self.path:
            payload = [
                {"system_name": "custom_steps_separated", "type_id": 10},
                {"system_name": "custom_preconds", "type_id": 3},
                {"system_name": "custom_platform", "type_id": 6},
            ]
        elif "get_projects" in self.path:
            payload = {"projects": [{"id": 1, "name": "Mobile Checkout"}]}
        elif "get_runs/1" in self.path:
            payload = {"runs": [
                {"id": 810, "name": "Mobile 6.42 · Regression", "passed_count": 18, "failed_count": 2, "untested_count": 6, "blocked_count": 1},
                {"id": 804, "name": "Payments · Smoke", "passed_count": 12, "failed_count": 0, "untested_count": 2, "blocked_count": 0},
                {"id": 799, "name": "Authentication · RC", "passed_count": 7, "failed_count": 1, "untested_count": 4, "blocked_count": 0},
            ]}
        elif "get_tests/810" in self.path:
            payload = {"tests": [
                {"id": 1, "case_id": 4421, "title": "Complete card payment", "status_id": 1, "refs": "PAY-302"},
                {"id": 2, "case_id": 4428, "title": "Decline an expired card", "status_id": 5, "refs": "PAY-319"},
                {"id": 3, "case_id": 4435, "title": "Issue a full refund", "status_id": 3, "refs": "PAY-341"},
                {"id": 4, "case_id": 4440, "title": "Retry after network interruption", "status_id": 2, "refs": "PAY-355"},
            ]}
        elif "get_case/4428" in self.path:
            payload = {"id": 4428, "title": "Decline an expired card", "refs": "PAY-319", "estimate": "2m", "custom_preconds": "Seller is signed in and has an active location.", "custom_steps_separated": [
                {"content": "Add an item and open Checkout.", "expected": "The payment methods screen is displayed."},
                {"content": "Select Card and present an expired card.", "expected": "The payment is declined with an actionable message."},
                {"content": "Dismiss the message.", "expected": "Checkout remains open and no payment is recorded."},
            ]}
        else:
            payload = {"error": "Not found"}
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        payload.setdefault("id", 4428)
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8790), Handler).serve_forever()
