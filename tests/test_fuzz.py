from __future__ import annotations

import random
import string
import unittest

from qasync.app import allowed_host, allowed_origin
from qasync.errors import ValidationError
from qasync.testrail import normalize_case_id
from qasync.vision import _bounded_current_case, _prompt


class DeterministicFuzzTests(unittest.TestCase):
    def test_case_id_parser_never_accepts_non_numeric_payloads(self):
        generator = random.Random(761234)
        alphabet = string.ascii_letters + string.punctuation + " \t\r\n"
        for _ in range(2_000):
            value = "".join(generator.choice(alphabet) for _ in range(generator.randrange(0, 80)))
            with self.assertRaises(ValidationError):
                normalize_case_id(value)

    def test_local_origin_and_host_filters_fail_closed(self):
        generator = random.Random(99218)
        alphabet = string.ascii_letters + string.digits + ".:/[]@%_-"
        for _ in range(2_000):
            value = "".join(generator.choice(alphabet) for _ in range(generator.randrange(1, 100)))
            if allowed_host(value):
                self.assertRegex(value.lower(), r"^(localhost|127\.0\.0\.1|\[::1\])(?::[0-9]+)?$")
            if allowed_origin(value):
                self.assertTrue(value.lower().startswith(("http://localhost", "http://127.0.0.1", "http://[::1]")))

    def test_prompt_builder_stays_bounded_for_nested_junk(self):
        generator = random.Random(4402)
        for _ in range(250):
            size = generator.randrange(0, 20_000)
            case = {
                "id": {"nested": ["junk"]}, "title": "t" * size,
                "preconditions": "p" * size,
                "steps": [{"content": "c" * size, "expected": "e" * size}] * generator.randrange(0, 130),
                "ignored": ["x" * size],
            }
            bounded = _bounded_current_case(case)
            self.assertLessEqual(len(bounded["title"]), 250)
            self.assertLessEqual(len(bounded["preconditions"]), 4_000)
            self.assertLessEqual(len(bounded["steps"]), 100)
            self.assertLess(len(_prompt("ios", "z" * size, case)), 35_000)
