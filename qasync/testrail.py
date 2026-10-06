from __future__ import annotations

import base64
import re
from typing import Any

from .config import Config
from .errors import ConfigurationError, ValidationError
from .http_client import request_json


def normalize_case_id(value: object) -> int:
    text = str(value or "").strip().upper()
    if text.startswith("C"):
        text = text[1:]
    if not text.isdigit() or int(text) <= 0:
        raise ValidationError("The ID must look like C123 or 123.")
    return int(text)


def normalize_run_id(value: object) -> int:
    """Accept a run id, an R-prefixed id, or a TestRail run URL pasted from the browser."""
    text = str(value or "").strip()
    match = re.search(r"/(?:runs|tests)/(?:view|overview)/(\d+)", text)
    if match:
        return int(match.group(1))
    if text.upper().startswith("R"):
        text = text[1:]
    if not text.isdigit() or int(text) <= 0:
        raise ValidationError(
            "Paste a TestRail run URL or its id, for example R200788 or "
            "https://tuempresa.testrail.com/index.php?/runs/view/200788"
        )
    return int(text)


class TestRailClient:
    def __init__(self, config: Config):
        if not config.testrail_ready:
            raise ConfigurationError(
                "TESTRAIL_URL, TESTRAIL_EMAIL or TESTRAIL_API_KEY is missing."
            )
        self.config = config

    def _headers(self) -> dict[str, str]:
        token = base64.b64encode(
            f"{self.config.testrail_email}:{self.config.testrail_api_key}".encode()
        ).decode()
        return {"Authorization": f"Basic {token}"}

    def _url(self, route: str) -> str:
        return f"{self.config.testrail_url}/index.php?/api/v2/{route}"

    def get_case(self, case_id: int) -> dict[str, Any]:
        return request_json(self._url(f"get_case/{case_id}"), headers=self._headers())

    @staticmethod
    def _collection(response: dict[str, Any], key: str) -> list[dict[str, Any]]:
        items = response.get(key, [])
        if not isinstance(items, list):
            raise ValidationError(f"TestRail returned an invalid '{key}' collection.")
        return [item for item in items if isinstance(item, dict)]

    def _all(self, route: str, key: str) -> list[dict[str, Any]]:
        limit, offset = 250, 0
        collected: list[dict[str, Any]] = []
        while True:
            response = request_json(
                self._url(f"{route}&limit={limit}&offset={offset}"),
                headers=self._headers(),
                allow_list=True,
            )
            if isinstance(response, list):
                return [item for item in response if isinstance(item, dict)]
            page = self._collection(response, key)
            collected.extend(page)
            size = response.get("size")
            if len(page) < limit or (isinstance(size, int) and size < limit):
                break
            offset += limit
            if offset >= 25_000:
                raise ValidationError(f"TestRail returned too many items in '{key}'.")
        return collected

    def get_case_fields(self) -> list[dict[str, Any]]:
        response = request_json(
            self._url("get_case_fields"), headers=self._headers(), allow_list=True
        )
        if isinstance(response, list):
            return [item for item in response if isinstance(item, dict)]
        for key in ("case_fields", "fields"):
            if key in response:
                return self._collection(response, key)
        raise ValidationError("TestRail returned no case field list.")

    def validate_configuration(self) -> dict[str, Any]:
        fields = self.get_case_fields()
        by_name = {str(field.get("system_name", "")): field for field in fields}
        errors: list[str] = []
        warnings: list[str] = []

        def applicable_configs(field: dict[str, Any]) -> list[dict[str, Any]]:
            configs = [item for item in field.get("configs", []) if isinstance(item, dict)]
            if not self.config.testrail_project_id:
                return configs
            project_id = str(self.config.testrail_project_id)
            return [item for item in configs if (
                (item.get("context") or {}).get("is_global")
                or project_id in {str(value) for value in (item.get("context") or {}).get("project_ids", [])}
            )]

        required = {
            self.config.testrail_steps_field: {10},
            self.config.testrail_preconditions_field: {1, 3},
        }
        for name, expected_types in required.items():
            field = by_name.get(name)
            if not field:
                errors.append(f"There is no field named {name}.")
                continue
            type_id = field.get("type_id")
            if isinstance(type_id, int) and type_id not in expected_types:
                errors.append(f"Field {name} has an incompatible type ({type_id}).")
            if field.get("configs") and not applicable_configs(field):
                errors.append(f"Field {name} is not enabled for the configured project.")

        platform_name = self.config.testrail_platform_field
        if platform_name:
            platform_field = by_name.get(platform_name)
            if not platform_field:
                errors.append(f"There is no field named de plataforma {platform_name}.")
            elif platform_field.get("type_id") not in {6, 12, None}:
                warnings.append(f"Field {platform_name} does not look like a dropdown or multiselect.")
            if not self.config.testrail_android_value or not self.config.testrail_ios_value:
                warnings.append("One of the configured Android or iOS values is missing.")
            elif self.config.testrail_android_value == self.config.testrail_ios_value:
                errors.append("Android and iOS cannot share the same platform value.")
            elif platform_field:
                option_ids: set[str] = set()
                for field_config in applicable_configs(platform_field):
                    items = (field_config.get("options") or {}).get("items", "")
                    if isinstance(items, str):
                        option_ids.update(
                            line.split(",", 1)[0].strip()
                            for line in items.splitlines() if "," in line
                        )
                    elif isinstance(items, dict):
                        option_ids.update(str(key) for key in items)
                for label, value in (
                    ("Android", self.config.testrail_android_value),
                    ("iOS", self.config.testrail_ios_value),
                ):
                    if option_ids and value not in option_ids:
                        errors.append(f"Value {value} de {label} does not exist in {platform_name}.")

        return {
            "valid": not errors,
            "errors": errors,
            "warnings": warnings,
            "fields_checked": len(fields),
        }

    def get_projects(self) -> list[dict[str, Any]]:
        return self._all("get_projects&is_completed=0", "projects")

    def get_runs(self, project_id: int) -> list[dict[str, Any]]:
        return self._all(f"get_runs/{project_id}&is_completed=0", "runs")

    def get_run(self, run_id: int) -> dict[str, Any]:
        return request_json(self._url(f"get_run/{run_id}"), headers=self._headers())

    def get_cases(self, project_id: int, suite_id: object = None, section_id: object = None) -> list[dict[str, Any]]:
        route = f"get_cases/{project_id}"
        for name, value in (("suite_id", suite_id), ("section_id", section_id)):
            if isinstance(value, int) and value > 0:
                route += f"&{name}={value}"
        return self._all(route, "cases")

    def get_configs(self, project_id: int) -> list[dict[str, Any]]:
        """Grupos de configuración del proyecto: ahí vive la lista de dispositivos.

        Se lee de TestRail en vez de mantenerse en la app para que cada proyecto
        traiga la suya y un dispositivo nuevo aparezca sin cambiar código.
        """
        response = request_json(
            self._url(f"get_configs/{project_id}"), headers=self._headers(), allow_list=True
        )
        if isinstance(response, list):
            return [item for item in response if isinstance(item, dict)]
        return self._collection(response, "configs")

    def get_plans(self, project_id: int) -> list[dict[str, Any]]:
        return self._all(f"get_plans/{project_id}&is_completed=0", "plans")

    def get_plan_runs(self, plan_id: int) -> list[dict[str, Any]]:
        """Runs inside a test plan.

        `get_runs` deliberately omits them, so a project whose work lives in plans
        looks empty otherwise. Expanded one plan at a time: eagerly walking every
        plan of a project costs one request each.
        """
        plan = request_json(self._url(f"get_plan/{plan_id}"), headers=self._headers())
        runs: list[dict[str, Any]] = []
        for entry in plan.get("entries", []):
            if not isinstance(entry, dict):
                continue
            for run in entry.get("runs", []):
                if isinstance(run, dict):
                    runs.append({**run, "entry_name": entry.get("name")})
        return runs

    def get_tests(self, run_id: int) -> list[dict[str, Any]]:
        return self._all(f"get_tests/{run_id}", "tests")

    def get_statuses(self) -> list[dict[str, Any]]:
        response = request_json(self._url("get_statuses"), headers=self._headers(), allow_list=True)
        if isinstance(response, list):
            return [item for item in response if isinstance(item, dict)]
        return self._collection(response, "statuses")

    def add_result_for_test(self, test_id: int, status_id: int, comment: str) -> dict[str, Any]:
        if test_id <= 0 or status_id <= 0:
            raise ValidationError("The TestRail test or status is invalid.")
        return request_json(
            self._url(f"add_result/{test_id}"), method="POST", headers=self._headers(),
            body={"status_id": status_id, "comment": str(comment)[:8000]},
        )

    def get_results_for_test(self, test_id: int) -> list[dict[str, Any]]:
        if test_id <= 0:
            raise ValidationError("The TestRail test is invalid.")
        return self._all(f"get_results_for_test/{test_id}", "results")

    def update_case(self, case_id: int, fields: dict[str, Any]) -> dict[str, Any]:
        return request_json(
            self._url(f"update_case/{case_id}"),
            method="POST",
            headers=self._headers(),
            body=fields,
        )
