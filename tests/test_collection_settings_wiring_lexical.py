#!/usr/bin/env python3
"""SAM-34 lexical gate: the per-group collection settings routes stay wired.

Nothing exercises ServerImpl's wiring in a unit test, and the failure modes are silent:

  * httplib dispatches in registration order with full-match regexes, so the bare
    GET /api/v1/inventory/software/collection-settings is taken by the generic
    GET /api/v1/inventory/{a}/{b} unless SoftwareCollectionSettingsRoutes registers first;
  * the PUT needs a step-up classification and a pre-auth body cap (boot refuses an unclassified
    sink route; an uncapped body is buffered ahead of the handler);
  * the OpenAPI literal must name all three paths;
  * /readyz must report a settings store that failed to open.

Each requirement below reads the source text and fails with the requirement id.
"""

import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "server" / "core" / "src"

PUT_PATTERN = r"/api/v1/inventory/software/collection-settings/([a-f0-9]+)"
PATHS = (
    "/inventory/software/collection-settings",
    "/inventory/software/collection-settings/{group_id}",
    "/inventory/software/hosts/{agent_id}/collection-settings",
)


def read(name: str) -> str:
    return (SRC / name).read_text(encoding="utf-8")


def check_order(problems: list) -> None:
    text = read("server.cpp")
    reg = text.find("SoftwareCollectionSettingsRoutes{}.register_routes(")
    rest = text.find("rest_api_v1_->register_routes(")
    if reg < 0:
        problems.append("R1: server.cpp does not register SoftwareCollectionSettingsRoutes")
    elif rest < 0:
        problems.append("R1: server.cpp does not contain rest_api_v1_->register_routes(")
    elif reg > rest:
        problems.append(
            "R1: SoftwareCollectionSettingsRoutes registers later than rest_api_v1_->register_routes; "
            "the generic GET /api/v1/inventory/{a}/{b} would take the bare list path"
        )
    for needle, rid in (
        (".store = software_collection_settings_store_.get()", "R2: routes Deps.store"),
        (".mgmt_store = mgmt_group_store_.get()", "R2: routes Deps.mgmt_store"),
        (".plugin_config_store = plugin_config_store_.get()", "R2: routes Deps.plugin_config_store"),
        ("probe_permission_unavailable_aware", "R2: routes Deps.probe_perm_fn"),
        (".software_collection_settings_store =", "R3: HealthRoutes::Deps store"),
        ("software_collection_settings_store_.reset()", "R4: stop() resets the store"),
    ):
        if needle not in text:
            problems.append(f"{rid} is not wired in server.cpp")
    fail_closed = re.search(
        r"software_collection_settings_store_->is_open\(\)\)\s*\{[^}]*startup_failed_\s*=\s*true",
        text,
    )
    if not fail_closed:
        problems.append("R5: a settings store that fails to open must set startup_failed_")


def check_policies(problems: list) -> None:
    step = read("step_up_policy.hpp")
    if not re.search(r'exempt\("PUT",\s*R"\(' + re.escape(PUT_PATTERN) + r'\)"', step):
        problems.append("R6: step_up_policy.hpp lacks the exempt PUT row for collection-settings")
    cap = read("body_cap_policy.hpp")
    if '"/api/v1/inventory/software/collection-settings"' not in cap:
        problems.append("R7: body_cap_policy.hpp lacks the collection-settings prefix row")


def check_openapi_and_health(problems: list) -> None:
    api = read("rest_api_v1.cpp")
    for p in PATHS:
        if f'"{p}"' not in api:
            problems.append(f"R8: the OpenAPI literal does not name {p}")
    health = read("health_routes.cpp")
    if '"software_collection_settings_store"' not in health:
        problems.append("R9: health_routes.cpp lacks the software_collection_settings_store row")


def main() -> int:
    problems: list = []
    check_order(problems)
    check_policies(problems)
    check_openapi_and_health(problems)
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print("collection settings wiring: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
