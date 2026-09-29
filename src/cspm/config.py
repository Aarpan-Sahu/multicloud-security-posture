"""Configuration from environment variables (12-factor). No secrets are ever hard-coded."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _list(name: str) -> list[str]:
    return [v.strip() for v in os.getenv(name, "").split(",") if v.strip()]


@dataclass
class Settings:
    aws_profile: str | None = field(default_factory=lambda: os.getenv("AWS_PROFILE") or None)
    aws_regions: list[str] = field(default_factory=lambda: _list("AWS_REGIONS"))
    aws_role_arn: str | None = field(default_factory=lambda: os.getenv("AWS_SCANNER_ROLE_ARN") or None)
    aws_external_id: str | None = field(default_factory=lambda: os.getenv("AWS_SCANNER_EXTERNAL_ID") or None)
    azure_subscription_ids: list[str] = field(default_factory=lambda: _list("AZURE_SUBSCRIPTION_IDS"))
    gcp_project_ids: list[str] = field(default_factory=lambda: _list("GCP_PROJECT_IDS"))
    llm_enabled: bool = field(default_factory=lambda: bool(os.getenv("ANTHROPIC_API_KEY")))
    llm_model: str = field(default_factory=lambda: os.getenv("CSPM_LLM_MODEL", "claude-sonnet-5"))
    snapshot_path: str = field(default_factory=lambda: os.getenv("CSPM_SNAPSHOT", "data/findings.json"))

    def collector_kwargs(self, provider: str) -> dict:
        if provider == "aws":
            return {"profile": self.aws_profile, "regions": self.aws_regions or None,
                    "role_arn": self.aws_role_arn, "external_id": self.aws_external_id}
        if provider == "azure":
            return {"subscription_ids": self.azure_subscription_ids or None}
        if provider == "gcp":
            return {"project_ids": self.gcp_project_ids or None}
        return {}
