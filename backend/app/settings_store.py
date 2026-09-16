import json
import os

from app.models import RiskModelSettings

"""Local persistence for the governed demo risk model.

Drafts are editable without changing decisions. Activating a model snapshots
it separately; the reasoning engine reads only that active snapshot. This is
deliberately small for the demo, but preserves the production-grade boundary:
an unapproved draft can never silently alter a risk decision.
"""

_SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "data", "risk_model_settings.json")
_ACTIVE_SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "data", "active_risk_model_settings.json")


def load_risk_model_settings() -> RiskModelSettings:
    if not os.path.exists(_SETTINGS_PATH):
        return RiskModelSettings()
    with open(_SETTINGS_PATH, "r") as f:
        return RiskModelSettings.model_validate(json.load(f))


def save_risk_model_settings(settings: RiskModelSettings) -> RiskModelSettings:
    os.makedirs(os.path.dirname(_SETTINGS_PATH), exist_ok=True)
    with open(_SETTINGS_PATH, "w") as f:
        json.dump(settings.model_dump(), f, indent=2)
    if settings.status == "active":
        with open(_ACTIVE_SETTINGS_PATH, "w") as f:
            json.dump(settings.model_dump(), f, indent=2)
    return settings


def load_active_risk_model_settings() -> RiskModelSettings:
    if not os.path.exists(_ACTIVE_SETTINGS_PATH):
        return RiskModelSettings(status="active")
    with open(_ACTIVE_SETTINGS_PATH, "r") as f:
        return RiskModelSettings.model_validate(json.load(f))
