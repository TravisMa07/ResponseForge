"""Trusted opt-in recorded-source configuration; raw fields confer no authority."""

from typing import Self

from pydantic import Field, model_validator

from responseforge.contracts import Contract, Id
from responseforge.dataset_contracts import DatasetArtifact, Slug
from responseforge.integrations.shuffle.models import UUIDString


class RecordedCase(Contract):
    profile: Slug
    artifact: DatasetArtifact
    scenario_id: Id
    event_ids: tuple[Id, ...] = Field(min_length=1, max_length=1)

    @model_validator(mode="after")
    def windows_only(self) -> Self:
        if self.artifact.format != "windows-event-xml":
            raise ValueError("Recorded runtime requires explicit Windows projection")
        return self


class RecordedCaseManifest(Contract):
    qualification_id: UUIDString
    cases: tuple[RecordedCase, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def unique_cases(self) -> Self:
        if (
            len({case.profile for case in self.cases}) != len(self.cases)
            or len({case.scenario_id for case in self.cases}) != len(self.cases)
        ):
            raise ValueError("Recorded case profiles and scenarios must be unique")
        return self


class RecordedConfig(RecordedCaseManifest):
    bundle_root: Id
    mock_path: Id


def recorded_provider_name(config: RecordedConfig) -> str:
    """Bind durable effects to one private DB scope without exposing its identity."""
    from responseforge.replay_contracts import digest
    return "recorded-mock-edr-" + digest([config.qualification_id, config.mock_path])[:24]
