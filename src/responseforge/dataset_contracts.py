"""Reviewed pinned dataset metadata; manifests never select arbitrary origins."""

import re
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, StrictInt, StringConstraints, model_validator

from responseforge.contracts import Contract, Sha256

Revision = Annotated[str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{40}$")]
Slug = Annotated[str, StringConstraints(strict=True, pattern=r"^[a-z0-9][a-z0-9-]{0,79}$")]
ReviewNote = Annotated[str, StringConstraints(strict=True, min_length=20, max_length=4096)]


def validate_source_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 512
        or re.fullmatch(r"[A-Za-z0-9_./-]+", value) is None
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or str(PurePosixPath(value)) != value
    ):
        raise ValueError("Invalid pinned source path")
    return value


class DatasetRights(Contract):
    license_id: Literal["Apache-2.0"]
    license_sha256: Sha256
    reviewed_paths: tuple[str, ...] = Field(min_length=1, max_length=32)
    review_note: ReviewNote

    @model_validator(mode="after")
    def reviewed(self) -> Self:
        for path in self.reviewed_paths:
            validate_source_path(path)
        if "LICENSE" not in self.reviewed_paths:
            raise ValueError("Root license review required")
        return self


class DatasetArtifact(Contract):
    artifact_id: Slug
    revision: Revision
    path: str
    sha256: Sha256
    size_bytes: Annotated[StrictInt, Field(ge=1, le=1048576)]
    format: Literal["sysmon-xml"]
    rights: DatasetRights

    @model_validator(mode="after")
    def pinned(self) -> Self:
        validate_source_path(self.path)
        if not self.path.startswith("datasets/"):
            raise ValueError("Dataset path required")
        return self

    @property
    def source_url(self) -> str:
        return f"https://github.com/splunk/attack_data/blob/{self.revision}/{self.path}"

    @property
    def download_url(self) -> str:
        return f"https://media.githubusercontent.com/media/splunk/attack_data/{self.revision}/{self.path}"

    @property
    def license_url(self) -> str:
        return f"https://raw.githubusercontent.com/splunk/attack_data/{self.revision}/LICENSE"
