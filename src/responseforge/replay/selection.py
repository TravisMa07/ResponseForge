"""Reproducible explicit recorded-source subsets, never silently edited events."""

from responseforge.replay import ReplayError
from responseforge.replay_contracts import ReplayBatch, digest


def select_recorded(batch: ReplayBatch, *, event_ids: tuple[str, ...]) -> ReplayBatch:
    try:
        snapshot = ReplayBatch.model_validate(batch.model_dump(mode="json", warnings=False))
        if (
            snapshot.origin is None
            or snapshot.origin.transformation != "windows-events-v1"
            or snapshot.origin.selected_event_ids is not None
            or not isinstance(event_ids, tuple)
            or not event_ids
            or any(not isinstance(value, str) for value in event_ids)
            or len(event_ids) != len(set(event_ids))
        ):
            raise ReplayError("Invalid recorded selection")
        selected_ids = tuple(sorted(event_ids))
        counts: dict[str, int] = {}
        for event in snapshot.events:
            counts[event.event_id] = counts.get(event.event_id, 0) + 1
        if any(counts.get(event_id) != 1 for event_id in selected_ids):
            raise ReplayError("Unknown or ambiguous recorded selection")
        events = tuple(event for event in snapshot.events if event.event_id in selected_ids)
        origin = snapshot.origin.model_copy(update={"selected_event_ids": selected_ids})
        return ReplayBatch(
            source_id="subset-" + digest([snapshot.source_id, snapshot.sha256, selected_ids]),
            sha256=snapshot.sha256, origin=origin, events=events,
            quarantine=snapshot.quarantine, duplicates=snapshot.duplicates,
        )
    except ReplayError:
        raise
    except (ValueError, TypeError, AttributeError):
        raise ReplayError("Invalid recorded selection") from None
