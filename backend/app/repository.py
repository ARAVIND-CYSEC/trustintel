from __future__ import annotations

from collections import defaultdict

from .models import ShareAccessEvent, ShareMetadata


class InMemoryShareRepository:
    def __init__(self) -> None:
        self.shares: dict[str, ShareMetadata] = {}
        self.events: dict[str, list[ShareAccessEvent]] = defaultdict(list)

    def put_share(self, share: ShareMetadata) -> ShareMetadata:
        self.shares[share.share_id] = share
        return share

    def get_share(self, share_id: str) -> ShareMetadata | None:
        return self.shares.get(share_id)

    def update_share(self, share: ShareMetadata) -> ShareMetadata:
        self.shares[share.share_id] = share
        return share

    def add_event(self, event: ShareAccessEvent) -> ShareAccessEvent:
        self.events[event.share_id].append(event)
        return event

    def get_events(self, share_id: str) -> list[ShareAccessEvent]:
        return self.events.get(share_id, [])
