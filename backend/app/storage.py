from __future__ import annotations

from pathlib import Path
from shutil import copyfileobj


class LocalStorage:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save_upload(self, source, target_name: str) -> Path:
        target = self.root / target_name
        with target.open("wb") as output:
            copyfileobj(source, output)
        return target
