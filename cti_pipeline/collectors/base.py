from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Collector(ABC):
    name: str = "base"

    @abstractmethod
    def collect(self) -> list[dict[str, Any]]:
        raise NotImplementedError
