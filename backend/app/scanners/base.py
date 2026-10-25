from abc import ABC, abstractmethod
from typing import Optional
from app.models.finding import Finding
from app.models.scan import ScannerExecutionStatus

class BaseScanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the scanner (e.g. Gitleaks, OSV, Semgrep)."""
        pass

    @property
    @abstractmethod
    def tool_version(self) -> str:
        """Version of the tool or engine."""
        pass

    @abstractmethod
    async def is_available(self) -> tuple[bool, str]:
        """Returns whether the scanner is installed/configured, plus descriptive status."""
        pass

    @abstractmethod
    async def scan(self, target_dir: str) -> tuple[list[Finding], ScannerExecutionStatus]:
        """Executes the scan on the given repository directory and returns normalized findings."""
        pass
