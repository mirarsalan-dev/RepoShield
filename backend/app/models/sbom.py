from typing import Optional
from pydantic import BaseModel, Field

class SBOMComponent(BaseModel):
    name: str = Field(description="Package or component name")
    version: str = Field(description="Detected version")
    ecosystem: str = Field(description="npm, PyPI, Go, Maven, Cargo, Composer")
    purl: Optional[str] = Field(default=None, description="Package URL specification e.g. pkg:npm/lodash@4.17.21")
    license: Optional[str] = Field(default="Unknown", description="Declared or detected license identifier")
    manifest_path: str = Field(description="File where dependency was declared")
    direct: bool = Field(default=True, description="True if top-level dependency, False if transitive")
    vulnerabilities_count: int = Field(default=0, description="Number of CVE/GHSA advisories affecting this component")
    vulnerability_ids: list[str] = Field(default_factory=list, description="List of CVE or GHSA IDs")

class SBOMReport(BaseModel):
    bom_format: str = "CycloneDX"
    spec_version: str = "1.5"
    serial_number: str
    repo_name: str
    commit_sha: Optional[str] = None
    generated_at: str
    total_components: int
    vulnerable_components: int
    direct_components: int
    transitive_components: int
    components: list[SBOMComponent]
