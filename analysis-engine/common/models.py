"""
Common data models for the analysis engine
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class PEInfo:
    """PE file information"""
    filename: str
    file_size: int
    file_type: str
    mime_type: str
    pe_type: str
    arch: str
    compile_time: Optional[str] = None
    linker_version: Optional[str] = None
    entry_point: Optional[int] = None
    image_base: Optional[int] = None
    subsystem: Optional[str] = None


@dataclass
class SectionInfo:
    """PE section information"""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: str
    entropy: float


@dataclass
class ImportInfo:
    """DLL import information"""
    dll: str
    functions: List[str]


@dataclass
class ExportInfo:
    """Export function information"""
    name: str
    ordinal: int
    address: int


@dataclass
class StringInfo:
    """Extracted strings"""
    ascii: List[str] = field(default_factory=list)
    unicode: List[str] = field(default_factory=list)
    suspicious: List[str] = field(default_factory=list)


@dataclass
class EntropyInfo:
    """Entropy analysis results"""
    overall: float = 0.0
    sections: List[Dict] = field(default_factory=list)
    high_entropy_sections: List[str] = field(default_factory=list)


@dataclass
class ResourceInfo:
    """PE resource information"""
    type: str
    id: int
    language: int
    size: int
    sha256: str


@dataclass
class YARAMatch:
    """YARA rule match"""
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[Dict]


@dataclass
class Finding:
    """Static analysis finding"""
    type: str
    severity: str  # low, medium, high, critical
    description: str
    evidence: str
    confidence: float  # 0.0 to 1.0


@dataclass
class IOC:
    """Indicator of Compromise"""
    type: str  # ip, domain, url, file_path, registry_key, hash
    value: str
    confidence: float
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StaticAnalysisResult:
    """Complete static analysis result"""
    success: bool
    timestamp: str
    file_info: Optional[PEInfo] = None
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[ImportInfo] = field(default_factory=list)
    exports: List[ExportInfo] = field(default_factory=list)
    strings: Optional[StringInfo] = None
    entropy: Optional[EntropyInfo] = None
    resources: List[ResourceInfo] = field(default_factory=list)
    yara_matches: List[YARAMatch] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)