"""
Common data models for the analysis engine
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class ClassifiedString:
    """Classified string with metadata"""
    value: str
    category: str
    severity: str
    evidence: str
    confidence: float


@dataclass
class StringIntelligenceResult:
    """String intelligence analysis result"""
    total_strings: int
    classified_strings: List[ClassifiedString]
    category_counts: Dict[str, int]
    suspicious_count: int
    ioc_candidates: List[ClassifiedString]
    severity_summary: Dict[str, int]


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
class DOSHeader:
    """DOS header information"""
    magic: str
    e_cblp: int
    e_cp: int
    e_crlc: int
    e_cparhdr: int
    e_minalloc: int
    e_maxalloc: int
    e_ss: int
    e_sp: int
    e_csum: int
    e_ip: int
    e_cs: int
    e_lfarlc: int
    e_ovno: int
    e_res: List[int]
    e_oemid: int
    e_oeminfo: int
    e_res2: List[int]
    e_lfanew: int


@dataclass
class COFFHeader:
    """COFF file header"""
    machine: str
    number_of_sections: int
    time_date_stamp: str
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: str


@dataclass
class OptionalHeader:
    """Optional header information"""
    magic: str
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int
    base_of_data: int
    image_base: int
    section_alignment: int
    file_alignment: int
    major_operating_system_version: int
    minor_operating_system_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    win32_version_value: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    subsystem: str
    dll_characteristics: int
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    loader_flags: int
    number_of_rva_and_sizes: int


@dataclass
class DataDirectory:
    """Data directory entry"""
    name: str
    virtual_address: int
    size: int


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
class TLSEntry:
    """TLS (Thread Local Storage) entry"""
    start_address_of_raw_data: int
    end_address_of_raw_data: int
    address_of_index: int
    address_of_callbacks: int
    size_of_zero_fill: int
    characteristics: int


@dataclass
class DebugInfo:
    """Debug information"""
    type: str
    timestamp: Optional[str] = None
    age: Optional[int] = None
    guid: Optional[str] = None
    pdb_filename: Optional[str] = None


@dataclass
class RichHeaderEntry:
    """Rich header entry"""
    product_id: int
    build_id: int
    count: int


@dataclass
class RichHeader:
    """Rich header information"""
    checksum: int
    entries: List[RichHeaderEntry]


@dataclass
class SignatureInfo:
    """Digital signature information"""
    signed: bool
    signer: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    algorithm: Optional[str] = None
    timestamp: Optional[str] = None
    verification_result: Optional[str] = None
    certificate_chain: List[str] = field(default_factory=list)


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
    severity: str
    description: str
    evidence: str
    confidence: float


@dataclass
class IOC:
    """Indicator of Compromise"""
    type: str
    value: str
    confidence: float
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APICapability:
    """API capability classification"""
    category: str
    description: str
    severity: str
    apis: List[str] = field(default_factory=list)


@dataclass
class APIAnalysisResult:
    """API intelligence analysis result"""
    categories: Dict[str, List[str]] = field(default_factory=dict)
    total_apis: int = 0
    total_categories: int = 0
    severity_summary: Dict[str, int] = field(default_factory=dict)
    top_categories: List[Dict] = field(default_factory=list)


@dataclass
class StaticAnalysisResult:
    """Complete static analysis result"""
    success: bool
    timestamp: str
    file_info: Optional[PEInfo] = None
    dos_header: Optional[DOSHeader] = None
    coff_header: Optional[COFFHeader] = None
    optional_header: Optional[OptionalHeader] = None
    data_directories: List[DataDirectory] = field(default_factory=list)
    sections: List[SectionInfo] = field(default_factory=list)
    imports: List[ImportInfo] = field(default_factory=list)
    exports: List[ExportInfo] = field(default_factory=list)
    strings: Optional[StringInfo] = None
    entropy: Optional[EntropyInfo] = None
    resources: List[ResourceInfo] = field(default_factory=list)
    tls: Optional[TLSEntry] = None
    debug_info: Optional[DebugInfo] = None
    rich_header: Optional[RichHeader] = None
    signature: Optional[SignatureInfo] = None
    yara_matches: List[YARAMatch] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    # API Intelligence
    api_intelligence: Dict[str, Any] = field(default_factory=dict)
    high_risk_apis: List[Dict] = field(default_factory=list)
    
    # String Intelligence
    string_intelligence: Dict[str, Any] = field(default_factory=dict)