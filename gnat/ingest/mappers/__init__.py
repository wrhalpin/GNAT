"""gnat.ingest.mappers — RecordMapper implementations."""
from gnat.ingest.mappers.mappers import (
    CEFMapper,
    CSVIndicatorMapper,
    ElasticResultMapper,
    EmailIOCMapper,
    FlatIOCMapper,
    MISPAttributeMapper,
    NVDCVEMapper,
    OpenIOCMapper,
    RSSEntryMapper,
    SplunkResultMapper,
    SQLRowMapper,
    STIXPassthroughMapper,
)

__all__ = [
    "FlatIOCMapper", "STIXPassthroughMapper", "MISPAttributeMapper",
    "CEFMapper", "SQLRowMapper", "CSVIndicatorMapper", "RSSEntryMapper",
    "EmailIOCMapper", "OpenIOCMapper", "SplunkResultMapper",
    "ElasticResultMapper", "NVDCVEMapper",
]
