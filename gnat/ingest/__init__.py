"""
gnat.ingest
==============

Unified ingestion framework for GNAT.

Provides readers, mappers, and a pipeline that chain together to ingest
threat intelligence from any source into STIX 2.1 ORM objects.

Quick start::

    from gnat.ingest import IngestPipeline
    from gnat.ingest.sources import PlainTextReader, CSVReader, STIXBundleReader
    from gnat.ingest.mappers import FlatIOCMapper, STIXPassthroughMapper

    # Ingest a plaintext IOC list
    result = (
        IngestPipeline("my-feed")
        .read_from(PlainTextReader("iocs.txt"))
        .map_with(FlatIOCMapper(tlp_marking="amber", confidence=75))
        .write_to(cli)
        .deduplicate()
        .run()
    )
    print(result)
"""

from gnat.ingest.base import (
    SourceReader,
    RecordMapper,
    IngestResult,
    DeduplicationCache,
    RawRecord,
)
from gnat.ingest.pipeline.pipeline import IngestPipeline

__all__ = [
    "SourceReader",
    "RecordMapper",
    "IngestResult",
    "DeduplicationCache",
    "RawRecord",
    "IngestPipeline",
]
