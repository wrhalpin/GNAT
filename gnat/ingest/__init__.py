"""
ctm_sak.ingest
==============

Unified ingestion framework for CTM-SAK.

Provides readers, mappers, and a pipeline that chain together to ingest
threat intelligence from any source into STIX 2.1 ORM objects.

Quick start::

    from ctm_sak.ingest import IngestPipeline
    from ctm_sak.ingest.sources import PlainTextReader, CSVReader, STIXBundleReader
    from ctm_sak.ingest.mappers import FlatIOCMapper, STIXPassthroughMapper

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

from ctm_sak.ingest.base import (
    SourceReader,
    RecordMapper,
    IngestResult,
    DeduplicationCache,
    RawRecord,
)
from ctm_sak.ingest.pipeline.pipeline import IngestPipeline

__all__ = [
    "SourceReader",
    "RecordMapper",
    "IngestResult",
    "DeduplicationCache",
    "RawRecord",
    "IngestPipeline",
]
