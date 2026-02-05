"""
FCS API schemas.

This module defines Pydantic schemas for FCS-related API responses,
including parameters data, events, file upload, and statistics.
"""
from typing import Dict, List, Union

from pydantic import BaseModel, Field


class FCSParameter(BaseModel):
    """FCS parameter model."""

    index: int
    """Parameter index number."""

    pnn: str
    """Parameter name (PnN)."""

    pns: str
    """Parameter stain name (PnS)."""

    range: int
    """Parameter range (PnR)."""

    display: str
    """Display type (LIN or LOG)."""

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "index": 1,
                    "pnn": "FSC-H",
                    "pns": "FSC-H",
                    "range": 16777215,
                    "display": "LIN",
                }
            ]
        }
    }


class FCSParametersResponseData(BaseModel):
    """FCS parameters response data."""

    total_events: int
    """Total number of events in the FCS file."""

    total_parameters: int
    """Total number of parameters in the FCS file."""

    parameters: List[FCSParameter]
    """List of FCS parameters."""

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "total_events": 34297,
                    "total_parameters": 26,
                    "parameters": [
                        {
                            "index": 1,
                            "pnn": "FSC-H",
                            "pns": "FSC-H",
                            "range": 16777215,
                            "display": "LIN",
                        }
                    ],
                }
            ]
        }
    }


class FCSEvent(BaseModel):
    """Individual FCS event with parameter values."""

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "FSC-H": 2500000,
                    "FSC-A": 2800000,
                    "SSC-H": 1200000,
                    "FL1-H": 150,
                }
            ]
        }
    }


class FCSEventsResponseData(BaseModel):
    """FCS events response data."""

    total_events: int
    """Total number of events in the FCS file."""

    limit: int
    """Maximum number of events returned in this response."""

    offset: int
    """Number of events skipped from the beginning."""

    events: List[Dict[str, Union[int, float]]]
    """List of events, where each event is a dictionary of parameter names to values."""

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "total_events": 34297,
                    "limit": 100,
                    "offset": 0,
                    "events": [{"FSC-H": 2500000, "SSC-H": 1200000}],
                }
            ]
        }
    }


# File upload schemas


class FCSFileResponse(BaseModel):
    """FCS file upload response schema."""

    file_id: str
    """Unique file identifier (short base62 string)."""

    filename: str
    """Original filename."""

    file_size: int
    """File size in bytes."""

    total_events: int
    """Total number of events in the FCS file."""

    total_parameters: int
    """Total number of parameters."""


# Statistics schemas


class FCSStatisticItem(BaseModel):
    """Single statistic item for one parameter."""

    parameter: str
    """Parameter name."""

    pns: str
    """Parameter stain name."""

    display: str
    """Display type (LIN or LOG)."""

    min: float
    """Minimum value."""

    max: float
    """Maximum value."""

    mean: float
    """Mean (average) value."""

    median: float
    """Median value."""

    std: float
    """Standard deviation."""


class FCSStatisticsResponseData(BaseModel):
    """Statistics endpoint response data."""

    total_events: int
    """Total number of events."""

    statistics: List[FCSStatisticItem]
    """List of statistics for each parameter."""


# Background task schemas


class StatisticsCalculateRequest(BaseModel):
    """Request to trigger statistics calculation."""

    file_id: str | None = Field(
        None, description="Optional file ID. If not provided, uses sample file."
    )


class TaskResponseData(BaseModel):
    """Task status response data."""

    task_id: int
    """Task ID (auto-increment integer)."""

    task_type: str
    """Task type (statistics or chunked_upload)."""

    status: str
    """Task status (pending, processing, finalizing, completed, failed, expired)."""

    created_at: str
    """Task creation timestamp (ISO format)."""

    completed_at: str | None = None
    """Task completion timestamp (ISO format)."""

    result: Dict | None = None
    """Task result data (statistics, upload progress, or error)."""


class TaskCreatedResponseData(BaseModel):
    """Response when background task is created."""

    task_id: int
    """Task ID (auto-increment integer)."""

    status: str
    """Task status."""

    message: str
    """Human-readable message."""


# Chunked upload schemas


class ChunkedUploadInitResponse(BaseModel):
    """Response when chunked upload session is initialized."""

    task_id: int
    """Upload session ID (task_id)."""

    filename: str
    """Original filename."""

    file_size: int
    """Total file size in bytes."""

    chunk_size: int
    """Size of each chunk in bytes."""

    total_chunks: int
    """Total number of chunks to upload."""

    status: str
    """Current session status (pending)."""

    expires_at: str | None = None
    """Session expiration timestamp (ISO format)."""


class ChunkedUploadChunkResponse(BaseModel):
    """Response after uploading a chunk."""

    task_id: int
    """Upload session ID."""

    chunk_number: int
    """Uploaded chunk number."""

    uploaded_chunks: int
    """Number of chunks uploaded so far."""

    total_chunks: int
    """Total number of chunks."""

    uploaded_bytes: int
    """Total bytes uploaded so far."""

    total_bytes: int
    """Total file size in bytes."""

    progress_percentage: float
    """Upload progress percentage."""

    status: str
    """Current session status (processing)."""


# Reserved for future implementation


class FCSFileCreate(BaseModel):
    """FCS file upload request schema (reserved for future use)."""

    is_public: bool = True
    """Whether the file should be publicly accessible."""
