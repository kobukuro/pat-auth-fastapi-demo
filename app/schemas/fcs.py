"""
FCS API schemas.

This module defines Pydantic schemas for FCS-related API responses,
including parameters data and file upload responses.
"""
from typing import Dict, List, Union

from pydantic import BaseModel


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


# Reserved for future implementation: File upload schemas


class FCSFileCreate(BaseModel):
    """FCS file upload request schema (reserved for future use)."""

    is_public: bool = True
    """Whether the file should be publicly accessible."""


class FCSFileResponse(BaseModel):
    """FCS file response schema (reserved for future use)."""

    file_id: str
    """Unique file identifier."""

    filename: str
    """Original filename."""

    total_events: int
    """Total number of events."""

    total_parameters: int
    """Total number of parameters."""

    upload_duration_ms: int | None
    """Upload duration in milliseconds."""
