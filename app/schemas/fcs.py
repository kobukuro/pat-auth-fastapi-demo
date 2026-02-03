"""
FCS API schemas.

This module defines Pydantic schemas for FCS-related API responses,
including parameters data and file upload responses.
"""
from typing import List

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
