"""
FCS file parsing service.

This module provides functions for parsing FCS (Flow Cytometry Standard) files
using the flowio library. It extracts parameters metadata from FCS files.
"""
import os
from dataclasses import dataclass
from pathlib import Path

from flowio import FlowData


# Configuration
SAMPLE_FCS_PATH = "app/data/sample.fcs"
UPLOAD_DIR = "app/uploads/fcs/"


@dataclass
class FCSParameter:
    """FCS parameter data."""
    index: int
    pnn: str  # Parameter name (PnN)
    pns: str  # Parameter stain name (PnS)
    range: int  # Parameter range (PnR)
    display: str  # Display type (LIN/LOG from PnE)


@dataclass
class FCSParametersData:
    """Complete FCS parameters response data."""
    total_events: int
    total_parameters: int
    parameters: list[FCSParameter]


@dataclass
class FCSEventsData:
    """Complete FCS events response data."""
    total_events: int
    limit: int
    offset: int
    events: list[dict[str, float | int]]


def get_sample_fcs_path() -> str:
    """
    Return the sample FCS file path.

    Returns:
        Absolute path to the sample FCS file.
    """
    return SAMPLE_FCS_PATH


def get_fcs_parameters(file_path: str) -> FCSParametersData:
    """
    Parse FCS file and extract parameters metadata.

    Args:
        file_path: Path to the FCS file.

    Returns:
        FCSParametersData containing total_events, total_parameters, and parameters list.

    Raises:
        FileNotFoundError: If the FCS file does not exist.
        ValueError: If the file is not a valid FCS file.
    """
    # Check if file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"FCS file not found: {file_path}")

    # Parse FCS file using flowio
    fcs = FlowData(file_path)

    # Extract total events
    total_events = fcs.event_count

    # Extract channel/parameter metadata
    parameters = []
    total_parameters = fcs.channel_count

    # Get PnN labels (parameter names)
    pnn_labels = fcs.pnn_labels if hasattr(fcs, "pnn_labels") else []

    # Get PnS labels (stain names)
    pns_labels = fcs.pns_labels if hasattr(fcs, "pns_labels") else []

    # Get PnR values (ranges)
    pnr_values = fcs.pnr_values if hasattr(fcs, "pnr_values") else []

    # Build parameters list
    for i in range(total_parameters):
        # Get parameter name (PnN)
        pnn = pnn_labels[i] if i < len(pnn_labels) else f"P{i + 1}"

        # Get stain name (PnS), default to PnN if not available
        pns = pns_labels[i] if i < len(pns_labels) else pnn

        # Get range (PnR)
        range_value = pnr_values[i] if i < len(pnr_values) else 0

        # Determine display type from flowio metadata
        # Based on the FCS file text segment, we can determine if it's LOG or LIN
        # For now, default to LIN for scatter parameters and LOG for fluorescence
        if pnn.startswith("FSC") or pnn.startswith("SSC") or pnn.startswith("Time"):
            display = "LIN"
        else:
            display = "LOG"

        param = FCSParameter(
            index=i + 1,
            pnn=str(pnn),
            pns=str(pns),
            range=int(range_value) if isinstance(range_value, (int, float)) else 0,
            display=display,
        )
        parameters.append(param)

    return FCSParametersData(
        total_events=total_events,
        total_parameters=total_parameters,
        parameters=parameters,
    )


def get_fcs_file_path(file_id: str | None, db) -> tuple[str, object | None]:
    """
    Query database for FCS file by file_id and return file path.

    This function is reserved for future use when file upload is implemented.

    Args:
        file_id: The file ID to query.
        db: Database session.

    Returns:
        Tuple of (file_path, fcs_file_record).
        If file_id is None, returns (sample_path, None).
        If file is not found, raises appropriate error.

    Raises:
        ValueError: If file_id is provided but file is not found.
    """
    from app.models.fcs_file import FCSFile
    from sqlalchemy import select

    if file_id is None:
        return get_sample_fcs_path(), None

    # Query database for file
    fcs_file = db.execute(
        select(FCSFile).where(FCSFile.file_id == file_id)
    ).scalar_one_or_none()

    if fcs_file is None:
        raise ValueError(f"FCS file with file_id '{file_id}' not found")

    return fcs_file.file_path, fcs_file


def get_fcs_events(file_path: str, limit: int = 100, offset: int = 0) -> FCSEventsData:
    """
    Parse FCS file and extract events data with pagination.

    Uses flowio.FlowData().as_array() to retrieve event data as 2-D NumPy array.
    Each row is one event, each column is one parameter.

    Args:
        file_path: Path to the FCS file.
        limit: Maximum number of events to return (default: 100).
        offset: Number of events to skip from the beginning (default: 0).

    Returns:
        FCSEventsData containing total_events, limit, offset, and events list.

    Raises:
        FileNotFoundError: If the FCS file does not exist.
        ValueError: If the file is not a valid FCS file.
    """
    # Check if file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"FCS file not found: {file_path}")

    # Parse FCS file
    fcs = FlowData(file_path)
    total_events = fcs.event_count

    # Get parameter names (PnN labels) for dictionary keys
    pnn_labels = fcs.pnn_labels if hasattr(fcs, "pnn_labels") else []

    # Get event data as 2-D NumPy array
    events_array = fcs.as_array(preprocess=False)

    # Handle offset beyond total events
    if offset >= total_events:
        return FCSEventsData(
            total_events=total_events,
            limit=limit,
            offset=offset,
            events=[]
        )

    # Apply pagination using NumPy slicing
    end_index = min(offset + limit, total_events)
    paginated_events = events_array[offset:end_index]

    # Convert to list of dictionaries with parameter names as keys
    events_list = []
    for event_row in paginated_events:
        event_dict = {}
        for i, param_name in enumerate(pnn_labels):
            if i < len(event_row):
                value = event_row[i]
                # Convert to int if whole number for cleaner JSON output
                if isinstance(value, (int, float)):
                    if value == int(value):
                        event_dict[str(param_name)] = int(value)
                    else:
                        event_dict[str(param_name)] = float(value)
                else:
                    event_dict[str(param_name)] = value
        events_list.append(event_dict)

    return FCSEventsData(
        total_events=total_events,
        limit=limit,
        offset=offset,
        events=events_list
    )
