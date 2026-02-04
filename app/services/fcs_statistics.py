"""
FCS statistics calculation service.

This module provides functions for calculating statistical metrics
for FCS files using NumPy vectorized operations for performance.
"""
from dataclasses import dataclass

import numpy as np
from flowio import FlowData


@dataclass
class FCSStatisticsResult:
    """Result of FCS statistics calculation."""

    total_events: int
    statistics: list[dict]


def calculate_fcs_statistics(file_path: str) -> FCSStatisticsResult:
    """
    Calculate statistics for FCS file using NumPy (vectorized, memory-efficient).

    Computes min, max, mean, median, and standard deviation for each parameter
    in the FCS file. Uses NumPy vectorized operations for performance (10-100x
    faster than Python loops).

    Args:
        file_path: Path to the FCS file

    Returns:
        FCSStatisticsResult containing total_events and statistics list

    Raises:
        FileNotFoundError: If the FCS file doesn't exist
        ValueError: If the file is not a valid FCS file
    """
    # Parse FCS file
    fcs = FlowData(file_path)
    events_array = fcs.as_array(preprocess=False)

    # Get parameter names (PnN labels)
    pnn_labels = fcs.pnn_labels if hasattr(fcs, "pnn_labels") else []

    # Calculate statistics for each parameter
    statistics = []

    for i, param_name in enumerate(pnn_labels):
        if i >= events_array.shape[1]:
            break

        # Extract parameter column (vectorized)
        param_data = events_array[:, i]

        # Determine display type
        # FSC/SSC/Time are LIN, fluorescence parameters are LOG
        if param_name.startswith(("FSC", "SSC", "Time")):
            display = "LIN"
        else:
            display = "LOG"

        # Calculate statistics using NumPy (fast, memory-efficient)
        stats = {
            "parameter": str(param_name),
            "pns": str(param_name),
            "display": display,
            "min": float(np.min(param_data)),
            "max": float(np.max(param_data)),
            "mean": float(np.mean(param_data)),
            "median": float(np.median(param_data)),
            "std": float(np.std(param_data)),
        }
        statistics.append(stats)

    return FCSStatisticsResult(
        total_events=fcs.event_count,
        statistics=statistics,
    )
