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
        """
        events_array 是一個 NumPy 二維陣列
        .shape[1]取得「第二個維度的大小」，也就是「欄位數量」
        例如：如果陣列形狀是 (10000, 8)，表示有 10000筆事件、8個參數，那麼 shape[1] 就是8
        
        i >= events_array.shape[1]：
            - 如果目前的索引 i 已經大於或等於欄位數量，表示「參數名稱清單比實際資料欄位還多」
            - 這種情況可能發生在 FCS 檔案格式不一致時
        break：
        立即跳出迴圈，不再繼續處理後續的參數
        這是一種「防禦性程式設計」，避免發生 IndexError
        """
        if i >= events_array.shape[1]:
            break

        # Extract parameter column (vectorized)
        """
        這是NumPy 陣列切片（array slicing），用來提取某一欄的全部資料
        :（冒號）：表示「所有列」
        i：表示「第 i 個欄位」
        整體意思：「取出第 i 欄的所有列」
        """
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
