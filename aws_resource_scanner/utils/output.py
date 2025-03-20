"""Output formatters for AWS resource scan results.

This module provides formatters for scan results in different formats.
"""
import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, TextIO, Union

from rich.console import Console
from rich.table import Table

from aws_resource_scanner.models import ScanResult
from aws_resource_scanner.utils.logger import logger

# Create console for rich output
console = Console()


def dynamic_format_output(scan_result: ScanResult, output_format: str = "table", output_file: Optional[Union[str, Path]] = None) -> None:
    """Dynamically format scan results based on model fields.

    Args:
        scan_result: Scan results to format
        output_format: Output format (json, csv, or table)
        output_file: Output file path (not used for table format)
    """
    def model_to_dict_list(models):
        """Convert a list of models to a list of dictionaries."""
        return [model.dict(exclude_none=True) for model in models]

    def write_dynamic_csv(data, file_path):
        """Write dynamic CSV data to a file."""
        if not data:
            return
        headers = data[0].keys()
        with open(file_path, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)

    def print_dynamic_table(data, title):
        """Print dynamic table data to the console."""
        if not data:
            return
        table = Table(title=title)
        headers = data[0].keys()
        for header in headers:
            table.add_column(header)
        for row in data:
            table.add_row(*[str(row.get(header, "")) for header in headers])
        console.print(table)

    # Process each resource type
    for resource_type, resources in scan_result.dict().items():
        if not resources:
            continue
        data = model_to_dict_list(resources)
        if output_format.lower() == "csv":
            file_path = output_file or Path(f"aws_resources_{resource_type}.csv")
            write_dynamic_csv(data, file_path)
            logger.info(f"Saved {resource_type} data to {file_path}")
        elif output_format.lower() == "table":
            print_dynamic_table(data, title=resource_type.replace('_', ' ').title())
        elif output_format.lower() == "json":
            json_str = json.dumps(json.loads(scan_result.json(exclude_none=True, by_alias=True)), indent=2)
            if output_file:
                with open(output_file, "w") as f:
                    f.write(json_str)
                logger.info(f"Saved JSON output to {output_file}")
            else:
                console.print_json(json_str)

def save_output(
    scan_result: ScanResult, 
    output_format: str = "table", 
    output_file: Optional[Union[str, Path]] = None
) -> None:
    """Save scan results in the specified format.

    Args:
        scan_result: Scan results to save
        output_format: Output format (json, csv, or table)
        output_file: Output file path (not used for table format)
    """
    dynamic_format_output(scan_result, output_format, output_file)