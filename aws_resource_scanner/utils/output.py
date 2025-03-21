"""Output formatters for AWS resource scan results.

This module provides formatters for scan results in different formats.
"""
import csv
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, TextIO, Union, Any

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
    try:
        def _convert_datetime(obj: Any) -> Any:
            """Convert datetime objects to ISO format strings recursively."""
            try:
                if isinstance(obj, datetime):
                    return obj.isoformat()
                elif isinstance(obj, dict):
                    return {k: _convert_datetime(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [_convert_datetime(item) for item in obj]
                return obj
            except Exception as e:
                logger.debug(f"Error converting datetime: {str(e)}")
                return str(obj)
            
        def model_to_dict_list(models):
            """Convert a list of models to a list of dictionaries."""
            result = []
            if not models:
                return result
                
            # Handle if models is actually a single datetime object
            if isinstance(models, datetime):
                return [{"value": str(_convert_datetime(models))}]
                
            # Handle regular list of models
            for model in models:
                # Check if model is a string or other primitive type
                if isinstance(model, (str, int, float, bool)):
                    # Convert primitive types to a simple dict with a value key
                    result.append({"value": model})
                    continue
                    
                try:
                    # Try to get model as dict (works for Pydantic models)
                    model_dict = model.dict(exclude_none=True)
                    
                    # Convert datetime objects to strings
                    for key, value in model_dict.items():
                        if isinstance(value, datetime):
                            model_dict[key] = _convert_datetime(value)
                            
                    result.append(model_dict)
                except AttributeError:
                    # If model doesn't have dict() method, try converting it directly
                    try:
                        # Try converting to dict if it's a dictionary-like object
                        model_dict = dict(model)
                        result.append(model_dict)
                    except (TypeError, ValueError):
                        # Last resort: convert to string and use as a single value
                        result.append({"value": str(model)})
                
            return result

        def write_dynamic_csv(data, file_path):
            """Write dynamic CSV data to a file."""
            if not data:
                return
            # Get all possible keys from all dictionaries
            all_keys = set()
            for item in data:
                all_keys.update(item.keys())
            
            headers = list(all_keys)
            with open(file_path, "w", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=headers)
                writer.writeheader()
                writer.writerows(data)
            logger.info(f"CSV data written to {file_path}")

        def print_dynamic_table(data, title):
            """Print dynamic table data to the console."""
            if not data:
                return
            
            # Create a table with an appropriate title
            table = Table(title=title)
            
            # Get all possible keys from all dictionaries
            all_keys = set()
            for item in data:
                all_keys.update(item.keys())
            
            # If we just have a single "value" key, simplify the column title
            headers = list(all_keys)
            if headers == ["value"]:
                table.add_column("Value")
            else:
                for header in headers:
                    table.add_column(header)
            
            # Add rows to the table
            for row in data:
                # If we just have a single "value" column, simplify
                if headers == ["value"]:
                    table.add_row(str(_convert_datetime(row.get("value", ""))))
                else:
                    table.add_row(*[str(_convert_datetime(row.get(header, ""))) for header in headers])
            
            console.print(table)

        # Handle JSON output format first - this processes the entire model at once
        if output_format.lower() == "json":
            try:
                # Use the model's built-in JSON serialization which handles datetime objects correctly
                json_str = json.dumps(json.loads(scan_result.json(exclude_none=True, by_alias=True)), indent=2)
                if output_file:
                    with open(output_file, "w") as f:
                        f.write(json_str)
                    logger.info(f"Saved JSON output to {output_file}")
                    console.print(f"[green]Results saved to {output_file}[/green]")
                    return  # Exit early to avoid processing individual resource types
                else:
                    console.print_json(json_str)
                    return  # Exit early
            except Exception as json_err:
                logger.error(f"Error generating JSON: {str(json_err)}")
                # Fallback to simpler JSON generation
                try:
                    # Get a safe dictionary representation with datetime objects converted
                    scan_dict = {}
                    raw_dict = scan_result.dict()
                    for key, value in raw_dict.items():
                        # Skip non-essential fields
                        if key in ['timestamp', 'regions']:
                            continue
                        # Convert datetime or keep as is
                        scan_dict[key] = _convert_datetime(value)
                    
                    json_str = json.dumps(scan_dict, indent=2)
                    if output_file:
                        with open(output_file, "w") as f:
                            f.write(json_str)
                        logger.info(f"Saved simplified JSON output to {output_file}")
                        console.print(f"[green]Results saved to {output_file}[/green]")
                        return  # Exit early
                    else:
                        console.print_json(json_str)
                        return  # Exit early
                except Exception as fallback_err:
                    logger.error(f"Error with fallback JSON generation: {str(fallback_err)}")
                    # Continue to process individual resource types as a last resort

        # Get a safe dictionary representation of the scan result with datetime objects converted to strings
        scan_dict = {}
        try:
            raw_dict = scan_result.dict()
            for key, value in raw_dict.items():
                # Handle timestamp fields directly in the ScanResult
                if isinstance(value, datetime):
                    scan_dict[key] = _convert_datetime(value)
                else:
                    scan_dict[key] = value
        except Exception as e:
            logger.error(f"Error converting scan result to dictionary: {str(e)}")
            # Fallback to using the model as is
            scan_dict = scan_result.__dict__ if hasattr(scan_result, '__dict__') else {'error': 'Could not process scan result'}

        # Process each resource type
        csv_files_written = []
        
        for resource_type, resources in scan_dict.items():
            try:
                if not resources or resource_type == 'timestamp':
                    continue
                    
                # Skip non-list resources (like timestamp)
                if not isinstance(resources, list):
                    continue
                    
                data = model_to_dict_list(resources)
                if not data:
                    continue
                    
                if output_format.lower() == "csv":
                    file_path = output_file
                    if not file_path:
                        # If no output file is specified, create one per resource type
                        file_path = Path(f"aws_resources_{resource_type}.csv")
                    elif len(scan_dict.keys()) > 2:  # More than just timestamp and one resource type
                        # If we have multiple resource types but one output file, append resource type to filename
                        base, ext = os.path.splitext(str(file_path))
                        file_path = f"{base}_{resource_type}{ext}"
                        
                    write_dynamic_csv(data, file_path)
                    csv_files_written.append(str(file_path))
                    
                elif output_format.lower() == "table" and not output_file:
                    # Only print tables if no output file was requested
                    print_dynamic_table(data, title=resource_type.replace('_', ' ').title())
            except Exception as resource_err:
                logger.error(f"Error processing resource type {resource_type}: {str(resource_err)}")
                if logger.level <= logging.DEBUG:
                    logger.exception(resource_err)
        
        # For CSV format with output file, print a summary
        if output_format.lower() == "csv" and csv_files_written:
            if len(csv_files_written) == 1 and output_file:
                console.print(f"[green]Results saved to {output_file}[/green]")
            else:
                console.print(f"[green]Results saved to the following files:[/green]")
                for file_path in csv_files_written:
                    console.print(f"  - {file_path}")
                    
    except Exception as e:
        logger.error(f"Error formatting output: {str(e)}")
        if logger.level <= logging.DEBUG:
            logger.exception(e)
        # Print a simplified error message to the console
        console.print(f"[bold red]Error formatting output:[/] {str(e)}")
        console.print("Try using --debug flag for more detailed error information.")

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