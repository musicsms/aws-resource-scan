"""Command-line interface for AWS Resource Scanner.

This module provides a CLI for scanning AWS resources.
"""
import logging
import os
import sys
from typing import List, Optional

import typer
from rich.console import Console

from aws_resource_scanner.scanner import AWSScannerBuilder
from aws_resource_scanner.utils.logger import logger

# Create Typer app
app = typer.Typer(
    help="AWS Resource Scanner - Scan AWS resources across multiple services",
    add_completion=False,
)

# Create console for rich output
console = Console()


@app.command()
def scan(
    regions: Optional[List[str]] = typer.Option(
        None,
        "--regions",
        "-r",
        help="AWS regions to scan (comma-separated)",
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        "-p",
        help="AWS profile to use for authentication",
    ),
    resources: Optional[str] = typer.Option(
        "all",
        "--resources",
        help=(
            "Resource types to scan (comma-separated). "
            "Options: ec2, sg (security groups), eks, node_group, lb (load balancers), "
            "s3, lambda, asg (auto scaling groups), all"
        ),
    ),
    role_arn: Optional[str] = typer.Option(
        None,
        "--role-arn",
        help="Full ARN of the role to assume (e.g., 'arn:aws:iam::123456789012:role/RoleName')",
    ),
    target_account_id: Optional[str] = typer.Option(
        None,
        "--account-id",
        "-a",
        help="Target AWS account ID to assume role in (used with --role-name)",
    ),
    role_name: Optional[str] = typer.Option(
        None,
        "--role-name",
        help="Name of the role to assume in the target account (used with --account-id)",
    ),
    role_session_name: Optional[str] = typer.Option(
        None,
        "--role-session-name",
        help="Session name for the assumed role session",
    ),
    external_id: Optional[str] = typer.Option(
        None,
        "--external-id",
        help="External ID for the role assumption, if required",
    ),
    output: str = typer.Option(
        "table",
        "--output",
        "-o",
        help="Output format (table, json, csv)",
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "--output-file",
        "-f",
        help="Output file path (required for json and csv formats)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        "-d",
        help="Enable debug logging",
    ),
):
    """Scan AWS resources across multiple services."""
    # Configure logging
    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)

    # Parse regions
    region_list = None
    if regions:
        region_list = [r.strip() for r in regions.split(",")]

    # Parse resource types
    resource_list = []
    if resources:
        resource_list = [r.strip() for r in resources.split(",")]

    # Validate output format and file
    output = output.lower()
    if output not in ["table", "json", "csv"]:
        console.print(f"[bold red]Error:[/] Invalid output format: {output}")
        console.print("Valid formats: table, json, csv")
        sys.exit(1)

    if output in ["json", "csv"] and not output_file:
        console.print(
            f"[bold red]Error:[/] Output file is required for {output} format"
        )
        sys.exit(1)

    try:
        # Build scanner with options
        scanner_builder = AWSScannerBuilder()

        if region_list:
            scanner_builder.with_regions(region_list)

        if profile:
            scanner_builder.with_profile(profile)
            
        # Set up cross-account role assumption if specified
        if role_arn:
            scanner_builder.with_role_arn(
                role_arn=role_arn,
                role_session_name=role_session_name,
                external_id=external_id
            )
        elif target_account_id and role_name:
            scanner_builder.with_assumed_role(
                target_account_id=target_account_id,
                role_name=role_name,
                role_session_name=role_session_name,
                external_id=external_id
            )

        if resource_list:
            scanner_builder.with_resource_types(resource_list)

        # Set output options
        scanner_builder.with_output_format(output)
        if output_file:
            scanner_builder.with_output_file(output_file)

        # Build and run scanner
        scanner = scanner_builder.build()
        scanner.scan_and_save()

    except Exception as e:
        console.print(f"[bold red]Error during scan:[/] {str(e)}")
        if logger.level <= logging.DEBUG:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    app() 