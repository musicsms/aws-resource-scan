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


def format_json(scan_result: ScanResult, indent: int = 2) -> str:
    """Format scan results as JSON.

    Args:
        scan_result: Scan results to format
        indent: JSON indentation level

    Returns:
        JSON string representation of the scan results
    """
    return json.dumps(
        json.loads(scan_result.json(exclude_none=True, by_alias=True)),
        indent=indent
    )


def format_csv(scan_result: ScanResult) -> Dict[str, List[List[str]]]:
    """Format scan results as CSV data.

    Args:
        scan_result: Scan results to format

    Returns:
        Dictionary mapping resource types to CSV data (header + rows)
    """
    csv_data = {}
    
    # Process EC2 instances
    if scan_result.ec2_instances:
        headers = [
            "ID", "Region", "Name", "Type", "State", "Private IP", "Public IP",
            "VPC ID", "Subnet ID", "Launch Time", "Security Groups"
        ]
        rows = []
        for instance in scan_result.ec2_instances:
            rows.append([
                instance.resource_id,
                instance.region,
                instance.name or "",
                instance.instance_type,
                instance.state,
                instance.private_ip_address or "",
                instance.public_ip_address or "",
                instance.vpc_id or "",
                instance.subnet_id or "",
                instance.launch_time.isoformat() if instance.launch_time else "",
                ",".join(instance.security_group_ids),
            ])
        csv_data["ec2_instances"] = [headers] + rows
    
    # Process Security Groups
    if scan_result.security_groups:
        headers = ["ID", "Region", "Name", "VPC ID", "Description", "Inbound Rules", "Outbound Rules"]
        rows = []
        for sg in scan_result.security_groups:
            # Format inbound rules
            inbound_rules = []
            for rule in sg.inbound_rules:
                protocol = rule.get("protocol", "-")
                port_range = rule.get("port_range", "-")
                sources = rule.get("ip_ranges", []) + rule.get("ipv6_ranges", []) + rule.get("group_references", [])
                inbound_rules.append(f"{protocol}:{port_range} from {','.join(sources) or 'anywhere'}")
            
            # Format outbound rules
            outbound_rules = []
            for rule in sg.outbound_rules:
                protocol = rule.get("protocol", "-")
                port_range = rule.get("port_range", "-")
                destinations = rule.get("ip_ranges", []) + rule.get("ipv6_ranges", []) + rule.get("group_references", [])
                outbound_rules.append(f"{protocol}:{port_range} to {','.join(destinations) or 'anywhere'}")
            
            rows.append([
                sg.resource_id,
                sg.region,
                sg.name or "",
                sg.vpc_id or "",
                sg.description or "",
                "; ".join(inbound_rules),
                "; ".join(outbound_rules),
            ])
        csv_data["security_groups"] = [headers] + rows
    
    # Process EKS Clusters
    if scan_result.eks_clusters:
        headers = ["Name", "Region", "Status", "Version", "Endpoint", "VPC ID", "Created At"]
        rows = []
        for cluster in scan_result.eks_clusters:
            rows.append([
                cluster.name or cluster.resource_id,
                cluster.region,
                cluster.status,
                cluster.kubernetes_version or "",
                cluster.endpoint or "",
                cluster.vpc_id or "",
                cluster.created_at.isoformat() if cluster.created_at else "",
            ])
        csv_data["eks_clusters"] = [headers] + rows
    
    # Process Node Groups
    if scan_result.node_groups:
        headers = ["Name", "Region", "Cluster", "Status", "Instance Types", "Capacity Type", "Disk Size"]
        rows = []
        for ng in scan_result.node_groups:
            rows.append([
                ng.name or ng.resource_id,
                ng.region,
                ng.cluster_name,
                ng.status,
                ",".join(ng.instance_types),
                ng.capacity_type or "",
                str(ng.disk_size) if ng.disk_size else "",
            ])
        csv_data["node_groups"] = [headers] + rows
    
    # Process Load Balancers
    if scan_result.load_balancers:
        headers = ["Name", "Region", "Type", "Scheme", "VPC ID", "DNS Name", "State"]
        rows = []
        for lb in scan_result.load_balancers:
            rows.append([
                lb.name or lb.resource_id,
                lb.region,
                lb.lb_type,
                lb.scheme or "",
                lb.vpc_id or "",
                lb.dns_name or "",
                lb.state or "",
            ])
        csv_data["load_balancers"] = [headers] + rows
    
    # Process S3 Buckets
    if scan_result.s3_buckets:
        headers = [
            "Name", "Region", "Created", "Versioning", "Public Access Blocked", 
            "Encryption", "Logging"
        ]
        rows = []
        for bucket in scan_result.s3_buckets:
            rows.append([
                bucket.name or bucket.resource_id,
                bucket.region,
                bucket.creation_date.isoformat() if bucket.creation_date else "",
                "Enabled" if bucket.versioning_enabled else "Disabled",
                "Yes" if bucket.public_access_blocked else "No",
                "Enabled" if bucket.encryption_enabled else "Disabled",
                "Enabled" if bucket.logging_enabled else "Disabled",
            ])
        csv_data["s3_buckets"] = [headers] + rows
    
    # Process Lambda Functions
    if scan_result.lambda_functions:
        headers = ["Name", "Region", "Runtime", "Memory", "Timeout", "Code Size", "Last Modified"]
        rows = []
        for func in scan_result.lambda_functions:
            rows.append([
                func.name or func.resource_id,
                func.region,
                func.runtime,
                str(func.memory_size) + " MB",
                str(func.timeout) + " sec",
                str(func.code_size) + " bytes",
                func.last_modified or "",
            ])
        csv_data["lambda_functions"] = [headers] + rows
    
    # Process Auto Scaling Groups
    if scan_result.auto_scaling_groups:
        headers = ["Name", "Region", "Min Size", "Max Size", "Desired Capacity", "Instances", "AZs"]
        rows = []
        for asg in scan_result.auto_scaling_groups:
            rows.append([
                asg.name or asg.resource_id,
                asg.region,
                str(asg.min_size),
                str(asg.max_size),
                str(asg.desired_capacity),
                str(len(asg.instance_ids)),
                ",".join(asg.availability_zones),
            ])
        csv_data["auto_scaling_groups"] = [headers] + rows
    
    return csv_data


def write_csv(scan_result: ScanResult, output_file: Optional[Union[str, Path]] = None) -> None:
    """Write scan results to CSV files.

    Args:
        scan_result: Scan results to write
        output_file: Base output file path (will be suffixed with resource type)
    """
    csv_data = format_csv(scan_result)
    
    for resource_type, data in csv_data.items():
        if not data:
            continue
        
        # Determine output file path
        if output_file:
            file_path = Path(output_file)
            if len(csv_data) > 1:
                # If multiple resource types, add suffix to filename
                file_stem = file_path.stem
                file_path = file_path.with_stem(f"{file_stem}_{resource_type}")
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = Path(f"aws_resources_{resource_type}_{timestamp}.csv")
        
        # Write CSV data
        with open(file_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(data)
            
        logger.info(f"Saved {resource_type} data to {file_path}")


def print_table(scan_result: ScanResult) -> None:
    """Print scan results as tables in the terminal.

    Args:
        scan_result: Scan results to print
    """
    # Print summary
    summary_table = Table(title="AWS Resource Scan Summary")
    summary_table.add_column("Resource Type")
    summary_table.add_column("Count")
    
    summary_table.add_row("EC2 Instances", str(len(scan_result.ec2_instances)))
    summary_table.add_row("Security Groups", str(len(scan_result.security_groups)))
    summary_table.add_row("EKS Clusters", str(len(scan_result.eks_clusters)))
    summary_table.add_row("Node Groups", str(len(scan_result.node_groups)))
    summary_table.add_row("Load Balancers", str(len(scan_result.load_balancers)))
    summary_table.add_row("S3 Buckets", str(len(scan_result.s3_buckets)))
    summary_table.add_row("Lambda Functions", str(len(scan_result.lambda_functions)))
    summary_table.add_row("Auto Scaling Groups", str(len(scan_result.auto_scaling_groups)))
    
    console.print(summary_table)
    
    # Ask if user wants to see details
    if not console.input("\nShow resource details? [y/N]: ").lower().startswith("y"):
        return
    
    # Print EC2 instances
    if scan_result.ec2_instances:
        ec2_table = Table(title="EC2 Instances")
        ec2_table.add_column("ID")
        ec2_table.add_column("Region")
        ec2_table.add_column("Name")
        ec2_table.add_column("Type")
        ec2_table.add_column("State")
        ec2_table.add_column("Private IP")
        ec2_table.add_column("Public IP")
        
        for instance in scan_result.ec2_instances:
            ec2_table.add_row(
                instance.resource_id,
                instance.region,
                instance.name or "",
                instance.instance_type,
                instance.state,
                instance.private_ip_address or "",
                instance.public_ip_address or "",
            )
        
        console.print(ec2_table)
    
    # Print Security Groups
    if scan_result.security_groups:
        sg_table = Table(title="Security Groups")
        sg_table.add_column("ID")
        sg_table.add_column("Region")
        sg_table.add_column("Name")
        sg_table.add_column("VPC ID")
        sg_table.add_column("Description")
        
        for sg in scan_result.security_groups:
            sg_table.add_row(
                sg.resource_id,
                sg.region,
                sg.name or "",
                sg.vpc_id or "",
                sg.description or "",
            )
        
        console.print(sg_table)
    
    # Print other resource tables similarly
    # ...
    
    # Print S3 buckets
    if scan_result.s3_buckets:
        s3_table = Table(title="S3 Buckets")
        s3_table.add_column("Name")
        s3_table.add_column("Region")
        s3_table.add_column("Created")
        s3_table.add_column("Versioning")
        s3_table.add_column("Public Access")
        s3_table.add_column("Encryption")
        
        for bucket in scan_result.s3_buckets:
            s3_table.add_row(
                bucket.name or bucket.resource_id,
                bucket.region,
                bucket.creation_date.isoformat() if bucket.creation_date else "",
                "✓" if bucket.versioning_enabled else "✗",
                "Blocked" if bucket.public_access_blocked else "Allowed",
                "✓" if bucket.encryption_enabled else "✗",
            )
        
        console.print(s3_table)
    
    # Print Lambda Functions
    if scan_result.lambda_functions:
        lambda_table = Table(title="Lambda Functions")
        lambda_table.add_column("Name")
        lambda_table.add_column("Region")
        lambda_table.add_column("Runtime")
        lambda_table.add_column("Memory")
        lambda_table.add_column("Last Modified")
        
        for func in scan_result.lambda_functions:
            lambda_table.add_row(
                func.name or func.resource_id,
                func.region,
                func.runtime,
                f"{func.memory_size} MB",
                func.last_modified or "",
            )
        
        console.print(lambda_table)


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
    if output_format.lower() == "json":
        json_str = format_json(scan_result)
        if output_file:
            with open(output_file, "w") as f:
                f.write(json_str)
            logger.info(f"Saved JSON output to {output_file}")
        else:
            console.print_json(json_str)
    
    elif output_format.lower() == "csv":
        write_csv(scan_result, output_file)
    
    elif output_format.lower() == "table":
        print_table(scan_result)
    
    else:
        logger.error(f"Unsupported output format: {output_format}")
        print_table(scan_result)  # Fall back to table format 