"""Command-line interface for AWS Resource Scanner.

This module provides a CLI for scanning AWS resources.
"""
import logging
import os
import sys
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

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
        # Handle different types of region input - could be a string or list
        if isinstance(regions, str):
            region_list = [r.strip() for r in regions.split(",")]
        else:
            # Process a list of regions, handling potential commas within elements
            region_list = []
            for region in regions:
                if ',' in region:
                    region_list.extend([r.strip() for r in region.split(',')])
                else:
                    region_list.append(region.strip())

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


@app.command()
def vpc_resources(
    vpc_id: str = typer.Argument(
        ...,
        help="ID of the VPC to query (e.g., vpc-12345678)",
    ),
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
    """Scan and display all resources that belong to the specified VPC."""
    # Configure logging
    if debug:
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logger.setLevel(logging.INFO)
        
    # Process region input
    region_list = []
    if regions:
        # Handle regions whether they're already split or come as comma-separated string
        if isinstance(regions, str):
            region_list = [r.strip() for r in regions.split(',')]
        else:
            # Process a list of regions, handling potential commas within elements
            region_list = []
            for region in regions:
                if ',' in region:
                    region_list.extend([r.strip() for r in region.split(',')])
                else:
                    region_list.append(region.strip())
    
    # Build scanner
    scanner_builder = AWSScannerBuilder()
    
    # Configure regions
    if region_list:
        scanner_builder.with_regions(region_list)
    
    # Configure authentication
    if profile:
        scanner_builder.with_profile(profile)
    
    # Configure role assumption
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
    
    # Configure output
    scanner_builder.with_output_format(output)
    if output_file:
        scanner_builder.with_output_file(output_file)
    
    # Set resource types - we need to scan all types to find VPC resources
    scanner_builder.with_resource_types(["all"])
    
    # Build scanner and perform scan
    scanner = scanner_builder.build()
    result = scanner.scan()
    
    # Filter resources by VPC ID
    vpc_resources = {
        "ec2_instances": [],
        "security_groups": [],
        "eks_clusters": [],
        "load_balancers": [],
        "lambda_functions": [],
        "subnets": [],
        "internet_gateways": [],
        "nat_gateways": [],
        "route_tables": [],
        "network_acls": [],
        "vpc_endpoints": [],
        "vpc_peering_connections": [],
    }
    
    # Filter EC2 instances
    for instance in result.ec2_instances:
        if instance.vpc_id == vpc_id:
            vpc_resources["ec2_instances"].append(instance)
            
    # Filter security groups
    for sg in result.security_groups:
        if sg.vpc_id == vpc_id:
            vpc_resources["security_groups"].append(sg)
            
    # Filter EKS clusters
    for cluster in result.eks_clusters:
        if cluster.vpc_id == vpc_id:
            vpc_resources["eks_clusters"].append(cluster)
            
    # Filter load balancers
    for lb in result.load_balancers:
        if lb.vpc_id == vpc_id:
            vpc_resources["load_balancers"].append(lb)
            
    # Filter Lambda functions with VPC configuration
    for func in result.lambda_functions:
        if func.vpc_config and "VpcId" in func.vpc_config and func.vpc_config["VpcId"] == vpc_id:
            vpc_resources["lambda_functions"].append(func)
            
    # Filter Subnets
    for subnet in result.subnets:
        if subnet.vpc_id == vpc_id:
            vpc_resources["subnets"].append(subnet)
            
    # Filter Internet Gateways
    for igw in result.internet_gateways:
        if igw.vpc_id == vpc_id:
            vpc_resources["internet_gateways"].append(igw)
            
    # Filter NAT Gateways
    for nat in result.nat_gateways:
        if nat.vpc_id == vpc_id:
            vpc_resources["nat_gateways"].append(nat)
            
    # Filter Route Tables
    for rtb in result.route_tables:
        if rtb.vpc_id == vpc_id:
            vpc_resources["route_tables"].append(rtb)
            
    # Filter Network ACLs
    for nacl in result.network_acls:
        if nacl.vpc_id == vpc_id:
            vpc_resources["network_acls"].append(nacl)
            
    # Filter VPC Endpoints
    for endpoint in result.vpc_endpoints:
        if endpoint.vpc_id == vpc_id:
            vpc_resources["vpc_endpoints"].append(endpoint)
            
    # Filter VPC Peering Connections (as requester)
    for peering in result.vpc_peering_connections:
        if peering.vpc_id == vpc_id or peering.peer_vpc_id == vpc_id:
            vpc_resources["vpc_peering_connections"].append(peering)
    
    # Display results
    if output.lower() == "table":
        console.print(f"[bold green]Resources in VPC: {vpc_id}[/bold green]")
        
        # Display EC2 instances
        if vpc_resources["ec2_instances"]:
            console.print("\n[bold]EC2 Instances:[/bold]")
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("Type")
            table.add_column("State")
            table.add_column("Network Interfaces")
            
            for instance in vpc_resources["ec2_instances"]:
                # Format network interface information
                if instance.network_interfaces:
                    interface_details = []
                    for ni in instance.network_interfaces:
                        ips = []
                        for ip_info in ni.private_ip_addresses:
                            ip_text = f"{ip_info['private_ip']}"
                            if "public_ip" in ip_info:
                                ip_text += f" ({ip_info['public_ip']})"
                            if ip_info["primary"]:
                                ip_text += " [primary]"
                            ips.append(ip_text)
                        
                        interface_text = f"ENI: {ni.network_interface_id}\n"
                        interface_text += f"Subnet: {ni.subnet_id}\n"
                        interface_text += f"IPs: {', '.join(ips)}"
                        interface_details.append(interface_text)
                    
                    network_info = "\n\n".join(interface_details)
                else:
                    # Fallback to simple display if no network interface data
                    private_ip = instance.private_ip_address or "N/A"
                    public_ip = f" ({instance.public_ip_address})" if instance.public_ip_address else ""
                    network_info = f"Primary IP: {private_ip}{public_ip}\nSubnet: {instance.subnet_id or 'N/A'}"
                
                table.add_row(
                    instance.resource_id,
                    instance.name or "",
                    instance.instance_type,
                    instance.state,
                    network_info
                )
                
        # Display Security Groups
        if vpc_resources["security_groups"]:
            console.print("\n[bold]Security Groups:[/bold]")
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("Description")
            
            for sg in vpc_resources["security_groups"]:
                table.add_row(
                    sg.resource_id,
                    sg.name or "",
                    sg.description or ""
                )
                
            console.print(table)
            
        # Display EKS Clusters
        if vpc_resources["eks_clusters"]:
            console.print("\n[bold]EKS Clusters:[/bold]")
            table = Table(show_header=True)
            table.add_column("Name")
            table.add_column("Status")
            table.add_column("Version")
            
            for cluster in vpc_resources["eks_clusters"]:
                table.add_row(
                    cluster.name or cluster.resource_id,
                    cluster.status,
                    cluster.kubernetes_version or ""
                )
                
            console.print(table)
            
        # Display Load Balancers
        if vpc_resources["load_balancers"]:
            console.print("\n[bold]Load Balancers:[/bold]")
            table = Table(show_header=True)
            table.add_column("Name")
            table.add_column("Type")
            table.add_column("DNS Name")
            table.add_column("State")
            
            for lb in vpc_resources["load_balancers"]:
                table.add_row(
                    lb.name or lb.resource_id,
                    lb.lb_type,
                    lb.dns_name or "",
                    lb.state or ""
                )
                
            console.print(table)
            
        # Display Lambda Functions
        if vpc_resources["lambda_functions"]:
            console.print("\n[bold]Lambda Functions:[/bold]")
            table = Table(show_header=True)
            table.add_column("Name")
            table.add_column("Runtime")
            table.add_column("Memory")
            table.add_column("Timeout")
            
            for func in vpc_resources["lambda_functions"]:
                table.add_row(
                    func.name or func.resource_id,
                    func.runtime,
                    str(func.memory_size) + " MB",
                    str(func.timeout) + " sec"
                )
                
            console.print(table)
            
        # Display Subnets
        if vpc_resources["subnets"]:
            console.print("\n[bold]Subnets:[/bold]")
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("CIDR Block")
            table.add_column("AZ")
            table.add_column("Available IPs")
            table.add_column("Public IP on Launch")
            
            for subnet in vpc_resources["subnets"]:
                table.add_row(
                    subnet.resource_id,
                    subnet.name or "",
                    subnet.cidr_block,
                    subnet.availability_zone,
                    str(subnet.available_ip_address_count),
                    "Yes" if subnet.map_public_ip_on_launch else "No"
                )
                
            console.print(table)
            
        # Display Internet Gateways
        if vpc_resources["internet_gateways"]:
            console.print("\n[bold]Internet Gateways:[/bold]")
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("State")
            
            for igw in vpc_resources["internet_gateways"]:
                table.add_row(
                    igw.resource_id,
                    igw.name or "",
                    igw.state or "attached"
                )
                
            console.print(table)
            
        # Display NAT Gateways
        if vpc_resources["nat_gateways"]:
            console.print("\n[bold]NAT Gateways:[/bold]")
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("Subnet")
            table.add_column("Type")
            table.add_column("State")
            table.add_column("Elastic IP")
            table.add_column("Private IP")
            
            for nat in vpc_resources["nat_gateways"]:
                table.add_row(
                    nat.resource_id,
                    nat.name or "",
                    nat.subnet_id,
                    nat.connectivity_type,
                    nat.state,
                    nat.elastic_ip_address or "",
                    nat.private_ip_address or ""
                )
                
            console.print(table)
            
        # Display Route Tables
        if vpc_resources["route_tables"]:
            console.print("\n[bold]Route Tables:[/bold]")
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("# Routes")
            table.add_column("# Associations")
            
            for rtb in vpc_resources["route_tables"]:
                table.add_row(
                    rtb.resource_id,
                    rtb.name or "",
                    str(len(rtb.routes)),
                    str(len(rtb.associations))
                )
                
            console.print(table)
            
        # Display Network ACLs
        if vpc_resources["network_acls"]:
            console.print("\n[bold]Network ACLs:[/bold]")
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("Default")
            table.add_column("# Rules")
            table.add_column("# Associations")
            
            for nacl in vpc_resources["network_acls"]:
                table.add_row(
                    nacl.resource_id,
                    nacl.name or "",
                    "Yes" if nacl.is_default else "No",
                    str(len(nacl.entries)),
                    str(len(nacl.associations))
                )
                
            console.print(table)
            
        # Display VPC Endpoints
        if vpc_resources["vpc_endpoints"]:
            console.print("\n[bold]VPC Endpoints:[/bold]")
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("Service")
            table.add_column("Type")
            table.add_column("State")
            
            for endpoint in vpc_resources["vpc_endpoints"]:
                table.add_row(
                    endpoint.resource_id,
                    endpoint.name or "",
                    endpoint.service_name,
                    endpoint.vpc_endpoint_type,
                    endpoint.state
                )
                
            console.print(table)
            
        # Display VPC Peering Connections
        if vpc_resources["vpc_peering_connections"]:
            console.print("\n[bold]VPC Peering Connections:[/bold]")
            table = Table(show_header=True)
            table.add_column("ID")
            table.add_column("Name")
            table.add_column("Peer VPC")
            table.add_column("Peer Region")
            table.add_column("Status")
            
            for peering in vpc_resources["vpc_peering_connections"]:
                peer_vpc = peering.vpc_id if peering.peer_vpc_id == vpc_id else peering.peer_vpc_id
                status_code = peering.status.get("Code", "unknown") if peering.status else "unknown"
                
                table.add_row(
                    peering.resource_id,
                    peering.name or "",
                    peer_vpc,
                    peering.peer_region or "same region",
                    status_code
                )
                
            console.print(table)
            
        # Print summary
        console.print("\n[bold]Summary:[/bold]")
        console.print(f"EC2 Instances: {len(vpc_resources['ec2_instances'])}")
        console.print(f"Security Groups: {len(vpc_resources['security_groups'])}")
        console.print(f"EKS Clusters: {len(vpc_resources['eks_clusters'])}")
        console.print(f"Load Balancers: {len(vpc_resources['load_balancers'])}")
        console.print(f"Lambda Functions: {len(vpc_resources['lambda_functions'])}")
        console.print(f"Subnets: {len(vpc_resources['subnets'])}")
        console.print(f"Internet Gateways: {len(vpc_resources['internet_gateways'])}")
        console.print(f"NAT Gateways: {len(vpc_resources['nat_gateways'])}")
        console.print(f"Route Tables: {len(vpc_resources['route_tables'])}")
        console.print(f"Network ACLs: {len(vpc_resources['network_acls'])}")
        console.print(f"VPC Endpoints: {len(vpc_resources['vpc_endpoints'])}")
        console.print(f"VPC Peering Connections: {len(vpc_resources['vpc_peering_connections'])}")
        console.print(f"Total resources: {sum(len(resources) for resources in vpc_resources.values())}")
    else:
        # For non-table outputs, use the output saving functionality
        from aws_resource_scanner.models import ScanResult
        vpc_result = ScanResult(
            regions=result.regions,
            ec2_instances=vpc_resources["ec2_instances"],
            security_groups=vpc_resources["security_groups"],
            eks_clusters=vpc_resources["eks_clusters"],
            load_balancers=vpc_resources["load_balancers"],
            lambda_functions=vpc_resources["lambda_functions"],
            node_groups=[],
            s3_buckets=[],
            auto_scaling_groups=[],
            vpcs=[vpc for vpc in result.vpcs if vpc.resource_id == vpc_id],
            subnets=vpc_resources["subnets"],
            internet_gateways=vpc_resources["internet_gateways"],
            nat_gateways=vpc_resources["nat_gateways"],
            route_tables=vpc_resources["route_tables"],
            network_acls=vpc_resources["network_acls"],
            vpc_endpoints=vpc_resources["vpc_endpoints"],
            vpc_peering_connections=vpc_resources["vpc_peering_connections"]
        )
        
        # Save results using configured output format
        from aws_resource_scanner.utils.output import save_output
        save_output(
            vpc_result, 
            output_format=output,
            output_file=output_file
        )
        
        console.print(f"Results saved to {output_file}")


if __name__ == "__main__":
    app() 