"""Main scanner module for AWS resources.

This module combines all resource scanners and provides a unified interface
for scanning and processing AWS resources.
"""
import logging
from typing import Dict, List, Optional, Set, Union

from aws_resource_scanner.models import ScanResult
from aws_resource_scanner.scanners.auto_scaling import AutoScalingGroupScanner
from aws_resource_scanner.scanners.ec2 import EC2Scanner
from aws_resource_scanner.scanners.eks import EKSClusterScanner, NodeGroupScanner
from aws_resource_scanner.scanners.elb import LoadBalancerScanner
from aws_resource_scanner.scanners.lambda_function import LambdaFunctionScanner
from aws_resource_scanner.scanners.s3 import S3BucketScanner
from aws_resource_scanner.scanners.security_group import SecurityGroupScanner
from aws_resource_scanner.scanners.vpc import VPCScanner
from aws_resource_scanner.scanners.vpc_resources import (
    SubnetScanner, InternetGatewayScanner, NatGatewayScanner, 
    RouteTableScanner, NetworkACLScanner, VPCEndpointScanner,
    VPCPeeringConnectionScanner
)
from aws_resource_scanner.utils.config import ScannerConfig
from aws_resource_scanner.utils.logger import logger
from aws_resource_scanner.utils.output import save_output


class AWSScannerBuilder:
    """Builder class for configuring and creating AWS resource scanners."""

    def __init__(self):
        """Initialize the scanner builder with default configuration."""
        self.config = ScannerConfig()
        self.resource_types = set()

    def with_regions(self, regions: List[str]) -> "AWSScannerBuilder":
        """Set AWS regions to scan.

        Args:
            regions: List of AWS region names

        Returns:
            Self for chaining
        """
        self.config.regions = regions
        return self

    def with_profile(self, profile_name: str) -> "AWSScannerBuilder":
        """Set AWS profile to use.

        Args:
            profile_name: AWS profile name

        Returns:
            Self for chaining
        """
        self.config.profile_name = profile_name
        return self

    def with_credentials(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: Optional[str] = None,
    ) -> "AWSScannerBuilder":
        """Set AWS credentials directly.

        Args:
            access_key_id: AWS access key ID
            secret_access_key: AWS secret access key
            session_token: Optional AWS session token

        Returns:
            Self for chaining
        """
        self.config.access_key_id = access_key_id
        self.config.secret_access_key = secret_access_key
        self.config.session_token = session_token
        return self

    def with_assumed_role(
        self,
        target_account_id: str,
        role_name: str,
        role_session_name: Optional[str] = None,
        external_id: Optional[str] = None,
    ) -> "AWSScannerBuilder":
        """Set AWS role to assume in another account using account ID and role name.
        
        This method constructs a role ARN from the account ID and role name.
        
        Args:
            target_account_id: Target AWS account ID to assume role in
            role_name: Name of the role to assume in the target account
            role_session_name: Optional session name for the assumed role session
            external_id: Optional external ID for the role assumption, if required
            
        Returns:
            Self for chaining
        """
        self.config.target_account_id = target_account_id
        self.config.role_name = role_name
        if role_session_name:
            self.config.role_session_name = role_session_name
        if external_id:
            self.config.external_id = external_id
        return self
        
    def with_role_arn(
        self,
        role_arn: str,
        role_session_name: Optional[str] = None,
        external_id: Optional[str] = None,
    ) -> "AWSScannerBuilder":
        """Set AWS role to assume using a full role ARN.
        
        Args:
            role_arn: Full ARN of the role to assume (e.g., 'arn:aws:iam::123456789012:role/RoleName')
            role_session_name: Optional session name for the assumed role session
            external_id: Optional external ID for the role assumption, if required
            
        Returns:
            Self for chaining
        """
        self.config.role_arn = role_arn
        if role_session_name:
            self.config.role_session_name = role_session_name
        if external_id:
            self.config.external_id = external_id
        return self

    def with_output_format(self, output_format: str) -> "AWSScannerBuilder":
        """Set output format for scan results.

        Args:
            output_format: Output format (json, csv, or table)

        Returns:
            Self for chaining
        """
        self.config.output_format = output_format
        return self

    def with_output_file(self, output_file: str) -> "AWSScannerBuilder":
        """Set output file for scan results.

        Args:
            output_file: Path to output file

        Returns:
            Self for chaining
        """
        self.config.output_file = output_file
        return self

    def with_log_level(self, log_level: int) -> "AWSScannerBuilder":
        """Set log level for the scanner.

        Args:
            log_level: Logging level (e.g., logging.INFO)

        Returns:
            Self for chaining
        """
        logger.setLevel(log_level)
        return self

    def with_resource_types(self, resource_types: List[str]) -> "AWSScannerBuilder":
        """Set resource types to scan.

        Args:
            resource_types: List of resource type identifiers

        Returns:
            Self for chaining
        """
        valid_types = {
            "ec2", "sg", "eks", "node_group", "lb", 
            "s3", "lambda", "asg", "vpc", "subnet", "igw", "nat", 
            "rtb", "nacl", "endpoint", "peering", "all"
        }
        
        for resource_type in resource_types:
            resource_type = resource_type.lower()
            if resource_type not in valid_types:
                logger.warning(f"Unknown resource type: {resource_type}")
                continue
                
            if resource_type == "all":
                self.resource_types = valid_types - {"all"}
                break
                
            self.resource_types.add(resource_type)
            
        return self

    def build(self) -> "AWSResourceScanner":
        """Build and return a configured scanner.

        Returns:
            Configured AWSResourceScanner instance
        """
        return AWSResourceScanner(self.config, self.resource_types)


class AWSResourceScanner:
    """Main scanner class for AWS resources.

    This class coordinates the scanning of multiple AWS resource types
    and combines the results.
    """

    def __init__(self, config: ScannerConfig, resource_types: Set[str] = None):
        """Initialize the scanner with configuration.

        Args:
            config: Scanner configuration
            resource_types: Set of resource types to scan (scans all if None)
        """
        self.config = config
        self.resource_types = resource_types or {
            "ec2", "security_group", "eks", "node_group", "load_balancer",
            "s3", "lambda", "auto_scaling_group", "vpc", "subnet", "igw", 
            "nat", "rtb", "nacl", "endpoint", "peering"
        }
        self.scanners = {}
        
        # Initialize scanners for enabled resource types
        if not self.resource_types or "ec2" in self.resource_types:
            self.scanners["ec2"] = EC2Scanner(config)
            
        if not self.resource_types or "security_group" in self.resource_types:
            self.scanners["security_group"] = SecurityGroupScanner(config)
            
        if not self.resource_types or "eks" in self.resource_types:
            self.scanners["eks"] = EKSClusterScanner(config)
            
        if not self.resource_types or "node_group" in self.resource_types:
            self.scanners["node_group"] = NodeGroupScanner(config)
            
        if not self.resource_types or "load_balancer" in self.resource_types:
            self.scanners["load_balancer"] = LoadBalancerScanner(config)
            
        if not self.resource_types or "s3" in self.resource_types:
            self.scanners["s3"] = S3BucketScanner(config)
            
        if not self.resource_types or "lambda" in self.resource_types:
            self.scanners["lambda"] = LambdaFunctionScanner(config)
            
        if not self.resource_types or "auto_scaling_group" in self.resource_types:
            self.scanners["auto_scaling_group"] = AutoScalingGroupScanner(config)
            
        if not self.resource_types or "vpc" in self.resource_types:
            self.scanners["vpc"] = VPCScanner(config)
            
        if not self.resource_types or "subnet" in self.resource_types:
            self.scanners["subnet"] = SubnetScanner(config)
            
        if not self.resource_types or "igw" in self.resource_types:
            self.scanners["igw"] = InternetGatewayScanner(config)
            
        if not self.resource_types or "nat" in self.resource_types:
            self.scanners["nat"] = NatGatewayScanner(config)
            
        if not self.resource_types or "rtb" in self.resource_types:
            self.scanners["rtb"] = RouteTableScanner(config)
            
        if not self.resource_types or "nacl" in self.resource_types:
            self.scanners["nacl"] = NetworkACLScanner(config)
            
        if not self.resource_types or "endpoint" in self.resource_types:
            self.scanners["endpoint"] = VPCEndpointScanner(config)
            
        if not self.resource_types or "peering" in self.resource_types:
            self.scanners["peering"] = VPCPeeringConnectionScanner(config)

    def scan(self) -> ScanResult:
        """Scan AWS resources based on the configuration.

        Returns:
            ScanResult with all scanned resources
        """
        # Create result object
        result = ScanResult(regions=list(self.config.regions))
        
        # EC2 instances
        if not self.resource_types or "ec2" in self.resource_types:
            ec2_scanner = EC2Scanner(self.config)
            result.ec2_instances = ec2_scanner.scan()
            
        # Security groups
        if not self.resource_types or "sg" in self.resource_types:
            sg_scanner = SecurityGroupScanner(self.config)
            result.security_groups = sg_scanner.scan()
            
        # EKS clusters
        if not self.resource_types or "eks" in self.resource_types:
            eks_scanner = EKSClusterScanner(self.config)
            result.eks_clusters = eks_scanner.scan()
            
        # EKS node groups
        if not self.resource_types or "node_group" in self.resource_types:
            node_group_scanner = NodeGroupScanner(self.config)
            result.node_groups = node_group_scanner.scan()
            
        # Load balancers
        if not self.resource_types or "lb" in self.resource_types:
            lb_scanner = LoadBalancerScanner(self.config)
            result.load_balancers = lb_scanner.scan()
            
        # S3 buckets
        if not self.resource_types or "s3" in self.resource_types:
            s3_scanner = S3BucketScanner(self.config)
            result.s3_buckets = s3_scanner.scan()
            
        # Lambda functions
        if not self.resource_types or "lambda" in self.resource_types:
            lambda_scanner = LambdaFunctionScanner(self.config)
            result.lambda_functions = lambda_scanner.scan()
            
        # Auto Scaling groups
        if not self.resource_types or "asg" in self.resource_types:
            asg_scanner = AutoScalingGroupScanner(self.config)
            result.auto_scaling_groups = asg_scanner.scan()
            
        # VPCs
        if not self.resource_types or "vpc" in self.resource_types:
            vpc_scanner = VPCScanner(self.config)
            result.vpcs = vpc_scanner.scan()
            
        # Subnets
        if not self.resource_types or "subnet" in self.resource_types:
            subnet_scanner = SubnetScanner(self.config)
            result.subnets = subnet_scanner.scan()
            
        # Internet Gateways
        if not self.resource_types or "igw" in self.resource_types:
            igw_scanner = InternetGatewayScanner(self.config)
            result.internet_gateways = igw_scanner.scan()
            
        # NAT Gateways
        if not self.resource_types or "nat" in self.resource_types:
            nat_scanner = NatGatewayScanner(self.config)
            result.nat_gateways = nat_scanner.scan()
            
        # Route Tables
        if not self.resource_types or "rtb" in self.resource_types:
            rtb_scanner = RouteTableScanner(self.config)
            result.route_tables = rtb_scanner.scan()
            
        # Network ACLs
        if not self.resource_types or "nacl" in self.resource_types:
            nacl_scanner = NetworkACLScanner(self.config)
            result.network_acls = nacl_scanner.scan()
            
        # VPC Endpoints
        if not self.resource_types or "endpoint" in self.resource_types:
            endpoint_scanner = VPCEndpointScanner(self.config)
            result.vpc_endpoints = endpoint_scanner.scan()
            
        # VPC Peering Connections
        if not self.resource_types or "peering" in self.resource_types:
            peering_scanner = VPCPeeringConnectionScanner(self.config)
            result.vpc_peering_connections = peering_scanner.scan()
        
        # Log summary
        logger.info(f"Scan complete. Found:")
        logger.info(f"  EC2 instances: {len(result.ec2_instances)}")
        logger.info(f"  Security groups: {len(result.security_groups)}")
        logger.info(f"  EKS clusters: {len(result.eks_clusters)}")
        logger.info(f"  EKS node groups: {len(result.node_groups)}")
        logger.info(f"  Load balancers: {len(result.load_balancers)}")
        logger.info(f"  S3 buckets: {len(result.s3_buckets)}")
        logger.info(f"  Lambda functions: {len(result.lambda_functions)}")
        logger.info(f"  Auto Scaling groups: {len(result.auto_scaling_groups)}")
        logger.info(f"  VPCs: {len(result.vpcs)}")
        logger.info(f"  Subnets: {len(result.subnets)}")
        logger.info(f"  Internet Gateways: {len(result.internet_gateways)}")
        logger.info(f"  NAT Gateways: {len(result.nat_gateways)}")
        logger.info(f"  Route Tables: {len(result.route_tables)}")
        logger.info(f"  Network ACLs: {len(result.network_acls)}")
        logger.info(f"  VPC Endpoints: {len(result.vpc_endpoints)}")
        logger.info(f"  VPC Peering Connections: {len(result.vpc_peering_connections)}")
        
        return result
        
    def scan_and_save(self) -> ScanResult:
        """Scan AWS resources and save the results.

        Returns:
            ScanResult containing all scanned resources
        """
        # Perform scan
        result = self.scan()
        
        # Save results using configured output format
        save_output(
            result, 
            output_format=self.config.output_format,
            output_file=self.config.output_file
        )
        
        return result 