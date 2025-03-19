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
        """Set specific resource types to scan.

        Args:
            resource_types: List of resource type names

        Returns:
            Self for chaining
        """
        valid_types = {
            "ec2", "sg", "security_group", "eks", "node_group", "lb", "load_balancer",
            "s3", "lambda", "asg", "auto_scaling_group", "all"
        }
        
        for rt in resource_types:
            rt_lower = rt.lower()
            if rt_lower == "all":
                self.resource_types = valid_types - {"all"}
                break
                
            # Map aliases to canonical names
            if rt_lower == "sg":
                self.resource_types.add("security_group")
            elif rt_lower == "lb":
                self.resource_types.add("load_balancer")
            elif rt_lower == "asg":
                self.resource_types.add("auto_scaling_group")
            elif rt_lower in valid_types:
                self.resource_types.add(rt_lower)
            else:
                logger.warning(f"Unknown resource type: {rt}, skipping")
        
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
            "s3", "lambda", "auto_scaling_group"
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

    def scan(self) -> ScanResult:
        """Scan AWS resources based on the configuration.

        Returns:
            ScanResult containing all scanned resources
        """
        logger.info(f"Starting AWS resource scan in regions: {', '.join(self.config.regions)}")
        
        # Initialize scan result
        result = ScanResult(regions=self.config.regions)
        
        # Scan EC2 instances
        if "ec2" in self.scanners:
            logger.info("Scanning EC2 instances...")
            result.ec2_instances = self.scanners["ec2"].scan()
            
        # Scan Security Groups
        if "security_group" in self.scanners:
            logger.info("Scanning Security Groups...")
            result.security_groups = self.scanners["security_group"].scan()
            
        # Scan EKS clusters
        if "eks" in self.scanners:
            logger.info("Scanning EKS clusters...")
            result.eks_clusters = self.scanners["eks"].scan()
            
        # Scan EKS node groups
        if "node_group" in self.scanners:
            logger.info("Scanning EKS node groups...")
            result.node_groups = self.scanners["node_group"].scan()
            
        # Scan load balancers
        if "load_balancer" in self.scanners:
            logger.info("Scanning Load Balancers...")
            result.load_balancers = self.scanners["load_balancer"].scan()
            
        # Scan S3 buckets
        if "s3" in self.scanners:
            logger.info("Scanning S3 buckets...")
            result.s3_buckets = self.scanners["s3"].scan()
            
        # Scan Lambda functions
        if "lambda" in self.scanners:
            logger.info("Scanning Lambda functions...")
            result.lambda_functions = self.scanners["lambda"].scan()
            
        # Scan Auto Scaling Groups
        if "auto_scaling_group" in self.scanners:
            logger.info("Scanning Auto Scaling Groups...")
            result.auto_scaling_groups = self.scanners["auto_scaling_group"].scan()
            
        logger.info("AWS resource scan complete")
        
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