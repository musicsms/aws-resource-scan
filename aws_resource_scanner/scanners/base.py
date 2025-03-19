"""Base scanner for AWS resources.

This module provides a base class for all AWS resource scanners.
"""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import AWSResource
from aws_resource_scanner.utils.config import ScannerConfig, create_regional_clients
from aws_resource_scanner.utils.logger import log_aws_error, logger

T = TypeVar("T", bound=AWSResource)


class BaseScanner(ABC, Generic[T]):
    """Base scanner for AWS resources.

    All resource scanners should inherit from this class and implement
    the scan_region method.
    """

    # AWS service name (e.g., 'ec2', 's3')
    service_name: str = ""
    # Human-readable resource type
    resource_type: str = ""
    # Model class to use for resources
    resource_model: Type[T] = None

    def __init__(self, config: ScannerConfig):
        """Initialize the scanner with configuration.

        Args:
            config: Scanner configuration
        """
        self.config = config
        self.clients = {}

        if not self.service_name:
            raise ValueError(f"{self.__class__.__name__} must define service_name")
        if not self.resource_type:
            raise ValueError(f"{self.__class__.__name__} must define resource_type")
        if not self.resource_model:
            raise ValueError(f"{self.__class__.__name__} must define resource_model")

    def initialize(self) -> None:
        """Initialize AWS clients for each region."""
        self.clients = create_regional_clients(self.config, self.service_name)
        logger.debug(f"Initialized {self.resource_type} scanner for regions: {', '.join(self.clients.keys())}")

    @abstractmethod
    def scan_region(self, region: str, client: boto3.client) -> List[T]:
        """Scan a specific region for resources.

        Args:
            region: AWS region name
            client: Boto3 client for the region

        Returns:
            List of resources found in the region
        """
        pass

    def parse_tags(self, tags_list: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
        """Parse AWS tags list into a dictionary.

        Args:
            tags_list: AWS tags list with Key and Value fields

        Returns:
            Dictionary of tags
        """
        if not tags_list:
            return {}
        
        return {tag.get("Key", ""): tag.get("Value", "") for tag in tags_list if "Key" in tag}

    def scan(self) -> List[T]:
        """Scan all configured regions for resources.

        Returns:
            List of resources found across all regions
        """
        if not self.clients:
            self.initialize()

        all_resources = []
        
        for region, client in self.clients.items():
            try:
                logger.info(f"Scanning {self.resource_type} in {region}...")
                region_resources = self.scan_region(region, client)
                all_resources.extend(region_resources)
                logger.info(f"Found {len(region_resources)} {self.resource_type} resources in {region}")
                
            except ClientError as e:
                log_aws_error(e, self.service_name, "scan", region)
            except Exception as e:
                logger.error(f"Error scanning {self.resource_type} in {region}: {str(e)}")
                if logger.level <= logging.DEBUG:
                    logger.exception(e)
                
        return all_resources 