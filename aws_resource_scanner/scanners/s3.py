"""S3 bucket resource scanner.

This module provides scanners for S3 buckets.
"""
import logging
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import S3Bucket
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class S3BucketScanner(BaseScanner[S3Bucket]):
    """Scanner for S3 buckets."""

    service_name = "s3"
    resource_type = "S3 Buckets"
    resource_model = S3Bucket

    def scan_region(self, region: str, client: boto3.client) -> List[S3Bucket]:
        """Scan a region for S3 buckets.

        Note: S3 buckets are global, but have a region associated with them.
        This method will list all buckets but filter to the specified region.

        Args:
            region: AWS region to scan
            client: Boto3 S3 client for the region

        Returns:
            List of S3Bucket resources
        """
        buckets = []
        
        try:
            # List all buckets
            response = client.list_buckets()
            
            for bucket in response.get("Buckets", []):
                bucket_name = bucket.get("Name")
                if not bucket_name:
                    continue
                
                try:
                    # Get bucket location (region)
                    location_response = client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location_response.get("LocationConstraint")
                    
                    # Handle special cases for regions
                    if bucket_region is None:
                        bucket_region = "us-east-1"  # Default region when location constraint is empty
                    elif bucket_region == "EU":
                        bucket_region = "eu-west-1"
                    
                    # Filter buckets to the specified region
                    if bucket_region != region:
                        continue
                    
                    # Create bucket ARN
                    arn = f"arn:aws:s3:::{bucket_name}"
                    
                    # Get bucket creation date
                    creation_date = bucket.get("CreationDate")
                    
                    # Check bucket versioning
                    versioning_enabled = False
                    try:
                        versioning_response = client.get_bucket_versioning(Bucket=bucket_name)
                        versioning_enabled = versioning_response.get("Status") == "Enabled"
                    except ClientError as e:
                        log_aws_error(e, self.service_name, "get_bucket_versioning", bucket_name)
                    
                    # Check bucket encryption
                    encryption_enabled = False
                    try:
                        client.get_bucket_encryption(Bucket=bucket_name)
                        encryption_enabled = True
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                            log_aws_error(e, self.service_name, "get_bucket_encryption", bucket_name)
                    
                    # Check public access block
                    public_access_blocked = False
                    try:
                        public_access_response = client.get_public_access_block(Bucket=bucket_name)
                        config = public_access_response.get("PublicAccessBlockConfiguration", {})
                        # Consider blocked if all settings are True
                        public_access_blocked = (
                            config.get("BlockPublicAcls", False) and
                            config.get("IgnorePublicAcls", False) and
                            config.get("BlockPublicPolicy", False) and
                            config.get("RestrictPublicBuckets", False)
                        )
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                            log_aws_error(e, self.service_name, "get_public_access_block", bucket_name)
                    
                    # Check logging configuration
                    logging_enabled = False
                    try:
                        logging_response = client.get_bucket_logging(Bucket=bucket_name)
                        logging_enabled = "LoggingEnabled" in logging_response
                    except ClientError as e:
                        log_aws_error(e, self.service_name, "get_bucket_logging", bucket_name)
                    
                    # Get bucket tags
                    tags = {}
                    try:
                        tag_response = client.get_bucket_tagging(Bucket=bucket_name)
                        tags = {tag["Key"]: tag["Value"] for tag in tag_response.get("TagSet", [])}
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "NoSuchTagSet":
                            log_aws_error(e, self.service_name, "get_bucket_tagging", bucket_name)
                    
                    # Create resource model
                    buckets.append(
                        S3Bucket(
                            resource_id=bucket_name,
                            region=region,
                            arn=arn,
                            name=bucket_name,
                            creation_date=creation_date,
                            versioning_enabled=versioning_enabled,
                            public_access_blocked=public_access_blocked,
                            encryption_enabled=encryption_enabled,
                            logging_enabled=logging_enabled,
                            tags=tags,
                        )
                    )
                    
                except ClientError as e:
                    log_aws_error(e, self.service_name, "describe_bucket", bucket_name)
                except Exception as e:
                    logger.error(f"Error processing S3 bucket '{bucket_name}': {str(e)}")
                    if logger.level <= logging.DEBUG:
                        logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "list_buckets", region)
            
        return buckets 