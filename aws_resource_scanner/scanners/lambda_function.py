"""Lambda function resource scanner.

This module provides scanners for AWS Lambda functions.
"""
import logging
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import LambdaFunction
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class LambdaFunctionScanner(BaseScanner[LambdaFunction]):
    """Scanner for Lambda functions."""

    service_name = "lambda"
    resource_type = "Lambda Functions"
    resource_model = LambdaFunction

    def scan_region(self, region: str, client: boto3.client) -> List[LambdaFunction]:
        """Scan a region for Lambda functions.

        Args:
            region: AWS region to scan
            client: Boto3 Lambda client for the region

        Returns:
            List of LambdaFunction resources
        """
        functions = []
        
        try:
            # List all Lambda functions in the region
            paginator = client.get_paginator("list_functions")
            
            for page in paginator.paginate():
                for function in page.get("Functions", []):
                    try:
                        function_name = function.get("FunctionName")
                        if not function_name:
                            continue
                        
                        # Extract function ARN
                        arn = function.get("FunctionArn")
                        
                        # Extract function details
                        runtime = function.get("Runtime", "unknown")
                        handler = function.get("Handler", "unknown")
                        code_size = function.get("CodeSize", 0)
                        timeout = function.get("Timeout", 0)
                        memory_size = function.get("MemorySize", 0)
                        last_modified = function.get("LastModified")  # This is a timestamp string, might need parsing
                        role = function.get("Role", "")
                        
                        # Extract VPC configuration if exists
                        vpc_config = function.get("VpcConfig", {})
                        
                        # Extract environment variables
                        env_vars = function.get("Environment", {}).get("Variables", {})
                        
                        # Get function tags
                        tags = {}
                        try:
                            tag_response = client.list_tags(Resource=arn)
                            tags = tag_response.get("Tags", {})
                        except ClientError as e:
                            log_aws_error(e, self.service_name, "list_tags", function_name)
                            
                        # Create resource model
                        functions.append(
                            LambdaFunction(
                                resource_id=function_name,
                                region=region,
                                arn=arn,
                                name=function_name,
                                runtime=runtime,
                                handler=handler,
                                code_size=code_size,
                                timeout=timeout,
                                memory_size=memory_size,
                                last_modified=last_modified,  # Might need to parse this string to datetime
                                role=role,
                                vpc_config=vpc_config,
                                environment_variables=env_vars,
                                tags=tags,
                            )
                        )
                        
                    except Exception as e:
                        logger.error(f"Error processing Lambda function in {region}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "list_functions", region)
            
        return functions 