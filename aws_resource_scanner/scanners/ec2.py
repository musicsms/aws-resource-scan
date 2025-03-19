"""EC2 resource scanner.

This module provides scanners for EC2 instances.
"""
import logging
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import EC2Instance
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class EC2Scanner(BaseScanner[EC2Instance]):
    """Scanner for EC2 instances."""

    service_name = "ec2"
    resource_type = "EC2 instances"
    resource_model = EC2Instance

    def scan_region(self, region: str, client: boto3.client) -> List[EC2Instance]:
        """Scan a region for EC2 instances.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of EC2Instance resources
        """
        instances = []
        paginator = client.get_paginator("describe_instances")
        
        try:
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        try:
                            instance_id = instance.get("InstanceId")
                            if not instance_id:
                                continue
                                
                            # Get instance ARN
                            arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:instance/{instance_id}"
                            
                            # Parse instance state
                            state = instance.get("State", {}).get("Name", "unknown")
                            
                            # Parse instance details
                            instance_type = instance.get("InstanceType", "unknown")
                            private_ip = instance.get("PrivateIpAddress")
                            public_ip = instance.get("PublicIpAddress")
                            vpc_id = instance.get("VpcId")
                            subnet_id = instance.get("SubnetId")
                            launch_time = instance.get("LaunchTime")
                            
                            # Get security group IDs
                            security_group_ids = [
                                sg.get("GroupId")
                                for sg in instance.get("SecurityGroups", [])
                                if sg.get("GroupId")
                            ]
                            
                            # Get IAM instance profile if present
                            iam_profile = None
                            if instance.get("IamInstanceProfile"):
                                iam_profile = instance.get("IamInstanceProfile", {}).get("Arn")
                            
                            # Get key name if present
                            key_name = instance.get("KeyName")
                            
                            # Parse tags
                            tags = self.parse_tags(instance.get("Tags", []))
                            name = tags.get("Name", instance_id)
                            
                            instances.append(
                                EC2Instance(
                                    resource_id=instance_id,
                                    region=region,
                                    arn=arn,
                                    name=name,
                                    instance_type=instance_type,
                                    state=state,
                                    private_ip_address=private_ip,
                                    public_ip_address=public_ip,
                                    vpc_id=vpc_id,
                                    subnet_id=subnet_id,
                                    launch_time=launch_time,
                                    security_group_ids=security_group_ids,
                                    iam_instance_profile=iam_profile,
                                    key_name=key_name,
                                    tags=tags,
                                )
                            )
                            
                        except Exception as e:
                            logger.error(f"Error processing EC2 instance in {region}: {str(e)}")
                            if logger.level <= logging.DEBUG:
                                logger.exception(e)
                            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_instances", region)
        
        return instances 