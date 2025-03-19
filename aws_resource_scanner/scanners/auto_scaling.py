"""Auto Scaling Group resource scanner.

This module provides scanners for AWS Auto Scaling Groups.
"""
import logging
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import AutoScalingGroup
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class AutoScalingGroupScanner(BaseScanner[AutoScalingGroup]):
    """Scanner for Auto Scaling Groups."""

    service_name = "autoscaling"
    resource_type = "Auto Scaling Groups"
    resource_model = AutoScalingGroup

    def scan_region(self, region: str, client: boto3.client) -> List[AutoScalingGroup]:
        """Scan a region for Auto Scaling Groups.

        Args:
            region: AWS region to scan
            client: Boto3 Auto Scaling client for the region

        Returns:
            List of AutoScalingGroup resources
        """
        groups = []
        
        try:
            # List all Auto Scaling Groups in the region
            paginator = client.get_paginator("describe_auto_scaling_groups")
            
            for page in paginator.paginate():
                for asg in page.get("AutoScalingGroups", []):
                    try:
                        asg_name = asg.get("AutoScalingGroupName")
                        if not asg_name:
                            continue
                        
                        # Get ASG ARN
                        arn = asg.get("AutoScalingGroupARN")
                        
                        # Extract ASG details
                        min_size = asg.get("MinSize", 0)
                        max_size = asg.get("MaxSize", 0)
                        desired_capacity = asg.get("DesiredCapacity", 0)
                        vpc_zone_identifier = asg.get("VPCZoneIdentifier")
                        
                        # Extract availability zones
                        availability_zones = asg.get("AvailabilityZones", [])
                        
                        # Extract instance IDs
                        instance_ids = [
                            instance.get("InstanceId") 
                            for instance in asg.get("Instances", [])
                            if instance.get("InstanceId")
                        ]
                        
                        # Extract launch template information
                        launch_template_id = None
                        launch_template_version = None
                        if "LaunchTemplate" in asg:
                            lt = asg.get("LaunchTemplate", {})
                            launch_template_id = lt.get("LaunchTemplateId")
                            launch_template_version = lt.get("Version")
                        
                        # Extract launch configuration
                        launch_configuration_name = asg.get("LaunchConfigurationName")
                        
                        # Extract load balancer info
                        load_balancer_names = asg.get("LoadBalancerNames", [])
                        target_group_arns = asg.get("TargetGroupARNs", [])
                        
                        # Parse tags
                        tags = self.parse_tags(asg.get("Tags", []))
                        name = tags.get("Name", asg_name)
                        
                        # Create resource model
                        groups.append(
                            AutoScalingGroup(
                                resource_id=asg_name,
                                region=region,
                                arn=arn,
                                name=name,
                                min_size=min_size,
                                max_size=max_size,
                                desired_capacity=desired_capacity,
                                launch_template_id=launch_template_id,
                                launch_template_version=launch_template_version,
                                launch_configuration_name=launch_configuration_name,
                                availability_zones=availability_zones,
                                vpc_zone_identifier=vpc_zone_identifier,
                                instance_ids=instance_ids,
                                load_balancer_names=load_balancer_names,
                                target_group_arns=target_group_arns,
                                tags=tags,
                            )
                        )
                        
                    except Exception as e:
                        logger.error(f"Error processing Auto Scaling Group in {region}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_auto_scaling_groups", region)
            
        return groups 