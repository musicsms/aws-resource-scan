"""Elastic Load Balancer resource scanner.

This module provides scanners for Application and Network Load Balancers.
"""
import logging
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import LoadBalancer
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class LoadBalancerScanner(BaseScanner[LoadBalancer]):
    """Scanner for Application and Network Load Balancers."""

    service_name = "elbv2"
    resource_type = "Load Balancers"
    resource_model = LoadBalancer

    def scan_region(self, region: str, client: boto3.client) -> List[LoadBalancer]:
        """Scan a region for Application and Network Load Balancers.

        Args:
            region: AWS region to scan
            client: Boto3 ELBv2 client for the region

        Returns:
            List of LoadBalancer resources
        """
        load_balancers = []
        
        try:
            # Get all load balancers
            paginator = client.get_paginator("describe_load_balancers")
            
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    try:
                        lb_arn = lb.get("LoadBalancerArn")
                        if not lb_arn:
                            continue
                        
                        # Extract load balancer details
                        lb_name = lb.get("LoadBalancerName")
                        lb_type = lb.get("Type", "unknown").lower()  # application or network
                        scheme = lb.get("Scheme")
                        vpc_id = lb.get("VpcId")
                        dns_name = lb.get("DNSName")
                        state = lb.get("State", {}).get("Code")
                        security_groups = lb.get("SecurityGroups", [])
                        
                        # Get availability zones
                        availability_zones = [
                            az.get("ZoneName") 
                            for az in lb.get("AvailabilityZones", [])
                            if az.get("ZoneName")
                        ]
                        
                        # Get tags for the load balancer
                        try:
                            tags_response = client.describe_tags(ResourceArns=[lb_arn])
                            tag_descriptions = tags_response.get("TagDescriptions", [])
                            
                            tags = {}
                            if tag_descriptions:
                                for tag in tag_descriptions[0].get("Tags", []):
                                    key = tag.get("Key")
                                    value = tag.get("Value")
                                    if key:
                                        tags[key] = value
                        except ClientError as e:
                            log_aws_error(e, self.service_name, "describe_tags", lb_arn)
                            tags = {}
                        
                        # Get listeners for the load balancer
                        listeners = []
                        try:
                            listeners_paginator = client.get_paginator("describe_listeners")
                            for listeners_page in listeners_paginator.paginate(LoadBalancerArn=lb_arn):
                                for listener in listeners_page.get("Listeners", []):
                                    listeners.append({
                                        "port": listener.get("Port"),
                                        "protocol": listener.get("Protocol"),
                                        "ssl_policy": listener.get("SslPolicy"),
                                    })
                        except ClientError as e:
                            log_aws_error(e, self.service_name, "describe_listeners", lb_arn)
                        
                        # Get target groups for the load balancer
                        target_groups = []
                        try:
                            tg_paginator = client.get_paginator("describe_target_groups")
                            for tg_page in tg_paginator.paginate(LoadBalancerArn=lb_arn):
                                for tg in tg_page.get("TargetGroups", []):
                                    target_groups.append({
                                        "name": tg.get("TargetGroupName"),
                                        "protocol": tg.get("Protocol"),
                                        "port": tg.get("Port"),
                                        "target_type": tg.get("TargetType"),
                                        "vpc_id": tg.get("VpcId"),
                                    })
                        except ClientError as e:
                            log_aws_error(e, self.service_name, "describe_target_groups", lb_arn)
                        
                        # Create resource model
                        load_balancers.append(
                            LoadBalancer(
                                resource_id=lb_arn.split("/")[-1],
                                region=region,
                                arn=lb_arn,
                                name=lb_name,
                                lb_type=lb_type,
                                scheme=scheme,
                                vpc_id=vpc_id,
                                dns_name=dns_name,
                                state=state,
                                security_groups=security_groups,
                                availability_zones=availability_zones,
                                listeners=listeners,
                                target_groups=target_groups,
                                tags=tags,
                            )
                        )
                        
                    except Exception as e:
                        lb_name = lb.get("LoadBalancerName", "unknown")
                        logger.error(f"Error processing load balancer '{lb_name}' in {region}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
                
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_load_balancers", region)
            
        return load_balancers 