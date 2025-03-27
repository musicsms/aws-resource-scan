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
                        
                        # Get listeners and their rules
                        listeners = []
                        routing_rules = []
                        try:
                            listeners_paginator = client.get_paginator("describe_listeners")
                            for listeners_page in listeners_paginator.paginate(LoadBalancerArn=lb_arn):
                                for listener in listeners_page.get("Listeners", []):
                                    listener_arn = listener.get("ListenerArn")
                                    listener_info = {
                                        "port": listener.get("Port"),
                                        "protocol": listener.get("Protocol"),
                                        "ssl_policy": listener.get("SslPolicy"),
                                        "certificates": listener.get("Certificates", []),
                                        "alpn_policy": listener.get("AlpnPolicy", [])
                                    }
                                    listeners.append(listener_info)

                                    # Get rules for each listener
                                    if listener_arn:
                                        try:
                                            rules_paginator = client.get_paginator("describe_rules")
                                            for rules_page in rules_paginator.paginate(ListenerArn=listener_arn):
                                                for rule in rules_page.get("Rules", []):
                                                    rule_info = {
                                                        "rule_arn": rule.get("RuleArn"),
                                                        "priority": rule.get("Priority"),
                                                        "conditions": rule.get("Conditions", []),
                                                        "actions": rule.get("Actions", []),
                                                        "is_default": rule.get("IsDefault", False)
                                                    }
                                                    routing_rules.append(rule_info)
                                        except ClientError as e:
                                            log_aws_error(e, self.service_name, "describe_rules", listener_arn)
                        except ClientError as e:
                            log_aws_error(e, self.service_name, "describe_listeners", lb_arn)
                        
                        # Get target groups and their health status
                        target_groups = []
                        target_health = []
                        try:
                            tg_paginator = client.get_paginator("describe_target_groups")
                            for tg_page in tg_paginator.paginate(LoadBalancerArn=lb_arn):
                                for tg in tg_page.get("TargetGroups", []):
                                    tg_arn = tg.get("TargetGroupArn")
                                    tg_info = {
                                        "name": tg.get("TargetGroupName"),
                                        "protocol": tg.get("Protocol"),
                                        "port": tg.get("Port"),
                                        "target_type": tg.get("TargetType"),
                                        "vpc_id": tg.get("VpcId"),
                                        "health_check": tg.get("HealthCheckEnabled", False),
                                        "health_check_path": tg.get("HealthCheckPath"),
                                        "health_check_port": tg.get("HealthCheckPort"),
                                        "health_check_protocol": tg.get("HealthCheckProtocol"),
                                        "health_check_timeout": tg.get("HealthCheckTimeoutSeconds"),
                                        "healthy_threshold": tg.get("HealthyThresholdCount"),
                                        "unhealthy_threshold": tg.get("UnhealthyThresholdCount"),
                                        "stickiness": tg.get("TargetGroupAttributes", {}).get("stickiness.enabled", False)
                                    }
                                    target_groups.append(tg_info)

                                    # Get health status for each target in the target group
                                    if tg_arn:
                                        try:
                                            health_response = client.describe_target_health(TargetGroupArn=tg_arn)
                                            target_health_info = {
                                                "target_group_name": tg.get("TargetGroupName"),
                                                "targets": [
                                                    {
                                                        "target_id": target.get("Target", {}).get("Id"),
                                                        "port": target.get("Target", {}).get("Port"),
                                                        "health_state": target.get("TargetHealth", {}).get("State"),
                                                        "reason": target.get("TargetHealth", {}).get("Reason"),
                                                        "description": target.get("TargetHealth", {}).get("Description")
                                                    }
                                                    for target in health_response.get("TargetHealthDescriptions", [])
                                                ]
                                            }
                                            target_health.append(target_health_info)
                                        except ClientError as e:
                                            log_aws_error(e, self.service_name, "describe_target_health", tg_arn)
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
                                target_health=target_health,
                                routing_rules=routing_rules,
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