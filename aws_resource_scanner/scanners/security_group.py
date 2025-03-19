"""Security Group resource scanner.

This module provides scanners for EC2 Security Groups.
"""
import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import SecurityGroup
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class SecurityGroupScanner(BaseScanner[SecurityGroup]):
    """Scanner for EC2 Security Groups."""

    service_name = "ec2"
    resource_type = "Security Groups"
    resource_model = SecurityGroup

    def _parse_rules(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse security group rules into a simplified format.

        Args:
            rules: Security group rules from AWS API

        Returns:
            List of simplified rule dictionaries
        """
        parsed_rules = []
        
        for rule in rules:
            # Extract IP ranges
            ip_ranges = [ip_range.get("CidrIp", "") 
                        for ip_range in rule.get("IpRanges", [])]
            
            # Extract IPv6 ranges
            ipv6_ranges = [ip_range.get("CidrIpv6", "") 
                          for ip_range in rule.get("Ipv6Ranges", [])]
            
            # Extract security group references
            group_references = [group.get("GroupId", "") 
                               for group in rule.get("UserIdGroupPairs", [])]
            
            # Extract protocol and ports
            protocol = rule.get("IpProtocol", "-1")
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 0)
            
            # Build the simplified rule
            simplified_rule = {
                "protocol": protocol,
                "port_range": f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                "ip_ranges": ip_ranges,
                "ipv6_ranges": ipv6_ranges,
                "group_references": group_references,
            }
            
            parsed_rules.append(simplified_rule)
            
        return parsed_rules

    def scan_region(self, region: str, client: boto3.client) -> List[SecurityGroup]:
        """Scan a region for Security Groups.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of SecurityGroup resources
        """
        security_groups = []
        paginator = client.get_paginator("describe_security_groups")
        
        try:
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    try:
                        sg_id = sg.get("GroupId")
                        if not sg_id:
                            continue
                            
                        # Get security group ARN
                        arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:security-group/{sg_id}"
                        
                        # Parse security group details
                        name = sg.get("GroupName", sg_id)
                        description = sg.get("Description")
                        vpc_id = sg.get("VpcId")
                        
                        # Parse inbound and outbound rules
                        inbound_rules = self._parse_rules(sg.get("IpPermissions", []))
                        outbound_rules = self._parse_rules(sg.get("IpPermissionsEgress", []))
                        
                        # Parse tags
                        tags = self.parse_tags(sg.get("Tags", []))
                        
                        security_groups.append(
                            SecurityGroup(
                                resource_id=sg_id,
                                region=region,
                                arn=arn,
                                name=name,
                                vpc_id=vpc_id,
                                description=description,
                                inbound_rules=inbound_rules,
                                outbound_rules=outbound_rules,
                                tags=tags,
                            )
                        )
                        
                    except Exception as e:
                        logger.error(f"Error processing Security Group in {region}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
                        
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_security_groups", region)
        
        return security_groups 