"""VPC resource scanner.

This module provides scanners for VPC resources.
"""
import logging
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import VPC
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class VPCScanner(BaseScanner[VPC]):
    """Scanner for VPC resources."""

    service_name = "ec2"
    resource_type = "VPCs"
    resource_model = VPC

    def scan_region(self, region: str, client: boto3.client) -> List[VPC]:
        """Scan a region for VPC resources.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of VPC resources
        """
        vpcs = []
        
        try:
            # Describe VPCs
            response = client.describe_vpcs()
            
            # Parse each VPC
            for vpc in response.get("Vpcs", []):
                try:
                    vpc_id = vpc.get("VpcId")
                    if not vpc_id:
                        continue
                        
                    # Get VPC ARN
                    arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:vpc/{vpc_id}"
                    
                    # Parse VPC attributes
                    cidr_block = vpc.get("CidrBlock", "")
                    is_default = vpc.get("IsDefault", False)
                    state = vpc.get("State", "unknown")
                    dhcp_options_id = vpc.get("DhcpOptionsId")
                    instance_tenancy = vpc.get("InstanceTenancy")
                    owner_id = vpc.get("OwnerId")
                    
                    # Get attribute information
                    try:
                        dns_support = client.describe_vpc_attribute(
                            VpcId=vpc_id,
                            Attribute='enableDnsSupport'
                        )
                        enable_dns_support = dns_support.get('EnableDnsSupport', {}).get('Value', True)
                        
                        dns_hostnames = client.describe_vpc_attribute(
                            VpcId=vpc_id,
                            Attribute='enableDnsHostnames'
                        )
                        enable_dns_hostnames = dns_hostnames.get('EnableDnsHostnames', {}).get('Value', False)
                    except Exception as e:
                        logger.debug(f"Error getting VPC attributes for {vpc_id}: {str(e)}")
                        enable_dns_support = True
                        enable_dns_hostnames = False
                    
                    # Parse tags
                    tags = self.parse_tags(vpc.get("Tags", []))
                    name = tags.get("Name", vpc_id)
                    
                    vpcs.append(
                        VPC(
                            resource_id=vpc_id,
                            region=region,
                            arn=arn,
                            name=name,
                            tags=tags,
                            cidr_block=cidr_block,
                            is_default=is_default,
                            state=state,
                            dhcp_options_id=dhcp_options_id,
                            instance_tenancy=instance_tenancy,
                            enable_dns_support=enable_dns_support,
                            enable_dns_hostnames=enable_dns_hostnames,
                            owner_id=owner_id
                        )
                    )
                except Exception as e:
                    logger.error(f"Error processing VPC {vpc.get('VpcId', 'unknown')}: {str(e)}")
                    if logger.level <= logging.DEBUG:
                        logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_vpcs", region)
        except Exception as e:
            logger.error(f"Error scanning VPCs in {region}: {str(e)}")
            if logger.level <= logging.DEBUG:
                logger.exception(e)
                
        return vpcs 