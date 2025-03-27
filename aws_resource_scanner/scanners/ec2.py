"""EC2 resource scanner.

This module provides scanners for EC2 instances.
"""
import logging
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import EC2Instance, NetworkInterface
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
                            
                            # For backward compatibility - these come from the instance top level
                            private_ip = instance.get("PrivateIpAddress")
                            public_ip = instance.get("PublicIpAddress")
                            vpc_id = instance.get("VpcId")
                            subnet_id = instance.get("SubnetId")
                            launch_time = instance.get("LaunchTime")
                            
                            # Get security group IDs at the instance level
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
                            
                            # Get AMI information
                            ami_id = instance.get("ImageId")
                            ami_name = None
                            platform_details = instance.get("PlatformDetails")
                            architecture = instance.get("Architecture")
                            
                            # Try to get AMI name if we have an AMI ID
                            if ami_id:
                                try:
                                    ami_response = client.describe_images(ImageIds=[ami_id])
                                    if ami_response.get("Images"):
                                        ami = ami_response["Images"][0]
                                        ami_name = ami.get("Name")
                                except ClientError as e:
                                    # AMI might not be accessible or might have been deleted
                                    log_aws_error(e, self.service_name, "describe_images", ami_id)
                            
                            # Process all network interfaces
                            network_interfaces = []
                            for interface in instance.get("NetworkInterfaces", []):
                                interface_id = interface.get("NetworkInterfaceId")
                                if not interface_id:
                                    continue
                                    
                                # Get private IPs and associated public IPs
                                private_ips = []
                                for private_ip_info in interface.get("PrivateIpAddresses", []):
                                    ip_data = {
                                        "private_ip": private_ip_info.get("PrivateIpAddress"),
                                        "primary": private_ip_info.get("Primary", False)
                                    }
                                    
                                    # Add public IP if exists
                                    if "Association" in private_ip_info and "PublicIp" in private_ip_info["Association"]:
                                        ip_data["public_ip"] = private_ip_info["Association"]["PublicIp"]
                                        
                                    private_ips.append(ip_data)
                                
                                # Get security groups for this interface
                                interface_sg_ids = [
                                    sg.get("GroupId")
                                    for sg in interface.get("Groups", [])
                                    if sg.get("GroupId")
                                ]
                                
                                # Create network interface object
                                network_interfaces.append(
                                    NetworkInterface(
                                        network_interface_id=interface_id,
                                        subnet_id=interface.get("SubnetId"),
                                        vpc_id=interface.get("VpcId"),
                                        description=interface.get("Description"),
                                        status=interface.get("Status"),
                                        primary=interface.get("Attachment", {}).get("DeviceIndex") == 0,
                                        private_ip_addresses=private_ips,
                                        security_group_ids=interface_sg_ids,
                                        attachment=interface.get("Attachment")
                                    )
                                )
                            
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
                                    ami_id=ami_id,
                                    ami_name=ami_name,
                                    platform_details=platform_details,
                                    architecture=architecture,
                                    tags=tags,
                                    network_interfaces=network_interfaces,
                                )
                            )
                            
                        except Exception as e:
                            logger.error(f"Error processing EC2 instance in {region}: {str(e)}")
                            if logger.level <= logging.DEBUG:
                                logger.exception(e)
                            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_instances", region)
        
        return instances 