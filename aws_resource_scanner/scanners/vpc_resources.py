"""VPC-related resource scanners.

This module provides scanners for VPC-related resources like Subnets, Internet Gateways, NAT Gateways, etc.
"""
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import (
    Subnet, InternetGateway, NatGateway, RouteTable, 
    NetworkACL, VPCEndpoint, VPCPeeringConnection
)
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class SubnetScanner(BaseScanner[Subnet]):
    """Scanner for Subnet resources."""

    service_name = "ec2"
    resource_type = "Subnets"
    resource_model = Subnet

    def scan_region(self, region: str, client: boto3.client) -> List[Subnet]:
        """Scan a region for Subnet resources.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of Subnet resources
        """
        subnets = []
        
        try:
            # Describe Subnets
            paginator = client.get_paginator("describe_subnets")
            
            for page in paginator.paginate():
                for subnet in page.get("Subnets", []):
                    try:
                        subnet_id = subnet.get("SubnetId")
                        if not subnet_id:
                            continue
                            
                        # Get Subnet ARN
                        arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:subnet/{subnet_id}"
                        
                        # Parse Subnet attributes
                        vpc_id = subnet.get("VpcId", "")
                        cidr_block = subnet.get("CidrBlock", "")
                        availability_zone = subnet.get("AvailabilityZone", "")
                        available_ip_address_count = subnet.get("AvailableIpAddressCount", 0)
                        default_for_az = subnet.get("DefaultForAz", False)
                        map_public_ip_on_launch = subnet.get("MapPublicIpOnLaunch", False)
                        state = subnet.get("State", "unknown")
                        owner_id = subnet.get("OwnerId")
                        
                        # Parse tags
                        tags = self.parse_tags(subnet.get("Tags", []))
                        name = tags.get("Name", subnet_id)
                        
                        subnets.append(
                            Subnet(
                                resource_id=subnet_id,
                                region=region,
                                arn=arn,
                                name=name,
                                tags=tags,
                                vpc_id=vpc_id,
                                cidr_block=cidr_block,
                                availability_zone=availability_zone,
                                available_ip_address_count=available_ip_address_count,
                                default_for_az=default_for_az,
                                map_public_ip_on_launch=map_public_ip_on_launch,
                                state=state,
                                owner_id=owner_id
                            )
                        )
                    except Exception as e:
                        logger.error(f"Error processing Subnet {subnet.get('SubnetId', 'unknown')}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_subnets", region)
        except Exception as e:
            logger.error(f"Error scanning Subnets in {region}: {str(e)}")
            if logger.level <= logging.DEBUG:
                logger.exception(e)
                
        return subnets


class InternetGatewayScanner(BaseScanner[InternetGateway]):
    """Scanner for Internet Gateway resources."""

    service_name = "ec2"
    resource_type = "Internet Gateways"
    resource_model = InternetGateway

    def scan_region(self, region: str, client: boto3.client) -> List[InternetGateway]:
        """Scan a region for Internet Gateway resources.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of Internet Gateway resources
        """
        internet_gateways = []
        
        try:
            # Describe Internet Gateways
            paginator = client.get_paginator("describe_internet_gateways")
            
            for page in paginator.paginate():
                for igw in page.get("InternetGateways", []):
                    try:
                        igw_id = igw.get("InternetGatewayId")
                        if not igw_id:
                            continue
                            
                        # Get Internet Gateway ARN
                        arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:internet-gateway/{igw_id}"
                        
                        # Get attached VPC, if any
                        vpc_id = None
                        state = None
                        
                        attachments = igw.get("Attachments", [])
                        if attachments:
                            vpc_id = attachments[0].get("VpcId")
                            state = attachments[0].get("State")
                        
                        owner_id = igw.get("OwnerId")
                        
                        # Parse tags
                        tags = self.parse_tags(igw.get("Tags", []))
                        name = tags.get("Name", igw_id)
                        
                        internet_gateways.append(
                            InternetGateway(
                                resource_id=igw_id,
                                region=region,
                                arn=arn,
                                name=name,
                                tags=tags,
                                vpc_id=vpc_id,
                                state=state,
                                owner_id=owner_id
                            )
                        )
                    except Exception as e:
                        logger.error(f"Error processing Internet Gateway {igw.get('InternetGatewayId', 'unknown')}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_internet_gateways", region)
        except Exception as e:
            logger.error(f"Error scanning Internet Gateways in {region}: {str(e)}")
            if logger.level <= logging.DEBUG:
                logger.exception(e)
                
        return internet_gateways


class NatGatewayScanner(BaseScanner[NatGateway]):
    """Scanner for NAT Gateway resources."""

    service_name = "ec2"
    resource_type = "NAT Gateways"
    resource_model = NatGateway

    def scan_region(self, region: str, client: boto3.client) -> List[NatGateway]:
        """Scan a region for NAT Gateway resources.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of NAT Gateway resources
        """
        nat_gateways = []
        
        try:
            # Describe NAT Gateways
            paginator = client.get_paginator("describe_nat_gateways")
            
            for page in paginator.paginate():
                for nat in page.get("NatGateways", []):
                    try:
                        nat_id = nat.get("NatGatewayId")
                        if not nat_id:
                            continue
                            
                        # Get NAT Gateway ARN
                        arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:natgateway/{nat_id}"
                        
                        # Parse NAT Gateway attributes
                        vpc_id = nat.get("VpcId", "")
                        subnet_id = nat.get("SubnetId", "")
                        state = nat.get("State", "unknown")
                        connectivity_type = nat.get("ConnectivityType", "public")  # Default to "public" if not specified
                        
                        # Handle create_time as a datetime object
                        create_time = nat.get("CreateTime")
                        
                        # Get public IP if available
                        elastic_ip_address = None
                        private_ip_address = None
                        network_interface_id = None
                        
                        nat_gateway_addresses = nat.get("NatGatewayAddresses", [])
                        if nat_gateway_addresses:
                            address = nat_gateway_addresses[0]
                            elastic_ip_address = address.get("PublicIp")
                            private_ip_address = address.get("PrivateIp")
                            network_interface_id = address.get("NetworkInterfaceId")
                        
                        # Parse tags
                        tags = self.parse_tags(nat.get("Tags", []))
                        name = tags.get("Name", nat_id)
                        
                        nat_gateways.append(
                            NatGateway(
                                resource_id=nat_id,
                                region=region,
                                arn=arn,
                                name=name,
                                tags=tags,
                                vpc_id=vpc_id,
                                subnet_id=subnet_id,
                                state=state,
                                connectivity_type=connectivity_type,
                                elastic_ip_address=elastic_ip_address,
                                private_ip_address=private_ip_address,
                                network_interface_id=network_interface_id,
                                create_time=create_time
                            )
                        )
                    except Exception as e:
                        logger.error(f"Error processing NAT Gateway {nat.get('NatGatewayId', 'unknown')}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_nat_gateways", region)
        except Exception as e:
            logger.error(f"Error scanning NAT Gateways in {region}: {str(e)}")
            if logger.level <= logging.DEBUG:
                logger.exception(e)
                
        return nat_gateways


class RouteTableScanner(BaseScanner[RouteTable]):
    """Scanner for Route Table resources."""

    service_name = "ec2"
    resource_type = "Route Tables"
    resource_model = RouteTable

    def scan_region(self, region: str, client: boto3.client) -> List[RouteTable]:
        """Scan a region for Route Table resources.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of Route Table resources
        """
        route_tables = []
        
        try:
            # Describe Route Tables
            paginator = client.get_paginator("describe_route_tables")
            
            for page in paginator.paginate():
                for rt in page.get("RouteTables", []):
                    try:
                        rt_id = rt.get("RouteTableId")
                        if not rt_id:
                            continue
                            
                        # Get Route Table ARN
                        arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:route-table/{rt_id}"
                        
                        # Parse Route Table attributes
                        vpc_id = rt.get("VpcId", "")
                        routes = rt.get("Routes", [])
                        associations = rt.get("Associations", [])
                        propagating_vgws = rt.get("PropagatingVgws", [])
                        owner_id = rt.get("OwnerId")
                        
                        # Parse tags
                        tags = self.parse_tags(rt.get("Tags", []))
                        name = tags.get("Name", rt_id)
                        
                        route_tables.append(
                            RouteTable(
                                resource_id=rt_id,
                                region=region,
                                arn=arn,
                                name=name,
                                tags=tags,
                                vpc_id=vpc_id,
                                routes=routes,
                                associations=associations,
                                propagating_vgws=propagating_vgws,
                                owner_id=owner_id
                            )
                        )
                    except Exception as e:
                        logger.error(f"Error processing Route Table {rt.get('RouteTableId', 'unknown')}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_route_tables", region)
        except Exception as e:
            logger.error(f"Error scanning Route Tables in {region}: {str(e)}")
            if logger.level <= logging.DEBUG:
                logger.exception(e)
                
        return route_tables


class NetworkACLScanner(BaseScanner[NetworkACL]):
    """Scanner for Network ACL resources."""

    service_name = "ec2"
    resource_type = "Network ACLs"
    resource_model = NetworkACL

    def scan_region(self, region: str, client: boto3.client) -> List[NetworkACL]:
        """Scan a region for Network ACL resources.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of Network ACL resources
        """
        network_acls = []
        
        try:
            # Describe Network ACLs
            paginator = client.get_paginator("describe_network_acls")
            
            for page in paginator.paginate():
                for nacl in page.get("NetworkAcls", []):
                    try:
                        nacl_id = nacl.get("NetworkAclId")
                        if not nacl_id:
                            continue
                            
                        # Get Network ACL ARN
                        arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:network-acl/{nacl_id}"
                        
                        # Parse Network ACL attributes
                        vpc_id = nacl.get("VpcId", "")
                        is_default = nacl.get("IsDefault", False)
                        entries = nacl.get("Entries", [])
                        associations = nacl.get("Associations", [])
                        owner_id = nacl.get("OwnerId")
                        
                        # Parse tags
                        tags = self.parse_tags(nacl.get("Tags", []))
                        name = tags.get("Name", nacl_id)
                        
                        network_acls.append(
                            NetworkACL(
                                resource_id=nacl_id,
                                region=region,
                                arn=arn,
                                name=name,
                                tags=tags,
                                vpc_id=vpc_id,
                                is_default=is_default,
                                entries=entries,
                                associations=associations,
                                owner_id=owner_id
                            )
                        )
                    except Exception as e:
                        logger.error(f"Error processing Network ACL {nacl.get('NetworkAclId', 'unknown')}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_network_acls", region)
        except Exception as e:
            logger.error(f"Error scanning Network ACLs in {region}: {str(e)}")
            if logger.level <= logging.DEBUG:
                logger.exception(e)
                
        return network_acls


class VPCEndpointScanner(BaseScanner[VPCEndpoint]):
    """Scanner for VPC Endpoint resources."""

    service_name = "ec2"
    resource_type = "VPC Endpoints"
    resource_model = VPCEndpoint

    def scan_region(self, region: str, client: boto3.client) -> List[VPCEndpoint]:
        """Scan a region for VPC Endpoint resources.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of VPC Endpoint resources
        """
        vpc_endpoints = []
        
        try:
            # Describe VPC Endpoints
            paginator = client.get_paginator("describe_vpc_endpoints")
            
            for page in paginator.paginate():
                for endpoint in page.get("VpcEndpoints", []):
                    try:
                        endpoint_id = endpoint.get("VpcEndpointId")
                        if not endpoint_id:
                            continue
                            
                        # Get VPC Endpoint ARN
                        arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:vpc-endpoint/{endpoint_id}"
                        
                        # Parse VPC Endpoint attributes
                        vpc_id = endpoint.get("VpcId", "")
                        service_name = endpoint.get("ServiceName", "")
                        state = endpoint.get("State", "unknown")
                        vpc_endpoint_type = endpoint.get("VpcEndpointType", "Gateway")
                        policy_document = endpoint.get("PolicyDocument")
                        subnet_ids = endpoint.get("SubnetIds", [])
                        network_interface_ids = endpoint.get("NetworkInterfaceIds", [])
                        dns_entries = endpoint.get("DnsEntries", [])
                        groups = endpoint.get("Groups", [])
                        private_dns_enabled = endpoint.get("PrivateDnsEnabled", False)
                        requester_managed = endpoint.get("RequesterManaged", False)
                        
                        # Handle created_at as a datetime object
                        created_at = endpoint.get("CreationTimestamp")
                        
                        route_table_ids = endpoint.get("RouteTableIds", [])
                        
                        # Parse tags
                        tags = self.parse_tags(endpoint.get("Tags", []))
                        name = tags.get("Name", endpoint_id)
                        
                        vpc_endpoints.append(
                            VPCEndpoint(
                                resource_id=endpoint_id,
                                region=region,
                                arn=arn,
                                name=name,
                                tags=tags,
                                vpc_id=vpc_id,
                                service_name=service_name,
                                state=state,
                                vpc_endpoint_type=vpc_endpoint_type,
                                policy_document=policy_document,
                                subnet_ids=subnet_ids,
                                network_interface_ids=network_interface_ids,
                                dns_entries=dns_entries,
                                groups=groups,
                                private_dns_enabled=private_dns_enabled,
                                requester_managed=requester_managed,
                                created_at=created_at,
                                route_table_ids=route_table_ids
                            )
                        )
                    except Exception as e:
                        logger.error(f"Error processing VPC Endpoint {endpoint.get('VpcEndpointId', 'unknown')}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_vpc_endpoints", region)
        except Exception as e:
            logger.error(f"Error scanning VPC Endpoints in {region}: {str(e)}")
            if logger.level <= logging.DEBUG:
                logger.exception(e)
                
        return vpc_endpoints


class VPCPeeringConnectionScanner(BaseScanner[VPCPeeringConnection]):
    """Scanner for VPC Peering Connection resources."""

    service_name = "ec2"
    resource_type = "VPC Peering Connections"
    resource_model = VPCPeeringConnection

    def scan_region(self, region: str, client: boto3.client) -> List[VPCPeeringConnection]:
        """Scan a region for VPC Peering Connection resources.

        Args:
            region: AWS region to scan
            client: Boto3 EC2 client for the region

        Returns:
            List of VPC Peering Connection resources
        """
        vpc_peering_connections = []
        
        try:
            # Describe VPC Peering Connections
            paginator = client.get_paginator("describe_vpc_peering_connections")
            
            for page in paginator.paginate():
                for peering in page.get("VpcPeeringConnections", []):
                    try:
                        peering_id = peering.get("VpcPeeringConnectionId")
                        if not peering_id:
                            continue
                            
                        # Get VPC Peering Connection ARN
                        arn = f"arn:aws:ec2:{region}:{client.meta.config.user_agent.split('/')[1].split(' ')[0]}:vpc-peering-connection/{peering_id}"
                        
                        # Parse VPC Peering Connection attributes
                        requester = peering.get("RequesterVpcInfo", {})
                        accepter = peering.get("AccepterVpcInfo", {})
                        
                        vpc_id = requester.get("VpcId", "")  # Requester VPC ID
                        peer_vpc_id = accepter.get("VpcId", "")  # Accepter VPC ID
                        peer_owner_id = accepter.get("OwnerId")
                        peer_region = accepter.get("Region")
                        
                        status = peering.get("Status", {})
                        
                        # Handle expiration_time as a datetime object
                        expiration_time = peering.get("ExpirationTime")
                        
                        # Get CIDR blocks
                        cidr_blocks = [block.get("CidrBlock") for block in requester.get("CidrBlockSet", []) if "CidrBlock" in block]
                        peer_cidr_blocks = [block.get("CidrBlock") for block in accepter.get("CidrBlockSet", []) if "CidrBlock" in block]
                        
                        # Parse tags
                        tags = self.parse_tags(peering.get("Tags", []))
                        name = tags.get("Name", peering_id)
                        
                        vpc_peering_connections.append(
                            VPCPeeringConnection(
                                resource_id=peering_id,
                                region=region,
                                arn=arn,
                                name=name,
                                tags=tags,
                                vpc_id=vpc_id,
                                peer_vpc_id=peer_vpc_id,
                                peer_owner_id=peer_owner_id,
                                peer_region=peer_region,
                                status=status,
                                cidr_blocks=cidr_blocks,
                                peer_cidr_blocks=peer_cidr_blocks,
                                expiration_time=expiration_time
                            )
                        )
                    except Exception as e:
                        logger.error(f"Error processing VPC Peering Connection {peering.get('VpcPeeringConnectionId', 'unknown')}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)
            
        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_vpc_peering_connections", region)
        except Exception as e:
            logger.error(f"Error scanning VPC Peering Connections in {region}: {str(e)}")
            if logger.level <= logging.DEBUG:
                logger.exception(e)
                
        return vpc_peering_connections 