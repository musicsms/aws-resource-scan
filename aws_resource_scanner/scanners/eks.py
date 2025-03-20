"""EKS resource scanner.

This module provides scanners for EKS clusters and node groups.
"""
import logging
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import EKSCluster, NodeGroup
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class EKSClusterScanner(BaseScanner[EKSCluster]):
    """Scanner for EKS Clusters."""

    service_name = "eks"
    resource_type = "EKS Clusters"
    resource_model = EKSCluster

    def scan_region(self, region: str, client: boto3.client) -> List[EKSCluster]:
        """Scan a region for EKS clusters.

        Args:
            region: AWS region to scan
            client: Boto3 EKS client for the region

        Returns:
            List of EKSCluster resources
        """
        clusters = []
        
        try:
            # List all clusters in the region
            paginator = client.get_paginator("list_clusters")
            cluster_names = []
            
            for page in paginator.paginate():
                cluster_names.extend(page.get("clusters", []))
            
            # Get details for each cluster
            for cluster_name in cluster_names:
                try:
                    response = client.describe_cluster(name=cluster_name)
                    cluster = response.get("cluster", {})
                    
                    if not cluster:
                        continue
                    
                    # Extract cluster details
                    cluster_arn = cluster.get("arn")
                    status = cluster.get("status")
                    endpoint = cluster.get("endpoint")
                    k8s_version = cluster.get("version")
                    role_arn = cluster.get("roleArn")
                    created_at = cluster.get("createdAt")
                    
                    # Extract VPC configuration
                    vpc_config = cluster.get("resourcesVpcConfig", {})
                    vpc_id = vpc_config.get("vpcId")
                    subnet_ids = vpc_config.get("subnetIds", [])
                    security_group_ids = vpc_config.get("securityGroupIds", [])
                    
                    # Extract endpoint access configuration
                    endpoint_public_access = vpc_config.get("endpointPublicAccess", False)
                    endpoint_private_access = vpc_config.get("endpointPrivateAccess", False)
                    
                    # Parse tags
                    tags = cluster.get("tags", {})
                    
                    clusters.append(
                        EKSCluster(
                            resource_id=cluster_name,
                            region=region,
                            arn=cluster_arn,
                            name=cluster_name,
                            status=status,
                            endpoint=endpoint,
                            kubernetes_version=k8s_version,
                            vpc_id=vpc_id,
                            subnet_ids=subnet_ids,
                            security_group_ids=security_group_ids,
                            role_arn=role_arn,
                            created_at=created_at,
                            tags=tags,
                            endpoint_public_access=endpoint_public_access,
                            endpoint_private_access=endpoint_private_access,
                        )
                    )
                    
                except ClientError as e:
                    log_aws_error(e, self.service_name, "describe_cluster", cluster_name)
                    
                except Exception as e:
                    logger.error(f"Error processing EKS cluster '{cluster_name}' in {region}: {str(e)}")
                    if logger.level <= logging.DEBUG:
                        logger.exception(e)
                    
        except ClientError as e:
            log_aws_error(e, self.service_name, "list_clusters", region)
            
        return clusters


class NodeGroupScanner(BaseScanner[NodeGroup]):
    """Scanner for EKS Node Groups."""

    service_name = "eks"
    resource_type = "EKS Node Groups"
    resource_model = NodeGroup

    def scan_region(self, region: str, client: boto3.client) -> List[NodeGroup]:
        """Scan a region for EKS node groups.

        Args:
            region: AWS region to scan
            client: Boto3 EKS client for the region

        Returns:
            List of NodeGroup resources
        """
        node_groups = []
        
        try:
            # List all clusters in the region
            paginator = client.get_paginator("list_clusters")
            cluster_names = []
            
            for page in paginator.paginate():
                cluster_names.extend(page.get("clusters", []))
            
            # For each cluster, list and describe node groups
            for cluster_name in cluster_names:
                try:
                    ng_paginator = client.get_paginator("list_nodegroups")
                    node_group_names = []
                    
                    for page in ng_paginator.paginate(clusterName=cluster_name):
                        node_group_names.extend(page.get("nodegroups", []))
                    
                    # Get details for each node group
                    for ng_name in node_group_names:
                        try:
                            response = client.describe_nodegroup(
                                clusterName=cluster_name, nodegroupName=ng_name
                            )
                            ng = response.get("nodegroup", {})
                            
                            if not ng:
                                continue
                            
                            # Extract node group details
                            ng_arn = ng.get("nodegroupArn")
                            status = ng.get("status")
                            instance_types = ng.get("instanceTypes", [])
                            capacity_type = ng.get("capacityType")
                            disk_size = ng.get("diskSize")
                            
                            # Extract scaling config
                            scaling_config = {}
                            sc = ng.get("scalingConfig", {})
                            scaling_config["min_size"] = sc.get("minSize", 0)
                            scaling_config["max_size"] = sc.get("maxSize", 0)
                            scaling_config["desired_size"] = sc.get("desiredSize", 0)
                            
                            # Parse tags
                            tags = ng.get("tags", {})
                            
                            node_groups.append(
                                NodeGroup(
                                    resource_id=ng_name,
                                    region=region,
                                    arn=ng_arn,
                                    name=ng_name,
                                    cluster_name=cluster_name,
                                    status=status,
                                    instance_types=instance_types,
                                    capacity_type=capacity_type,
                                    disk_size=disk_size,
                                    scaling_config=scaling_config,
                                    tags=tags,
                                )
                            )
                            
                        except ClientError as e:
                            log_aws_error(e, self.service_name, "describe_nodegroup", f"{cluster_name}/{ng_name}")
                            
                        except Exception as e:
                            logger.error(f"Error processing node group '{ng_name}' in cluster '{cluster_name}' in {region}: {str(e)}")
                            if logger.level <= logging.DEBUG:
                                logger.exception(e)
                                
                except ClientError as e:
                    log_aws_error(e, self.service_name, "list_nodegroups", cluster_name)
                    
        except ClientError as e:
            log_aws_error(e, self.service_name, "list_clusters", region)
            
        return node_groups 