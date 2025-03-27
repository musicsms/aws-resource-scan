"""RDS resource scanner.

This module provides scanners for RDS instances and clusters.
"""
import logging
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from aws_resource_scanner.models import RDSInstance, RDSCluster
from aws_resource_scanner.scanners.base import BaseScanner
from aws_resource_scanner.utils.logger import log_aws_error, logger


class RDSInstanceScanner(BaseScanner[RDSInstance]):
    """Scanner for RDS instances."""

    service_name = "rds"
    resource_type = "RDS Instances"
    resource_model = RDSInstance

    def scan_region(self, region: str, client: boto3.client) -> List[RDSInstance]:
        """Scan a region for RDS instances.

        Args:
            region: AWS region to scan
            client: Boto3 RDS client for the region

        Returns:
            List of RDSInstance resources
        """
        instances = []
        
        try:
            paginator = client.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for instance in page.get("DBInstances", []):
                    try:
                        instance_id = instance.get("DBInstanceIdentifier")
                        if not instance_id:
                            continue

                        # Extract instance details
                        arn = instance.get("DBInstanceArn")
                        engine = instance.get("Engine")
                        engine_version = instance.get("EngineVersion")
                        instance_class = instance.get("DBInstanceClass")
                        status = instance.get("DBInstanceStatus")
                        storage_type = instance.get("StorageType")
                        allocated_storage = instance.get("AllocatedStorage", 0)

                        # Security settings
                        publicly_accessible = instance.get("PubliclyAccessible", False)
                        storage_encrypted = instance.get("StorageEncrypted", False)
                        kms_key_id = instance.get("KmsKeyId")
                        ca_certificate = instance.get("CACertificateIdentifier")
                        
                        # Security groups
                        security_groups = []
                        vpc_security_groups = []
                        for sg in instance.get("DBSecurityGroups", []):
                            if sg.get("DBSecurityGroupName"):
                                security_groups.append(sg["DBSecurityGroupName"])
                        
                        for vpc_sg in instance.get("VpcSecurityGroups", []):
                            if vpc_sg.get("VpcSecurityGroupId"):
                                vpc_security_groups.append({
                                    "id": vpc_sg["VpcSecurityGroupId"],
                                    "status": vpc_sg.get("Status", "unknown")
                                })

                        # Network settings
                        endpoint = instance.get("Endpoint", {})
                        vpc_id = instance.get("DBSubnetGroup", {}).get("VpcId")
                        subnet_group = instance.get("DBSubnetGroup", {}).get("DBSubnetGroupName")
                        availability_zone = instance.get("AvailabilityZone")
                        multi_az = instance.get("MultiAZ", False)

                        # Performance and monitoring
                        perf_insights = instance.get("PerformanceInsightsEnabled", False)
                        perf_insights_kms = instance.get("PerformanceInsightsKMSKeyId")
                        enhanced_monitoring = instance.get("EnhancedMonitoringResourceArn")
                        monitoring_interval = instance.get("MonitoringInterval", 0)

                        # Backup and maintenance
                        backup_retention = instance.get("BackupRetentionPeriod", 0)
                        backup_window = instance.get("PreferredBackupWindow")
                        maintenance_window = instance.get("PreferredMaintenanceWindow")
                        latest_restorable = instance.get("LatestRestorableTime")

                        # Cluster information
                        cluster_id = instance.get("DBClusterIdentifier")
                        is_writer = None
                        if cluster_id:
                            # For Aurora instances, determine if this is the writer instance
                            is_writer = instance.get("PromotionTier", 1) == 1

                        # Get tags
                        try:
                            if arn:
                                tags_response = client.list_tags_for_resource(ResourceName=arn)
                                tags = {
                                    tag["Key"]: tag["Value"]
                                    for tag in tags_response.get("TagList", [])
                                    if tag.get("Key")
                                }
                        except ClientError as e:
                            log_aws_error(e, self.service_name, "list_tags_for_resource", instance_id)
                            tags = {}

                        # Create resource model
                        instances.append(
                            RDSInstance(
                                resource_id=instance_id,
                                region=region,
                                arn=arn,
                                name=instance_id,
                                engine=engine,
                                engine_version=engine_version,
                                instance_class=instance_class,
                                status=status,
                                storage_type=storage_type,
                                allocated_storage=allocated_storage,
                                publicly_accessible=publicly_accessible,
                                storage_encrypted=storage_encrypted,
                                kms_key_id=kms_key_id,
                                ca_certificate_identifier=ca_certificate,
                                security_groups=security_groups,
                                vpc_security_groups=vpc_security_groups,
                                endpoint=endpoint,
                                vpc_id=vpc_id,
                                subnet_group=subnet_group,
                                availability_zone=availability_zone,
                                multi_az=multi_az,
                                performance_insights_enabled=perf_insights,
                                performance_insights_kms_key_id=perf_insights_kms,
                                enhanced_monitoring_arn=enhanced_monitoring,
                                monitoring_interval=monitoring_interval,
                                backup_retention_period=backup_retention,
                                backup_window=backup_window,
                                maintenance_window=maintenance_window,
                                latest_restorable_time=latest_restorable,
                                cluster_identifier=cluster_id,
                                is_cluster_writer=is_writer,
                                tags=tags,
                            )
                        )

                    except Exception as e:
                        instance_id = instance.get("DBInstanceIdentifier", "unknown")
                        logger.error(f"Error processing RDS instance '{instance_id}' in {region}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)

        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_db_instances", region)

        return instances


class RDSClusterScanner(BaseScanner[RDSCluster]):
    """Scanner for RDS clusters (Aurora)."""

    service_name = "rds"
    resource_type = "RDS Clusters"
    resource_model = RDSCluster

    def scan_region(self, region: str, client: boto3.client) -> List[RDSCluster]:
        """Scan a region for RDS clusters.

        Args:
            region: AWS region to scan
            client: Boto3 RDS client for the region

        Returns:
            List of RDSCluster resources
        """
        clusters = []
        
        try:
            paginator = client.get_paginator("describe_db_clusters")
            for page in paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    try:
                        cluster_id = cluster.get("DBClusterIdentifier")
                        if not cluster_id:
                            continue

                        # Extract cluster details
                        arn = cluster.get("DBClusterArn")
                        engine = cluster.get("Engine")
                        engine_version = cluster.get("EngineVersion")
                        status = cluster.get("Status")

                        # Security settings
                        storage_encrypted = cluster.get("StorageEncrypted", False)
                        kms_key_id = cluster.get("KmsKeyId")
                        iam_auth = cluster.get("IAMDatabaseAuthenticationEnabled", False)
                        deletion_protection = cluster.get("DeletionProtection", False)
                        publicly_accessible = False  # Determined by instance configuration

                        # Security groups
                        security_groups = []
                        vpc_security_groups = []
                        for sg in cluster.get("DBSecurityGroups", []):
                            if sg.get("DBSecurityGroupName"):
                                security_groups.append(sg["DBSecurityGroupName"])
                        
                        for vpc_sg in cluster.get("VpcSecurityGroups", []):
                            if vpc_sg.get("VpcSecurityGroupId"):
                                vpc_security_groups.append({
                                    "id": vpc_sg["VpcSecurityGroupId"],
                                    "status": vpc_sg.get("Status", "unknown")
                                })

                        # Network settings
                        endpoint = cluster.get("Endpoint")
                        reader_endpoint = cluster.get("ReaderEndpoint")
                        port = cluster.get("Port")
                        vpc_id = cluster.get("DBSubnetGroup")
                        subnet_group = cluster.get("DBSubnetGroup")
                        availability_zones = cluster.get("AvailabilityZones", [])
                        multi_az = len(availability_zones) > 1

                        # Backup and maintenance
                        backup_retention = cluster.get("BackupRetentionPeriod", 0)
                        backup_window = cluster.get("PreferredBackupWindow")
                        maintenance_window = cluster.get("PreferredMaintenanceWindow")
                        latest_restorable = cluster.get("EarliestRestorableTime")

                        # Cluster members
                        members = []
                        reader_instances = []
                        writer_instance = None
                        
                        for member in cluster.get("DBClusterMembers", []):
                            instance_arn = member.get("DBInstanceIdentifier")
                            if instance_arn:
                                members.append(instance_arn)
                                if member.get("IsClusterWriter", False):
                                    writer_instance = instance_arn
                                else:
                                    reader_instances.append(instance_arn)

                        # Get tags
                        try:
                            if arn:
                                tags_response = client.list_tags_for_resource(ResourceName=arn)
                                tags = {
                                    tag["Key"]: tag["Value"]
                                    for tag in tags_response.get("TagList", [])
                                    if tag.get("Key")
                                }
                        except ClientError as e:
                            log_aws_error(e, self.service_name, "list_tags_for_resource", cluster_id)
                            tags = {}

                        # Create resource model
                        clusters.append(
                            RDSCluster(
                                resource_id=cluster_id,
                                region=region,
                                arn=arn,
                                name=cluster_id,
                                engine=engine,
                                engine_version=engine_version,
                                status=status,
                                storage_encrypted=storage_encrypted,
                                kms_key_id=kms_key_id,
                                iam_database_authentication_enabled=iam_auth,
                                deletion_protection=deletion_protection,
                                publicly_accessible=publicly_accessible,
                                security_groups=security_groups,
                                vpc_security_groups=vpc_security_groups,
                                endpoint=endpoint,
                                reader_endpoint=reader_endpoint,
                                port=port,
                                vpc_id=vpc_id,
                                subnet_group=subnet_group,
                                availability_zones=availability_zones,
                                multi_az=multi_az,
                                backup_retention_period=backup_retention,
                                preferred_backup_window=backup_window,
                                preferred_maintenance_window=maintenance_window,
                                latest_restorable_time=latest_restorable,
                                members=members,
                                reader_instances=reader_instances,
                                writer_instance=writer_instance,
                                tags=tags,
                            )
                        )

                    except Exception as e:
                        cluster_id = cluster.get("DBClusterIdentifier", "unknown")
                        logger.error(f"Error processing RDS cluster '{cluster_id}' in {region}: {str(e)}")
                        if logger.level <= logging.DEBUG:
                            logger.exception(e)

        except ClientError as e:
            log_aws_error(e, self.service_name, "describe_db_clusters", region)

        return clusters 