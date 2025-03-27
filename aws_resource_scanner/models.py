"""Data models for AWS resources.

This module defines Pydantic models for various AWS resources.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field


class AWSResource(BaseModel):
    """Base model for all AWS resources."""

    resource_id: str
    region: str
    resource_type: str
    arn: Optional[str] = None
    name: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)


class NetworkInterface(BaseModel):
    """EC2 Network Interface model."""
    
    network_interface_id: str
    subnet_id: str
    vpc_id: str
    description: Optional[str] = None
    status: str  # "available", "in-use", etc.
    primary: bool = False
    private_ip_addresses: List[Dict[str, Any]] = Field(default_factory=list)
    # This would include both private_ip and any associated public_ip
    security_group_ids: List[str] = Field(default_factory=list)
    attachment: Optional[Dict[str, Any]] = None


class EC2Instance(AWSResource):
    """EC2 instance resource model."""

    resource_type: str = "ec2_instance"
    instance_type: str
    state: str
    # Keep these for backward compatibility and primary interface
    private_ip_address: Optional[str] = None
    public_ip_address: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    # Add support for multiple interfaces
    network_interfaces: List[NetworkInterface] = Field(default_factory=list)
    launch_time: Optional[datetime] = None
    security_group_ids: List[str] = Field(default_factory=list)
    iam_instance_profile: Optional[str] = None
    key_name: Optional[str] = None
    # AMI information
    ami_id: Optional[str] = None
    ami_name: Optional[str] = None
    platform_details: Optional[str] = None
    architecture: Optional[str] = None


class SecurityGroup(AWSResource):
    """Security Group resource model."""

    resource_type: str = "security_group"
    vpc_id: Optional[str] = None
    description: Optional[str] = None
    inbound_rules: List[Dict[str, Any]] = Field(default_factory=list)
    outbound_rules: List[Dict[str, Any]] = Field(default_factory=list)
    

class EKSCluster(AWSResource):
    """EKS Cluster resource model."""

    resource_type: str = "eks_cluster"
    status: str
    endpoint: Optional[str] = None
    kubernetes_version: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_ids: List[str] = Field(default_factory=list)
    security_group_ids: List[str] = Field(default_factory=list)
    role_arn: Optional[str] = None
    created_at: Optional[datetime] = None
    endpoint_public_access: bool = False
    endpoint_private_access: bool = False


class NodeGroup(AWSResource):
    """EKS Node Group resource model."""

    resource_type: str = "node_group"
    cluster_name: str
    status: str
    instance_types: List[str] = Field(default_factory=list)
    capacity_type: Optional[str] = None  # ON_DEMAND or SPOT
    disk_size: Optional[int] = None
    scaling_config: Dict[str, int] = Field(default_factory=dict)


class LoadBalancer(AWSResource):
    """Load Balancer resource model."""

    resource_type: str = "load_balancer"
    lb_type: str  # "application" or "network"
    scheme: Optional[str] = None
    vpc_id: Optional[str] = None
    dns_name: Optional[str] = None
    state: Optional[str] = None
    security_groups: List[str] = Field(default_factory=list)
    availability_zones: List[str] = Field(default_factory=list)
    listeners: List[Dict[str, Any]] = Field(default_factory=list)
    target_groups: List[Dict[str, Any]] = Field(default_factory=list)
    # Enhanced target group details
    target_health: List[Dict[str, Any]] = Field(default_factory=list)
    routing_rules: List[Dict[str, Any]] = Field(default_factory=list)


class S3Bucket(AWSResource):
    """S3 Bucket resource model."""

    resource_type: str = "s3_bucket"
    creation_date: Optional[datetime] = None
    versioning_enabled: bool = False
    public_access_blocked: bool = True
    encryption_enabled: bool = False
    logging_enabled: bool = False


class LambdaFunction(AWSResource):
    """Lambda Function resource model."""

    resource_type: str = "lambda_function"
    runtime: str
    handler: str
    code_size: int
    timeout: int
    memory_size: int
    last_modified: Optional[datetime] = None
    role: str
    vpc_config: Optional[Dict[str, Any]] = None
    environment_variables: Dict[str, str] = Field(default_factory=dict)


class AutoScalingGroup(AWSResource):
    """Auto Scaling Group resource model."""

    resource_type: str = "auto_scaling_group"
    min_size: int
    max_size: int
    desired_capacity: int
    launch_template_id: Optional[str] = None
    launch_template_version: Optional[str] = None
    launch_configuration_name: Optional[str] = None
    availability_zones: List[str] = Field(default_factory=list)
    vpc_zone_identifier: Optional[str] = None
    instance_ids: List[str] = Field(default_factory=list)
    load_balancer_names: List[str] = Field(default_factory=list)
    target_group_arns: List[str] = Field(default_factory=list)


class VPC(AWSResource):
    """VPC resource model."""

    resource_type: str = "vpc"
    cidr_block: str
    is_default: bool = False
    state: str
    dhcp_options_id: Optional[str] = None
    instance_tenancy: Optional[str] = None
    enable_dns_support: bool = True
    enable_dns_hostnames: bool = False
    owner_id: Optional[str] = None


class Subnet(AWSResource):
    """Subnet resource model."""

    resource_type: str = "subnet"
    vpc_id: str
    cidr_block: str
    availability_zone: str
    available_ip_address_count: int
    default_for_az: bool = False
    map_public_ip_on_launch: bool = False
    state: str
    owner_id: Optional[str] = None


class InternetGateway(AWSResource):
    """Internet Gateway resource model."""

    resource_type: str = "internet_gateway"
    vpc_id: Optional[str] = None
    state: Optional[str] = None
    owner_id: Optional[str] = None


class NatGateway(AWSResource):
    """NAT Gateway resource model."""

    resource_type: str = "nat_gateway"
    vpc_id: str
    subnet_id: str
    state: str
    connectivity_type: str  # "public" or "private"
    elastic_ip_address: Optional[str] = None
    private_ip_address: Optional[str] = None
    network_interface_id: Optional[str] = None
    create_time: Optional[datetime] = None


class RouteTable(AWSResource):
    """Route Table resource model."""

    resource_type: str = "route_table"
    vpc_id: str
    routes: List[Dict[str, Any]] = Field(default_factory=list)
    associations: List[Dict[str, Any]] = Field(default_factory=list)
    propagating_vgws: List[Dict[str, Any]] = Field(default_factory=list)
    owner_id: Optional[str] = None


class NetworkACL(AWSResource):
    """Network ACL resource model."""

    resource_type: str = "network_acl"
    vpc_id: str
    is_default: bool = False
    entries: List[Dict[str, Any]] = Field(default_factory=list)
    associations: List[Dict[str, Any]] = Field(default_factory=list)
    owner_id: Optional[str] = None


class VPCEndpoint(AWSResource):
    """VPC Endpoint resource model."""

    resource_type: str = "vpc_endpoint"
    vpc_id: str
    service_name: str
    state: str
    vpc_endpoint_type: str  # "Interface", "Gateway", or "GatewayLoadBalancer"
    policy_document: Optional[str] = None
    subnet_ids: List[str] = Field(default_factory=list)
    network_interface_ids: List[str] = Field(default_factory=list)
    dns_entries: List[Dict[str, str]] = Field(default_factory=list)
    groups: List[Dict[str, str]] = Field(default_factory=list)
    private_dns_enabled: bool = False
    requester_managed: bool = False
    created_at: Optional[datetime] = None
    route_table_ids: List[str] = Field(default_factory=list)


class VPCPeeringConnection(AWSResource):
    """VPC Peering Connection resource model."""

    resource_type: str = "vpc_peering_connection"
    vpc_id: str  # Requester VPC ID
    peer_vpc_id: str  # Accepter VPC ID
    peer_owner_id: Optional[str] = None
    peer_region: Optional[str] = None
    status: Dict[str, str] = Field(default_factory=dict)
    cidr_blocks: List[str] = Field(default_factory=list)
    peer_cidr_blocks: List[str] = Field(default_factory=list)
    expiration_time: Optional[datetime] = None


class RDSInstance(AWSResource):
    """RDS Instance resource model."""

    resource_type: str = "rds_instance"
    engine: str
    engine_version: str
    instance_class: str
    status: str
    storage_type: str
    allocated_storage: int
    # Security
    publicly_accessible: bool = False
    storage_encrypted: bool = False
    kms_key_id: Optional[str] = None
    ca_certificate_identifier: Optional[str] = None
    security_groups: List[str] = Field(default_factory=list)
    vpc_security_groups: List[Dict[str, str]] = Field(default_factory=list)
    # Network
    endpoint: Optional[Dict[str, Any]] = None
    vpc_id: Optional[str] = None
    subnet_group: Optional[str] = None
    availability_zone: Optional[str] = None
    multi_az: bool = False
    # Performance and monitoring
    performance_insights_enabled: bool = False
    performance_insights_kms_key_id: Optional[str] = None
    enhanced_monitoring_arn: Optional[str] = None
    monitoring_interval: int = 0
    # Backup and maintenance
    backup_retention_period: int = 0
    backup_window: Optional[str] = None
    maintenance_window: Optional[str] = None
    latest_restorable_time: Optional[datetime] = None
    # Cluster info (if part of Aurora cluster)
    cluster_identifier: Optional[str] = None
    is_cluster_writer: Optional[bool] = None


class RDSCluster(AWSResource):
    """RDS Cluster resource model (for Aurora)."""

    resource_type: str = "rds_cluster"
    engine: str
    engine_version: str
    status: str
    # Security
    storage_encrypted: bool = False
    kms_key_id: Optional[str] = None
    iam_database_authentication_enabled: bool = False
    deletion_protection: bool = False
    publicly_accessible: bool = False
    security_groups: List[str] = Field(default_factory=list)
    vpc_security_groups: List[Dict[str, str]] = Field(default_factory=list)
    # Network
    endpoint: Optional[str] = None
    reader_endpoint: Optional[str] = None
    port: Optional[int] = None
    vpc_id: Optional[str] = None
    subnet_group: Optional[str] = None
    availability_zones: List[str] = Field(default_factory=list)
    multi_az: bool = False
    # Backup and maintenance
    backup_retention_period: int = 0
    preferred_backup_window: Optional[str] = None
    preferred_maintenance_window: Optional[str] = None
    latest_restorable_time: Optional[datetime] = None
    # Cluster members
    members: List[str] = Field(default_factory=list)  # List of instance ARNs
    reader_instances: List[str] = Field(default_factory=list)
    writer_instance: Optional[str] = None


class ScanResult(BaseModel):
    """Results of an AWS resource scan."""

    timestamp: datetime = Field(default_factory=datetime.now)
    regions: List[str]
    ec2_instances: List[EC2Instance] = Field(default_factory=list)
    security_groups: List[SecurityGroup] = Field(default_factory=list)
    eks_clusters: List[EKSCluster] = Field(default_factory=list)
    node_groups: List[NodeGroup] = Field(default_factory=list)
    load_balancers: List[LoadBalancer] = Field(default_factory=list)
    s3_buckets: List[S3Bucket] = Field(default_factory=list)
    lambda_functions: List[LambdaFunction] = Field(default_factory=list)
    auto_scaling_groups: List[AutoScalingGroup] = Field(default_factory=list)
    vpcs: List[VPC] = Field(default_factory=list)
    subnets: List[Subnet] = Field(default_factory=list)
    internet_gateways: List[InternetGateway] = Field(default_factory=list)
    nat_gateways: List[NatGateway] = Field(default_factory=list)
    route_tables: List[RouteTable] = Field(default_factory=list)
    network_acls: List[NetworkACL] = Field(default_factory=list)
    vpc_endpoints: List[VPCEndpoint] = Field(default_factory=list)
    vpc_peering_connections: List[VPCPeeringConnection] = Field(default_factory=list)
    rds_instances: List[RDSInstance] = Field(default_factory=list)
    rds_clusters: List[RDSCluster] = Field(default_factory=list)

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat()
        } 