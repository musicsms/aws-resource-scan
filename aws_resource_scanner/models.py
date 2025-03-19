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


class EC2Instance(AWSResource):
    """EC2 instance resource model."""

    resource_type: str = "ec2_instance"
    instance_type: str
    state: str
    private_ip_address: Optional[str] = None
    public_ip_address: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    launch_time: Optional[datetime] = None
    security_group_ids: List[str] = Field(default_factory=list)
    iam_instance_profile: Optional[str] = None
    key_name: Optional[str] = None


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

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat()
        } 