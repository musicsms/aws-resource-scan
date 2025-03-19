"""Tests for AWS Resource Scanner data models."""
import pytest
from datetime import datetime

from aws_resource_scanner.models import (
    AWSResource,
    EC2Instance,
    SecurityGroup,
    S3Bucket,
    LambdaFunction,
    ScanResult,
)


def test_aws_resource_base():
    """Test the base AWSResource model."""
    resource = AWSResource(
        resource_id="test-id",
        region="us-east-1",
        resource_type="test-type",
        arn="arn:aws:test:us-east-1:123456789012:test/test-id",
        name="Test Resource",
        tags={"Environment": "Test", "Owner": "UnitTest"},
    )
    
    assert resource.resource_id == "test-id"
    assert resource.region == "us-east-1"
    assert resource.resource_type == "test-type"
    assert resource.arn == "arn:aws:test:us-east-1:123456789012:test/test-id"
    assert resource.name == "Test Resource"
    assert resource.tags == {"Environment": "Test", "Owner": "UnitTest"}


def test_ec2_instance():
    """Test the EC2Instance model."""
    instance = EC2Instance(
        resource_id="i-1234567890abcdef0",
        region="us-east-1",
        name="Test Instance",
        instance_type="t2.micro",
        state="running",
        private_ip_address="10.0.0.1",
        public_ip_address="54.123.456.789",
        vpc_id="vpc-12345678",
        subnet_id="subnet-12345678",
        launch_time=datetime(2023, 1, 1, 12, 0, 0),
        security_group_ids=["sg-12345678"],
    )
    
    assert instance.resource_id == "i-1234567890abcdef0"
    assert instance.resource_type == "ec2_instance"
    assert instance.instance_type == "t2.micro"
    assert instance.state == "running"
    assert instance.private_ip_address == "10.0.0.1"
    assert instance.public_ip_address == "54.123.456.789"
    assert instance.vpc_id == "vpc-12345678"
    assert instance.subnet_id == "subnet-12345678"
    assert instance.launch_time == datetime(2023, 1, 1, 12, 0, 0)
    assert instance.security_group_ids == ["sg-12345678"]


def test_scan_result():
    """Test the ScanResult model."""
    # Create a simple EC2 instance
    instance = EC2Instance(
        resource_id="i-1234567890abcdef0",
        region="us-east-1",
        name="Test Instance",
        instance_type="t2.micro",
        state="running",
    )
    
    # Create a simple S3 bucket
    bucket = S3Bucket(
        resource_id="test-bucket",
        region="us-east-1",
        name="test-bucket",
    )
    
    # Create a scan result with these resources
    result = ScanResult(
        regions=["us-east-1"],
        ec2_instances=[instance],
        s3_buckets=[bucket],
    )
    
    # Test that the resources were properly added
    assert len(result.regions) == 1
    assert result.regions[0] == "us-east-1"
    assert len(result.ec2_instances) == 1
    assert result.ec2_instances[0].resource_id == "i-1234567890abcdef0"
    assert len(result.s3_buckets) == 1
    assert result.s3_buckets[0].resource_id == "test-bucket"
    
    # Test empty lists for resources we didn't add
    assert len(result.security_groups) == 0
    assert len(result.eks_clusters) == 0
    assert len(result.node_groups) == 0
    assert len(result.load_balancers) == 0
    assert len(result.lambda_functions) == 0
    assert len(result.auto_scaling_groups) == 0 