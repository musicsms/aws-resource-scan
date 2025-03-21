"""Configuration utilities for AWS Resource Scanner.

This module handles loading configuration from environment variables
and creating properly configured AWS sessions.
"""
import os
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, ProfileNotFound
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load environment variables from .env file if it exists
load_dotenv()


class ScannerConfig(BaseModel):
    """Configuration settings for the AWS resource scanner."""

    regions: List[str] = Field(
        default_factory=lambda: [os.getenv("AWS_DEFAULT_REGION", "ap-southeast-1")]
    )
    profile_name: Optional[str] = Field(default=os.getenv("AWS_PROFILE"))
    access_key_id: Optional[str] = Field(default=os.getenv("AWS_ACCESS_KEY_ID"))
    secret_access_key: Optional[str] = Field(default=os.getenv("AWS_SECRET_ACCESS_KEY"))
    session_token: Optional[str] = Field(default=os.getenv("AWS_SESSION_TOKEN"))
    output_format: str = Field(default=os.getenv("AWS_OUTPUT_FORMAT", "table"))
    output_file: Optional[str] = Field(default=os.getenv("AWS_OUTPUT_FILE"))
    # Either provide a full role ARN or the account ID + role name combination
    role_arn: Optional[str] = Field(default=os.getenv("AWS_ROLE_ARN"))
    target_account_id: Optional[str] = Field(default=os.getenv("AWS_TARGET_ACCOUNT_ID"))
    role_name: Optional[str] = Field(default=os.getenv("AWS_ROLE_NAME"))
    role_session_name: str = Field(default=os.getenv("AWS_ROLE_SESSION_NAME", "AWSResourceScannerSession"))
    external_id: Optional[str] = Field(default=os.getenv("AWS_EXTERNAL_ID"))


def create_session(
    region: str,
    profile_name: Optional[str] = None,
    access_key_id: Optional[str] = None,
    secret_access_key: Optional[str] = None,
    session_token: Optional[str] = None,
    role_arn: Optional[str] = None,
    target_account_id: Optional[str] = None,
    role_name: Optional[str] = None,
    role_session_name: str = "AWSResourceScannerSession",
    external_id: Optional[str] = None,
) -> boto3.Session:
    """Create a boto3 session with the specified credentials and region.

    If role_arn or (target_account_id and role_name) are provided, assumes the 
    specified role and returns a session with those credentials.

    Args:
        region: AWS region name (e.g., 'us-east-1')
        profile_name: AWS profile name to use
        access_key_id: AWS access key ID
        secret_access_key: AWS secret access key
        session_token: AWS session token for temporary credentials
        role_arn: Full ARN of the role to assume (e.g., 'arn:aws:iam::123456789012:role/RoleName')
        target_account_id: Target AWS account ID to assume role in
        role_name: Name of the role to assume in the target account
        role_session_name: Session name for the assumed role session
        external_id: External ID for the role assumption, if required

    Returns:
        boto3.Session: Configured boto3 session

    Raises:
        ValueError: If credentials are not provided or cannot be found
    """
    try:
        # Create initial session based on credentials or profile
        if access_key_id and secret_access_key:
            initial_session = boto3.Session(
                region_name=region,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                aws_session_token=session_token,
            )
        elif profile_name:
            initial_session = boto3.Session(
                region_name=region,
                profile_name=profile_name,
            )
        else:
            # Use default credential provider chain
            initial_session = boto3.Session(region_name=region)

        # Verify initial session has credentials
        if initial_session.get_credentials() is None:
            raise ValueError(
                "No AWS credentials found. Please provide credentials "
                "via environment variables, profile, or AWS credential provider chain."
            )

        # If role assumption is requested
        # Determine the role ARN - either directly provided or constructed from account ID and role name
        assume_role_arn = role_arn
        if not assume_role_arn and target_account_id and role_name:
            assume_role_arn = f"arn:aws:iam::{target_account_id}:role/{role_name}"
            
        if assume_role_arn:
            sts_client = initial_session.client('sts')
            
            # Prepare assume role parameters
            assume_role_params = {
                'RoleArn': assume_role_arn,
                'RoleSessionName': role_session_name,
                'DurationSeconds': 3600,  # 1 hour
            }
            
            # Add external ID if provided
            if external_id:
                assume_role_params['ExternalId'] = external_id
                
            try:
                # Assume the role
                assumed_role = sts_client.assume_role(**assume_role_params)
                
                # Create a new session with the assumed role credentials
                session = boto3.Session(
                    region_name=region,
                    aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                    aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                    aws_session_token=assumed_role['Credentials']['SessionToken'],
                )
                
                return session
                
            except ClientError as e:
                role_display = role_arn or f"{role_name} in account {target_account_id}"
                raise ValueError(f"Error assuming role {role_display}: {str(e)}")
        
        # If no role assumption needed, return the initial session
        return initial_session

    except ProfileNotFound:
        raise ValueError(f"AWS profile '{profile_name}' not found")
    except ClientError as e:
        raise ValueError(f"Error creating AWS session: {str(e)}")


def create_regional_clients(
    config: ScannerConfig, service_name: str
) -> Dict[str, boto3.client]:
    """Create boto3 clients for each region in the configuration.

    Args:
        config: Scanner configuration containing regions and credentials
        service_name: AWS service name (e.g., 'ec2', 's3')

    Returns:
        Dict[str, boto3.client]: Dictionary mapping regions to boto3 clients
    """
    clients = {}
    for region in config.regions:
        session = create_session(
            region=region,
            profile_name=config.profile_name,
            access_key_id=config.access_key_id,
            secret_access_key=config.secret_access_key,
            session_token=config.session_token,
            role_arn=config.role_arn,
            target_account_id=config.target_account_id,
            role_name=config.role_name,
            role_session_name=config.role_session_name,
            external_id=config.external_id,
        )
        clients[region] = session.client(service_name)
    return clients 