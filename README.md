# AWS Resource Scanner

A Python tool to scan and report AWS resources across multiple services including EC2, Security Groups, EKS, Load Balancers, S3, Lambda, and more.

## Features

- Scans multiple AWS resource types:
  - EC2 Instances
  - Security Groups
  - EKS Clusters
  - Node Groups and Nodes
  - Application and Network Load Balancers
  - S3 Buckets
  - Lambda Functions
  - Auto Scaling Groups
  - VPCs
  - Subnets
  - Internet Gateways
  - NAT Gateways
  - Route Tables
  - Network ACLs
  - VPC Endpoints
  - VPC Peering Connections
- Outputs results in various formats (JSON, CSV, console table)
- Supports filtering and customization of scan results
- Multi-region scanning support
- Cross-account scanning via role assumption
- Secure credential handling
- Query resources by VPC ID

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aws-resource-scan.git
cd aws-resource-scan

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root or set the following environment variables:

```
# Direct authentication
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1

# Cross-account role assumption (option 1 - full ARN)
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/ResourceScannerRole

# Cross-account role assumption (option 2 - account ID and role name) 
AWS_TARGET_ACCOUNT_ID=123456789012
AWS_ROLE_NAME=ResourceScannerRole
```

Alternatively, configure your AWS CLI credentials using `aws configure`.

## Usage

AWS Resource Scanner provides two main commands:
- `scan`: For scanning AWS resources across multiple services
- `vpc-resources`: For querying resources associated with a specific VPC

### Scanning Resources

```bash
# Scan all supported resources
python -m aws_resource_scanner scan

# Scan specific resource types
python -m aws_resource_scanner scan --resources ec2,s3,lambda,vpc,subnet,igw,nat,rtb,nacl,endpoint,peering

# Scan VPC resources only
python -m aws_resource_scanner scan --resources vpc,subnet,igw,nat,rtb,nacl,endpoint,peering

# Scan resources in specific regions
python -m aws_resource_scanner scan --regions us-east-1,us-west-2

# Scan resources in another account using role assumption (option 1 - full ARN)
python -m aws_resource_scanner scan --role-arn arn:aws:iam::123456789012:role/ResourceScannerRole

# Scan resources in another account using role assumption (option 2 - account ID and role name)
python -m aws_resource_scanner scan --account-id 123456789012 --role-name ResourceScannerRole

# Output format options
python -m aws_resource_scanner scan --output json --output-file resources.json
python -m aws_resource_scanner scan --output csv --output-file resources.csv
```

### Cross-Account Scanning

To scan resources in another AWS account, you have two options:

#### Option 1: Using Full Role ARN

```bash
python -m aws_resource_scanner scan --role-arn arn:aws:iam::123456789012:role/ResourceScannerRole [--external-id your-external-id]
```

#### Option 2: Using Account ID and Role Name

1. Set up a role in the target account with appropriate permissions
2. Configure trust relationship to allow your source account to assume the role
3. Run the scanner with account ID and role name:

```bash
python -m aws_resource_scanner scan --account-id 123456789012 --role-name ResourceScannerRole [--external-id your-external-id]
```

For detailed instructions on setting up the cross-account role, see [Cross-Account Role Setup](docs/cross_account_role.md).

## VPC Resources Scanning

AWS Resource Scanner provides comprehensive scanning capabilities for VPC and related resources:

### VPC Resource Types

The following resource types can be scanned:

- `vpc`: Virtual Private Clouds - your private network in AWS
- `subnet`: Subnets within a VPC (public and private)
- `igw`: Internet Gateways that enable internet access from your VPC
- `nat`: NAT Gateways providing outbound internet access for private subnets
- `rtb`: Route Tables containing routing rules for network traffic
- `nacl`: Network ACLs providing stateless packet filtering at the subnet level
- `endpoint`: VPC Endpoints for private connectivity to AWS services
- `peering`: VPC Peering Connections linking VPCs together

Each resource type has a shorthand identifier that can be used with the `--resources` flag:

| Resource Type | Shorthand |
|---------------|-----------|
| VPC | vpc |
| Subnet | subnet |
| Internet Gateway | igw |
| NAT Gateway | nat |
| Route Table | rtb |
| Network ACL | nacl |
| VPC Endpoint | endpoint |
| VPC Peering Connection | peering |

### VPC Resources Command

The `vpc-resources` command allows you to query all resources that belong to a specific VPC:

```bash
# Basic usage - must provide a VPC ID
python -m aws_resource_scanner vpc-resources vpc-12345678

# With region specification
python -m aws_resource_scanner vpc-resources vpc-12345678 --regions us-east-1,us-west-2

# With AWS profile
python -m aws_resource_scanner vpc-resources vpc-12345678 --profile my-aws-profile

# Output as JSON or CSV (requires output-file parameter)
python -m aws_resource_scanner vpc-resources vpc-12345678 --output json --output-file vpc-resources.json
python -m aws_resource_scanner vpc-resources vpc-12345678 --output csv --output-file vpc-resources.csv

# Cross-account scanning with role assumption
python -m aws_resource_scanner vpc-resources vpc-12345678 --role-arn arn:aws:iam::123456789012:role/ResourceScannerRole
```

This command collects and displays all resources associated with the specified VPC, including:

- EC2 Instances in the VPC
- Security Groups attached to the VPC
- EKS Clusters in the VPC
- Load Balancers in the VPC
- Lambda Functions with VPC configuration
- Subnets within the VPC
- Internet Gateways attached to the VPC
- NAT Gateways in the VPC
- Route Tables for the VPC
- Network ACLs protecting the VPC
- VPC Endpoints for private AWS service access
- VPC Peering Connections (both as requester and accepter)

#### Default Output Format

By default, the command displays results in a formatted table in the console, with sections for each resource type and a summary of all resources found.

#### Example Output (Table Format)

```
Resources in VPC: vpc-12345678

EC2 Instances:
┌────────────────┬───────────────┬──────────┬─────────┬─────────────┬────────────┬─────────────┐
│ ID             │ Name          │ Type     │ State   │ Private IP  │ Public IP  │ Subnet      │
├────────────────┼───────────────┼──────────┼─────────┼─────────────┼────────────┼─────────────┤
│ i-0abc123def456│ Web Server    │ t3.micro │ running │ 10.0.1.10   │ 54.12.34.56│ subnet-123a │
│ i-0def456abc789│ App Server    │ t3.small │ running │ 10.0.2.20   │            │ subnet-456b │
└────────────────┴───────────────┴──────────┴─────────┴─────────────┴────────────┴─────────────┘

Subnets:
┌─────────────┬──────────────┬──────────────┬────────────┬──────────────┬───────────────────┐
│ ID          │ Name         │ CIDR Block   │ AZ         │ Available IPs│ Public IP on Launch│
├─────────────┼──────────────┼──────────────┼────────────┼──────────────┼───────────────────┤
│ subnet-123a │ Public-1a    │ 10.0.1.0/24  │ us-east-1a │ 251          │ Yes               │
│ subnet-456b │ Private-1a   │ 10.0.2.0/24  │ us-east-1a │ 251          │ No                │
└─────────────┴──────────────┴──────────────┴────────────┴──────────────┴───────────────────┘

[... additional tables for other resource types ...]

Summary:
EC2 Instances: 2
Security Groups: 3
EKS Clusters: 0
Load Balancers: 1
Lambda Functions: 2
Subnets: 6
Internet Gateways: 1
NAT Gateways: 2
Route Tables: 3
Network ACLs: 2
VPC Endpoints: 4
VPC Peering Connections: 1
Total resources: 27
```

#### JSON and CSV Output

For programmatic access or further analysis, you can output the results in JSON or CSV format using the `--output` and `--output-file` options.

The command provides a comprehensive view of all components within a VPC, helping with auditing, documentation, and infrastructure management.

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
mypy aws_resource_scanner
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 