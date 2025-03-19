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
- Outputs results in various formats (JSON, CSV, console table)
- Supports filtering and customization of scan results
- Multi-region scanning support
- Cross-account scanning via role assumption
- Secure credential handling

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

```bash
# Scan all supported resources
python -m aws_resource_scanner

# Scan specific resource types
python -m aws_resource_scanner --resources ec2,s3,lambda

# Scan resources in specific regions
python -m aws_resource_scanner --regions us-east-1,us-west-2

# Scan resources in another account using role assumption (option 1 - full ARN)
python -m aws_resource_scanner --role-arn arn:aws:iam::123456789012:role/ResourceScannerRole

# Scan resources in another account using role assumption (option 2 - account ID and role name)
python -m aws_resource_scanner --account-id 123456789012 --role-name ResourceScannerRole

# Output format options
python -m aws_resource_scanner --output json --output-file resources.json
python -m aws_resource_scanner --output csv --output-file resources.csv
```

### Cross-Account Scanning

To scan resources in another AWS account, you have two options:

#### Option 1: Using Full Role ARN

```bash
python -m aws_resource_scanner --role-arn arn:aws:iam::123456789012:role/ResourceScannerRole [--external-id your-external-id]
```

#### Option 2: Using Account ID and Role Name

1. Set up a role in the target account with appropriate permissions
2. Configure trust relationship to allow your source account to assume the role
3. Run the scanner with account ID and role name:

```bash
python -m aws_resource_scanner --account-id 123456789012 --role-name ResourceScannerRole [--external-id your-external-id]
```

For detailed instructions on setting up the cross-account role, see [Cross-Account Role Setup](docs/cross_account_role.md).

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