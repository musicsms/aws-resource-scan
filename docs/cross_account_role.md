# Cross-Account Role Setup

This document explains how to set up an IAM role in a target AWS account that allows the AWS Resource Scanner to assume it and scan resources.

## Prerequisites

- Administrative access to both the source account (where you run the scanner) and target account (that you want to scan)
- AWS CLI installed and configured

## Step 1: Create the IAM Role in the Target Account

You can create the IAM role using the AWS Management Console, AWS CLI, or Infrastructure as Code (e.g., CloudFormation, Terraform).

### Using AWS CLI

1. Create a trust policy file named `trust-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SOURCE_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "EXTERNAL_ID"
        }
      }
    }
  ]
}
```

Replace:
- `SOURCE_ACCOUNT_ID` with your source AWS account ID where you run the scanner
- `EXTERNAL_ID` with a secure random string (optional but recommended for security)

2. Create the IAM role:

```bash
aws iam create-role --role-name ResourceScannerRole --assume-role-policy-document file://trust-policy.json
```

3. Note the full role ARN from the output:

```json
{
    "Role": {
        "Path": "/",
        "RoleName": "ResourceScannerRole",
        "RoleId": "AROAXXXXXXXXXXXXXXXXX",
        "Arn": "arn:aws:iam::TARGET_ACCOUNT_ID:role/ResourceScannerRole",
        ...
    }
}
```

You'll need this ARN for the scanner configuration.

## Step 2: Attach Permissions to the Role

The role needs permissions to scan resources. You can use AWS managed policies or create a custom policy.

For a comprehensive scanner, you might want to attach the following read-only policies:

```bash
# Attach AWS managed read-only policies
aws iam attach-role-policy --role-name ResourceScannerRole --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

For more granular control, create a custom policy with only the required permissions:

1. Create a file named `scanner-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "elasticloadbalancing:Describe*",
        "eks:Describe*",
        "eks:List*",
        "s3:Get*",
        "s3:List*",
        "lambda:List*",
        "lambda:Get*",
        "autoscaling:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
```

2. Create the policy:

```bash
aws iam create-policy --policy-name ResourceScannerPolicy --policy-document file://scanner-policy.json
```

3. Attach the policy to the role:

```bash
aws iam attach-role-policy --role-name ResourceScannerRole --policy-arn arn:aws:iam::TARGET_ACCOUNT_ID:policy/ResourceScannerPolicy
```

Replace `TARGET_ACCOUNT_ID` with your target AWS account ID.

## Step 3: Run the Scanner

Now you can run the scanner using the created role. You have two options:

### Option 1: Using the full Role ARN

```bash
python -m aws_resource_scanner --role-arn arn:aws:iam::TARGET_ACCOUNT_ID:role/ResourceScannerRole --external-id EXTERNAL_ID
```

### Option 2: Using Account ID and Role Name separately

```bash
python -m aws_resource_scanner --account-id TARGET_ACCOUNT_ID --role-name ResourceScannerRole --external-id EXTERNAL_ID
```

Replace:
- `TARGET_ACCOUNT_ID` with your target AWS account ID
- `EXTERNAL_ID` with the same external ID you used in the trust policy (if applicable)

## Troubleshooting

If you encounter permission issues:

1. Check the trust relationship in the IAM role
2. Verify that the role has the necessary permissions
3. Ensure that the external ID matches between your scanner command and the trust policy
4. Check AWS CloudTrail logs for any access denied errors

## Security Considerations

- Use an external ID to prevent confused deputy problems
- Follow the principle of least privilege: only grant the permissions necessary for scanning
- Consider setting condition keys in the trust policy to restrict when the role can be assumed
- Regularly rotate any credentials used to assume the role 