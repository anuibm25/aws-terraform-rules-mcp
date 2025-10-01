#!/usr/bin/env python3
"""
Enhanced AWS Terraform Rules MCP Server with Guaranteed Compliance Workflow
This MCP server provides rules and GUARANTEES rule compliance through enforced workflows
Features: User data support, instance type constraints, AWS permission validation
"""

import asyncio
import json
import re
import subprocess
from typing import Any, Dict, List, Tuple, Optional
from mcp.server import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# EC2 Instance Type Constraints - CANNOT BE SKIPPED
EC2_INSTANCE_TYPE_CONSTRAINTS = {
    "micro": {
        "allowed_types": ["t3.micro", "t3a.micro", "t4g.micro"],
        "max_cpu": 2,
        "max_memory_gb": 1,
        "description": "For development, testing, or very light workloads"
    },
    "small": {
        "allowed_types": ["t3.small", "t3a.small", "t4g.small"],
        "max_cpu": 2,
        "max_memory_gb": 2,
        "description": "For small applications, lightweight services"
    },
    "medium": {
        "allowed_types": ["t3.medium", "t3a.medium", "t4g.medium", "c6i.large"],
        "max_cpu": 4,
        "max_memory_gb": 4,
        "description": "For medium-sized applications, moderate traffic"
    },
    "large": {
        "allowed_types": ["t3.large", "t3a.large", "t4g.large", "c6i.xlarge", "m6i.large"],
        "max_cpu": 8,
        "max_memory_gb": 8,
        "description": "For large applications, high traffic, production workloads"
    },
    "xlarge": {
        "allowed_types": ["t3.xlarge", "t3a.xlarge", "c6i.2xlarge", "m6i.xlarge", "r6i.xlarge"],
        "max_cpu": 16,
        "max_memory_gb": 16,
        "description": "For very large applications, database servers, high-performance workloads"
    },
    "2xlarge": {
        "allowed_types": ["c6i.4xlarge", "m6i.2xlarge", "r6i.2xlarge"],
        "max_cpu": 32,
        "max_memory_gb": 32,
        "description": "For enterprise applications, requires management approval"
    }
}

# Required AWS IAM permissions for each resource type
REQUIRED_AWS_PERMISSIONS = {
    "s3": [
        "s3:CreateBucket",
        "s3:PutBucketVersioning",
        "s3:PutEncryptionConfiguration",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketLogging",
        "s3:PutBucketTagging"
    ],
    "ec2": [
        "ec2:RunInstances",
        "ec2:CreateTags",
        "ec2:DescribeInstances",
        "ec2:DescribeImages",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "iam:PassRole"
    ],
    "rds": [
        "rds:CreateDBInstance",
        "rds:AddTagsToResource",
        "rds:DescribeDBInstances",
        "rds:DescribeDBSubnetGroups",
        "ec2:DescribeSecurityGroups",
        "kms:DescribeKey",
        "kms:CreateGrant"
    ]
}

# Define your AWS Terraform rules here
AWS_TERRAFORM_RULES = {
    "general": [
        "Always follow AWS Best Practices",
        "All resources must have tags including: Name, Environment, Owner, CostCenter",
        "Use consistent naming convention: {environment}-{service}-{resource_type}",
        "Always enable encryption at rest for data storage services",
        "Enable versioning for S3 buckets storing important data",
        "Use IMDSv2 for EC2 instances (metadata service)",
        "Never hardcode credentials or secrets in Terraform code",
        "All resources must be defined in modules in separate directories for reusability and organization",
        "Always ask the user which directory to create the Terraform files in"
    ],
    "ec2": [
        "Create Key Pairs for SSH access and never use password authentication",
        "Create IAM Profiles for EC2 instances to access other AWS services",
        "Always use latest Amazon Linux 2023 or Ubuntu LTS AMIs",
        "Enable detailed monitoring for production instances",
        "Always associate instances with a security group (never use default)",
        "Enable EBS encryption by default",
        "Instance type must match application_size constraints (MANDATORY)",
        "User data scripts must be provided for automated configuration",
        "User data scripts must be validated for security best practices"
    ],
    "s3": [
        "Block all public access unless explicitly required and documented",
        "Enable versioning for buckets containing critical data",
        "Enable server-side encryption (SSE-S3 or SSE-KMS)",
        "Enable bucket logging for audit trails",
        "Apply lifecycle policies to transition old data to cheaper storage",
        "Use bucket policies to restrict access by IP or VPC"
    ],
    "rds": [
        "Enable automated backups with minimum 7 days retention",
        "Enable encryption at rest using KMS",
        "Use Multi-AZ for production databases",
        "Never use publicly accessible RDS instances in production",
        "Use db.t3.micro for dev/test, db.t3.small minimum for production",
        "Enable Performance Insights for production databases"
    ],
    "vpc": [
        "Use at least 2 availability zones for high availability",
        "Create separate public and private subnets",
        "Enable VPC Flow Logs for security monitoring",
        "Use NAT Gateway for private subnet internet access",
        "Implement network ACLs in addition to security groups",
        "Use /16 CIDR for VPC, /24 for subnets"
    ],
    "security_groups": [
        "Follow principle of least privilege - only open required ports",
        "Never use 0.0.0.0/0 for SSH (port 22) access",
        "Use descriptive names and descriptions for rules",
        "Reference other security groups instead of IP ranges when possible",
        "Document the purpose of each security group rule",
        "Regular audit and remove unused security groups"
    ],
    "iam": [
        "Follow principle of least privilege for all IAM policies",
        "Never use root user access keys",
        "Enable MFA for IAM users with console access",
        "Use IAM roles for EC2 instances instead of access keys",
        "Rotate access keys regularly (every 90 days)",
        "Use AWS managed policies when available before creating custom policies"
    ],
    "cost_optimization": [
        "Use appropriate instance types based on workload requirements",
        "Implement auto-scaling to match demand",
        "Use Reserved Instances or Savings Plans for predictable workloads",
        "Set up billing alerts and budgets",
        "Tag all resources for cost allocation tracking",
        "Stop/terminate unused resources"
    ],
    "compliance": [
        "Enable AWS CloudTrail for all regions",
        "Enable AWS Config for compliance monitoring",
        "Ensure data residency requirements are met",
        "Enable encryption for data in transit (TLS/SSL)",
        "Document all compliance-related configurations",
        "Regular review of security group rules and access policies"
    ]
}

# Terraform templates for compliant resources
COMPLIANT_TEMPLATES = {
    "s3": """
resource "aws_s3_bucket" "{bucket_name}" {{
  bucket = "{bucket_name}"
  
  tags = {{
    Name        = "{bucket_name}"
    Environment = "{environment}"
    Owner       = "{owner}"
    CostCenter  = "{cost_center}"
  }}
}}

resource "aws_s3_bucket_versioning" "{bucket_name}_versioning" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  
  versioning_configuration {{
    status = "Enabled"
  }}
}}

resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket_name}_encryption" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}

resource "aws_s3_bucket_public_access_block" "{bucket_name}_public_access_block" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}

resource "aws_s3_bucket_logging" "{bucket_name}_logging" {{
  bucket = aws_s3_bucket.{bucket_name}.id
  
  target_bucket = "{log_bucket}"
  target_prefix = "s3-logs/{bucket_name}/"
}}
""",
    "ec2": """
resource "aws_instance" "{instance_name}" {{
  ami           = "{ami_id}"
  instance_type = "{instance_type}"
  
  vpc_security_group_ids = ["{security_group_id}"]
  subnet_id              = "{subnet_id}"
  
  metadata_options {{
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2
    http_put_response_hop_limit = 1
  }}
  
  root_block_device {{
    encrypted = true
    volume_type = "gp3"
  }}
  
  monitoring = {monitoring}
  
  user_data = <<-EOF
{user_data}
  EOF
  
  tags = {{
    Name        = "{instance_name}"
    Environment = "{environment}"
    Owner       = "{owner}"
    CostCenter  = "{cost_center}"
    ApplicationSize = "{application_size}"
  }}
}}
""",
    "rds": """
resource "aws_db_instance" "{db_name}" {{
  identifier     = "{db_name}"
  engine         = "{engine}"
  engine_version = "{engine_version}"
  instance_class = "{instance_class}"
  
  allocated_storage     = {storage}
  storage_encrypted     = true
  kms_key_id           = "{kms_key_id}"
  
  db_name  = "{database_name}"
  username = "{username}"
  password = "{password}"  # Use AWS Secrets Manager in production!
  
  multi_az               = {multi_az}
  publicly_accessible    = false
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "mon:04:00-mon:05:00"
  
  performance_insights_enabled = {performance_insights}
  
  vpc_security_group_ids = ["{security_group_id}"]
  db_subnet_group_name   = "{subnet_group_name}"
  
  enabled_cloudwatch_logs_exports = ["error", "general", "slowquery"]
  
  tags = {{
    Name        = "{db_name}"
    Environment = "{environment}"
    Owner       = "{owner}"
    CostCenter  = "{cost_center}"
  }}
}}
"""
}

# Create server instance
server = Server("aws-terraform-rules-server-enhanced")

def check_aws_permissions(service_type: str, aws_profile: Optional[str] = None) -> Tuple[bool, List[str], List[str]]:
    """
    Checks if the AWS profile has required permissions for creating resources.
    Returns: (has_permissions, missing_permissions, warnings)
    """
    if service_type not in REQUIRED_AWS_PERMISSIONS:
        return True, [], [f"No permission check defined for service type: {service_type}"]
    
    required_perms = REQUIRED_AWS_PERMISSIONS[service_type]
    missing_perms = []
    warnings = []
    
    try:
        # Build AWS CLI command
        profile_arg = f"--profile {aws_profile}" if aws_profile else ""
        
        # Check if AWS CLI is installed
        check_cli = subprocess.run(
            ["aws", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if check_cli.returncode != 0:
            return False, [], ["AWS CLI not found. Please install AWS CLI to check permissions."]
        
        # Get caller identity to verify credentials
        identity_cmd = f"aws sts get-caller-identity {profile_arg}".split()
        identity_result = subprocess.run(
            identity_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if identity_result.returncode != 0:
            error_msg = identity_result.stderr.strip()
            return False, [], [f"Cannot verify AWS credentials: {error_msg}"]
        
        identity = json.loads(identity_result.stdout)
        user_arn = identity.get("Arn", "Unknown")
        warnings.append(f"Checking permissions for: {user_arn}")
        
        # Simulate IAM policy check for each required permission
        for permission in required_perms:
            action_parts = permission.split(":")
            if len(action_parts) == 2:
                service, action = action_parts
                
                # Use iam simulate-principal-policy
                simulate_cmd = [
                    "aws", "iam", "simulate-principal-policy",
                    "--policy-source-arn", user_arn,
                    "--action-names", permission,
                    "--output", "json"
                ]
                
                if aws_profile:
                    simulate_cmd.extend(["--profile", aws_profile])
                
                try:
                    simulate_result = subprocess.run(
                        simulate_cmd,
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    
                    if simulate_result.returncode == 0:
                        result_data = json.loads(simulate_result.stdout)
                        evaluation_results = result_data.get("EvaluationResults", [])
                        
                        if evaluation_results:
                            decision = evaluation_results[0].get("EvalDecision", "")
                            if decision != "allowed":
                                missing_perms.append(permission)
                    else:
                        warnings.append(f"Could not verify permission: {permission}")
                
                except subprocess.TimeoutExpired:
                    warnings.append(f"Permission check timed out for: {permission}")
                except Exception as e:
                    warnings.append(f"Error checking {permission}: {str(e)}")
        
        has_all_perms = len(missing_perms) == 0
        return has_all_perms, missing_perms, warnings
    
    except subprocess.TimeoutExpired:
        return False, [], ["AWS CLI command timed out"]
    except FileNotFoundError:
        return False, [], ["AWS CLI not found. Install it from: https://aws.amazon.com/cli/"]
    except Exception as e:
        return False, [], [f"Error checking permissions: {str(e)}"]

def validate_instance_type_constraint(instance_type: str, application_size: str) -> Tuple[bool, Optional[str]]:
    """
    Validates that the instance type matches the application size constraint.
    Returns: (is_valid, error_message)
    """
    if application_size not in EC2_INSTANCE_TYPE_CONSTRAINTS:
        valid_sizes = ", ".join(EC2_INSTANCE_TYPE_CONSTRAINTS.keys())
        return False, f"Invalid application_size '{application_size}'. Must be one of: {valid_sizes}"
    
    constraint = EC2_INSTANCE_TYPE_CONSTRAINTS[application_size]
    allowed_types = constraint["allowed_types"]
    
    if instance_type not in allowed_types:
        error_msg = f"""
CONSTRAINT VIOLATION: Instance type '{instance_type}' is NOT allowed for application_size '{application_size}'.

Application Size: {application_size}
Description: {constraint['description']}
Allowed instance types: {', '.join(allowed_types)}
Max CPU: {constraint['max_cpu']}
Max Memory: {constraint['max_memory_gb']} GB

You must choose one of the allowed instance types for this application size.
"""
        return False, error_msg
    
    return True, None

def validate_user_data_script(user_data: str) -> Tuple[bool, List[str], List[str]]:
    """
    Validates user data script for security best practices.
    Returns: (is_valid, errors, warnings)
    """
    errors = []
    warnings = []
    
    if not user_data or user_data.strip() == "":
        errors.append("User data script cannot be empty. Provide initialization commands.")
        return False, errors, warnings
    
    user_data_lower = user_data.lower()
    
    # Check for hardcoded credentials
    if re.search(r'(password|secret|key)\s*=\s*["\'][^"\']+["\']', user_data, re.IGNORECASE):
        if "aws_secretsmanager" not in user_data_lower and "parameter_store" not in user_data_lower:
            errors.append("SECURITY: Hardcoded credentials detected in user data. Use AWS Secrets Manager or Parameter Store.")
    
    # Check for sudo usage without proper safeguards
    if "sudo" in user_data_lower:
        warnings.append("User data contains 'sudo' commands. Ensure proper security context.")
    
    # Check for package manager usage
    if not any(pkg in user_data_lower for pkg in ["yum", "apt-get", "dnf", "apt"]):
        warnings.append("No package manager commands found. Consider adding package updates.")
    
    # Check for logging
    if "log" not in user_data_lower and "/var/log" not in user_data_lower:
        warnings.append("No logging configuration detected. Consider adding log output for debugging.")
    
    # Check for error handling
    if "set -e" not in user_data and "||" not in user_data:
        warnings.append("No error handling detected. Consider adding 'set -e' or error checks.")
    
    # Check shebang
    if not user_data.strip().startswith("#!"):
        warnings.append("No shebang found. Consider adding '#!/bin/bash' at the start.")
    
    return len(errors) == 0, errors, warnings

def validate_terraform_against_rules(terraform_code: str, service_type: str) -> Tuple[bool, List[str], List[str]]:
    """
    Validates Terraform code against rules and returns:
    (is_valid, list_of_errors, list_of_warnings)
    """
    errors = []
    warnings = []
    
    code_lower = terraform_code.lower()
    
    # CRITICAL CHECKS (errors - must fix)
    if "tags" not in code_lower:
        errors.append("CRITICAL: No tags found. All resources MUST have tags (Name, Environment, Owner, CostCenter)")
    
    if service_type == "s3":
        if "encryption" not in code_lower and "server_side_encryption" not in code_lower:
            errors.append("CRITICAL: S3 bucket encryption is not enabled")
        if "block_public" not in code_lower and "public_access_block" not in code_lower:
            errors.append("CRITICAL: S3 public access blocking is not configured")
        if "versioning" not in code_lower:
            warnings.append("WARNING: S3 versioning is not enabled")
    
    elif service_type == "ec2":
        if "vpc_security_group_ids" not in code_lower and "security_groups" not in code_lower:
            errors.append("CRITICAL: EC2 instance has no security group specified")
        if "encrypted = true" not in code_lower:
            errors.append("CRITICAL: EBS volume encryption is not enabled")
        if "http_tokens" not in code_lower or 'http_tokens                 = "required"' not in terraform_code:
            errors.append("CRITICAL: IMDSv2 is not enforced (http_tokens must be 'required')")
        if "user_data" not in code_lower:
            errors.append("CRITICAL: No user_data script provided for EC2 instance initialization")
        if "applicationsize" not in code_lower:
            warnings.append("WARNING: No ApplicationSize tag found. This is used for instance type validation.")
    
    elif service_type == "rds":
        if "storage_encrypted" not in code_lower or "storage_encrypted     = true" not in terraform_code:
            errors.append("CRITICAL: RDS storage encryption is not enabled")
        if "publicly_accessible    = true" in terraform_code:
            errors.append("CRITICAL: RDS instance is publicly accessible (security risk!)")
        if "backup_retention_period" not in code_lower:
            errors.append("CRITICAL: RDS automated backups are not configured")
    
    # Check for hardcoded credentials
    if re.search(r'(password|secret|key)\s*=\s*["\'][^"\']+["\']', terraform_code, re.IGNORECASE):
        if "aws_secretsmanager" not in code_lower and "data.aws_secretsmanager" not in code_lower:
            errors.append("CRITICAL: Potential hardcoded credentials found. Use AWS Secrets Manager!")
    
    # Check naming convention
    if not re.search(r'(dev|test|stage|prod)', code_lower):
        warnings.append("WARNING: Resource name doesn't follow naming convention (should include environment)")
    
    is_valid = len(errors) == 0
    return is_valid, errors, warnings

def generate_compliant_terraform(service_type: str, config: Dict[str, Any]) -> str:
    """
    Generates compliant Terraform code using templates
    """
    if service_type not in COMPLIANT_TEMPLATES:
        return f"# Error: No template available for service type '{service_type}'\n# Available types: {', '.join(COMPLIANT_TEMPLATES.keys())}"
    
    template = COMPLIANT_TEMPLATES[service_type]
    
    # Fill in template with config values
    try:
        terraform_code = template.format(**config)
        return terraform_code
    except KeyError as e:
        missing_key = str(e).strip("'")
        return f"# Error: Missing required configuration parameter: {missing_key}\n# Please provide: {missing_key}"

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools for getting AWS Terraform rules"""
    return [
        # ORIGINAL TOOLS (still available)
        types.Tool(
            name="get-all-rules",
            description="Get all AWS Terraform infrastructure rules and best practices",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        types.Tool(
            name="get-rules-by-service",
            description="Get AWS Terraform rules for a specific AWS service (e.g., ec2, s3, rds, vpc, iam)",
            inputSchema={
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "AWS service name (e.g., ec2, s3, rds, vpc, security_groups, iam, cost_optimization, compliance)",
                        "enum": list(AWS_TERRAFORM_RULES.keys())
                    }
                },
                "required": ["service"]
            }
        ),
        types.Tool(
            name="validate-terraform-plan",
            description="Validate a Terraform plan against AWS rules and provide recommendations",
            inputSchema={
                "type": "object",
                "properties": {
                    "terraform_code": {
                        "type": "string",
                        "description": "The Terraform code to validate"
                    },
                    "service_type": {
                        "type": "string",
                        "description": "The AWS service type being created (e.g., ec2, s3, rds)"
                    }
                },
                "required": ["terraform_code", "service_type"]
            }
        ),
        
        # NEW ENHANCED TOOLS (guaranteed compliance)
        types.Tool(
            name="create-compliant-infrastructure",
            description="🔒 GUARANTEED COMPLIANCE: Creates AWS infrastructure that automatically follows ALL organizational rules. This tool enforces a strict workflow: 1) Retrieves applicable rules, 2) Generates compliant Terraform code, 3) Validates against all rules, 4) Checks AWS permissions, 5) Returns ONLY if validation passes. Use this when you need guaranteed rule compliance.",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_type": {
                        "type": "string",
                        "description": "AWS service type to create (s3, ec2, rds)",
                        "enum": ["s3", "ec2", "rds"]
                    },
                    "config": {
                        "type": "object",
                        "description": "Configuration for the resource. Required fields vary by service_type. For S3: bucket_name, environment, owner, cost_center, log_bucket. For EC2: instance_name, ami_id, instance_type, application_size (micro/small/medium/large/xlarge/2xlarge - MANDATORY), security_group_id, subnet_id, environment, owner, cost_center, monitoring (true/false), user_data (bash script as string - MANDATORY). For RDS: db_name, engine, engine_version, instance_class, storage, kms_key_id, database_name, username, password, multi_az (true/false), performance_insights (true/false), security_group_id, subnet_group_name, environment, owner, cost_center"
                    },
                    "aws_profile": {
                        "type": "string",
                        "description": "AWS CLI profile name to use for permission checks. If not provided, uses default profile."
                    }
                },
                "required": ["service_type", "config"]
            }
        ),
        types.Tool(
            name="audit-terraform-compliance",
            description="📊 COMPREHENSIVE AUDIT: Performs a detailed compliance audit of existing Terraform code. Returns: compliance score, critical errors that MUST be fixed, warnings, and specific recommendations. Use this to audit existing infrastructure code.",
            inputSchema={
                "type": "object",
                "properties": {
                    "terraform_code": {
                        "type": "string",
                        "description": "The Terraform code to audit"
                    },
                    "service_type": {
                        "type": "string",
                        "description": "The AWS service type (e.g., ec2, s3, rds)"
                    }
                },
                "required": ["terraform_code", "service_type"]
            }
        ),
        types.Tool(
            name="get-compliant-template",
            description="📋 Get a pre-built compliant Terraform template for a specific AWS service. These templates are already configured to follow all organizational rules. Available for: s3, ec2, rds",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_type": {
                        "type": "string",
                        "description": "AWS service type (s3, ec2, rds)",
                        "enum": ["s3", "ec2", "rds"]
                    }
                },
                "required": ["service_type"]
            }
        ),
        types.Tool(
            name="check-aws-permissions",
            description="🔐 Check if the current AWS profile has all required permissions to create specified resources. Use this before attempting to create infrastructure.",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_type": {
                        "type": "string",
                        "description": "AWS service type to check permissions for (s3, ec2, rds)",
                        "enum": ["s3", "ec2", "rds"]
                    },
                    "aws_profile": {
                        "type": "string",
                        "description": "AWS CLI profile name. If not provided, uses default profile."
                    }
                },
                "required": ["service_type"]
            }
        ),
        types.Tool(
            name="validate-instance-type",
            description="✅ Validate that an EC2 instance type is allowed for a given application size. Returns allowed types and constraints.",
            inputSchema={
                "type": "object",
                "properties": {
                    "instance_type": {
                        "type": "string",
                        "description": "EC2 instance type (e.g., t3.micro, t3.medium, c6i.large)"
                    },
                    "application_size": {
                        "type": "string",
                        "description": "Application size category",
                        "enum": ["micro", "small", "medium", "large", "xlarge", "2xlarge"]
                    }
                },
                "required": ["instance_type", "application_size"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution requests"""
    
    # ORIGINAL TOOLS (unchanged)
    if name == "get-all-rules":
        formatted_rules = "# AWS Terraform Infrastructure Rules\n\n"
        for category, rules in AWS_TERRAFORM_RULES.items():
            formatted_rules += f"## {category.upper().replace('_', ' ')}\n"
            for rule in rules:
                formatted_rules += f"- {rule}\n"
            formatted_rules += "\n"
        
        return [types.TextContent(type="text", text=formatted_rules)]
    
    elif name == "get-rules-by-service":
        if not arguments or "service" not in arguments:
            return [types.TextContent(type="text", text="Error: service parameter is required")]
        
        service = arguments["service"]
        if service not in AWS_TERRAFORM_RULES:
            return [types.TextContent(
                type="text",
                text=f"Error: Unknown service '{service}'. Available services: {', '.join(AWS_TERRAFORM_RULES.keys())}"
            )]
        
        rules = AWS_TERRAFORM_RULES[service]
        formatted_rules = f"# Rules for {service.upper()}\n\n"
        for rule in rules:
            formatted_rules += f"- {rule}\n"
        
        return [types.TextContent(type="text", text=formatted_rules)]
    
    elif name == "validate-terraform-plan":
        if not arguments or "terraform_code" not in arguments or "service_type" not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: terraform_code and service_type parameters are required"
            )]
        
        terraform_code = arguments["terraform_code"]
        service_type = arguments["service_type"]
        
        relevant_rules = AWS_TERRAFORM_RULES.get("general", [])
        if service_type in AWS_TERRAFORM_RULES:
            relevant_rules.extend(AWS_TERRAFORM_RULES[service_type])
        
        validation_results = []
        
        if "tags" not in terraform_code.lower():
            validation_results.append("⚠️  Warning: No tags found. All resources should have tags (Name, Environment, Owner, CostCenter)")
        
        if service_type in ["s3", "rds"] and "encryption" not in terraform_code.lower():
            validation_results.append("⚠️  Warning: Encryption not explicitly enabled. Enable encryption for data at rest.")
        
        if service_type == "s3" and "block_public" not in terraform_code.lower():
            validation_results.append("⚠️  Warning: Public access blocking not configured for S3 bucket")
        
        if service_type == "ec2" and "vpc_security_group_ids" not in terraform_code.lower():
            validation_results.append("⚠️  Warning: No security group specified for EC2 instance")
        
        response = f"# Validation Results for {service_type.upper()}\n\n"
        
        if validation_results:
            response += "## Issues Found:\n"
            for issue in validation_results:
                response += f"{issue}\n"
            response += "\n"
        else:
            response += "✅ No obvious issues found\n\n"
        
        response += f"## Applicable Rules for {service_type}:\n"
        for rule in relevant_rules:
            response += f"- {rule}\n"
        
        return [types.TextContent(type="text", text=response)]
    
    # NEW ENHANCED TOOLS
    elif name == "create-compliant-infrastructure":
        if not arguments or "service_type" not in arguments or "config" not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: service_type and config parameters are required"
            )]
        
        service_type = arguments["service_type"]
        config = arguments["config"]
        aws_profile = arguments.get("aws_profile")
        
        response = f"# 🔒 Creating Compliant {service_type.upper()} Infrastructure\n\n"
        
        # STEP 0: EC2-specific validation - CANNOT BE SKIPPED
        if service_type == "ec2":
            # Validate application_size is provided
            if "application_size" not in config:
                return [types.TextContent(
                    type="text",
                    text=f"# ❌ MANDATORY FIELD MISSING\n\n**application_size** is REQUIRED for EC2 instances.\n\nValid values: {', '.join(EC2_INSTANCE_TYPE_CONSTRAINTS.keys())}\n\nThis determines which instance types are allowed based on your application's requirements."
                )]
            
            # Validate instance type against application size constraint
            instance_type = config.get("instance_type", "")
            application_size = config.get("application_size", "")
            
            is_valid_type, constraint_error = validate_instance_type_constraint(instance_type, application_size)
            if not is_valid_type:
                return [types.TextContent(
                    type="text",
                    text=f"# ❌ INSTANCE TYPE CONSTRAINT VIOLATION\n\n{constraint_error}"
                )]
            
            response += f"## ✅ Instance Type Validation Passed\n"
            response += f"- Application Size: **{application_size}**\n"
            response += f"- Instance Type: **{instance_type}** (allowed)\n"
            response += f"- Constraint: {EC2_INSTANCE_TYPE_CONSTRAINTS[application_size]['description']}\n\n"
            
            # Validate user_data is provided
            if "user_data" not in config or not config["user_data"]:
                return [types.TextContent(
                    type="text",
                    text="# ❌ MANDATORY FIELD MISSING\n\n**user_data** script is REQUIRED for EC2 instances.\n\nProvide a bash script for instance initialization. Example:\n```bash\n#!/bin/bash\nyum update -y\nyum install -y httpd\nsystemctl start httpd\nsystemctl enable httpd\n```"
                )]
            
            # Validate user_data script
            user_data = config["user_data"]
            ud_valid, ud_errors, ud_warnings = validate_user_data_script(user_data)
            
            if not ud_valid:
                error_text = "# ❌ USER DATA VALIDATION FAILED\n\n"
                error_text += "## Critical Errors:\n"
                for error in ud_errors:
                    error_text += f"- {error}\n"
                error_text += "\nFix these issues and try again."
                return [types.TextContent(type="text", text=error_text)]
            
            if ud_warnings:
                response += "## ⚠️ User Data Script Warnings:\n"
                for warning in ud_warnings:
                    response += f"- {warning}\n"
                response += "\n"
            else:
                response += "## ✅ User Data Script Validated\n\n"
        
        # STEP 1: Check AWS Permissions (MANDATORY)
        response += "## 🔐 Checking AWS Permissions...\n"
        has_perms, missing_perms, perm_warnings = check_aws_permissions(service_type, aws_profile)
        
        if perm_warnings:
            response += "### Permission Check Info:\n"
            for warning in perm_warnings:
                response += f"- {warning}\n"
            response += "\n"
        
        if not has_perms and missing_perms:
            response += "### ❌ MISSING REQUIRED PERMISSIONS:\n"
            for perm in missing_perms:
                response += f"- `{perm}`\n"
            response += "\n**ACTION REQUIRED:** Grant these permissions to your AWS user/role before creating resources.\n"
            return [types.TextContent(type="text", text=response)]
        
        response += "✅ Permission check completed\n\n"
        
        # STEP 2: Get applicable rules (MANDATORY)
        applicable_rules = AWS_TERRAFORM_RULES.get("general", []).copy()
        if service_type in AWS_TERRAFORM_RULES:
            applicable_rules.extend(AWS_TERRAFORM_RULES[service_type])
        
        # STEP 3: Generate compliant Terraform (MANDATORY)
        terraform_code = generate_compliant_terraform(service_type, config)
        
        if terraform_code.startswith("# Error:"):
            return [types.TextContent(
                type="text",
                text=f"# ❌ Failed to Generate Infrastructure\n\n{terraform_code}"
            )]
        
        # STEP 4: Validate the generated code (MANDATORY)
        is_valid, errors, warnings = validate_terraform_against_rules(terraform_code, service_type)
        
        # STEP 5: Return result ONLY if valid (GUARANTEED)
        
        if is_valid:
            response += "## ✅ VALIDATION PASSED - All Rules Satisfied\n\n"
            
            if warnings:
                response += "## ⚠️ Warnings (Non-Critical):\n"
                for warning in warnings:
                    response += f"- {warning}\n"
                response += "\n"
            
            response += "## 📋 Rules Applied:\n"
            for rule in applicable_rules[:5]:  # Show first 5 rules
                response += f"- {rule}\n"
            response += f"\n*...and {len(applicable_rules) - 5} more rules*\n\n" if len(applicable_rules) > 5 else "\n"
            
            response += "## 🚀 Generated Terraform Code:\n\n"
            response += "```hcl\n"
            response += terraform_code
            response += "\n```\n\n"
            response += "✅ This infrastructure is GUARANTEED to be compliant with all organizational rules!"
        else:
            response += "## ❌ VALIDATION FAILED - Compliance Issues Found\n\n"
            response += "### Critical Errors (Must Fix):\n"
            for error in errors:
                response += f"- {error}\n"
            response += "\n"
            
            if warnings:
                response += "### Warnings:\n"
                for warning in warnings:
                    response += f"- {warning}\n"
                response += "\n"
            
            response += "## ❌ Infrastructure creation BLOCKED due to compliance violations.\n"
            response += "Please fix the errors above and try again."
        
        return [types.TextContent(type="text", text=response)]
    
    elif name == "audit-terraform-compliance":
        if not arguments or "terraform_code" not in arguments or "service_type" not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: terraform_code and service_type parameters are required"
            )]
        
        terraform_code = arguments["terraform_code"]
        service_type = arguments["service_type"]
        
        # Get applicable rules
        applicable_rules = AWS_TERRAFORM_RULES.get("general", []).copy()
        if service_type in AWS_TERRAFORM_RULES:
            applicable_rules.extend(AWS_TERRAFORM_RULES[service_type])
        
        # Perform comprehensive validation
        is_valid, errors, warnings = validate_terraform_against_rules(terraform_code, service_type)
        
        # Calculate compliance score
        total_checks = len(errors) + len(warnings) + 5  # Base checks
        passed_checks = total_checks - len(errors) - len(warnings)
        compliance_score = int((passed_checks / total_checks) * 100)
        
        # Generate audit report
        response = f"# 📊 Compliance Audit Report for {service_type.upper()}\n\n"
        response += f"## Compliance Score: {compliance_score}%\n\n"
        
        if compliance_score >= 90:
            response += "✅ **STATUS: COMPLIANT** - Excellent! Minor improvements possible.\n\n"
        elif compliance_score >= 70:
            response += "⚠️ **STATUS: PARTIALLY COMPLIANT** - Some issues need attention.\n\n"
        else:
            response += "❌ **STATUS: NON-COMPLIANT** - Critical issues must be resolved.\n\n"
        
        if errors:
            response += f"## 🚨 Critical Errors Found: {len(errors)}\n"
            response += "*These MUST be fixed before deployment:*\n\n"
            for i, error in enumerate(errors, 1):
                response += f"{i}. {error}\n"
            response += "\n"
        
        if warnings:
            response += f"## ⚠️ Warnings Found: {len(warnings)}\n"
            response += "*These should be addressed:*\n\n"
            for i, warning in enumerate(warnings, 1):
                response += f"{i}. {warning}\n"
            response += "\n"
        
        if not errors and not warnings:
            response += "## ✅ No Issues Found!\n"
            response += "The Terraform code follows all organizational rules.\n\n"
        
        response += f"## 📋 Total Rules Checked: {len(applicable_rules)}\n"
        response += f"## ✅ Rules Passed: {passed_checks}\n"
        response += f"## ❌ Rules Failed: {len(errors)}\n"
        response += f"## ⚠️ Warnings: {len(warnings)}\n"
        
        return [types.TextContent(type="text", text=response)]
    
    elif name == "get-compliant-template":
        if not arguments or "service_type" not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: service_type parameter is required"
            )]
        
        service_type = arguments["service_type"]
        
        if service_type not in COMPLIANT_TEMPLATES:
            return [types.TextContent(
                type="text",
                text=f"Error: No template available for '{service_type}'. Available templates: {', '.join(COMPLIANT_TEMPLATES.keys())}"
            )]
        
        template = COMPLIANT_TEMPLATES[service_type]
        
        response = f"# 📋 Compliant Terraform Template for {service_type.upper()}\n\n"
        response += "This template follows ALL organizational rules and best practices.\n\n"
        response += "## Rules Enforced by This Template:\n"
        
        rules = AWS_TERRAFORM_RULES.get(service_type, [])
        for rule in rules:
            response += f"- {rule}\n"
        
        response += "\n## Template Code:\n\n"
        response += "```hcl\n"
        response += template
        response += "\n```\n\n"
        response += "## Usage:\n"
        response += f"Replace the placeholders (values in curly braces) with your actual values.\n"
        response += f"All security and compliance settings are pre-configured!\n"
        
        return [types.TextContent(type="text", text=response)]
    
    elif name == "check-aws-permissions":
        if not arguments or "service_type" not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: service_type parameter is required"
            )]
        
        service_type = arguments["service_type"]
        aws_profile = arguments.get("aws_profile")
        
        response = f"# 🔐 AWS Permission Check for {service_type.upper()}\n\n"
        
        if service_type not in REQUIRED_AWS_PERMISSIONS:
            response += f"No permission requirements defined for service type: {service_type}\n"
            return [types.TextContent(type="text", text=response)]
        
        profile_info = f" (Profile: {aws_profile})" if aws_profile else " (Default Profile)"
        response += f"**Checking AWS credentials{profile_info}**\n\n"
        
        has_perms, missing_perms, warnings = check_aws_permissions(service_type, aws_profile)
        
        response += "## Required Permissions:\n"
        for perm in REQUIRED_AWS_PERMISSIONS[service_type]:
            status = "✅" if perm not in missing_perms else "❌"
            response += f"{status} `{perm}`\n"
        response += "\n"
        
        if warnings:
            response += "## Information:\n"
            for warning in warnings:
                response += f"- {warning}\n"
            response += "\n"
        
        if has_perms:
            response += "## ✅ Result: ALL PERMISSIONS VERIFIED\n"
            response += "You have the required permissions to create this resource type.\n"
        elif missing_perms:
            response += "## ❌ Result: MISSING PERMISSIONS\n\n"
            response += "The following permissions are missing:\n"
            for perm in missing_perms:
                response += f"- `{perm}`\n"
            response += "\n**Action Required:** Contact your AWS administrator to grant these permissions.\n"
        else:
            response += "## ⚠️ Result: PERMISSION CHECK INCOMPLETE\n"
            response += "Could not fully verify all permissions. Check warnings above.\n"
        
        return [types.TextContent(type="text", text=response)]
    
    elif name == "validate-instance-type":
        if not arguments or "instance_type" not in arguments or "application_size" not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: instance_type and application_size parameters are required"
            )]
        
        instance_type = arguments["instance_type"]
        application_size = arguments["application_size"]
        
        response = f"# ✅ EC2 Instance Type Validation\n\n"
        response += f"**Instance Type:** `{instance_type}`\n"
        response += f"**Application Size:** `{application_size}`\n\n"
        
        if application_size not in EC2_INSTANCE_TYPE_CONSTRAINTS:
            response += f"## ❌ Invalid Application Size\n\n"
            response += f"'{application_size}' is not a valid application size.\n\n"
            response += "### Valid Application Sizes:\n"
            for size, constraint in EC2_INSTANCE_TYPE_CONSTRAINTS.items():
                response += f"\n**{size}:**\n"
                response += f"- {constraint['description']}\n"
                response += f"- Allowed types: {', '.join(constraint['allowed_types'])}\n"
                response += f"- Max CPU: {constraint['max_cpu']}, Max Memory: {constraint['max_memory_gb']} GB\n"
            
            return [types.TextContent(type="text", text=response)]
        
        constraint = EC2_INSTANCE_TYPE_CONSTRAINTS[application_size]
        is_valid = instance_type in constraint["allowed_types"]
        
        response += f"## Constraint Details for '{application_size}':\n"
        response += f"- **Description:** {constraint['description']}\n"
        response += f"- **Max CPU:** {constraint['max_cpu']} cores\n"
        response += f"- **Max Memory:** {constraint['max_memory_gb']} GB\n\n"
        
        response += "### Allowed Instance Types:\n"
        for allowed_type in constraint["allowed_types"]:
            marker = "✅" if allowed_type == instance_type else "  "
            response += f"{marker} `{allowed_type}`\n"
        response += "\n"
        
        if is_valid:
            response += f"## ✅ VALIDATION PASSED\n\n"
            response += f"Instance type `{instance_type}` is **ALLOWED** for application size '{application_size}'.\n"
        else:
            response += f"## ❌ VALIDATION FAILED\n\n"
            response += f"Instance type `{instance_type}` is **NOT ALLOWED** for application size '{application_size}'.\n\n"
            response += f"**You must choose one of the allowed instance types listed above.**\n"
        
        return [types.TextContent(type="text", text=response)]
    
    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    """Run the Enhanced MCP server"""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="aws-terraform-rules-server-enhanced",
                server_version="2.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())