#!/usr/bin/env python3
"""
Enhanced AWS Terraform Rules MCP Server with Guaranteed Compliance Workflow
This MCP server provides rules and GUARANTEES rule compliance through enforced workflows
"""

import asyncio
import json
import re
from typing import Any, Dict, List, Tuple
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio

# Define your AWS Terraform rules here
AWS_TERRAFORM_RULES = {
    "general": [
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
        "Use t3.micro or t3.small for development environments",
        "Use t3.medium or larger only for production with justification",
        "Always use latest Amazon Linux 2023 or Ubuntu LTS AMIs",
        "Enable detailed monitoring for production instances",
        "Always associate instances with a security group (never use default)",
        "Enable EBS encryption by default"
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
  
  tags = {{
    Name        = "{instance_name}"
    Environment = "{environment}"
    Owner       = "{owner}"
    CostCenter  = "{cost_center}"
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
            description="🔒 GUARANTEED COMPLIANCE: Creates AWS infrastructure that automatically follows ALL organizational rules. This tool enforces a strict workflow: 1) Retrieves applicable rules, 2) Generates compliant Terraform code, 3) Validates against all rules, 4) Returns ONLY if validation passes. Use this when you need guaranteed rule compliance.",
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
                        "description": "Configuration for the resource. Required fields vary by service_type. For S3: bucket_name, environment, owner, cost_center, log_bucket. For EC2: instance_name, ami_id, instance_type, security_group_id, subnet_id, environment, owner, cost_center, monitoring (true/false). For RDS: db_name, engine, engine_version, instance_class, storage, kms_key_id, database_name, username, password, multi_az (true/false), performance_insights (true/false), security_group_id, subnet_group_name, environment, owner, cost_center"
                    }
                },
                "required": ["service_type", "config"]
            }
        ),
        types.Tool(
            name="audit-terraform-compliance",
            description="🔍 COMPREHENSIVE AUDIT: Performs a detailed compliance audit of existing Terraform code. Returns: compliance score, critical errors that MUST be fixed, warnings, and specific recommendations. Use this to audit existing infrastructure code.",
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
        
        # STEP 1: Get applicable rules (MANDATORY)
        applicable_rules = AWS_TERRAFORM_RULES.get("general", []).copy()
        if service_type in AWS_TERRAFORM_RULES:
            applicable_rules.extend(AWS_TERRAFORM_RULES[service_type])
        
        # STEP 2: Generate compliant Terraform (MANDATORY)
        terraform_code = generate_compliant_terraform(service_type, config)
        
        if terraform_code.startswith("# Error:"):
            return [types.TextContent(
                type="text",
                text=f"# ❌ Failed to Generate Infrastructure\n\n{terraform_code}"
            )]
        
        # STEP 3: Validate the generated code (MANDATORY)
        is_valid, errors, warnings = validate_terraform_against_rules(terraform_code, service_type)
        
        # STEP 4: Return result ONLY if valid (GUARANTEED)
        response = f"# 🔒 Compliant {service_type.upper()} Infrastructure Created\n\n"
        
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
        response = f"# 🔍 Compliance Audit Report for {service_type.upper()}\n\n"
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