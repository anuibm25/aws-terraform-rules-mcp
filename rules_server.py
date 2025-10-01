#!/usr/bin/env python3
"""
AWS Terraform Rules MCP Server
This MCP server provides rules and constraints for creating AWS infrastructure with Terraform
"""

import asyncio
import json
from typing import Any
from mcp.server import InitializationOptions
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

# Create server instance
server = Server("aws-terraform-rules-server")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available tools for getting AWS Terraform rules"""
    return [
        types.Tool(
            name="pre-terraform-check",
            description="REQUIRED: Must be called before creating ANY AWS infrastructure. Returns rules that must be followed.",
            inputSchema={
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "AWS service type"}
                },
                "required": ["service"]
            }
        ),
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
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution requests"""
    
    if name == "get-all-rules":
        # Return all rules formatted nicely
        formatted_rules = "# AWS Terraform Infrastructure Rules\n\n"
        for category, rules in AWS_TERRAFORM_RULES.items():
            formatted_rules += f"## {category.upper().replace('_', ' ')}\n"
            for rule in rules:
                formatted_rules += f"- {rule}\n"
            formatted_rules += "\n"
        
        return [types.TextContent(
            type="text",
            text=formatted_rules
        )]
    
    elif name == "get-rules-by-service":
        if not arguments or "service" not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: service parameter is required"
            )]
        
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
        
        return [types.TextContent(
            type="text",
            text=formatted_rules
        )]
    
    elif name == "validate-terraform-plan":
        if not arguments or "terraform_code" not in arguments or "service_type" not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: terraform_code and service_type parameters are required"
            )]
        
        terraform_code = arguments["terraform_code"]
        service_type = arguments["service_type"]
        
        # Get relevant rules
        relevant_rules = AWS_TERRAFORM_RULES.get("general", [])
        if service_type in AWS_TERRAFORM_RULES:
            relevant_rules.extend(AWS_TERRAFORM_RULES[service_type])
        
        # Simple validation checks
        validation_results = []
        
        # Check for tags
        if "tags" not in terraform_code.lower():
            validation_results.append("⚠️  Warning: No tags found. All resources should have tags (Name, Environment, Owner, CostCenter)")
        
        # Check for encryption (if S3 or RDS)
        if service_type in ["s3", "rds"] and "encryption" not in terraform_code.lower():
            validation_results.append("⚠️  Warning: Encryption not explicitly enabled. Enable encryption for data at rest.")
        
        # Check for public access (S3)
        if service_type == "s3" and "block_public" not in terraform_code.lower():
            validation_results.append("⚠️  Warning: Public access blocking not configured for S3 bucket")
        
        # Check for security group on EC2
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
        
        return [types.TextContent(
            type="text",
            text=response
        )]
    
    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    """Run the MCP server"""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="aws-terraform-rules-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())