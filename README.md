# AWS Terraform Rules MCP Server

A Model Context Protocol (MCP) server that provides AWS Terraform infrastructure rules and compliance validation.

## Overview

This MCP server helps developers create secure, compliant AWS infrastructure using Terraform by providing:

- **AWS-specific rules and constraints** for EC2, S3, RDS, VPC, and other services
- **Compliance validation** with organizational policies
- **Instance type constraints** based on application size requirements
- **Security best practices** enforcement
- **Guaranteed compliance workflow** for infrastructure creation

## Features

### Basic Rules Server (`rules_server.py`)
- Provides AWS Terraform rules for major services
- Returns compliance recommendations
- Basic rule validation

### Enhanced Rules Server (`rules_server_enhanced.py`)
- Advanced compliance validation
- AWS permission checking
- Template generation with rule enforcement

### Advanced Enhanced Server (`rules_server_enhanced2.py`)
- **Instance type constraints** based on application size (micro, small, medium, large, xlarge, 2xlarge)
- **User data support** for EC2 instances
- **Guaranteed compliance workflow** that enforces all rules
- **AWS permission validation** before infrastructure creation
- **Template generation** with automatic rule compliance

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/anuibm25/aws-terraform-rules-mcp.git
   cd aws-terraform-rules-mcp
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Add the server to your MCP configuration file (typically `mcp.json`):

```json
{
  "servers": {
    "aws-terraform-rules_enhanced": {
      "command": "path/to/your/venv/Scripts/python.exe",
      "args": [
        "path/to/rules_server_enhanced2.py"
      ],
      "timeout": 60000,
      "disabled": false
    }
  }
}
```

## Usage

The server provides several tools:

### Rule Management
- `get-all-rules`: Get all AWS Terraform rules
- `get-rules-by-service`: Get rules for specific AWS services
- `get-compliant-template`: Get pre-built compliant templates

### Validation and Compliance
- `validate-terraform-plan`: Validate Terraform code against rules
- `audit-terraform-compliance`: Comprehensive compliance audit
- `validate-instance-type`: Validate EC2 instance types for application size

### Infrastructure Creation
- `create-compliant-infrastructure`: Create guaranteed compliant infrastructure
- `check-aws-permissions`: Check AWS permissions before creation

## EC2 Instance Type Constraints

The server enforces instance type constraints based on application size:

- **micro**: t3.micro, t3a.micro, t4g.micro (dev/testing)
- **small**: t3.small, t3a.small, t4g.small (small applications)
- **medium**: t3.medium, t3a.medium, t4g.medium, c6i.large (medium applications)
- **large**: t3.large, t3a.large, t4g.large, c6i.xlarge, m6i.large (production)
- **xlarge**: t3.xlarge, t3a.xlarge, c6i.2xlarge, m6i.xlarge, r6i.xlarge (high-performance)
- **2xlarge**: t3.2xlarge, c6i.4xlarge, m6i.2xlarge, r6i.2xlarge (enterprise)

## AWS Rules Covered

- **General**: Tagging, naming conventions, encryption, security
- **EC2**: Instance types, monitoring, security groups, EBS encryption
- **S3**: Public access, versioning, encryption, lifecycle policies
- **RDS**: Backups, encryption, Multi-AZ, Performance Insights
- **VPC**: High availability, security groups, network ACLs
- **IAM**: Least privilege, MFA, policy validation
- **Security Groups**: Port restrictions, source limitations
- **Cost Optimization**: Right-sizing, reserved instances, lifecycle management

## Files

- `rules_server.py`: Basic MCP server with AWS Terraform rules
- `rules_server_enhanced.py`: Enhanced server with compliance validation
- `rules_server_enhanced2.py`: Advanced server with instance constraints and guaranteed compliance
- `requirements.txt`: Python dependencies
- `s3-bucket.tf`: Example compliant S3 bucket configuration
- `.gitignore`: Git ignore patterns for Python projects

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions or issues, please open an issue on GitHub or contact the maintainers.