# MetaHub

<p align="center">
  <img src="docs/imgs/metahub.png" alt="MetaHub" width="200"/>
</p>

<p align="center">
  <b>MetaHub</b> is the automated contextual enrichment tool for AWS Security Hub and ASFF security findings.
</p>

# Table of Contents

- [Description](#description)
- [Context](#context)
- [Ownership](#ownership)
- [Run with Python](#run-with-python)
- [Run with Docker](#run-with-docker)
- [Run with Lambda](#run-with-lambda)
- [AWS Authentication](#aws-authentication)
- [Configuring Security Hub](#configuring-security-hub)
- [Usage](#usage)
- [Examples](#investigations-examples)
- [Inputs](#Inputs)
- [Outputs](#Outputs)
- [Output Modes](#output-modes-1)
- [Findings Aggregation](#findings-aggregation)
- [MetaChecks](#MetaChecks-1)
- [MetaTags](#MetaTags-1)
- [MetaTrails](#metatrails-1)
- [Filtering](#Filtering)
- [Updating Workflow Status](#updating-workflow-status)
- [Enriching Findings](#enriching-findings-1)

# Description

**MetaHub** is a powerful security findings **context** and **ownership** enrichment tool designed for use with [AWS Security Hub](https://aws.amazon.com/security-hub) or any [ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) security scanner. It helps automate the process of contextualizing your findings with information from your environment, such as tags, trails, associations, related findings, and more. MetaHub can also be used to filter, deduplicate, group, report, suppress, or update your findings in automated workflows.

When analyzing a security finding, the severity alone is not sufficient to determine the issue's impact. To understand the importance of the finding, you need to gather additional information about the affected resource from your context, which is not available in the finding itself. Manually collecting this information from other sources can be time-consuming and error-prone, especially when dealing with multiple findings. **MetaHub** automates this process for you, allowing you to focus on the real issues, reduce noise and false positives, and improve the time it takes to detect and respond to genuine security issues in your environment.

MetaHub is designed for use as a CLI tool or within automated workflows, such as AWS Security Hub custom actions, AWS Lambda functions, or AWS Step Functions.

With MetaHub, you can combine security findings from any number of security scanners, regardless of whether findings are duplicated between them or not. This allows you to take advantage of each scanner's strengths, as one scanner may detect a finding that another misses. MetaHub automatically groups and deduplicates your findings by affected resources, enabling you to work with them as a single finding - for example, changing the workflow status of all related findings at once.

<details>
<summary>If you are investigating the security finding <b>[EC2.8]</b> for <b>EC2 Instance i-0a8d32b54be32085e</b>, which indicates that the instance should use Instance Metadata Service Version 2 (IMDSv2), MetaHub can enrich your finding with a wealth of contextual information, including the existence of other security findings for the affected resource, Environment, Classification, Owner, or any other Tagging from your affected resource (MetaTags), Who created it and when (MetaTrails), which Security Groups the instance is associated with, and whether they have unrestricted rules (MetaChecks), which EBSs the instance is associated with, and whether they are encrypted (MetaChecks), if the instance is associated with Auto Scaling Groups, if those Auto Scaling groups are associated to Launch Configurations or Launch Templates (MetaChecks), if the instance is associated with IAM roles (MetaChecks) and if any of the policies attached to that role has issues. You also get IP addresses, DNS domains, and other useful information (MetaChecks). Additionally, MetaHub can determine if the instance is effectively public and effectively encrypted (MetaChecks).
</summary>

```
{
  "arn:aws:ec2:us-east-1:012345678901:instance/i-0a8d32b54be32085e": {
    "findings": [
      "SSM.1 EC2 instances should be managed by AWS Systems Manager",
      "EC2.24 EC2 paravirtual instance types should not be used",
      "EC2.9 EC2 instances should not have a public IPv4 address",
      "EC2.8 EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)",
      "EC2.17 EC2 instances should not use multiple ENIs"
    ],
    "AwsAccountId": "012345678901",
    "AwsAccountAlias": "",
    "Region": "us-east-1",
    "ResourceType": "AwsEc2Instance",
    "metachecks": {
      "it_has_public_ip": "54.91.141.118",
      "it_has_private_ip": "172.11.12.77",
      "it_has_key": "my_service-key",
      "it_has_private_dns": "ip-172-11-12-77.ec2.internal",
      "it_has_public_dns": "ec2-54-91-141-118.compute-1.amazonaws.com",
      "its_associated_with_iam_roles": { ------> The instance is associated with IAM Roles, we drill down to the IAM Roles
        "arn:aws:iam::012345678901:role/ec2/stg-my_service-role-20230416111756821500000001": {
          "its_associated_with_iam_policies": { ------> The IAM Role is associated with IAM Policies, we drill down to the IAM Policies
            "arn:aws:iam::aws:policy/SecurityAudit": {
              "it_has_name": "SecurityAudit",
              "it_has_description": "The security audit template grants access to read security configuration metadata. It is useful for software that audits the configuration of an AWS account.",
              "is_attached": 1,
              "is_customer_managed": false,
              "its_associated_with_iam_groups": false,
              "its_associated_with_iam_users": false,
              "its_associated_with_iam_roles": [
                {
                  "RoleName": "stg-my_service-role-20230416111756821500000001",
                  "RoleId": "AROAUTVHV2BQVMEGGVMFI"
                }
              ],
              "is_principal_cross_account": [],
              "is_principal_wildcard": [],
              "is_unrestricted": [],
              "is_actions_wildcard": []
            }
          },
          "it_has_iam_inline_policies": false,
          "is_unrestricted": false
        }
      },
      "its_associated_with_security_groups": { ------> The instance is associated with Security Groups, we drill down to the Security Groups
        "arn:aws:ec2:us-east-1:012345678901:security-group/sg-001017bf587019b86": {
          "its_associated_with_network_interfaces": [
            "eni-0f86cdb6ced163d60"
          ],
          "its_associated_with_ec2_instances": [
            "i-0a8d32b54be32085e"
          ],
          "its_associated_with_ips_public": [
            "54.91.141.118"
          ],
          "its_associated_with_managed_services": false,
          "its_referenced_by_a_security_group": false,
          "is_ingress_rules_unrestricted": false,
          "is_egress_rules_unrestricted": [
            {
              "SecurityGroupRuleId": "sgr-0a31d5ff5b2b25f23",
              "GroupId": "sg-001017bf587019b86",
              "GroupOwnerId": "012345678901",
              "IsEgress": true,
              "IpProtocol": "udp",
              "FromPort": 53,
              "ToPort": 53,
              "CidrIpv4": "0.0.0.0/0",
              "Tags": []
            },
            {
              "SecurityGroupRuleId": "sgr-00682e51072c40475",
              "GroupId": "sg-001017bf587019b86",
              "GroupOwnerId": "012345678901",
              "IsEgress": true,
              "IpProtocol": "tcp",
              "FromPort": 80,
              "ToPort": 80,
              "CidrIpv4": "0.0.0.0/0",
              "Tags": []
            },
            {
              "SecurityGroupRuleId": "sgr-0a28e73d590555f66",
              "GroupId": "sg-001017bf587019b86",
              "GroupOwnerId": "012345678901",
              "IsEgress": true,
              "IpProtocol": "tcp",
              "FromPort": 443,
              "ToPort": 443,
              "CidrIpv4": "0.0.0.0/0",
              "Tags": []
            }
          ],
          "is_public": false,
          "is_default": false
        }
      },
      "is_instance_metadata_v2": true,
      "is_instance_metadata_hop_limit_1": true,
      "its_associated_with_ebs": [
        "vol-0f9cd9f4fe5142f55",
        "vol-038b595a488a2ab0b"
      ],
      "its_associated_with_ebs_unencrypted": false,
      "its_associated_with_an_asg": "stg-asg",
      "its_associated_with_an_asg_launch_configuration": false,
      "its_associated_with_an_asg_launch_template": {
        "LaunchTemplateId": "lt-0a6809a0720dd2cb7",
        "LaunchTemplateName": "stg-my_service-lt-20230416111759116700000004",
        "Version": "3"
      },
      "is_public": false,
      "is_encrypted": true,
      "is_running": true
    },
    "metatags": {
      "aws:autoscaling:groupName": "stg-asg",
      "environment": "stg",
      "service": "my_service",
      "terraform": "true",
      "aws:ec2launchtemplate:version": "3",
      "aws:ec2launchtemplate:id": "lt-0a6809a0720dd2cb7",
      "Name": "my_service"
    },
    "metatrails": {
      "RunInstances": {
        "Username": "root",
        "EventTime": "2023-04-16 13:58:34+02:00"
      }
    }
  }
}
```
</details>

# Context

In MetaHub, context refers to information not available in the finding itself but necessary to understand it. For example, when investigating a security finding for an EC2 Instance, you may need to know if the instance is effectively public and encrypted, its associations, whether it has unrestricted security groups, if it is associated with IAM roles, or if it has other security findings. MetaHub can enrich your finding with all this information, enabling you to make informed decisions or automate alerting, ownership assignment, forwarding, suppression, severity vs impact definitions, or any other required action.

MetaHub doesn't stop at the affected resource itself; it also analyzes any associated or attached resources. For instance, if there is a security finding on an EC2 instance, MetaHub will not only analyze the instance but also the security groups attached to it, including their rules. MetaHub will examine the IAM roles that the affected resource is using and the policies attached to those roles for any issues. It will analyze the EBS attached to the instance and determine if they are encrypted. It will also analyze the Auto Scaling Groups that the instance is associated with and how. MetaHub will also analyze the VPC, Subnets, and other resources associated with the instance.

# Ownership

MetaHub also focuses on ownership detection. It can determine the owner of the affected resource in various ways. This information can be used to automatically assign a security finding to the correct owner, escalate it, or make decisions based on this information, such as automated remediations.

MetaHub can determine the owner of the affected resource through different methods:

  - With MetaTags (AWS tags)
  - With MetaTrails (AWS CloudTrail)
  - With MetaAccount (Information about the account where the resource is running)
  - With MetaChecks (Information about the resource itself and it's associations)

# Use Cases

You can read the following articles on MetaHub practical use-cases:

- [MetaHub integration with Prowler as a local scanner for context enrichment](https://medium.com/@gabriel_87/metahub-use-cases-part-i-metahub-integration-with-prowler-as-a-local-scanner-for-context-f3540e18eaa1)
- Automatic Security Hub findings suppression using MetaTags
- Utilizing MetaHub as an AWS Security Hub Custom Action
- Generating Custom Enriched Dashboards
- AWS Security Hub Insights based on MetaChecks and MetaTags.

# Features

**MetaHub** provides a range of ways to list and manage AWS Security Hub findings, including investigation, suppression, updating, and integration with other tools or alerting systems. To avoid *Shadowing* and *Duplication*, MetaHub organizes related findings together when they pertain to the same resource. For more information, refer to [Findings Aggregation](#findings-aggregation)

**MetaHub** queries the affected resources directly in the affected account to provide additional context using the following options:

- **MetaTags** (`--meta-tags`): Queries tagging from affected resources
- **MetaTrails** (`--meta-trails`): Queries CloudTrail in the affected account to identify who created the resource and when, as well as any other related critical events
- **MetaChecks** (`--meta-checks`): Fetches extra information from the affected resource, such as whether it is public, encrypted, associated with, or referenced by other resources.
  
MetaHub supports filters on top of these Meta* outputs to automate the detection of other resources with the same issues. For instance, you can list all resources that are effectively public, not encrypted, and tagged as `Environment=production` `Service="My Insecure Service"`. You can use **[MetaChecks](#MetaChecks-1) filters** using the option `--mh-filters-checks` and **[MetaTags](#MetaTags-1) filters** using the option `--mh-filters-tags`. The results of your filters are managed in an aggregate way that allows you to update your findings together when necessary or send them to other tools, such as ticketing or alerting systems. Refer to [Filtering](#Filtering) for more information.

**MetaHub** also supports **AWS Security Hub filtering** the same way you would work with AWS CLI utility using the option `--sh-filters` and using YAML templates with the option `--sh-template`. You can save your favorite filters in YAML templates and reuse them for any integration. You can combine Security Hub filters with Meta Filters together. For more information, refer to [Filtering](#Filtering).

With **MetaHub**, you can back **enrich your findings directly in AWS Security Hub** using the option `--enrich-findings`. This action will update your AWS Security Hub findings using the field `UserDefinedFields`. You can then create filters or [Insights](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-insights.html) directly in AWS Security Hub. Refer to [Enriching Findings](#enriching-findings) for more information.

**MetaHub** also allows you to execute **bulk updates** to AWS Security Hub findings, such as changing Workflow Status using the option `--update-findings`. You can update your queries' output altogether instead of updating each finding individually. When updating findings using MetaHub, you also update the field `Note` of your finding with a custom text for future reference. Refer to [Updating Workflow Status](#updating-workflow-status) for more information.

**MetaHub** supports different **outputs** like **inventory**, **statistics**, **short**, or **full**. All outputs are programmatically usable to be integrated with your favorite tools. Refer to [Outputs](#Outputs). You can export outputs as **JSON**, **CSV**, and **HTML** files using the [Output Modes](#output-modes) options.

**MetaHub** supports **multi-account setups**. You can run the tool from any environment by assuming roles in your AWS Security Hub `master` account and your `child/service` accounts where your resources live. This allows you to fetch aggregated data from multiple accounts using your AWS Security Hub multi-account implementation while also fetching and enriching those findings with data from the accounts where your affected resources live based on your needs. Refer to [Configuring Security Hub](#configuring-security-hub) for more information.

# Run with Python

**MetaHub** is a Python3 program. You need to have Python3 installed in your system and the required python modules described in the file `requirements.txt`.

Requirements can be installed in your system manually (using pip3) or using a Python virtual environment (suggested method).

## Run it using Python Virtual Environment

1. Clone the repository: `git clone git@github.com:gabrielsoltz/metahub.git`
2. Change to repostiory dir: `cd metahub`
3. Create a virtual environment for this project: `python3 -m venv venv/metahub`
4. Activate the virtual environment you just created: `source venv/metahub/bin/activate`
5. Install metahub requirements: `pip3 install -r requirements.txt`
6. Run: `./metahub -h`
7. Deactivate your virtual environment after you finish with: `deactivate`

Next time you only need steps 4 and 6 to use the program.

Alternatively, you can run this tool using Docker. 

# Run with Docker

You can run MetaHub using Docker, either building the docker image locally or using the publicly available image from AWS Registry.

You can set your AWS credentials using environment adding to your docker run command:
```
-e AWS_DEFAULT_REGION -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN
```

## Run it using Public Docker Image
<p align="center">
  <a href="https://gallery.ecr.aws/n2p8q5p4/metahub"><img width="120" height=19" alt="AWS ECR Gallery" src="https://user-images.githubusercontent.com/3985464/151531396-b6535a68-c907-44eb-95a1-a09508178616.png"></a>
</p>

1. Run: `docker run -ti public.ecr.aws/n2p8q5p4/metahub:latest ./metahub -h`
 
## Build and Run Docker locally

1. Clone the repository: `git clone git@github.com:gabrielsoltz/metahub.git`
3. Change to repostiory dir: `cd metahub`
4. Build docker image: `docker build -t metahub .`
5. Run: `docker run -ti metahub ./metahub -h`


# Run with Lambda

**MetaHub** is Lambda/Serverless ready! You can run MetaHub directly on an AWS Lambda function without any additional infrastructure required.

Running MetaHub in a Lambda function allows you to automate its execution based on your defined triggers.

Terraform code is provided for deploying the Lambda function and all its dependencies.

## Lambda use-cases

- Trigger the MetaHub Lambda function each time there is a new AWS Security Hub finding to enrich that finding back in AWS Security Hub.
- Trigger the MetaHub Lambda function each time there is a new AWS Security Hub finding for suppression based on MetaChecks or MetaTags.
- Trigger the MetaHub Lambda function to identify the affected owner of an AWS Security Finding based on MetaTags or MetaTrails and assign that finding to your internal systems.
- Trigger the MetaHub Lambda function to create a ticket with enriched context.

## Customize behaviour

You can customize the Lambda behavior by editing the `lib/lambda.py` file, for example, by adding your filters.

## Deploying Lambda

For deploying the Lambda function:

1. Create a MetaHub Zip package
2. Create a MetaHub layer package
3. Deploy Lambda function

### Create a MetaHub Zip package

You will need to create a zip package for the lambda with MetaHub code, for doing this:

- `cd metahub`
- `zip -r terraform/zip/lambda.zip lib`

### Create a MetaHub layer package

You will need to create a Lambda layer with all MetaHub python dependencies. 

- `cd metahub`
- `mkdir layer`
- `cd layer`
- `mkdir -p python/lib/python3.9/site-packages`
- `pip3 install -r ../requirements.txt --target python/lib/python3.9/site-packages`
- `zip -r9 ../terraform/zip/metahub-layer.zip .`
- `cd ..`
- `rm -r layer`

### Deploy Lambda

You can find the code for deploying the lambda function under the `terraform/` folder.

- `terraform init`
- `terraform apply`


# AWS Authentication

- Ensure you have AWS credentials setup on your local machine (or from where you will run MetaHub).

For example, you can use `aws configure` option. 
  ```sh
  aws configure
  ```

Or you can export your credentials to the environment. 

  ```sh
  export AWS_DEFAULT_REGION="us-east-1"
  export AWS_ACCESS_KEY_ID="ASXXXXXXX"
  export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
  export AWS_SESSION_TOKEN="XXXXXXXXX"
  ```

# Configuring Security Hub

You have three options to configure where and how AWS Security Hub is running:

- `--sh-region`: The AWS Region where Security Hub is running. If you don't specify a region, it will use the one configured in your environment. If you are using AWS Security Hub Cross-Region aggregation, you should use that region as the --sh-region option so that you can fetch all findings together.
- `--sh-account` and `--sh-assume-role`: The AWS Account ID where Security Hub is running and the AWS IAM role to assume in that account. These options are helpful when you are logged in to a different AWS Account than the one where AWS Security Hub is running or when running AWS Security Hub in a multiple AWS Account setup. Both options must be used together. The role provided needs to have enough policies to get and update findings in AWS Security Hub (if needed). If you don't specify a `--sh-account`, MetaHub will assume the one you are logged in.
- You can use the managed policy: `arn:aws:iam::aws:policy/AWSSecurityHubFullAccess` 

## Configuring MetaChecks and MetaTags

- The option `--mh-assume-role` let you configure the role to assume in the affected account when you are using AWS Security Hub in a [Multiple Account setup](#multiple-account-setup) for executing `--meta-checks` and `--meta-tags`.
- For MetaTags, you need the policy: `tag:get_resources`
- For MetaCheks, you can use the managed policy: `arn:aws:iam::aws:policy/SecurityAudit`
- For MetaTrails, you need the policy: `cloudtrail:LookupEvents`
- If you need it to log in and assume a role in the same account, use the options `--mh-assume-role` to specify the role you want to use for `--meta-checks` and `--meta-tags` and the option `--sh-assume-role` for specifying the role you want to assume to read/write from AWS Security Hub.

## Single Account Setup 

- If you are running MetaHub for a single AWS account setup (AWS Security Hub is not aggregating findings from other accounts), you don't need to use any of the assume-role options. Check that your credentials can get_findings from AWS Security Hub (and update them if you want to use the options --update-findings or --enrich-findings) and that you can describe services.
- Still, if your IAM requires it, it is possible to log in and assume a role in the same account. Just use the options `--mh-assume-role` to specify the role and `--sh-account` with the same AWS Account ID where you are logged in. 

## Multiple Account Setup

- If you are running MetaHub for a multiple AWS Account setup (AWS Security Hub is aggregating findings from multiple AWS Accounts), you must provide the role to assume for MetaChecks and MetaTags as the affected resources are not in the same AWS Account that the AWS Security Hub findings. The `--mh-assume-role` will be used to connect with the affected resources directly in the affected account. This role needs to have enough policies for being able to describe resources. 
- If you are logged in to a Master/SSO/Jump AWS Account that you use just for logging in, you then probably need to specify all the options together: `--sh-account` and `--sh-assume-role` for specifying where AWS Security Hub is running and which role to assume, and `--mh-assume-role` to specify which role to assume in the affected AWS Accounts when you are using `--meta-checks` and `--meta-tags`. If you use the same role for AWS Security Hub and the affected AWS Accounts, specify both have the same value.
- You can choose to provide `--sh-account` and `--sh-assume-role` as needed. For example, if you are logged in to the same account as AWS Security Hub, you don't need to assume a role there. But you can if needed. 

# Investigations Examples

## Investigating security findings using Security Hub filters

- List all affected resources by AWS Security Hub findings with default filters (`RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub"`):
```
./metahub --list-findings
```

- Show the statistics output:
```
./metahub --list-findings --outputs statistics
```

- Filter only one resource:
```
./metahub --list-findings --sh-filters RecordState=ACTIVE ResourceId=<<ARN>>
```

- Filter only one AWS Account and show statistics:
```
./metahub --list-findings --sh-filters RecordState=ACTIVE AwsAccountId=<<Account Id>> --outputs statistics
```

## Investigating resources based on MetaTags (Tagging)

- List all affected resources by AWS Security Hub findings and enrich them with MetaTags (Tagging):
```
./metahub --list-findings --meta-tags
```

- Filter only the affected resources that have the Tag "Environment" with the value "Production"
```
./metahub --list-findings --meta-tags --mh-filters-tags Environment=production
```

- Filter only the affected resources that have the Tag "Environment" with the value "Production", which are `HIGH` severity:
```
./metahub --list-findings --sh-filters RecordState=ACTIVE SeverityLabel=HIGH --meta-tags --mh-filters-tags Environment=production
```

## Investigating resources based on MetaChecks

- List all MetaChecks available:
```
./metahub --list-findings --list-meta-checks
```

- List all affected resources by AWS Security Hub findings and enrich them with MetaChecks:
```
./metahub --list-findings --meta-checks
```

- Filter only the affected resources that are effectively public:
```
./metahub --list-findings --meta-checks --mh-filters-checks is_public=True
```

- Show the previous list of affected resources in inventory output:
```
./metahub --list-findings --meta-checks --mh-filters-checks is_public=True --outputs inventory
```

- Filter only the affected resources that are unencrypted:
```
./metahub --list-findings --meta-checks --mh-filters-checks is_encrypted=False
```

- Filter only the affected resources that are unencrypted and have a Tag "Classification" with the value "PI":
```
./metahub --list-findings --meta-checks --mh-filters-checks is_encrypted=False --meta-tags --mh-fiters-tags Classification=PI
```

- Filter only the affected resources that are unencrypted and have a Tag "Classification" with the value "PI" and output a CSV:
```
./metahub --list-findings --meta-checks --mh-filters-checks is_encrypted=True --meta-tags --mh-fiters-tags Classification=PI --output-modes csv
```

## Investigating a finding

- List all affected resources for specific Security Hub findings, for example: `EC2.19 Security groups should not allow unrestricted access to ports with high risk`:
```
./metahub --list-findings --sh-filters RecordState=ACTIVE Title="EC2.19 Security groups should not allow unrestricted access to ports with high risk"
```

- Enable MetaChecks to get more info for those resources:
```
./metahub --list-findings --sh-filters RecordState=ACTIVE Title="EC2.19 Security groups should not allow unrestricted access to ports with high risk" --meta-checks
```

- Filter only the affected resources that are associated with public IPs:
```
./metahub --list-findings --sh-filters RecordState=ACTIVE Title="EC2.19 Security groups should not allow unrestricted access to ports with high risk" --meta-checks --mh-filters-checks its_associated_with_public_ips=True
```

- Update all related AWS Security Findings to `NOTIFIED` with a Note `Ticket ID: 123`:
```
./metahub --list-findings --sh-filters RecordState=ACTIVE Title="EC2.19 Security groups should not allow unrestricted access to ports with high risk" --meta-checks --mh-filters-checks its_associated_with_public_ips=True --update-findings Workflow=NOTIFIED Note="Ticket ID: 123"
```

# Usage

- [Help](#help)
- [Listing Findings](#listing-findings)
- [Security Hub Filters](#security-hub-filters)
- [MetaChecks](#metachecks)
- [MetaTags](#metatags)
- [MetaTrails](#MetaTrails)
- [Updating Findings Workflow Status](#updating-findings-workflow-status)
- [Enriching Findings](#enriching-findings-1)
- [Output Modes](#output-modes)
- [SH House Keeping](#sh-house-keeping)
- [Debug](#debug)

## Help

Show help menu:

```sh
./metahub --help
```

## Listing Findings

Fetch findings with default options (`--sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW`, `--outputs short`, `--output-mode json` and `--input securityhub`):

```sh
./metahub
```

Fetch and list findings (terminal) with default options (`--sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW`, `--outputs short`, `--output-mode json` and `--input securityhub`):

```sh
./metahub --list-findings
```

Fetch and list findings (terminal) with outputs `full` and output-modes `json` and `html`:

```sh
./metahub --list-findings --outputs full --output-modes json html
```

Fetch findings with default filters and outputs `inventory` and `statistics`:

```sh
./metahub --outputs inventory statistics
```

## Security Hub Filters

Read more about [filtering](#Filtering)

Fetch findings with SH filters `SeverityLabel=CRITICAL ResourceType=AwsEc2SecurityGroup ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW` and list (terminal):

```sh
./metahub --list-findings --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL ResourceType=AwsEc2SecurityGroup
```

Fetch findings with SH filters `Id=<<FINDING ARN>>` and list (terminal):

```sh
./metahub --list-findings --sh-filters Id=Id=arn:aws:securityhub:eu-west-1:0123456790:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.9/finding/5f6cb8eb-1234-1234-aa84-01de254ea42c
```

## MetaChecks

Show all available MetaChecks by Resource Type:

```sh
./metahub --list-meta-checks
```

Fetch and list findings (terminal) with default options (`--sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW`, `--outputs short`, `--output-mode json` and `--input securityhub`) with MetaChecks enabled:

```sh
./metahub --list-findings --meta-checks
```

Fetch findings with SH filters `SeverityLabel=CRITICAL ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW` and list (terminal) with MetaChecks enabled and MetaChecks filters `is_public=True`:

```sh
./metahub --list-findings --meta-checks -sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL --mh-filters-checks is_public=True
```

Fetch findings with SH filters `ResourceType=AwsEc2SecurityGroup ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW` and list (terminal) with MetaChecks enabled and MetaChecks filters `its_associated_with_public_ips=True` and outputs `short` and `statistics`:

```sh
./metahub --list-findings --meta-checks --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup --mh-filters-checks its_associated_with_public_ips=True --outputs short statistics
```

## MetaTags

Fetch and list findings (terminal) with default options (`--sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW`, `--outputs short`, `--output-mode json` and `--input securityhub`) with MetaTags enabled:

```sh
./metahub --list-findings --meta-tags
```

Fetch findings with SH filters `SeverityLabel=CRITICAL ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW` and list (terminal) with MetaTags enabled and MetaTags filters `Environment=production`:

```sh
./metahub --list-findings --meta-tags -sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL --mh-filters-tags Environment=production
```

Fetch findings with SH filters `SeverityLabel=CRITICAL ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW` and list (terminal) with MetaTags and MetaChecks enabled and MetaTags filters `Environment=production`:

```sh
./metahub --list-findings --meta-tags -sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL --mh-filters-tags Environment=production --meta-checks
```

## MetaTrails

Fetch and list findings (terminal) with default options (`--sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW`, `--outputs short`, `--output-mode json` and `--input securityhub`) with MetaTrails enabled:

```sh
./metahub --list-findings --meta-trails
```

Fetch and list findings (terminal) with default options (`--sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW`, `--outputs short`, `--output-mode json` and `--input securityhub`) with MetaTrails, MetaChecks and MetaTags enabled:

```sh
./metahub --list-findings --meta-trails --meta-checks --meta-tags
```

## Updating Findings Workflow Status

Fetch findings with SH filters `Title="S3.8 S3 Block Public Access setting should be enabled at the bucket-level" ResourceType=AwsS3Bucket ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW` and list (terminal) with MetaChecks enabled and MetaChecks filters `is_public=False` and update Workflow Status to `SUPPRESSED` with a Note `Suppressing reason: non-public S3 buckets`:

```sh
./metahub --list-findings --meta-checks --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsS3Bucket Title="S3.8 S3 Block Public Access setting should be enabled at the bucket-level" --mh-filters-checks is_public=False --update-findings Note="Suppressing reason: non-public S3 buckets" Workflow=SUPPRESSED
```

> ### Updating Findings Workflow Status (House Keeping Tasks)
>
> If your Security Hub is not cleaning up ARCHIVED, PASSED or NOT_AVAILABLE findings, you can use the following commands:
>

Fetch findings with SH filters `WorkflowStatus=NEW ComplianceStatus=PASSED` and list (terminal) and update Workflow Status to `RESOLVED` with a Note `House Keeping - Move PASSED findings to RESOLVED`:

```sh
./metahub --list-findings --sh-filters WorkflowStatus=NEW ComplianceStatus=PASSED --outputs statistics --update-findings Note="House Keeping - Move PASSED findings to RESOLVED" Workflow=RESOLVED
```

Fetch findings with SH filters `WorkflowStatus=NEW ComplianceStatus=NOT_AVAILABLE` and list (terminal) and update Workflow Status to `RESOLVED` with a Note `Move NOT_AVAILABLE findings to RESOLVED`:

```sh
./metahub --list-findings --sh-filters WorkflowStatus=NEW ComplianceStatus=NOT_AVAILABLE --outputs statistics --update-findings Note="House Keeping - Move NOT_AVAILABLE findings to RESOLVED" Workflow=RESOLVED
```

Fetch findings with SH filters `WorkflowStatus=NEW RecordState=ARCHIVED` and list (terminal) and update Workflow Status to `RESOLVED` with a Note `Move ARCHIVED findings to RESOLVED`:

```sh
./metahub --list-findings --sh-filters WorkflowStatus=NEW RecordState=ARCHIVED --outputs statistics --update-findings Note="House Keeping - Move ARCHIVED findings to RESOLVED" Workflow=RESOLVED
```

## Enriching Findings

Fetch and list findings (terminal) with default options (`--sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW`, `--outputs short`, `--output-mode json` and `--input securityhub`) with MetaTags enabled and enrich them back in AWS Security Hub:

```sh
./metahub --list-findings --meta-tags --enrich-findings
```

## Output Modes

Fetch and list findings (terminal) with default options (`--sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW`, `--outputs short` and `--input securityhub`) with MetaTags and MetaTags filters `Owner=Security` with output-modes `json html csv`

```sh
./metahub --list-findings --meta-tags --mh-filters-tags Owner=Security --output-modes json html csv
```

## Debug

Set Log Level: INFO. 
Options: WARNING, ERROR or DEBUG (Default: ERROR)

```sh
./metahub --log-level INFO
```

# Inputs

MetaHub can read security findings directly from AWS Security Hub or an input file generated by any other scanner in ASFF format. By default, MetaHub will try to fetch from AWS Security Hub. 

If you want to read from an input ASFF file, you need to use the options:: `--inputs file-asff --input-asff path/to/the/file.json.asff`

When using a file as input, you can't use the option `--sh-filters` for filter findings, as this option relies on AWS API for filtering. You can't use the options `--update-findings` or `--enrich-findings` as those findings are not in AWS Security Hub. If you are reading from both sources, only the findings from AWS Security Hub will be updated.

You also can combine AWS Security Hub findings with an input ASFF file specifying both inputs: `--inputs file-asff securityhub --input-asff path/to/the/file.json.asff`


# Outputs

**MetaHub** supports different data outputs using the option `--outputs`. By default, the output is `short`. You can combine more than one output by using spaces between them, for example: `--outputs full inventory`. The outputs you choose will be written to a json file by default (`--output-mode json`), or you can specify other modes. You can enrich these outputs by using [`--meta-checks`](#MetaChecks-1), [`--meta-tags`](#metatags-1) and [`--meta-trails`](#metatrails-1) options.

- [Short](#short)
- [Full](#Full)
- [Inventory](#inventory)
- [Statistics](#statistics)

## Short

The default output. You get the findings title under each affected resource and the `AwsAccountId`, `AwsAccountAlias`, `Region`, and `ResourceType`:

```
  "arn:aws:sagemaker:us-east-1:ofuscated:notebook-instance/ofuscated": {
    "findings": [
      "SageMaker.2 SageMaker notebook instances should be launched in a custom VPC",
      "SageMaker.3 Users should not have root access to SageMaker notebook instances",
      "SageMaker.1 Amazon SageMaker notebook instances should not have direct internet access"
    ],
    "AwsAccountId": "ofuscated",
    "AwsAccountAlias": "ofuscated",
    "Region": "us-east-1",
    "ResourceType": "AwsSageMakerNotebookInstance"
  },
```  


## Full

The full output. Use `--outputs full`. Show all findings with all data. Findings are organized by ResourceId (ARN). For each finding, you will also get: `SeverityLabel`, `Workflow`, `RecordState`, `Compliance`, `Id` and `ProductArn`:

```
  "arn:aws:sagemaker:eu-west-1:ofuscated:notebook-instance/ofuscated": {
    "findings": [
      {
        "SageMaker.3 Users should not have root access to SageMaker notebook instances": {
          "SeverityLabel": "HIGH",
          "Workflow": {
            "Status": "NEW"
          },
          "RecordState": "ACTIVE",
          "Compliance": {
            "Status": "FAILED"
          },
          "Id": "arn:aws:securityhub:eu-west-1:ofuscated:subscription/aws-foundational-security-best-practices/v/1.0.0/SageMaker.3/finding/12345-0193-4a97-9ad7-bc7c1730eec6",
          "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub"
        }
      },
      {
        "SageMaker.2 SageMaker notebook instances should be launched in a custom VPC": {
          "SeverityLabel": "HIGH",
          "Workflow": {
            "Status": "NEW"
          },
          "RecordState": "ACTIVE",
          "Compliance": {
            "Status": "FAILED"
          },
          "Id": "arn:aws:securityhub:eu-west-1:ofuscated:subscription/aws-foundational-security-best-practices/v/1.0.0/SageMaker.2/finding/12345-e8e1-4915-9881-965104b0aabf",
          "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub"
        }
      },
      {
        "SageMaker.1 Amazon SageMaker notebook instances should not have direct internet access": {
          "SeverityLabel": "HIGH",
          "Workflow": {
            "Status": "NEW"
          },
          "RecordState": "ACTIVE",
          "Compliance": {
            "Status": "FAILED"
          },
          "Id": "arn:aws:securityhub:eu-west-1:ofuscated:subscription/aws-foundational-security-best-practices/v/1.0.0/SageMaker.1/finding/12345-3a21-4016-a8e5-f5173b44e90a",
          "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub"
        }
      }
    ],
    "AwsAccountId": "ofuscated",
    "AwsAccountAlias": "ofuscated",
    "Region": "eu-west-1",
    "ResourceType": "AwsSageMakerNotebookInstance"
  },
```

## Inventory

You can use `--outputs inventory` to get only a list of resources' ARNs.

```
[
  "arn:aws:sagemaker:us-east-1:ofuscated:notebook-instance/ofuscated",
  "arn:aws:sagemaker:eu-west-1:ofuscated:notebook-instance/ofuscated"
]
```

## Statistics

You can use `--outputs statistics` to get statistics about your search. You get statistics by each field:

```
{
  "Title": {
    "SageMaker.1 Amazon SageMaker notebook instances should not have direct internet access": 2,
    "SageMaker.2 SageMaker notebook instances should be launched in a custom VPC": 2,
    "SageMaker.3 Users should not have root access to SageMaker notebook instances": 2,
  },
  "SeverityLabel": {
    "HIGH": 6
  },
  "Workflow": {
    "NEW": 6
  },
  "RecordState": {
    "ACTIVE": 6
  },
  "Compliance": {
    "FAILED": 6
  },
  "ProductArn": {
    "arn:aws:securityhub:eu-west-1::product/aws/securityhub": 3,
    "arn:aws:securityhub:us-east-1::product/aws/securityhub": 3
  },
  "ResourceType": {
    "AwsSageMakerNotebookInstance": 6
  },
  "AwsAccountId": {
    "ofuscated": 6
  },
  "AwsAccountAlias": {
    "ofuscated": 6
  },
  "Region": {
    "eu-west-1": 3,
    "us-east-1": 3
  },
  "ResourceId": {
    "arn:aws:sagemaker:eu-west-1:ofuscated:notebook-instance/ofuscated": 3,
    "arn:aws:sagemaker:us-east-1:ofuscated:notebook-instance/ofuscated": 3
  }
}
```

# Output Modes

The default output mode is JSON. MetaHub can also generate rich HTML and CSV reports. You can combine them as you need. The Outputs will be saved in the folder `/outputs` with the execution date.

- [JSON](#json)
- [HTML](#html)
- [CSV](#csv)

## JSON

This is the default output. MetaHub will generate one JSON file for each `--outputs` chosen.

For example: `./metahub --outputs full inventory --meta-tags ` will generate two JSON files, one for full and one for inventory outputs.

## HTML

You can create rich HTML reports of your findings, adding MetaChecks and MetaTags as part of them. Use `--output-modes html`

HTML Reports are interactive in many ways:
- You can add/remove columns.
- You can sort and filter by any column.
- You can auto-filter by any column
- You can group/ungroup findings
- You can also download that data to xlsx, csv, html and json.

> You can customize which MetaChecks and MetaTags to use as column headers using the options `--output-meta-tags-columns` and `--output-meta-checks-columns` as a list of columns. If the MetaChecks or MetaTags you specified as columns don't exist for the affected resource, they will be empty. You need to be running MetaHub with the options `--meta-checks` or `--meta-tags` to be able to fill those columns. If you don't specify columns, all MetaChecks and all MetaTags that appear in your outputs will be used as columns (if they are enabled `--meta-checks --meta-tags`)

For example, you can enable MetaTags and add "Owner" and "Environment" as columns to your report using: 

`./metahub --meta-tags --output-modes html --output-meta-tags-columns Owner Environment`

<p align="center">
  <img src="docs/imgs/html-export.png" alt="html-example"/>
</p>

## CSV

You can create a CSV custom report from your findings, adding MetaChecks and MetaTags as part of them. Use `--output-modes csv`

> You can customize which MetaChecks and MetaTags to use as column headers using the options `--output-meta-tags-columns` and `--output-meta-checks-columns` as a list of columns. If the MetaChecks or MetaTags you specified as columns don't exist for the affected resource, they will be empty. You need to be running MetaHub with the options `--meta-checks` or `--meta-tags` to be able to fill those columns. If you don't specify columns, all MetaChecks and all MetaTags that appear in your outputs will be used as columns (if they are enabled `--meta-checks --meta-tags`)

For example, you can generate two csv outputs, one for full and one for inventory, with MetaTags and MetaChecks enabled, adding columns `is_encrypted` from MetaChecks and `Name` and `Owner` from MetaTags:

`./metahub --outputs full inventory --meta-tags --output-meta-tags-columns Name Owner --meta-checks --output-meta-checks-columns is_encrypted --output-modes csv`

<p align="center">
  <img src="docs/imgs/csv-export.png" alt="csv-example"/>
</p>

# Findings Aggregation

Working with AWS Security Hub findings sometimes introduces the problem of Shadowing and Duplication.

Shadowing is when two checks refer to the same issue, but one in a more generic way than the other one.

Duplication is when you use more than one standard and get the same problem from more than one.

Think of a Security Group with port 3389/TCP open to 0.0.0.0/0.

If you are using one of the default Security Standards like `AWS-Foundational-Security-Best-Practices,` you will get two findings for the same issue:

  - `EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports`
  - `EC2.19 Security groups should not allow unrestricted access to ports with high risk`

If you are also using the standard CIS AWS Foundations Benchmark, you will also get an extra finding:

  - `4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389`

Now imagine that SG is not in use. In that case, Security Hub will show an additional fourth finding for your resource!

  - `EC2.22 Unused EC2 security groups should be removed`

So now you have in your dashboard four findings for one resource!

Suppose you are working with multi-account setups and many resources. In that case, this could result in many findings that refer to the same thing without adding any extra value to your analysis.

## MetaHub aggregation by Affected Resource

**MetaHub** aggregates security findings under the affected resource. MetaHub provides four different outputs, two of which include the findings: `short` (the default one) and `full`. (In addition, you also have `statistics` and `inventory` outputs.)

This is how MetaHub shows the previous example with default output (`short`):

```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
    "EC2.19 Security groups should not allow unrestricted access to ports with high risk",
    "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports",
    "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
    "EC2.22 Unused EC2 security groups should be removed"
  ],
  "AwsAccountId": "01234567890",
  "AwsAccountAlias": "ofuscated",
  "Region": "eu-west-1",
  "ResourceType": "AwsEc2SecurityGroup"
}
```

And this is the `--outputs full`:

```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
    {
      "EC2.19 Security groups should not allow unrestricted access to ports with high risk": {
        "SeverityLabel": "CRITICAL",
        "Workflow": {
          "Status": "NEW"
        },
        "RecordState": "ACTIVE",
        "Compliance": {
          "Status": "FAILED"
        },
        "Id": "arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.22/finding/01234567890-1234-1234-1234-01234567890",
        "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub"
      }
    },
    {
      "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports": {
        "SeverityLabel": "HIGH",
        "Workflow": {
          "Status": "NEW"
        },
        "RecordState": "ACTIVE",
        "Compliance": {
          "Status": "FAILED"
        },
        "Id": "arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.22/finding/01234567890-1234-1234-1234-01234567890",
        "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub"
      }
    },
    {
      "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389": {
        "SeverityLabel": "HIGH",
        "Workflow": {
          "Status": "NEW"
        },
        "RecordState": "ACTIVE",
        "Compliance": {
          "Status": "FAILED"
        },
        "Id": "arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.22/finding/01234567890-1234-1234-1234-01234567890",
        "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub"
      }
    },
    {
      "EC2.22 Unused EC2 security groups should be removed": {
        "SeverityLabel": "MEDIUM",
        "Workflow": {
          "Status": "NEW"
        },
        "RecordState": "ACTIVE",
        "Compliance": {
          "Status": "FAILED"
        },
        "Id": "arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.22/finding/01234567890-1234-1234-1234-01234567890",
        "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub"
      }
    }
  ],
  "AwsAccountId": "01234567890",
  "AwsAccountAlias": "ofuscated",
  "Region": "eu-west-1",
  "ResourceType": "AwsEc2SecurityGroup"
}
```

Your findings are combined under the ARN of the resource affected, ending in only one result or one non-compliant resource.

You can now work in MetaHub with all these four findings together as if they were only one. For example, you can update these four Workflow Status findings using only one command, See [Updating Workflow Status](#updating-workflow-status)

# MetaChecks

On top of the AWS Security Hub findings, **MetaHub** can run additional checks directly on the affected resource in the affected account. We call these, **MetaChecks**. 

**MetaChecks** has the capability to retrieve information from every related resource associated with the affected resource. For instance, when checking an EC2 Instance, MetaChecks can gather information from its associated Security Groups, including details about which ports are open and from where. Additionally, MetaChecks can fetch information from the IAM roles that are linked to the EC2 Instance, including the permissions granted to those roles. 

Each MetaChecks not only answer the MetaCheck question but also provide you with extra information, for example the offending policies or the offending security groups. If a resource is public, it can give you the public entrypoint (ip, dns, endpoint) and the ports open to the public.

You can filter your findings based on MetaChecks output using the option `--mh-filters-checks MetaCheckName=True/False`. See [MetaChecks Filtering](#metachecks-filtering)

If you want to add your MetaChecks, follow this [guide](metachecks.md). Pull requests are more than welcome.

There are two special types of MetaChecks: [Drilled MetaChecks](#drilled-metachecks) and [Magic MetaChecks](#magic-metachecks). Then you have the rest of MetaChecks, we call them standard MetaChecks.

## Drilled MetaChecks

Drilled MetaChecks can connet into the associated resources of the affected resource, for example Security Groups and IAM Roles and Policies. The drilled **MetaChecks** are: `its_associated_with_security_groups`, `its_associated_with_iam_roles`, `its_associated_with_iam_policies`. There are also 2 MetaChecks `it_has_resource_policy` and `it_has_iam_inline_policies` that are not real drilled MetaChecks because they are not drilling in an external associated resoruce, but they are drilling in the resource policy itself so we added them to the list.

### its_associated_with_security_groups

Resources that can be associated with Security Groups are checked by this MetaCheck to provide a comprehensive list of all associated Security Groups. MetaHub will then fetch the rules from these Security Groups to answer the following questions:

-  "is_ingress_rules_unrestricted": You get a list of the ingress rules that are unrestricted.
-  "is_egress_rule_unrestricted": You get a list of the egress rules that are unrestricted.

```
├── affected-resource
│   ├── ...
│   ├── metachecks
│   │   ├── its_associated_with_security_groups
│   │   │   ├── security-group-1
│   │   │   │   └── is_ingress_rules_unrestricted
│   │   │   │       ├── rule-1 (port X open 0.0.0.0/0)
│   │   │   │   └── is_egress_rule_unrestricted
│   │   │   ├── security-group-2
│   │   │   │   └── is_ingress_rules_unrestricted
│   │   │   │   └── is_egress_rule_unrestricted
│   │   │   └── security-group-3
```

```
  "its_associated_with_security_groups": {
    "arn:aws:ec2:eu-west-1:012345678901:security-group/sg-012345678901": {
      "is_ingress_rules_unrestricted": [],
      "is_egress_rule_unrestricted": [
        {
          "SecurityGroupRuleId": "sgr-012345678901",
          "GroupId": "sg-012345678901",
          "GroupOwnerId": "012345678901",
          "IsEgress": true,
          "IpProtocol": "tcp",
          "FromPort": 5432,
          "ToPort": 5432,
          "CidrIpv4": "0.0.0.0/0",
          "Tags": []
        }
      ]
    }
  },
```

### its_associated_with_iam_roles

Resources that can be associated with IAM Roles are checked by this MetaCheck to provide all the associated IAM Roles, and from every role it will fetch the IAM policies to answer the following questions:

- "is_principal_wildcard": If the policy principal is defined as a wildcard (*)
- "is_principal_cross_account": If the policy principal is defined as a cross account
- "is_principal_external": If the policy principal is defined as an external account (not in the same organization)
- "is_actions_wildcard": If the policy actions are defined as a wildcard (*)

```
├── affected-resource
│   ├── ...
│   ├── metachecks
│   │   ├── its_associated_with_iam_roles
│   │   │   ├── role-1
│   │   │   │   ├── its_associated_with_iam_policies
│   │   │   │       ├── policy-a
│   │   │   │       │       ├── is_principal_wildcard
│   │   │   │       │       │   ├── statement-1
│   │   │   │       │       ├── is_principal_cross_account
│   │   │   │       │       │   ├── statement-cross-account
│   │   │   │       │       ├── is_principal_external
│   │   │   │       │       │   ├── statement-external
│   │   │   │       │       ├── is_public
│   │   │   │       │       │   ├── statement-public
│   │   │   │       │       ├── is_actions_wildcard
│   │   │   │       │       │   ├── statement-actions-wildcard
│   │   │   ├── role-2
│   │   │   └── role-3
```

```
  "its_associated_with_iam_roles": {
    "arn:aws:iam::0123456789012:role/security-role": {
      "its_associated_with_iam_policies": {
        "arn:aws:iam::0123456789012:policy/policy-a": {
            "is_principal_wildcard": [],
            "is_principal_cross_account": [],
            "is_principal_external": [],
            "is_public": [],
            "is_actions_wildcard": []
          },
        },
        "arn:aws:iam::0123456789012:policy/policy-b": {
            "is_principal_wildcard": [],
            "is_principal_cross_account": [],
            "is_principal_external": [],
            "is_public": [],
            "is_actions_wildcard": []
          },
        },
```

### its_associated_with_iam_policies

TBD

### it_has_resource_policy

Resources that can have a resource policy are checked by this MetaCheck to analyze it policy to answer the following questions:

- "is_principal_wildcard": If the policy principal is defined as a wildcard (*)
- "is_principal_cross_account": If the policy principal is defined as a cross account
- "is_principal_external": If the policy principal is defined as an external account (not in the same organization)
- "is_actions_wildcard": If the policy actions are defined as a wildcard (*)

```
├── affected-resource
│   ├── ...
│   ├── metachecks
│   │   ├── it_has_resource_policy
│   │   │    └── is_principal_wildcard
│   │   │         ├── statement-wildcard
│   │   │     └── is_principal_cross_account
│   │   │         ├── statement-cross-account
│   │   │     └── is_principal_external
│   │   │         ├── statement-external
│   │   │     └── is_public
│   │   │         ├── statement-public
│   │   │     └── is_actions_wildcard
│   │   │         ├── statement-actions-wildcard
```

```
      "it_has_resource_policy": {
          "is_principal_wildcard": [],
          "is_principal_cross_account": [
            {
              "Sid": "permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::0123456789012:root"
              },
              "Action": "s3:*",
              "Resource": [
                "arn:aws:s3:::bucket-name",
                "arn:aws:s3:::bucket-name/*"
              ]
            }
          ],
          "is_principal_external": [],
          "is_public": [],
          "is_actions_wildcard": [
            {
              "Sid": "permissions",
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::0123456789012:root"
              },
              "Action": "s3:*",
              "Resource": [
                "arn:aws:s3:::bucket-name",
                "arn:aws:s3:::bucket-name/*"
              ]
            }
          ]
        },
      },
```

### it_has_iam_inline_policies

TBD

## Magic MetaChecks

**MetaHub** provides a set of **MetaChecks** called "magic" that are defined across all resources. These **MetaChecks** are useful for filtering all resources in the same way. The magic **MetaChecks** are: `is_public`, `is_unrestricted`, `is_encrypted`, and `is_attached`. If any of these magic MetaChecks are not applicable for a particular resource, they will be `False`.

You can use these **MetaChecks** to filter across all resource types based on specific criteria. For instance, you can filter all resources that are public using the **MetaCheck** `is_public` (`./metahub --mh-filters-checks is_public=True`), or you can filter all resources that are public and not encrypted using the **MetaCheck** `is_public` and `is_encrypted` (`./metahub --mh-filters-checks is_public=True is_encrypted=False`).

### is_public

This **MetaCheck** refers to the network accessibility of a resource. A resource must be effectively public, meaning that if a resource has a public IP, but the security group is closed, the resource is not considered public.

This **MetaCheck** answer with the public endpoint of the resource and the ports that are open.

For example: 

```
"100.100.100.100": [
  {
    "from_port": 80, 
    "to_port": 80, 
    "ip_protocol": tcp
  },
  {
    "from_port": 3389, 
    "to_port": 3389, 
    "ip_protocol": tcp
  }
]
```

You can use the output of this MetaCheck to integrate with other network scanning tools like Nmap.

### is_unrestricted

This **MetaCheck** refers to the policy of a resource. A resource must be effectively unrestricted, meaning that if a resource has a policy that allows all actions and all principals, but it has a condition, the resource is not considered unrestricted. Examples of unrestricted resources include S3 Buckets, SQS Queues, SNS Topics, and more.

### is_encrypted

This **MetaCheck** refers to the encryption of a resource. If the resource supports both at-rest and in-transit encryption, both must be effectively encrypted. For example, if an ElasticSearch cluster is encrypted at rest but not in transit, the resource is not considered encrypted.

If a resource is associated with another resource, such as an EC2 Instance attached to an EBS Volume, the resource is considered encrypted if the associated resource is encrypted.

### is_attached

This **MetaCheck** refers to the attachment of a resource. If the resource supports attachments, it must be effectively attached. Examples of attached resources include Security Groups, IAM Roles, and Subnets.

## List of MetaChecks

| TYPE               | MetaCheck                                       | AwsAutoScalingLaunchConfiguration | AwsEc2Instance    | AwsEc2LaunchTemplate | AwsEc2NetworkAcl | AwsEc2SecurityGroup | AwsEksCluster     | AwsElastiCacheCacheCluster | AwsElasticsearchDomain | AwsIamPolicy      | AwsLambdaFunction | AwsRdsDbCluster   | AwsRdsDbInstance  | AwsS3Bucket       | AwsSnsTopic | AwsSqsQueue | AwsIamRole |
|--------------------|-------------------------------------------------|-----------------------------------|-------------------|----------------------|------------------|---------------------|-------------------|----------------------------|------------------------|-------------------|-------------------|-------------------|-------------------|-------------------|-------------|-------------|------------|
| Drilled MetaCheck  | its_associated_with_security_groups             | YES                               | YES               | YES                  | -                | DRILLED             | YES               | YES                        | YES                    | -                 | YES               | YES               | YES               | -                 | -           | -           | -          |
|                    | ├─ its_associated_with_network_interfaces       |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ its_associated_with_ec2_instances            |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ its_associated_with_ips_public               |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ its_associated_with_managed_services         |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ its_referenced_by_a_security_group           |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ is_ingress_rules_unrestricted                |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ is_egress_rules_unrestricted                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ is_public                                    |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | └─ is_default                                   |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    |                                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Drilled MetaCheck  | its_associated_with_iam_roles                   | YES                               | YES               | YES                  | -                | -                   | YES               | -                          | -                      | YES (Not Drilled) | YES               | YES               | YES               | -                 | -           | -           | DRILLED    |
|                    | ├─ it_has_iam_inline_policies                   |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ is_principal_wildcard                       |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ is_principal_cross_account                  |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ is_principal_external                       |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├└─ is_actions_wildcard                         |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ its_associated_with_iam_policies             |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ it_has_name                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ it_has_description                          |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ is_attached                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ is_customer_managed                         |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ its_associated_with_iam_groups              |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ its_associated_with_iam_users               |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ its_associated_with_iam_roles               |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ is_principal_cross_account                  |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├├─ is_unrestricted                             |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├└─ is_actions_wildcard                         |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | └─  is_unrestricted                             |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    |                                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Drilled MetaCheck  | its_associated_with_iam_policies                | -                                 | -                 | -                    | -                | -                   | -                 | -                          | -                      | DRILLED           | -                 | -                 | -                 | -                 | -           | -           | YES        |
|                    | ├─ it_has_name                                  |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ it_has_description                           |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ is_attached                                  |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ is_customer_managed                          |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ its_associated_with_iam_groups               |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ its_associated_with_iam_users                |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ its_associated_with_iam_roles                |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ is_principal_cross_account                   |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ is_unrestricted                              |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | └─ is_actions_wildcard                          |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    |                                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Drilled MetaCheck  | it_has_resource_policy                          | -                                 | -                 | -                    | -                | -                   | -                 | -                          | YES                    | -                 | YES               | -                 | -                 | YES               | YES         | YES         | -          |
|                    | ├─ is_principal_cross_account                   |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ is_principal_wildcard                        |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | ├─ is_unrestricted                              |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | └─ is_actions_wildcard                          |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    |                                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Magic MetaCheck    | is_public                                       | YES (True/False)                  | YES (public_dict) | YES (True/False)     | YES (True/False) | YES (public_dict)   | YES (public_dict) | YES (public_dict)          | YES (public_dict)      | -                 | YES (public_dict) | YES (public_dict) | YES (public_dict) | YES (public_dict) | -           | -           | -          |
| Magic MetaCheck    | is_unrestricted                                 | -                                 | -                 | -                    | -                | -                   | -                 | -                          | YES                    | YES               | YES               | -                 | -                 | YES               | YES         | YES         | YES        |
| Magic MetaCheck    | is_encrypted                                    |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Magic MetaCheck    | is_attached                                     |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    |                                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | is_instance_metadata_v2                         | X                                 | X                 | X                    |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | is_instance_metadata_hop_limit_1                | X                                 | X                 | X                    |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    |                                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | its_associated_with_an_asg                      |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | its_associated_with_asg_instances               | X                                 | X                 | X                    |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | its_associated_with_an_asg_launch_configuration |                                   | X                 |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | its_associated_with_an_asg_launch_template      |                                   | X                 |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    |                                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | its_associated_with_ebs                         |                                   | X                 |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | its_associated_with_ebs_unencrypted             |                                   | X                 |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    |                                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | its_associated_with_vpc                         |                                   |                   |                      |                  |                     |                   |                            | X                      |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | its_associated_with_subnets                     |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    |                                                 |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
| Standard MetaCheck | it_has_public_endpoint                          |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |
|                    | it_has_public                                   |                                   |                   |                      |                  |                     |                   |                            |                        |                   |                   |                   |                   |                   |             |             |            |


## MetaChecks Naming

MetaChecks are defined in the form of:

- [is_](#is_)
- [its_associated_with_](#its_associated_with)
- [it_has_](#it_has)
- [its_referenced_by_](#its_referenced_by)

### is_

> Refers to the affected resource itself.

Examples:

- is_running
- is_default

### its_associated_with

> Resources that are independent (they have their own ARN) and are associated with the affected resource. When `True` returns `something_its_associated_with` in the form of a list of ARNs or a dictionary if there is a drilled MetaCheck available which is checking the associated resource.

Examples:

- its_associated_with_subnets
- its_associated_with_security_groups
- its_associated_with_iam_roles
- its_associated_with_iam_policies
- its_associated_with_its_associated_with_vpc

### it_has

> Properties that only exist as part of the affected resource. When `True` returns a list of `something_it_has`.

Examples:

- it_has_bucket_acl_cross_account
- it_has_public_endpoint

### its_referenced_by

> These are resources that have their own ARN and reference the affected resource without being directly associated with it. When `True` returns a list of `something_that_is_referencing_the_affected_resource`...

Examples:

- its_referenced_by_a_security_group


# MetaTags

**MetaHub** relies on [AWS Resource Groups Tagging API](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/overview.html) to query the tags associated with your resources by using the option `--meta-tags.`

Note that not all AWS resource type supports this API. You can check [supported services](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/supported-services.html).

Tags are a crucial part of understanding your context. Tagging strategies often include: 
- Environment (like Production, Staging, Development, etc.)
- Data classification (like Confidential, Restricted, etc.)
- Owner (like a team, a squad, a business unit, etc.)
- Compliance (like PCI, SOX, etc.)

If you follow a proper tagging strategy, you can filter and generate interesting outputs. For example, you could list all findings related to a specific team and provide that data directly to that team.

`./metahub --list-findings --sh-filters ResourceId=arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890 --meta-tags`

```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
  ...
  ],
  "AwsAccountId": "01234567890",
  "AwsAccountAlias": "ofuscated",
  "Region": "eu-west-1",
  "ResourceType": "AwsEc2SecurityGroup",
  "metatags": {
    "Name": "testSG",
    "Environment": "Production",
    "Classification": "Restricted",
    "Owner": "Security Team"
  }
}
```

So now, in addition to the `findings` section, we have an extra section, `metatags.` Each entry combines the Tag and Value associated with the affected resource.

You can filter your findings based on MetaTags output using the option `--mh-filters-tags Tag=Value`. See [MetaTags Filtering](#metatags-filtering)

# MetaTrails

MetaTrails queries CloudTrail in the affected account to identify critical events related to the affected resource, such as creating events, using the option `--meta-trails`.


```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
  ...
  ],
  "AwsAccountId": "01234567890",
  "AwsAccountAlias": "ofuscated",
  "Region": "eu-west-1",
  "ResourceType": "AwsEc2SecurityGroup",
  "metatrails": {
    "AuthorizeSecurityGroupIngress": {
      "Username": "root",
      "EventTime": "2023-02-25 15:35:21-03:00"
    },
    "CreateSecurityGroup": {
      "Username": "root",
      "EventTime": "2023-02-25 15:35:21-03:00"
    }
  }
}
```

For this resource type, you get two critical events:

- `CreateSecurityGroup`: Security Group Creation
- `AuthorizeSecurityGroupIngress`: Security Group Rule Creation

You can add/modify the critical events for each resource type by editing the configuration file: `config/resources.py`

# Filtering

You can filter the findings and resources that you get from Security Hub in different ways and combine all of them to get exactly what you are looking for, then re-use those filters to create alerts.

- [Security Hub Filtering using YAML templates](#security-hub-filtering-using-yaml-templates)
- [Security Hub Filtering](#security-hub-filtering)
- [MetaChecks Filtering](#metachecks-filtering)
- [MetaTags Filtering](#metatags-filtering)

## Security Hub Filtering using YAML templates

**MetaHub** lets you create complex filters using YAML files (templates) that you can reuse when needed. YAML templates let you write filters using any comparison supported by AWS Security Hub like `'EQUALS'|'PREFIX'|'NOT_EQUALS'|'PREFIX_NOT_EQUALS'`. You can call your YAML file using the option `--sh-template <<FILE>>`.

You can find examples under the folder [templates](templates)

- Filter using YAML template default.yml:
```sh
./metaHub --list-findings --sh-template templates/default.yml
```

## Security Hub Filtering

MetaHub supports filtering AWS Security Hub findings in the form of `KEY=VALUE` filtering for AWS Security Hub using the option `--sh-filters`, the same way you would filter using AWS CLI but limited to the `EQUALS` comparison. If you want another comparison, use the option `--sh-template` [Security Hub Filtering using YAML templates](#security-hub-filtering-using-yaml-templates).

You can check available filters in [AWS Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html#SecurityHub.Client.get_findings)

```sh
./metahub --list-findings --sh-filters <KEY=VALUE>
```
If you don't specify any filters, defaults filters are applied: `ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW`

Passing filters using this option resets the default filters. If you want to add filters to the defaults, you need to specify them in addition to the default ones. For example, adding SeverityLabel to the defaults filters:

```sh
./metahub --list-findings --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW
```
If a value contains spaces, you should specify it using double quotes: `ProductName="Security Hub"`

You can add how many different filters you need to your query and also add the same filter key with different values:

Examples:

- Filter by Severity (CRITICAL):
```sh
./metaHub --list-findings --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL
```
- Filter by Severity (CRITICAL and HIGH):
```sh
./metaHub --list-findings --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL SeverityLabel=HIGH
```
- Filter by Severity and AWS Account:
```sh
./metaHub --list-findings --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL AwsAccountId=1234567890
```
- Filter by Check Title:
```sh
./metahub --list-findings --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW Title="EC2.22 Unused EC2 security groups should be removed"
```
- Filter by AWS Resource Type:
```sh
./metahub --list-findings --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup
```
- Filter by Resource Id:
```sh
./metahub --list-findings --sh-filters ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW ResourceId="arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890"
```
- Filter by Finding Id:
```sh
./metahub --list-findings --sh-filters Id="arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.19/finding/01234567890-1234-1234-1234-01234567890"
```
- Filter by Compliance Status:
```sh
./metahub --list-findings --sh-filters ComplianceStatus=FAILED
```

## MetaChecks Filtering

**MetaHub** supports **MetaChecks filters** in the form of `KEY=VALUE` where the value can only be `True` or `False` using the option `--mh-filters-checks`. You can use as many filters as you want and separate them using spaces. If you specify more than one filter, you will get all resources that match **all** filters.

MetaChecks filters only support `True` or `False` values:
- A MetaChecks filter set to **True** means `True` or with data.
- A MetaChecks filter set to **False** means `False` or without data.

You must enable MetaChecks to filter by them with the option `--meta-checks`.

MetaChecks filters run after AWS Security Hub filters:

1. MetaHub fetches AWS Security Findings based on the filters you specified using `--sh-filters` (or the default ones).
2. MetaHub executes MetaChecks for the AWS affected resources based on the previous list of findings
3. MetaHub only shows you the resources that match your `--mh-filters-checks`, so it's a subset of the resources from point 1.

Examples:

- Get all Security Groups (`ResourceType=AwsEc2SecurityGroup`) with AWS Security Hub findings that are ACTIVE and NEW (`RecordState=ACTIVE WorkflowStatus=NEW`) only if they are associated to Network Interfaces (`its_associated_with_network_interfaces=True`):
```sh
./metahub --list-findings --meta-checks --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup --mh-filters-checks its_associated_with_network_interfaces=True
```

- Get all S3 Buckets (`ResourceType=AwsS3Bucket`) only if they are public (`is_public=True`):
```sh
./metahub --list-findings --meta-checks --sh-filters ResourceType=AwsS3Bucket --mh-filters-checks is_public=False
```

- Get all Security Groups that are unused (`Title="EC2.22 Unused EC2 security groups should be removed" RecordState=ACTIVE ComplianceStatus=FAILED`) and are not referenced by other security groups (`its_referenced_by_another_sg=False`) (ready to be removed):
```sh
./metahub --list-findings --sh-filters Title="EC2.22 Unused EC2 security groups should be removed" RecordState=ACTIVE ComplianceStatus=FAILED --meta-checks --mh-filters-checks its_referenced_by_another_sg=False
```

You can list all available MetaChecks using `--list-meta-checks`

## MetaTags Filtering

**MetaHub** supports **MetaTags filters** in the form of `KEY=VALUE` where KEY is the Tag name and value is the Tag Value. You can use as many filters as you want and separate them using spaces. Specifying multiple filters will give you all resources that match **at least one** filter.

You need to enable MetaTags to filter by them with the option `--meta-tags`.

MetaTags filters run after AWS Security Hub filters:

1. MetaHub fetches AWS Security Findings based on the filters you specified using `--sh-filters` (or the default ones).
2. MetaHub executes MetaTags for the AWS affected resources based on the previous list of findings
3. MetaHub only shows you the resources that match your `--mh-filters-tags`, so it's a subset of the resources from point 1.

Examples:

- Get all Security Groups (`ResourceType=AwsEc2SecurityGroup`) with AWS Security Hub findings that are ACTIVE and NEW (`RecordState=ACTIVE WorkflowStatus=NEW`) only if they are tagged with a tag `Environment` and value `Production`:
```sh
./metahub --list-findings --meta-tags --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup --mh-filters-tags Environment=Production
```

# Updating Workflow Status

You can use **MetaHub** to update your AWS Security Findings Workflow Status in bulk. You will use the option `-update-findings' to update all the findings realted to your filters. This means you can update one, ten, or thousands of findings using only one command.

For example, using the following filter: `./metahub --list-findings --sh-filters ResourceType=AwsSageMakerNotebookInstance RecordState=ACTIVE WorkflowStatus=NEW` I found two affected resources with three finding each making six security hub findings in total.

Running the following update command will update those six findings' workflow status to `NOTIFIED` with a Note:

```sh
--update-findings Workflow=NOTIFIED Note="Enter your ticket id or reason here as a note that you will add to the finding as part of this update"
```

<p align="center">
  <img src="docs/imgs/update-findings-1.png" alt="update-findings" width="850"/>
</p>

<p align="center">
  <img src="docs/imgs/update-findings-2.png" alt="update-findings" width="850"/>
</p>

Workflow Status options are: `NOTIFIED`, `NEW`, `RESOLVED`, and `SUPPRESSED`

AWS Security Hub API is limited to 100 findings per update. Metahub will split your results into 100 items chucks to avoid this limitation and update your findings beside the amount.

See more examples under [Updating Findings Workflow Status](#updating-findings-workflow-status)

# Enriching Findings

You can use **MetaHub** to enrich your AWS Security Findings with `MetaTags` and `MetaChecks` outputs. Enriching your findings means updating those findings directly in Security Hub. **MetaHub** uses the `UserDefinedFields` field to add all the MetaChecks and MetaTags available for the affected resource.

By enriching your findings directly in AWS Security Hub, you can take advantage of features like Insights and Filters by using the extra information that was not available in Security Hub before. 

For example, you want to enrich all AWS Security Hub findings with `WorkflowStatus=NEW`, `RecordState=ACTIVE`, and `ResourceType=AwsS3Bucket` that are MetaCheck i`s_public=True` with MetaChecks and MetaTags:

```sh
./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsS3Bucket --meta-tags --meta-checks --mh-filters-checks is_public=True --enrich-findings  
```

<p align="center">
  <img src="docs/imgs/enrich-findings-1.png" alt="update-findings" width="850"/>
</p>
