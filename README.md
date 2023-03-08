# MetaHub

<p align="center">
  <img src="docs/imgs/metahub.png" alt="MetaHub" width="200"/>
</p>

<p align="center">
  <b>MetaHub</b> is the command line utility for ASFF and AWS Security Hub.
</p>

# Table of Contents

- [Description](#description)
- [Features](#features)
- [Examples](#investigations-examples)
- [Run with Python](#run-with-python)
- [Run with Docker](#run-with-docker)
- [Run with Lambda](#run-with-lambda)
- [AWS Authentication](#aws-authentication)
- [Configuring Security Hub](#configuring-security-hub)
- [Usage](#usage)
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

**MetaHub** is an [ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) security context enrichment and command line utility for [AWS Security Hub](https://aws.amazon.com/security-hub). 

Using **MetaHub**, you can enrich your security findings with **your** context to use that context for filtering, deduplicating, grouping, reporting, automating, suppressing, or updating and enrichment directly in AWS Security Hub. **MetaHub** interacts with reading/writing from AWS Security Hub API or directly from ASFF files. You can combine these sources as you want to enrich your findings further.

<p align="center">
  <img src="docs/imgs/diagram-metahub.drawio.png" alt="Diagram" width="850"/>
</p>


**MetaHub** aggregates and deduplicates your findings by affected resources, no matter what amount of scanners, to focus on fixing the real problems, not the findings themselves.

If you are investigating the security finding **EC2.19 Security groups should not allow unrestricted access to ports with high risk** for Security Group **sg-0880509d75f330c7f**, MetaHub can enrich your finding with the following information from your context:

- If there are other security findings for the affected resource
- The Environment, Classification, Owner, or any other Tagging from your affected resource (**MetaTags**)
- Who created and when (**MetaTrails**)
- If another service references the Security Group (**MetaChecks**):
  - `its_referenced_by_another_sg`
- What is the Security Group associated with (**MetaChecks**):
  - `its_associated_with_network_interfaces`
  - `its_associated_with_ec2_instances`
  - `its_associated_with_managed_services`
- If the Security Group is Public and how (**MetaChecks**):
  - `its_associated_with_public_ips`
  - `it_has_rules_unrestricted`
  - `is_public`

```
  "arn:aws:ec2:us-east-1:012345678901:security-group/sg-0880509d75f330c7f": {
    "findings": [
      "EC2.19 Security groups should not allow unrestricted access to ports with high risk",
      "Security groups should only allow unrestricted incoming traffic for authorized ports",
      "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports",
    ],
    "AwsAccountId": "012345678901",
    "AwsAccountAlias": "AccountA",
    "Region": "us-east-1",
    "ResourceType": "AwsEc2SecurityGroup",
    "metachecks": {
      "its_associated_with_network_interfaces": [
        "eni-0722ce7f253e8c9e0"
      ],
      "its_associated_with_ec2_instances": [
        "i-0b57aa16e1d0c6bbd"
      ],
      "its_associated_with_ips_public": [
        "55.93.78.x"
      ],
      "its_associated_with_managed_services": false,
      "its_referenced_by_another_sg": false,
      "it_has_rules_unrestricted": [
        {
          "SecurityGroupRuleId": "sgr-0cb04c3cb0a14df23",
          "GroupId": "sg-0880509d75f330c7f",
          "GroupOwnerId": "012345678901",
          "IsEgress": false,
          "IpProtocol": "tcp",
          "FromPort": 22,
          "ToPort": 22,
          "CidrIpv4": "0.0.0.0/0",
          "Tags": []
        }
      ],
      "is_public": true,
      "is_default": false
    },
    "metatags": {
      "Name": "Testing Security Group",
      "Environment": "Production",
      "Classification": "Restricted",
      "Owner": "Security Team"
    },
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
}
```

# Features

**MetaHub** introduces different **ways of listing AWS Security Hub findings** for investigation, suppression, updating, and integrating with other tools or alerting systems. MetaHub focuses on avoiding **Shadowing** and **Duplication** by organizing the findings together when they are related to the same resource. See [Findings Aggregation](#findings-aggregation)

**MetaHub** queries the affected resources in the affected account directly to add extra information from your context using: 

  - **MetaTags** (`--meta-tags`): MetaTags queries tagging from affected resources 
  - **MetaTrails** (`--meta-trails`): MetaTrails queries CloudTrail in affected account to identify who and when created the resource and any other related critical event 
  - **MetaChecks** (`--meta-checks`): MetaChecks fetches extra information from the affected resource like, if it is public?, is encrypted? is associated with...?, is referenced by...?, it has..?
  
**MetaHub** supports filters on top of these Meta* outputs to automate detecting other resources with the same issues. For example, listing all resources that are effectively public, not encrypted, and are tagged as `Environment=production Service="My Insecure Service"`. See [MetaChecks](#MetaChecks-1) and [MetaTags](#MetaTags-1). You can use **MetaChecks filters** using the option `--mh-filters-checks` and **MetaTags filters** using the option `--mh-filters-tags`. The result of your filters is then managed in an aggregate way that lets you update your findings all together when it's necessary or send them to other tools like ticketing or alerting systems. See [Filtering](#Filtering)

**MetaHub** also supports **AWS Security Hub filtering** the same way you would work with AWS CLI utility using the option `--sh-filters` and using YAML templates with the option `--sh-template`. YAML templates let you save your favorite filters and re-use them when you need them for any integration. You can combine Security Hub filters with Meta Filters together. See [Filtering](#Filtering). 

**MetaHub** lets you back enrich your findings directly in AWS Security Hub using the option `--enrich-findings`. This action will update your AWS Security Hub findings using the field `UserDefinedFields`. You can then create filters or insights directly in AWS Security Hub. See [Enriching Findings](#enriching-findings)

**MetaHub** lets you execute **bulk updates** to AWS Security Hub findings, like changing Workflow Status using the option (`--update-findings`). You can update your queries' output altogether instead of by one-by-one findings. When updating findings using MetaHub, you also update the field `Note` of your finding with a custom text for future reference. See [Updating Workflow Status](#updating-workflow-status)

**MetaHub** supports different **outputs** like `inventory`, `statistics`, `short`, or `full`. All outputs are programmatically usable to be integrated with your favorite tools. See [Outputs](#Outputs). Outputs can be exported as JSON, CSV, and HTML files using the [Output Modes](#output-modes) options.

**MetaHub** supports **multi-account setups**, letting you run the tool from any environment by assuming roles in your AWS Security Hub master account and your child/service accounts where your resources live. This allows you to fetch aggregated data from multiple accounts using your AWS Security Hub master implementation while also fetching and enriching those findings with data from the accounts where your affected resources live based on your needs. See [Configuring Security Hub](#configuring-security-hub)

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

MetaHub is Lambda/Serverless ready! You can run MetaHub directly on a Lambda function without any other Infra required. 

Running MetaHub in a Lambda function lets you automate its execution based on your defined triggers or even manually. 

Terraform code is provided for deploying the lambda and all its dependencies. 

## Lambda use-cases

- Trigger MetaHub lambda function each time there is a new AWS Security Hub finding to enrich that finding back in AWS Security Hub
- Trigger MetaHub lambda function each time there is a new AWS Security Hub finding for suppressing based on MetaChecks or MetaTags
- Trigger MetaHub lambda for identifying AWS Security Finding affected-owner based on MetaTags or MetaTrails and assign that finding to your internal systems
- Trigger MetaHub lambda function for creating a ticket with enriched context

## Customize behaviour

You can customize Lambda behaviour by editing the file `lib/lambda.py`, for example adding your filters.

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
- `zip -r9 terraform/zip/metahub-layer.zip .`
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

You can use three options to configure where and how AWS Security Hub is running:

- `--sh-region`: The AWS Region where Security Hub is running. If you don't specify any region, it will use the one configured in your environment. If you are using [AWS Security Hub Cross-Region aggregation](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html), you should use that region as the `--sh-region` option so that you can fetch all findings together. 
- `--sh-account` and `--sh-assume-role`: The AWS Account ID where Security Hub is running (`--sh-account`) and the AWS IAM role to assume in that account (`--sh-assume-role`). These options are helpful when you are logged in to a different AWS Account than the one where AWS Security Hub is running or when running AWS Security Hub in a multiple AWS Account setup. Both options must be used together. The role provided needs to have enough policies to get and update findings in AWS Security Hub (if needed). If you don't specify a `--sh-account`, MetaHub will assume the one you are logged in.
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

Think again about that Security Group. Let's assume it's associated, so we have three AWS Security Hub findings combined in one MetaHub result:

```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
    "EC2.19 Security groups should not allow unrestricted access to ports with high risk",
    "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports",
    "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
  ],
  "AwsAccountId": "01234567890",
  "AwsAccountAlias": "ofuscated",
  "Region": "eu-west-1",
  "ResourceType": "AwsEc2SecurityGroup"
}
```

Can we go further based on the findings and get more information? For example, check what this Security Group is associated with, if it's public or not, if it's referenced by any other resource, and get all this information together in the same simple output that MetaHub provides and even filter on top of that information.

Let's rerun MetaHub for the previous finding with MetaChecks enabled:

`./metahub --list-findings --sh-filters ResourceId=arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890 --meta-checks`

```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
  ...
  ],
  "AwsAccountId": "01234567890",
  "AwsAccountAlias": "ofuscated",
  "Region": "eu-west-1",
  "ResourceType": "AwsEc2SecurityGroup",
  "metachecks": {
    "its_associated_with_network_interfaces": [
      "eni-01234567890",
      "eni-01234567891",
      "eni-01234567892",
      "eni-01234567893",
      "eni-01234567894"
    ],
    "its_associated_with_ec2_instances": [
      "i-01234567899",
      "i-01234567898",
      "i-01234567897",
      "i-01234567896",
      "i-01234567895",
      "i-01234567894"
    ],
    "its_associated_with_public_ips": [
      "200.200.200.200"
    ],
    "its_associated_with_managed_services": false,
    "its_referenced_by_another_sg": [
      "sg-02222222222",
      "sg-03333333333"
    ],
    "it_has_rules_unrestricted": [
      {
        "SecurityGroupRuleId": "sgr-01234567899",
        "GroupId": "sg-01234567899",
        "GroupOwnerId": "01234567899",
        "IsEgress": false,
        "IpProtocol": "tcp",
        "FromPort": 3389,
        "ToPort": 3389,
        "CidrIpv4": "0.0.0.0/0",
        "Tags": []
      }
      ],
      "is_public": true,
      "is_default": false
  }
}
```

So now, in addition to the `findings` section, we have an extra section, `metachecks.` 

MetaChecks are defined by ResourceType. For the previous example, the resource type is `AwsEc2SecurityGroup`. 

6 MetaChecks were executed against the affected resource: 

- `its_associated_with_network_interfaces`
- `its_associated_with_ec2_instances`
- `its_associated_with_public_ips`
- `its_associated_with_managed_services`
- `its_referenced_by_another_sg`
- `it_has_rules_unrestricted`
- `is_public` 
- `is_default`

Each MetaChecks not only answer the MetaCheck question but also provide you with extra information, like resources that you can use for your favorite integrations.

You can filter your findings based on MetaChecks output using the option `--mh-filters-checks MetaCheckName=True/False`. See [MetaChecks Filtering](#metachecks-filtering)

If you want to add your MetaChecks, follow this [guide](metachecks.md). Pull requests are more than welcome.

## List of MetaChecks

<table>
<thead>
  <tr>
    <th>ResourceType</th>
    <th>MetaCheck</th>
    <th>Description</th>
    <th>If True returns</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="8">AwsEc2SecurityGroup</td>
    <td>its_associated_with_network_interfaces</td>
    <td>Check if the Security Group is associated to Network Interfaces (ENIs).</td>
    <td>List of associated  `NetworkInterfaceId`</td>
  </tr>
  <tr>
    <td>its_associated_with_ec2_instances</td>
    <td>Check if the Security Group is associated to EC2 Instances.</td>
    <td>List of associated&nbsp;&nbsp;`InstanceId`</td>
  </tr>
  <tr>
    <td>its_associated_with_managed_services</td>
    <td>Check if the Security Group is associated to AWS Managed Services (like ELB, ALB, EFS, etc.).</td>
    <td>List of associated&nbsp;&nbsp;`Descriptions`</td>
  </tr>
  <tr>
    <td>its_associated_with_ips_public</td>
    <td>Check if the Security Group is associated to Network Interfaces (ENIs) with Public IPs.</td>
    <td>List of associated&nbsp;&nbsp;`Public Ips`</td>
  </tr>
  <tr>
    <td>it_has_rules_unrestricted</td>
    <td>Check if the Security Group has unerestricted rules</td>
    <td>List of unrestricted `SecurityGroupRules`</td>
  </tr>
  <tr>
    <td>is_public</td>
    <td>Check if the Security Group is Public based `is_associated_to_public_ips.` and `it_has_rules_unrestricted`</td>
    <td>True</td>
  </tr>
  <tr>
    <td>its_referenced_by_another_sg</td>
    <td>Check if the Security Group is referenced by another Security Group.</td>
    <td>List of SG&nbsp;&nbsp;`GroupId` referencing the SG</td>
  </tr>
  <tr>
    <td>is_default</td>
    <td>Check if the Security Group is the default one.</td>
    <td>True</td>
  </tr>
  <tr>
    <td rowspan="13">AwsS3Bucket</td>
    <td>it_has_bucket_acl</td>
    <td>Check if the S3 Bucket has a bucket ACL.</td>
    <td>The Bucket ACL</td>
  </tr>
  <tr>
    <td>it_has_bucket_acl_public</td>
    <td>Check if the S3 Bucket ACL contains at least one public statement (`AllUsers` or `AuthenticatedUsers`)</td>
    <td>The Bucket ACL Grant which is Public</td>
  </tr>
  <tr>
    <td>it_has_bucket_acl_cross_account</td>
    <td>Check if the S3 Bucket ACL is granted to another AWS Account based on CanonicalUser</td>
    <td>The Bucket ACL Grant which is Granted cross-account</td>
  </tr>
  <tr>
    <td>it_has_policy</td>
    <td>Check if the resource has a resource policy.</td>
    <td>The policy</td>
  </tr>
  <tr>
    <td>it_has_policy_principal_cross_account</td>
    <td>Check if the resource policy has a cross-account (from another AWS account) principal </td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_principal_wildcard</td>
    <td>Check if the resource policy has a wildcard (*) principal</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_public</td>
    <td>Check if the resource policy has a wildcard (*) principal with any restricting condition</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_actions_wildcard</td>
    <td>Check if the resource policy has a wildcard (*) actions</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_public_access_block_enabled</td>
    <td>Check if the S3 Bucket Public Access Block is enabled</td>
    <td>The bucket Public Access Block</td>
  </tr>
  <tr>
    <td>is_public</td>
    <td>Check if bucket is `it_has_website_enabled` and `it_has_bucket_policy_public` or `it_has_bucket_acl_public` is True.</td>
    <td>True</td>
  </tr>
  <tr>
    <td>is_unrestricted</td>
    <td>Check if either `it_has_bucket_policy_public` or `it_has_bucket_acl_public` is True.</td>
    <td></td>
  </tr>
  <tr>
    <td>is_encrypted</td>
    <td>Check if the S3 Bucket is encrypted (SSE)</td>
    <td>True</td>
  </tr>
  <tr>
    <td>it_has_website_enabled</td>
    <td>Check if the S3 Bucket is configured as website</td>
    <td>Endpoint URL</td>
  </tr>
  <tr>
    <td rowspan="10">AwsElasticsearchDomain</td>
    <td>it_has_policy</td>
    <td>Check if the resource has a resource policy.</td>
    <td>The policy</td>
  </tr>
  <tr>
    <td>it_has_policy_principal_cross_account</td>
    <td>Check if the resource policy has a cross-account (from another AWS account) principal </td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_principal_wildcard</td>
    <td>Check if the resource policy has a wildcard (*) principal</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_public</td>
    <td>Check if the resource policy has a wildcard (*) principal with any restricting condition</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_actions_wildcard</td>
    <td>Check if the resource policy has a wildcard (*) actions</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_public_endpoint</td>
    <td>Check if the Elastic Search Domain has a public endpoint</td>
    <td>The public endpoint</td>
  </tr>
  <tr>
    <td>is_public</td>
    <td>Check if the Elastic Search Domain is public based on is_access_policies_public and it_has_public_endpoint</td>
    <td>True</td>
  </tr>
  <tr>
    <td>is_rest_encrypted</td>
    <td>Check if the Elastic Search Domain is configured with `EncryptionAtRestOptions`</td>
    <td>True</td>
  </tr>
  <tr>
    <td>is_transit_encrypted</td>
    <td>Check if the Elastic Search Domain is configured with `NodeToNodeEncryptionOptions`</td>
    <td>True</td>
  </tr>
  <tr>
    <td>is_encrypted</td>
    <td>Check if the Elastic Search Domain is encrypted by checking `is_rest_encrypted` and `is_node_to_node_encrypted`</td>
    <td>True</td>
  </tr>
  <tr>
    <td rowspan="19">AwsEc2Instance</td>
    <td>it_has_public_ip</td>
    <td>Check if the EC2 Instance has a Public Ip</td>
    <td>List of Public Ips</td>
  </tr>
  <tr>
    <td>it_has_private_ip</td>
    <td>Check if the EC2 Instance has a Private Ip</td>
    <td>List of Private Ips</td>
  </tr>
  <tr>
    <td>it_has_public_dns</td>
    <td>Check if the EC2 Instance has a Public DNS</td>
    <td>The public DNS</td>
  </tr>
  <tr>
    <td>it_has_private_dns</td>
    <td>Check if the EC2 Instance has a Private DNS</td>
    <td>The private DNS</td>
  </tr>
  <tr>
    <td>it_has_key</td>
    <td>Check if the EC2 Instance has key pair</td>
    <td>The name of the key pair</td>
  </tr>
  <tr>
    <td>is_running</td>
    <td>Check if the EC2 Instance is in "running" state</td>
    <td>True</td>
  </tr>
  <tr>
    <td>its_associated_with_security_groups</td>
    <td>Check if the EC2 Instance is associated to Security Groups</td>
    <td>The List of Security Groups Ids</td>
  </tr>
  <tr>
    <td>its_associated_with_security_group_rules_unrestricted</td>
    <td>Check if the EC2 Instance is associated to Security Groups rules that has unrestricted rules (open to 0.0.0.0/0 or ::/0)</td>
    <td>The list of unrestricted rules</td>
  </tr>
  <tr>
    <td>is_public</td>
    <td>Check if the EC2 Instance is public by checking if `it_has_public_ip` and `is_associated_to_security_group_rules_unrestricted`</td>
    <td>True</td>
  </tr>
  <tr>
    <td>it_has_instance_profile</td>
    <td>Check if the EC2 Instance has an Instance Profile</td>
    <td>The ARN of the instance profile</td>
  </tr>
  <tr>
    <td>it_has_instance_profile_roles</td>
    <td>Check if the EC2 Instance has an Instance Profile and is related to a Role</td>
    <td>The ARN of the role</td>
  </tr>
  <tr>
    <td>is_instance_metadata_v2</td>
    <td>Check if the EC2 Instance is configured with Instance Metadata Service Version 2 (IMDSv2)</td>
    <td>True</td>
  </tr>
  <tr>
    <td>is_instance_metadata_hop_limit_1</td>
    <td>Check if the EC2 Instance Metadata is limited to 1 hop</td>
    <td>True</td>
  </tr>
  <tr>
    <td>its_associated_with_ebs</td>
    <td>Check if the EC2 Instance has EBS associated</td>
    <td>The list of `VolumeId` associated to the instance</td>
  </tr>
  <tr>
    <td>its_associated_with_ebs_unencrypted</td>
    <td>Check if the EC2 Instance has EBS associated that are unencrypted</td>
    <td>The list of `VolumeId` associated to the instance that are unencrypted</td>
  </tr>
  <tr>
    <td>is_encrypted</td>
    <td>Check if the EC2 Instance is encrypted by checking if `it_has_unencrypted_ebs`</td>
    <td>True</td>
  </tr>
  <tr>
    <td>its_associated_with_an_asg</td>
    <td>Check if the EC2 Instance it's part of an Auto Scaling Group</td>
    <td>The `AutoScalingGroupName`</td>
  </tr>
  <tr>
    <td>its_associated_with_an_asg_launch_configuration</td>
    <td>Check if the EC2 Instance it's part of an Auto Scaling Group with a Launch Configuration</td>
    <td>The `LaunchConfigurationName`</td>
  </tr>
  <tr>
    <td>its_associated_with_an_asg_launch_template</td>
    <td>Check if the EC2 Instance it's part of an Auto Scaling Group with a Launch Template</td>
    <td>The `LaunchTemplate`</td>
  </tr>
  <tr>
    <td rowspan="4">AwsAutoScalingLaunchConfiguration</td>
    <td>is_instance_metadata_v2</td>
    <td>Check if the Launch Configuration is configured with Instance Metadata Service Version 2 (IMDSv2)</td>
    <td>True</td>
  </tr>
  <tr>
    <td>is_instance_metadata_hop_limit_1</td>
    <td>Check if the Launch Configuration Instance Metadata is limited to 1 hop</td>
    <td>True</td>
  </tr>
  <tr>
    <td>its_associated_with_an_asg</td>
    <td>Check if the Launch Configuration It's associated with an Auto Scaling Group</td>
    <td>The `AutoScalingGroupARN`</td>
  </tr>
  <tr>
    <td>its_associated_with_asg_instances</td>
    <td>Check if the Launch Configuration It's associated with an Auto Scaling Group with EC2 Instances</td>
    <td>The list of `InstanceId`</td>
  </tr>
  <tr>
    <td rowspan="5">AwsEc2LaunchTemplate</td>
    <td>is_instance_metadata_v2</td>
    <td>Check if the Launch Template is configured with Instance Metadata Service Version 2 (IMDSv2)</td>
    <td>True</td>
  </tr>
  <tr>
    <td>is_instance_metadata_hop_limit_1</td>
    <td>Check if the Launch Template Instance Metadata is limited to 1 hop</td>
    <td>True</td>
  </tr>
  <tr>
    <td>its_associated_with_an_asg</td>
    <td>Check if the Launch Template It's associated with an Auto Scaling Group</td>
    <td>The `AutoScalingGroupARN`</td>
  </tr>
  <tr>
    <td>its_associated_with_asg_instances</td>
    <td>Check if the Launch Template It's associated with an Auto Scaling Group with EC2 Instances</td>
    <td>The list of `InstanceId`</td>
  </tr>
  <tr>
    <td>it_has_name</td>
    <td>Check if the Launch Template has a name configured</td>
    <td>The `LaunchTemplateName`</td>
  </tr>
  <tr>
    <td rowspan="2">AwsEc2NetworkAcl</td>
    <td>its_associated_with_subnets</td>
    <td>Check if the Network ACL is associated to Subnets</td>
    <td>The list of `SubnetId`</td>
  </tr>
  <tr>
    <td>is_default</td>
    <td>Check if the Network ACL is the default one</td>
    <td>True</td>
  </tr>
  <tr>
    <td rowspan="6">AwsLambdaFunction</td>
    <td>it_has_policy</td>
    <td>Check if the resource has a resource policy.</td>
    <td>The policy</td>
  </tr>
  <tr>
    <td>it_has_policy_principal_cross_account</td>
    <td>Check if the resource policy has a cross-account (from another AWS account) principal </td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_principal_wildcard</td>
    <td>Check if the resource policy has a wildcard (*) principal</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_public</td>
    <td>Check if the resource policy has a wildcard (*) principal with any restricting condition</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_actions_wildcard</td>
    <td>Check if the resource policy has a wildcard (*) actions</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>its_associated_with_a_role</td>
    <td>Check if Lambda Function it's associated with an IAM role (execution role)</td>
    <td>The Role ARN</td>
  </tr>
  <tr>
    <td rowspan="5">AwsElastiCacheCacheCluster</td>
    <td>is_rest_encrypted</td>
    <td>Check if the Elastic Cache is configured with `AtRestEncryptionEnabled`</td>
    <td>True</td>
  </tr>
  <tr>
    <td>is_transit_encrypted</td>
    <td>Check if the Elastic Cache is configured with `TransitEncryptionEnabled`</td>
    <td>True</td>
  </tr>
  <tr>
    <td>is_encrypted</td>
    <td>Check if the Elastic Cache is encrypted by checking `is_rest_encrypted` and `is_node_to_node_encrypted`</td>
    <td>True</td>
  </tr>
  <tr>
    <td>its_associated_with_security_groups</td>
    <td>Check if the Elastic Cache is associated to Security Groups</td>
    <td>The list of `SecurityGroups`</td>
  </tr>
  <tr>
    <td>its_associated_with_security_group_rules_unrestricted</td>
    <td>Check if the Elastic Cache is associated with Security Groups rules that are unrestricted (open to 0.0.0.0/0 or ::/0)</td>
    <td>The list of unrestricted rules</td>
  </tr>
  <tr>
    <td rowspan="7">AwsSqsQueue</td>
    <td>is_encrypted</td>
    <td>Check if the resource is encrypted checking `SqsManagedSseEnabled`</td>
    <td>The `SqsManagedSseEnabled`</td>
  </tr>
  <tr>
    <td>it_has_policy</td>
    <td>Check if the resource has a resource policy.</td>
    <td>The policy</td>
  </tr>
  <tr>
    <td>it_has_policy_principal_cross_account</td>
    <td>Check if the resource policy has a cross-account (from another AWS account) principal </td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_principal_wildcard</td>
    <td>Check if the resource policy has a wildcard (*) principal</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_public</td>
    <td>Check if the resource policy has a wildcard (*) principal with any restricting condition</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>it_has_policy_actions_wildcard</td>
    <td>Check if the resource policy has a wildcard (*) actions</td>
    <td>The offending statements</td>
  </tr>
  <tr>
    <td>is_public</td>
    <td>Check if the resource is public by checking if `it_has_policy_public`</td>
    <td>True</td>
  </tr>
</tbody>
</table>

## MetaChecks Naming

MetaChecks are defined in the form of:

- [is_](#is_)
- [its_associated_with_](#its_associated_with)
- [it_has_](#it_has)
- [its_referenced_by_](#its_referenced_by)

### is_

> Refers to the affected resource itself.

#### Public

Public refers to Network Layer. It must be effectively Public, meaning that if a resource has a Public IP, but the Security Group is closed, the resource is not Public. 

- is_public

#### Unrestricted

Unrestricted refer to Policies Layer (API, IAM, Resources Policies, Rules, etc.). 

- is_unrestricted

#### Encryption

- is_encrypted
- is_rest_encrypted
- is_transit_encrypted

#### Default

- is_default

#### Status

- is_running

### its_associated_with

> Resources that are independent (they have their own ARN) and are associated with the affected resource

When True returns a list of something_is_associated_with...

- its_associated_with_<something_is_associated_with>
- its_associated_with_<something_is_associated_with>_unencrypted
- its_associated_with_<something_is_associated_with>_unrestricted_cross_account
- its_associated_with_<something_is_associated_with>_unrestricted_wildcard
- its_associated_with_<something_is_associated_with>_public

### it_has

> Properties that only exist as part of the affected resource

When True returns a list of something_it_has...

- it_has_<something_it_has>
- it_has_<something_it_has>_unencrypted
- it_has_<something_it_has>_unrestricted_cross_account
- it_has_<something_it_has>_unrestricted_wildcard
- it_has_<something_it_has>_public

### its_referenced_by

> Resources that are independent (they have their own ARN) and are referencing the affected resource without being associated to it

When True returns a list of something_that_is_referencing_the_affected_resource...

- its_referenced_by_<something_that_is_referencing_the_affected_resource>


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
