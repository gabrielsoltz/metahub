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
- [Impact](#impact)
- [Architecture](#architecture)
- [Use Cases](#use-cases)
- [Features](#features)
- [Run with Python](#run-with-python)
- [Run with Docker](#run-with-docker)
- [Run with Lambda](#run-with-lambda)
- [Run with Security Hub Custom Action](#run-with-security-hub-custom-action)
- [AWS Authentication](#aws-authentication)
- [Configuring Security Hub](#configuring-security-hub)
- [Configuring MetaChecks, MetaTags and MetaTrails](#configuring-metachecks-metatags-and-metatrails)
- [Quick Run](#quick-run)
- [Inputs](#Inputs)
- [Output Modes](#output-modes)
- [Findings Aggregation](#findings-aggregation)
- [MetaChecks](#metachecks)
- [MetaTags](#metatags)
- [MetaTrails](#metatrails)
- [Filtering](#Filtering)
- [Updating Workflow Status](#updating-workflow-status)
- [Enriching Findings](#enriching-findings)
- [Configuration](#configuration)

# Description

**MetaHub** is a powerful security findings **context** and **ownership** enrichment tool designed for use with [AWS Security Hub](https://aws.amazon.com/security-hub) or any [ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) security scanner. It helps automate the process of contextualizing your findings with information from your environment, such as tags, trails, associations, related findings, and more. MetaHub can also be used to filter, deduplicate, group, report, suppress, or update your findings in automated workflows.

When analyzing a security finding, the severity alone is not sufficient to determine the issue's impact. To understand the importance of the finding, you need to gather additional information about the affected resource from your context, which is not available in the finding itself. Manually collecting this information from other sources can be time-consuming and error-prone, especially when dealing with multiple findings. **MetaHub** automates this process for you, allowing you to focus on the real issues, reduce noise and false positives, and improve the time it takes to detect and respond to genuine security issues in your environment.

MetaHub is designed for use as a CLI tool or within automated workflows, such as AWS Security Hub custom actions or AWS Lambda functions.

With MetaHub, you can combine security findings from any number of security scanners, regardless of whether findings are duplicated between them or not. This allows you to take advantage of each scanner's strengths, as one scanner may detect a finding that another misses. MetaHub automatically groups and deduplicates your findings by affected resources, enabling you to work with them as a single finding - for example, changing the workflow status of all related findings at once.

<img src="metahub-min.gif" />

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

# Impact

> :warning: This is an experimental feature. It is not yet available in the current release. If you find it useful, please provide feedback. 

Most Security Scanners only provides you with the severity of the finding, but this is not enough to determine the impact of the finding on the affected resource. For example, a security group with unrestricted access to a port with high risk is a severe finding, but if the security group is not attached to any resource, it may not be as critical as if it were attached to a production EC2 instance. MetaHub can automatically generate an impact score for each security finding and affected resource, leveraging both the context of the affected resource and the severity of the finding itself. This score proves invaluable for prioritizing findings and directing attention to the most critical issues first. Additionally, it can be utilized to automate alerts and escalations.

The impact score is based on two factors: **Meta_Score** and **Findings_Score**.

## Impact Meta Score

The impact meta score is determined based on the context of the affected resource. It is calculated using the following formula: 

`Meta_Score = SUM AllAvailableProperties(Impact Property Weight * Impact Value Score) / Total Impact Property Weights`

### Default Meta Properties

By default, MetaHub checks for each affected resource the following impact properties, you can edit this values in the [impact.yaml](lib/impact/impact.yaml) file:

- **Attachment**: Checking if the affected is effectively attached, based on MetaCheck `is_attached`.
  - Weight: 10
- **Status**: Checking if the affected is effectively running, based on MetaCheck `is_running`.
  - Weight: 5
- **Network**: Checking if the affected is effectively public, based on MetaCheck `is_public`.
  - Weight: 1
- **Policy**: Checking if the affected is effectively unrestricted, based on MetaCheck `is_unrestricted`.
  - Weight: 1
- **Encryption**: Checking if the affected is effectively encrypted, based on MetaCheck `is_encrypted`.
  - Encryption: 0.1
- **Environment**: Checking if the affected is effectively in production, staging or development based on MetaTags `Environment`.
  - Weight: 1

### Custom Meta Properties

You can define your own impact properties and weights based on your context by editing the [impact.yaml](lib/impact/impact.yaml). For example, you can add MetaTags or MetaAccount checks for defining accounts or resources that are more critical than others.

## Impact Findings Score

The impact findings score is determined based on the severity of all related findings. It is calculated using the following formula: `**Findings_Score** = Max(Findings Severity) / Highest Severity`

- **Findings Severity Weight**: Signifies the weight assigned to the severity of the finding.
- **Max Severity Weights**: Represents the highest possible severity weight among all findings.

## Impact Interpretation

- A lower impact score suggests a relatively lower impact of the finding.
- Conversely, a higher impact score indicates a more significant impact of the finding on the affected resources.

By utilizing this comprehensive impact scoring system, MetaHub empowers security professionals to make informed decisions, prioritize effectively, and manage security threats proactively.

## Impact Defintion Examples

For the findings `Security groups should not allow unrestricted access to ports with high risk`:

- If the security group is not attached to any resource, the impact score will be: 0 (0%)

`((Attachment: 10 * 0) + (Status: n/a) + (Network: 1 * 0) + (Policy: n/a) + (Encryption: n/a) + (Environment: 1 * 1)) / 12 = 0`

- If the security group is attached to a production private EC2 instance, the impact score will be: 0.75 (75%)

`((Attachment: 10 * 1) + (Status: n/a) + (Network: 1 * 0) + (Policy: n/a) + (Encryption: n/a) + (Environment: 1 * 1)) / 12 = 0.75`

- If the security group is attached to a development public EC2 instance, the impact score will be: 0.916 (91.6%)

`((Attachment: 10 * 1) + (Status: n/a) + (Network: 1 * 1) + (Policy: n/a) + (Encryption: n/a) + (Environment: 1 * 0)) / 12 = 0.916`

- If the security group is attached to a production public EC2 instance, the impact score will be: 1 (100%)

`((Attachment: 10 * 1) + (Status: n/a) + (Network: 1 * 1) + (Policy: n/a) + (Encryption: n/a) + (Environment: 1 * 1)) / 12 = 1`

# Architecture

<p align="center">
  <img src="docs/imgs/diagram-metahub.drawio.png" alt="Diagram" width="850"/>
</p>

# Use Cases

You can read the following articles on MetaHub practical use-cases:

- [MetaHub integration with Prowler as a local scanner for context enrichment](https://medium.com/@gabriel_87/metahub-use-cases-part-i-metahub-integration-with-prowler-as-a-local-scanner-for-context-f3540e18eaa1)
- Automatic Security Hub findings suppression using MetaTags
- Utilizing MetaHub as an AWS Security Hub Custom Action
- Generating Custom Enriched Dashboards
- AWS Security Hub Insights based on MetaChecks and MetaTags.

# Features

**MetaHub** provides a range of ways to list and manage security findings, including investigation, suppression, updating, and integration with other tools or alerting systems. To avoid *Shadowing* and *Duplication*, MetaHub organizes related findings together when they pertain to the same resource. For more information, refer to [Findings Aggregation](#findings-aggregation)

**MetaHub** queries the affected resources directly in the affected account to provide additional context using the following options:

- **[MetaTags](#MetaTags)** (`--meta-tags`): Queries tagging from affected resources
- **[MetaTrails](#MetaTrails)** (`--meta-trails`): Queries CloudTrail in the affected account to identify who created the resource and when, as well as any other related critical events
- **[MetaChecks](#MetaChecks)** (`--meta-checks`): Fetches extra information from the affected resource, such as whether it is public, encrypted, associated with, or referenced by other resources.
- **[MetaAccount](#MetaChecks)** (`--meta-account`): Fetches extra information from the account where the affected resource is running, such as the account name, security contacts, and other information.
  
MetaHub supports filters on top of these Meta* outputs to automate the detection of other resources with the same issues. For instance, you can list all resources that are effectively public, not encrypted, and tagged as `Environment=production` `Service="My Insecure Service"`. You can use **[MetaChecks filters](#metachecks-filtering)** using the option `--mh-filters-checks` and **[MetaTags filters](#metatags-filtering)** using the option `--mh-filters-tags`. The results of your filters are managed in an aggregate way that allows you to update your findings together when necessary or send them to other tools, such as ticketing or alerting systems. 

**MetaHub** also supports **[AWS Security Hub filtering](security-hub-filtering)** the same way you would work with AWS CLI utility using the option `--sh-filters` and using YAML templates with the option `--sh-template`. You can save your favorite filters in YAML templates and reuse them for any integration. You can combine Security Hub filters with Meta Filters together.

With **MetaHub**, you can back **[enrich your findings directly in AWS Security Hub](#enriching-findings)** using the option `--enrich-findings`. This action will update your AWS Security Hub findings using the field `UserDefinedFields`. You can then create filters or [Insights](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-insights.html) directly in AWS Security Hub. 

**MetaHub** also allows you to execute **[bulk updates](#updating-workflow-status)** to AWS Security Hub findings, such as changing Workflow Status using the option `--update-findings`. You can update your queries' output altogether instead of updating each finding individually. When updating findings using MetaHub, you also update the field `Note` of your finding with a custom text for future reference. 

**MetaHub** supports different **[Output Modes](#output-modes)**, some of them **json based** like **json-inventory**, **json-statistics**, **json-short**, **json-full**, but also powerfull **csv** and **html** outputs that you can customize to adapt to your needs. 

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

## Customize Lambda behaviour

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
- `mkdir -p layer/python/lib/python3.9/site-packages`
- `pip3 install -r requirements.txt --target layer/python/lib/python3.9/site-packages`
- `cd layer && zip -r9 ../terraform/zip/metahub-layer.zip . && cd ..`
- `rm -r layer`

### Deploy Lambda

You can find the code for deploying the lambda function under the `terraform/` folder.

- `terraform init`
- `terraform apply`


# Run with Security Hub Custom Action

**MetaHub** can be run as a Security Hub Custom Action. This allows you to run MetaHub directly from the Security Hub console for a selected finding or for a selected set of findings.

<p align="center">
  <img src="docs/imgs/custom_action.png" alt="custom_action" width="850"/>
</p>

The custom action then will triggered a Lambda function that will run MetaHub for the selected findings.

You need to first create the Lambda function and then create the custom action in Security Hub.

For creating the lambda function, follow the instructions in the [Run with Lambda](#run-with-lambda) section.

For creating the AWS Security Hub custom action, follow this step by step [guide](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-custom-actions.html).


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

- If you are running MetaHub for a single AWS account setup (AWS Security Hub is not aggregating findings from different accounts), you don't need to use any adittional options, MetaHub will use the credentials in your environment. Still, if your IAM desgin requires it, it is possible to log in and assume a role in the same account you are logged in. Just use the options `--sh-assume-role` to specify the role and `--sh-account` with the same AWS Account ID where you are logged in. 

- `--sh-region`: The AWS Region where Security Hub is running. If you don't specify a region, it will use the one configured in your environment. If you are using AWS Security Hub Cross-Region aggregation, you should use that region as the --sh-region option so that you can fetch all findings together.

- `--sh-account` and `--sh-assume-role`: The AWS Account ID where Security Hub is running and the AWS IAM role to assume in that account. These options are helpful when you are logged in to a different AWS Account than the one where AWS Security Hub is running or when running AWS Security Hub in a multiple AWS Account setup. Both options must be used together. The role provided needs to have enough policies to get and update findings in AWS Security Hub (if needed). If you don't specify a `--sh-account`, MetaHub will assume the one you are logged in.

- `--sh-profile`: You can also provide your aws profile name to use for AWS Security Hub. If you don't specify a profile. When using this option, you don't need to specify `--sh-account` or `--sh-assume-role` as MetaHub will use the credentials from the profile. If you are using `--sh-account` and `--sh-assume-role`, those options takes precedence over `--sh-profile`.

## IAM Policy for Security Hub

This is the minimum IAM policy you need to read and write from AWS Security Hub. If you don't want to update your findings with MetaHub, you can remove the `securityhub:BatchUpdateFindings` action.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "securityhub:GetFindings",
                "securityhub:ListFindingAggregators",
                "securityhub:BatchUpdateFindings",
                "iam:ListAccountAliases"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

# Configuring MetaChecks, MetaTags, and MetaTrails

- If you are running MetaHub for a multiple AWS Account setup (AWS Security Hub is aggregating findings from multiple AWS Accounts), you must provide the role to assume for MetaChecks, MetaTags and MetaTrails, because the affected resources are not in the same AWS Account that the AWS Security Hub findings. The `--mh-assume-role` will be used to connect with the affected resources directly in the affected account. This role needs to have enough policies for being able to describe resources. 

- The option `--mh-assume-role` let you configure the role to assume in the affected account when you are using AWS Security Hub in a [Multiple Account setup](#multiple-account-setup) for executing `--meta-checks`, `--meta-tags` and `--meta-trails`.

## IAM Policy for Meta* options

- For MetaTags, you need a policy allowing the action: 
  - `tag:GetResources`
- For MetaCheks, you can use the managed policy: 
  - `arn:aws:iam::aws:policy/SecurityAudit` and 
  - `lambda:GetFunction`
  - `lambda:GetFunctionUrlConfig`
- For MetaTrails, you need a policy allowing the action: 
  - `cloudtrail:LookupEvents`
- For MetaAccount, you need a policy allowing the action: 
  - `account:GetAlternateContact`
  - `iam:ListAccountAliases`

# Quick Run

- List all findings by AWS Security Hub findings with default filters (`RecordState=ACTIVE WorkflowStatus=NEW`):
```
./metahub
```

- Show the statistics output:
```
./metahub --list-findings statistics
```

- List only one finding:
```
./metahub --list-findings short --sh-filters Id=<<Finding ID>>
```

- Filter only ACTIVE findings for one resource and show the short output:
```
./metahub --list-findings short --sh-filters RecordState=ACTIVE ResourceId=<<ARN>>
```

- Filter only ACTIVE findings for one AWS Account and show the statistics output:
```
./metahub --list-findings statistics --sh-filters RecordState=ACTIVE AwsAccountId=<<Account Id>>
```

- List all affected resources by AWS Security Hub findings and enrich them with MetaTags (Tagging):
```
./metahub --meta-tags
```

- Filter only the affected resources that have the Tag "Environment" with the value "Production"
```
./metahub --meta-tags --mh-filters-tags Environment=production
```

- Filter only the affected resources that have the Tag "Environment" with the value "Production", which are `HIGH` severity:
```
./metahub --sh-filters RecordState=ACTIVE SeverityLabel=HIGH --meta-tags --mh-filters-tags Environment=production
```

- List all MetaChecks available:
```
./metahub --list-meta-checks
```

- List all affected resources by AWS Security Hub findings and enrich them with MetaChecks and show the short output:
```
./metahub --list-findings short --meta-checks
```

- Filter only the affected resources that are effectively public:
```
./metahub --meta-checks --mh-filters-checks is_public=True
```

- Show the previous list of affected resources in inventory output:
```
./metahub --meta-checks --mh-filters-checks is_public=True --list-findings inventory
```

- Filter only the affected resources that are unencrypted:
```
./metahub --meta-checks --mh-filters-checks is_encrypted=False
```

- Filter only the affected resources that are unencrypted and have a Tag "Classification" with the value "PI":
```
./metahub --meta-checks --mh-filters-checks is_encrypted=False --meta-tags --mh-fiters-tags Classification=PI
```

- Filter only the affected resources that are unencrypted and have a Tag "Classification" with the value "PI" and output a CSV:
```
./metahub --meta-checks --mh-filters-checks is_encrypted=True --meta-tags --mh-fiters-tags Classification=PI --output-modes csv
```

- List all affected resources for specific Security Hub findings, for example: `EC2.19 Security groups should not allow unrestricted access to ports with high risk` and show the statistics output:
```
./metahub --list-findings statistics --sh-filters RecordState=ACTIVE Title="EC2.19 Security groups should not allow unrestricted access to ports with high risk"
```

- Enable MetaChecks to get more info for those resources:
```
./metahub --sh-filters RecordState=ACTIVE Title="EC2.19 Security groups should not allow unrestricted access to ports with high risk" --meta-checks
```

- Filter only the affected resources that are public:
```
./metahub --sh-filters RecordState=ACTIVE Title="EC2.19 Security groups should not allow unrestricted access to ports with high risk" --meta-checks --mh-filters-checks is_public=True
```

- Update all related AWS Security Findings to `NOTIFIED` with a Note `Ticket ID: 123`:
```
./metahub --sh-filters RecordState=ACTIVE Title="EC2.19 Security groups should not allow unrestricted access to ports with high risk" --meta-checks --mh-filters-checks is_public=True --update-findings Workflow=NOTIFIED Note="Ticket ID: 123"
```

- Fetch findings with SH filters `Title="S3.8 S3 Block Public Access setting should be enabled at the bucket-level" ResourceType=AwsS3Bucket RecordState=ACTIVE WorkflowStatus=NEW` and list (terminal) with MetaChecks enabled and MetaChecks filters `is_public=False` and update Workflow Status to `SUPPRESSED` with a Note `Suppressing reason: non-public S3 buckets`:

```sh
./metahub --list-findings short --meta-checks --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsS3Bucket Title="S3.8 S3 Block Public Access setting should be enabled at the bucket-level" --mh-filters-checks is_public=False --update-findings Note="Suppressing reason: non-public S3 buckets" Workflow=SUPPRESSED
```

- Fetch and list findings (terminal) with default options with MetaTags enabled and enrich them back in AWS Security Hub:

```sh
./metahub --list-findings short --meta-tags --enrich-findings
```

- See the full list of options:
```sh
./metahub --help
```

# Inputs

MetaHub can read security findings directly from AWS Security Hub or from inputs file generated by any other scanner in ASFF format. By default, MetaHub will try to fetch from AWS Security Hub. 

If you want to read from an input ASFF file, you need to use the options:: `--inputs file-asff --input-asff path/to/the/file.json.asff path/to/the/file2.json.asff `

When using a file as input, you can't use the option `--sh-filters` for filter findings, as this option relies on AWS API for filtering. You can't use the options `--update-findings` or `--enrich-findings` as those findings are not in AWS Security Hub. 

You also can combine AWS Security Hub findings with an input ASFF file specifying both inputs: `--inputs file-asff securityhub --input-asff path/to/the/file.json.asff`

If you are reading from both sources, only the findings from AWS Security Hub will be updated.

# Output Modes

They are the different ways to show the results.

By default, all outputs modes are enabled: `json-short`, `json-full`, `json-statistics`, `json-inventory`, `html` and `csv`. 

The Outputs will be saved in the folder `/outputs` with the execution date.

If you want to only generate a specific output mode, you can use the option `--output-modes` with the desired output mode. For example: `--output-modes json-short` or `--output-modes json-short json-full`

- [JSON](#json)
- [HTML](#html)
- [CSV](#csv)

## JSON

### JSON-Short

Show all findings title together under each affected resource and the `AwsAccountId`, `Region`, and `ResourceType`:

```
  "arn:aws:sagemaker:us-east-1:ofuscated:notebook-instance/ofuscated": {
    "findings": [
      "SageMaker.2 SageMaker notebook instances should be launched in a custom VPC",
      "SageMaker.3 Users should not have root access to SageMaker notebook instances",
      "SageMaker.1 Amazon SageMaker notebook instances should not have direct internet access"
    ],
    "AwsAccountId": "ofuscated",
    "Region": "us-east-1",
    "ResourceType": "AwsSageMakerNotebookInstance"
  },
```  


### JSON-Full

Show all findings with all data. Findings are organized by ResourceId (ARN). For each finding, you will also get: `SeverityLabel`, `Workflow`, `RecordState`, `Compliance`, `Id` and `ProductArn`:

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
    "Region": "eu-west-1",
    "ResourceType": "AwsSageMakerNotebookInstance"
  },
```

### JSON-Inventory

Show a list of all resources with their ARN.

```
[
  "arn:aws:sagemaker:us-east-1:ofuscated:notebook-instance/ofuscated",
  "arn:aws:sagemaker:eu-west-1:ofuscated:notebook-instance/ofuscated"
]
```

### JSON-Statistics

Show statistics for each field/value. In the output you will see each field/value and the amount of ocurrences, for example, the following output shows statistics for six findings. 

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

## HTML

You can create rich HTML reports of your findings, adding MetaChecks and MetaTags as part of them.

HTML Reports are interactive in many ways:
- You can add/remove columns.
- You can sort and filter by any column.
- You can auto-filter by any column
- You can group/ungroup findings
- You can also download that data to xlsx, csv, html and json.

<p align="center">
  <img src="docs/imgs/html-export.png" alt="html-example"/>
</p>

## CSV

You can create a CSV custom report from your findings, adding MetaChecks and MetaTags as part of them.

<p align="center">
  <img src="docs/imgs/csv-export.png" alt="csv-example"/>
</p>

## Customize HTML or CSV Outputs

You can customize which MetaChecks and MetaTags to use as column headers using the options `--output-meta-tags-columns` and `--output-meta-checks-columns` as a list of columns. If the MetaChecks or MetaTags you specified as columns don't exist for the affected resource, they will be empty. You need to be running MetaHub with the options `--meta-checks` or `--meta-tags` to be able to fill those columns. If you don't specify columns, all MetaChecks and all MetaTags that appear in your outputs will be used as columns (if they are enabled `--meta-checks --meta-tags`)

For example,  you can generate a html output, with MetaTags and add "Owner" and "Environment" as columns to your report using: 

`./metahub --meta-tags --output-modes html --output-meta-tags-columns Owner Environment`

For example, you can generate a csv output, with MetaTags and MetaChecks enabled, adding columns `is_encrypted` from MetaChecks and `Name` and `Owner` from MetaTags:

`./metahub --meta-tags --output-meta-tags-columns Name Owner --meta-checks --output-meta-checks-columns is_encrypted --output-modes csv`

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

**MetaHub** aggregates security findings under the affected resource.

This is how MetaHub shows the previous example with output-mode json-short:

```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
    "EC2.19 Security groups should not allow unrestricted access to ports with high risk",
    "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports",
    "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
    "EC2.22 Unused EC2 security groups should be removed"
  ],
  "AwsAccountId": "01234567890",
  "Region": "eu-west-1",
  "ResourceType": "AwsEc2SecurityGroup"
}
```

This is how MetaHub shows the previous example with output-mode json-full:

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

Each MetaChecks not only answer the MetaCheck question but also provide you with extra information, for example the offending policies or the offending security groups rules. If a resource is public, it can give you the public entrypoint (ip, dns, endpoint) and the ports open to the public.

You can filter your findings based on MetaChecks output using the option `--mh-filters-checks MetaCheckName=True/False`. See [MetaChecks Filtering](#metachecks-filtering)

If you want to add your MetaChecks, follow this [guide](metachecks.md). Pull requests are more than welcome.

There are two special types of MetaChecks: [Drilled MetaChecks](#drilled-metachecks) and [Impact MetaChecks](#impact-metachecks). Then you have the rest of MetaChecks, we call them standard MetaChecks.

## Drilled MetaChecks

Drilled MetaChecks can connet into the associated resources of the affected resource, for example Security Groups, IAM Roles, IAM Policies, AutoScaling Groups, EBS, etc. and run MetaChecks on them.

For example, each time you run a MetaCheck on an EC2 Instance, MetaHub will run the MetaCheck `its_associated_with_security_groups` to understand if the EC2 Instance it's associated with any Security Group. If it is, MetaHub will run the MetaCheck drilled into those Security Groups and run all the related Security Group MetaChecks on them:

```
<Affected Resource>
└─ its_associated_with_security_groups
    ├─ its_associated_with_network_interfaces
    ├─ its_associated_with_ec2_instances
    ├─ its_associated_with_ips_public
    ├─ its_associated_with_managed_services
    ├─ its_referenced_by_a_security_group
    ├─ is_ingress_rules_unrestricted
    ├─ is_egress_rules_unrestricted
    ├─ is_public
    └─ is_default
```

Drilled MetaChecks are key to undertand the context of your security findings by understanding the associated resources and their configuration.

If you don't need to run drilled MetaChecks, you can disable them using the option `--no-drill-down`. See [Drilled MetaChecks](#drilled-metachecks). By default they are enabled.

### Drilled MetaChecks list

The following is the list of drilled MetaChecks:

- `its_associated_with_security_groups`: If it's True, runs MetaChecks from: `AwsEc2SecurityGroup`.
- `its_associated_with_iam_roles`:  If it's True, runs MetaChecks from: `AwsIamRole`
- `its_associated_with_iam_policies`:  If it's True, runs MetaChecks from: `AwsIamPolicy`
- `its_associated_with_autoscaling_group`:  If it's True, runs MetaChecks from: `AwsAutoScalingAutoScalingGroup`
- `its_associated_with_ebs`:  If it's True, runs MetaChecks from: `AwsEc2Volume`
- `its_associated_with_vpc`:  If it's True, runs MetaChecks from: `AwsEc2Vpc`
- `its_associated_with_subnets`:  If it's True, runs MetaChecks from: `AwsEc2Subnet`
- `its_associated_with_route_tables`:  If it's True, runs MetaChecks from: `AwsEc2RouteTable`

## Impact MetaChecks

Impact MetaChecks are defined across all resources. These MetaChecks defines properties that are important for defining the impact of a security finding. For example, if a resource is public, if a resource is encrypted, if a resource is attached to another resource, etc. These MetaChecks are defined for every resource type but the result of it depends on each resource type, for example, for an EC2 Instance to be `is_public` in MetaHub, the instance needs to have a Public IP and needs to be associated with a Security Group that has an ingress rule open to the public.

Impact MetaChecks are also useful to filter across all resources no matter the resource type, for example, you can filter all resources that are public using the MetaCheck `is_public` (`./metahub --mh-filters-checks is_public=True`), or you can filter all resources that are public and not encrypted using the MetaCheck `is_public` and `is_encrypted` (`./metahub --mh-filters-checks is_public=True is_encrypted=False`).

Impact MetaChecks are: `is_public`, `is_unrestricted`, `is_encrypted`, and `is_attached`.

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

## Standard MetaChecks

Depending on each resource type, they are other MetaChecks that are defined, you can list all MetaChecks using the option: `./metahub --list-meta-checks`.

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

`./metahub --sh-filters ResourceId=arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890 --meta-tags`

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
./metaHub --sh-template templates/default.yml
```

## Security Hub Filtering

MetaHub supports filtering AWS Security Hub findings in the form of `KEY=VALUE` filtering for AWS Security Hub using the option `--sh-filters`, the same way you would filter using AWS CLI but limited to the `EQUALS` comparison. If you want another comparison, use the option `--sh-template` [Security Hub Filtering using YAML templates](#security-hub-filtering-using-yaml-templates).

You can check available filters in [AWS Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html#SecurityHub.Client.get_findings)

```sh
./metahub --sh-filters <KEY=VALUE>
```
If you don't specify any filters, defaults filters are applied: `RecordState=ACTIVE WorkflowStatus=NEW`

Passing filters using this option resets the default filters. If you want to add filters to the defaults, you need to specify them in addition to the default ones. For example, adding SeverityLabel to the defaults filters:

```sh
./metahub --sh-filters RecordState=ACTIVE WorkflowStatus=NEW
```
If a value contains spaces, you should specify it using double quotes: `ProductName="Security Hub"`

You can add how many different filters you need to your query and also add the same filter key with different values:

Examples:

- Filter by Severity (CRITICAL):
```sh
./metaHub --sh-filters RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL
```
- Filter by Severity (CRITICAL and HIGH):
```sh
./metaHub --sh-filters RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL SeverityLabel=HIGH
```
- Filter by Severity and AWS Account:
```sh
./metaHub --sh-filters RecordState=ACTIVE WorkflowStatus=NEW SeverityLabel=CRITICAL AwsAccountId=1234567890
```
- Filter by Check Title:
```sh
./metahub --sh-filters RecordState=ACTIVE WorkflowStatus=NEW Title="EC2.22 Unused EC2 security groups should be removed"
```
- Filter by AWS Resource Type:
```sh
./metahub --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup
```
- Filter by Resource Id:
```sh
./metahub --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceId="arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890"
```
- Filter by Finding Id:
```sh
./metahub --sh-filters Id="arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.19/finding/01234567890-1234-1234-1234-01234567890"
```
- Filter by Compliance Status:
```sh
./metahub --sh-filters ComplianceStatus=FAILED
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
./metahub --meta-checks --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup --mh-filters-checks its_associated_with_network_interfaces=True
```

- Get all S3 Buckets (`ResourceType=AwsS3Bucket`) only if they are public (`is_public=True`):
```sh
./metahub --meta-checks --sh-filters ResourceType=AwsS3Bucket --mh-filters-checks is_public=False
```

- Get all Security Groups that are unused (`Title="EC2.22 Unused EC2 security groups should be removed" RecordState=ACTIVE ComplianceStatus=FAILED`) and are not referenced by other security groups (`its_referenced_by_another_sg=False`) (ready to be removed):
```sh
./metahub --sh-filters Title="EC2.22 Unused EC2 security groups should be removed" RecordState=ACTIVE ComplianceStatus=FAILED --meta-checks --mh-filters-checks its_referenced_by_another_sg=False
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
./metahub --meta-tags --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup --mh-filters-tags Environment=Production
```

# Updating Workflow Status

You can use **MetaHub** to update your AWS Security Hub Findings workflow status (`NOTIFIED`, `NEW`, `RESOLVED`, `SUPPRESSED`) with a single command. You will use the `--update-findings` option to update all the findings from your MetaHub query. This means you can update one, ten, or thousands of findings using only one command. AWS Security Hub API is limited to 100 findings per update. Metahub will split your results into 100 items chucks to avoid this limitation and update your findings beside the amount.

For example, using the following filter: `./metahub --sh-filters ResourceType=AwsSageMakerNotebookInstance RecordState=ACTIVE WorkflowStatus=NEW` I found two affected resources with three finding each making six Security Hub findings in total.

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

The `--update-findings` will ask you for confirmation before updating your findings. You can skip this confirmation by using the option `--no-actions-confirmation`.

# Enriching Findings

You can use **MetaHub** to enrich back your AWS Security Hub Findings with `MetaTags`, `MetaChecks`, `MetaTrails` and `MetaAccount` outputs using the option `--enrich-findings`. Enriching your findings means updating them directly in AWS Security Hub. **MetaHub** uses the `UserDefinedFields` field for this.

By enriching your findings directly in AWS Security Hub, you can take advantage of features like Insights and Filters by using the extra information not available in Security Hub before. 

For example, you want to enrich all AWS Security Hub findings with `WorkflowStatus=NEW`, `RecordState=ACTIVE`, and `ResourceType=AwsS3Bucket` that are MetaCheck `is_public=True` with MetaChecks and MetaTags:

```sh
./metahub --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsS3Bucket --meta-tags --meta-checks --mh-filters-checks is_public=True --enrich-findings  
```

<p align="center">
  <img src="docs/imgs/enrich-findings-1.png" alt="update-findings" width="850"/>
</p>

The `--enrich-findings` will ask you for confirmation before enriching your findings. You can skip this confirmation by using the option `--no-actions-confirmation`.


# Configuration

**MetaHub** uses configuration files that let you customize some checks behaviors, default filters, and more. The configuration files are located in `lib/config/`. You can edit them using your favorite text editor.