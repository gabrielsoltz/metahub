# MetaHub

<p align="center">
  <img src="metahub.png" alt="MetaHub"/>
</p>

<p align="center">
  <b>MetaHub</b> is the command line utility for AWS Security Hub.
</p>

## Table of Contents

- [Description](#description)
- [Features](#features)
- [Requirements](#requirements)
- [AWS Authentication](#aws-authentication)
- [Usage](#usage)
- [Advanced Usage](#advanced-usage)
- [Outputs](#Outputs)
- [Findings Aggregation](#findings-aggregation)
- [MetaChecks](#MetaChecks)
- [Filtering](#Filtering)
- [Updating Findings](#Updating-Findings)

## Description

**MetaHub** is a command line utility for [AWS Security Hub](https://aws.amazon.com/security-hub) that lets you work with multiple standards, multiple checks, and thousands of findings in a very simple and advanced way by sorting, aggregating, filtering, and updating your data. In addition, **MetaHub** adds **MetaChecks**, an effortless and flexible way to do any tests on top of your resources to improve the level of confidence in your findings.

## Features

**MetaHub** introduces a better way to organize the findings for the Security Analyst by avoiding Shadowing and Duplication. See [Findings Aggregation](#findings-aggregation)

**MetaHub** adds extra custom functionality and checks on top of findings, **MetaChecks**. See [MetaChecks](#MetaChecks)

**MetaHub** supports AWS Security Hub findings filtering the same way you would work with CLI utility using the option `--sh-filters`. In addition, it supports filtering on top of MetaChecks `--mh-filters` to get a much better valuable output based on your search. See [Filtering](#Filtering)

**MetaHub** lets you execute bulk updates to AWS Security Hub findings, like changing Workflow states. See [Updating Findings](#Updating-Findings)

**MetaHub** supports different output options like `json`, `inventory`, `statistics` and `short`. All of them are programatically usable ready to be integrated with your favorite tools. See [Outputs](#Outputs)

## Requirements

**MetaHub** is a Python3 program. You need to have Python3 installed in your system and the required python modules described in the file `requirements.txt`.

Requirements can be installed in your system manually (using pip3) or using a Python virtual environment (suggested method).

Alternatively you can run this tool using Docker. 

### Run it using Python Virtual Environment

1. Clone the repository: `git clone git@github.com:gabrielsoltz/metahub.git`
2. Change to repostiory dir: `cd metahub`
3. Create virtual environment for this project: `python3 -m venv venv/metahub`
4. Activate the virtual environment you just created: `source venv/metahub/bin/activate`
5. Install metahub requirements: `pip3 install -r requirements.txt`
6. Run: `./metahub -h`
7. Deactivate your virtaul environment after you finish with: `deactivate`

Next time you only need steps 4 and 6 to use the program. 

### Run it using Docker

1. Clone the repository: `git clone git@github.com:gabrielsoltz/metahub.git`
3. Change to repostiory dir: `cd metahub`
4. Build docker image: `docker build -t metahub .`
5. Run: `docker run -e AWS_DEFAULT_REGION -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN --rm -ti metahub ./metahub -h`

## AWS Authentication

- You need to be authenticated to AWS to be able to connect with AWS Security Hub to fetch findings.
- You need to be authenticated to AWS to be able to connect to resources and run MetaChecks.

    ```sh
    aws configure
    ```

    or

    ```sh
    export AWS_DEFAULT_REGION="region"
    export AWS_ACCESS_KEY_ID="ASXXXXXXX"
    export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
    export AWS_SESSION_TOKEN="XXXXXXXXX"
    ```

- Those credentials must be associated to a user or role with proper permissions to do all checks. You can use managed policy: `arn:aws:iam::aws:policy/SecurityAudit` 

If you are using a Multi Account setup see [Advanced Usage](#advanced-usage)

## Usage

### Usage :: Listing and Filtering

#### List findings with default filters 

  ```sh
  ./metahub --list-findings
  ```

#### List findings with filters SeverityLabel=CRITICAL ResourceType=AwsEc2SecurityGroup

  ```sh
  ./metahub --list-findings --sh-filters SeverityLabel=CRITICAL ResourceType=AwsEc2SecurityGroup
  ```

See more about [filtering](#Filtering)

#### List findings with default filters and MetaChecks enabled

  ```sh
  ./metahub --list-findings --meta-checks
  ```

#### List findings with filters SeverityLabel=CRITICAL and MetaChecks filters is_public=True
##### Meaning: list everything with critical findings that is public

  ```sh
  ./metahub --list-findings --meta-checks -sh-filters SeverityLabel=CRITICAL --mh-filters is_public=True
  ```

#### List findings with filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup and MetaChecks filters is_attached_to_public_ips=True
##### Meaning: list all security groups attached to resources with public ips

  ```sh
  ./metahub --list-findings --meta-checks --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup --mh-filters is_attached_to_public_ips=True
  ```

#### List findings with filters ResourceType=AwsS3Bucket and MetaChecks filters is_public=True
##### Meaning: list all public buckets

  ```sh
  ./metahub --list-findings --meta-checks --sh-filters ResourceType=AwsS3Bucket --mh-filters is_public=True
  ```

#### List findings with filters Title="EC2.22 Unused EC2 security groups should be removed" RecordState=ACTIVE ComplianceStatus=FAILED and MetaChecks filters is_referenced_by_another_sg=False
##### Meaning: list all security groups unused and not referenced at all

  ```sh
  ./metahub --list-findings --sh-filters Title="EC2.22 Unused EC2 security groups should be removed" RecordState=ACTIVE ComplianceStatus=FAILED --meta-checks --mh-filters-new is_referenced_by_another_sg=False
  ```

### Usage :: Updating Findings

#### Supress all findings related to AWSS3Bucket resource type for the ones that are not public

  ```sh
  ./metahub --list-findings --meta-checks --sh-filters ResourceType=AwsS3Bucket --mh-filters is_public=False --update-findings Note="SUPRESSING non-public S3 buckets" Workflow=SUPRESSED
  ```

#### Supress all findings related to AwsEc2SecurityGroup resource type for the ones that are not public

  ```sh
  ./metahub --list-findings --meta-checks --sh-filters ResourceType=AwsEc2SecurityGroup --mh-filters is_public=False --update-findings Note="SUPRESSING non-public AwsEc2SecurityGroup" Workflow=SUPRESSED
  ```

#### House Keeping

You can use MetaHub to automate some House Keeping tasks that AWS Security Hub in some cases is not handling correctly, like Resolving findings in an automated way. 

##### Move PASSED findings to RESOLVED

  ```sh
  ./metahub --list-findings --sh-filters WorkflowStatus=NEW ComplianceStatus=PASSED --output statistics --update-findings Note="House Keeping - Move PASSED findings to RESOLVED" Workflow=RESOLVED
  ```

##### Move NOT_AVAILABLE findings to RESOLVED

  ```sh
  ./metahub --list-findings --sh-filters WorkflowStatus=NEW ComplianceStatus=NOT_AVAILABLE --output statistics --update-findings Note="House Keeping - Move NOT_AVAILABLE findings to RESOLVED" Workflow=RESOLVED
  ```

##### Move ARCHIVED findings to RESOLVED

  ```sh
  ./metahub --list-findings --sh-filters WorkflowStatus=NEW RecordState=ARCHIVED --output statistics --update-findings Note="House Keeping - Move ARCHIVED findings to RESOLVED" Workflow=RESOLVED
  ```


### List Metachecks available

  ```sh
  ./metahub --list-metachecks
  ```

### Show help

  ```sh
  ./metahub --help
  ```

### Change Log Level (INFO, WARNING, ERROR or DEBUG. Default: ERROR)

  ```sh
  ./metahub --log-level INFO
  ```


## Advanced Usage

### Multi Accounts Setups

If you are running AWS Security Hub in the same account as your resources, you can skip this part. 

**MetaHub** supports 3 different Multi Accounts setups in addition to the single account setup.

- Running MetaHub where AWS Security Hub master is running, but your resources are running in different AWS Accounts. See [Assuming a role for your Child Accounts](#Assuming-a-role-for-your-Child-AWS-Accounts)
- Running MetaHub in a different AWS Account than the one where AWS Security Hub is running. Your resources are in this account. See [Assuming a role for Security Hub](#Assuming-a-role-for-AWS-Security-Hub)
- Running MetaHub in a different AWS Account than the one where AWS Security Hub is running, and your resources are running. See [Assuming a role for Security Hub and your Child AWS Accounts](#Assuming-a-role-for-Security-Hub-and-your-Child-AWS-Accounts)

### Assuming a role for your Child AWS Accounts

In this scenario, you are running **MetaHub** in a different AWS Account than the one your resources are running.
You need to assume a role to connect to your resources to execute MetaChecks. 

Use `--mh-assume-role` to specify the AWS IAM Role to be assumed in that AWS Account.

```sh
./metahub --list-findings --mh-assume-role SecurityRole
```

### Assuming a role for AWS Security Hub

In this scenario, you are running **MetaHub** in a different AWS Account than the one where AWS Security Hub runs as Master. 
You need to assume a role to connect with AWS Security Hub and fetch all security findings.

Use `--sh-account` to specify the AWS Account ID where AWS Security Hub is running.
Use `--sh-assume-role` to specify the AWS IAM Role to be assumed in that AWS Account.

```sh
./metahub --list-findings --sh-account 01234567890 --sh-assume-role SecurityRole
```

### Assuming a role for Security Hub and your Child AWS Accounts

Combine all options

```sh
./metahub --list-findings --sh-account 01234567890 --sh-assume-role SecurityRole --mh-assume-role SecurityRole
```

## Outputs

**MetaHub** supports different type of outputs format and data by using the option `--output`

### Json

You can use `--output json` to save your data to a file. **MetaHub** will save the file to the directory you are running it with the name of `output.json`

### Short

You can use `--output short` to reduce the findings section to show only the Title.

### Inventory

You can use `--output inventory` to get only the list of resource's ARNs.

### Statistics

You can use `--output statistics` to get statistics about your search. 

## Findings Aggregation

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

### MetaHub Aggregation by Resource

**MetaHub** aggregates all findings under the affected resource. You have 2 possible outputs, the short one and the default one:

This is how MetaHub shows the previous example using the `--output-short` output:

```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
    "EC2.19 Security groups should not allow unrestricted access to ports with high risk",
    "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports",
    "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
    "EC2.22 Unused EC2 security groups should be removed"
  ]
}
```

And this is how MetaHub shows you the output using the default output:

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
        "Id": "arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.22/finding/01234567890-1234-1234-1234-01234567890",
        "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub",
        "Type": "AwsEc2SecurityGroup"
      }
    },
    {
      "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports": {
        "SeverityLabel": "HIGH",
        "Workflow": {
          "Status": "NEW"
        },
        "RecordState": "ACTIVE",
        "Id": "arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.22/finding/01234567890-1234-1234-1234-01234567890",
        "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub",
        "Type": "AwsEc2SecurityGroup"
      }
    },
    {
      "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389": {
        "SeverityLabel": "HIGH",
        "Workflow": {
          "Status": "NEW"
        },
        "RecordState": "ACTIVE",
        "Id": "arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.22/finding/01234567890-1234-1234-1234-01234567890",
        "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub",
        "Type": "AwsEc2SecurityGroup"
      }
    },
    {
      "EC2.22 Unused EC2 security groups should be removed": {
        "SeverityLabel": "MEDIUM",
        "Workflow": {
          "Status": "NEW"
        },
        "RecordState": "ACTIVE",
        "Id": "arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.22/finding/01234567890-1234-1234-1234-01234567890",
        "ProductArn": "arn:aws:securityhub:eu-west-1::product/aws/securityhub",
        "Type": "AwsEc2SecurityGroup"
      }
    }
    }
  ],
  "AwsAccountId": "01234567890"
}
```

Your findings are combined under the ARN of the resource affected, ending in only one result or one non-compliant resource.

You can now work in MetaHub with all these four findings together as if they were only one. For example you can update these four findings using only one command, See [Updating Findings](#Updating-Findings)

## MetaChecks

On top of the AWS Security Hub findings, **MetaHub** can run additional checks. We call these, **MetaChecks**. 

Think again about that SG. Let's assume it's attached to something, so we have three AWS Security Hub findings combined in one MetaHub result:

```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
    "EC2.19 Security groups should not allow unrestricted access to ports with high risk",
    "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports",
    "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
  ]
}
```

The check `EC2.19` it's classified as `Critical` severity by the Security Standard.

What if we can go further based on the findings and get more information? For example, check what this SG is attached to, if it's public or not, for how long, and who did it, and get all this information in the same simple output that MetaHub provides and even filter on top of that information.

Let's run MetaHub again for the previous finding with MetaChecks enabled:

```sh
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
  ...
  ],
  "AwsAccountId": "01234567890",
  "metachecks": {
    "is_attached_to_network_interfaces": [
      "eni-01234567890",
      "eni-01234567891",
      "eni-01234567892",
      "eni-01234567893",
      "eni-01234567894"
    ],
    "is_attached_to_ec2_instances": [
      "i-01234567899",
      "i-01234567898",
      "i-01234567897",
      "i-01234567896",
      "i-01234567895",
      "i-01234567894"
    ],
    "is_attached_to_public_ips": [
      "200.200.200.200"
    ],
    "is_attached_to_managed_services": false,
    "is_public": true,
    "is_referenced_by_another_sg": [
      "sg-02222222222",
      "sg-03333333333"
    ]
    "tags": {
      "Environment": "Production",
      "Name": "MyGroupName",
      "Owner": "Blameless",
    }
  }
}
```

So now, in addition to the `findings` section we have an extra section `metachecks.`

MetaChecks are defined by ResourceType. For the previous example, the resource type is `AwsEc2SecurityGroup`.

You can use MetaChecks for your filters or for updating resources. See [Filtering](#Filtering)

Use cases examples:
- Trigger an alert when you find a SG open for port 3389/TCP and it's attached to a Public resource. 
- Change severity for a finding that is related with port 3389/TCP from Critical to High when is NOT attached to a public resource.

# Filtering

## Security Hub Filtering

MetaHub supports KEY=VALUE filtering for AWS Security Hub, the same way you would filter using AWS CLI.

```sh
./metahub --list-findings --sh-filters <KEY=VALUE>
```
Default Filters (without passing any): `RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub"`

Passing filters using this option resets the default filters, so if you want to add filters to the defaults one, you need to add them to your filter. 

For example, adding SeverityLabel to the defaults filters:

```sh
./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" SeverityLabel=CRITICAL
```
Filters are defined as key=value. If a value contains spaces, you should use it with double quotes: KeyToFilter="this is a value."

You can add how many filters you need to your query.

Examples:

- Filter by Severity:
```sh
./metaHub --list-findings --sh-filters SeverityLabel=CRITICAL
```
- Filter by Severity and AWS Account:
```sh
./metaHub --list-findings --sh-filters SeverityLabel=CRITICAL AwsAccountId=1234567890
```
- Filter by Check Title:
```sh
./metahub --list-findings --sh-filters Title="EC2.22 Unused EC2 security groups should be removed"
```
- Filter by AWS Resource Type:
```sh
./metahub --list-findings --sh-filters ResourceType=AwsEc2SecurityGroup
```
- Filter by Resource Id:
```sh
./metahub --list-findings --sh-filters ResourceId="arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890"
```
- Filter by Finding Id:
```sh
./metahub --list-findings --sh-filters Id="arn:aws:securityhub:eu-west-1:01234567890:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.19/finding/01234567890-1234-1234-1234-01234567890"
```
- Filter by Compliance Status:
```sh
./metahub --list-findings --sh-filters ComplianceStatus=FAILED
```

You can check available filters in [AWS Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html#SecurityHub.Client.get_findings)

## MetaChecks Filtering

MetaHub supports filtering for MetaChecks in the form of a Key=Value. You can use how many filters you want and separate them using spaces. If you specify more than one check, you will get all resources that match at least one of the checks. 

MetaChecks filters only supports True or False value:
- A MetaChecks filter set to **True** means `True` or with data.
- A MetaChecks filter set to **False** means `False` or without data.

The MetaCheck filters are applied to the output of the MetaCheck that executes over your AWS Resources. 

This is the workflow:

1. MetaHub fetches AWS Security Findings based on the filters you specifi using `--sh-filters` (or the default ones).
2. MetaHub executes MetaChecks for the AWS affected resources based on the previous list of findings
3. MetaHub only shows you the resources that matches your `--mh-filters`, so it's a subset of the resources from point 1.

Examples:

- Get all Security Groups (`ResourceType=AwsEc2SecurityGroup`) with AWS Security Hub findings that are ACTIVE and NEW (`RecordState=ACTIVE WorkflowStatus=NEW`) only if they are attached to Network Interfaces (`is_attached_to_network_interfaces=True`):
```sh
./metahub --list-findings --meta-checks --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup --mh-filters is_attached_to_network_interfaces=True
```

- Get all S3 Buckets (`ResourceType=AwsS3Bucket`) only if they are public (`is_public=True`):
```sh
./metahub --list-findings --meta-checks --sh-filters ResourceType=AwsS3Bucket --mh-filters is_public=False
```

- Get all Security Groups that are unused (`Title="EC2.22 Unused EC2 security groups should be removed" RecordState=ACTIVE ComplianceStatus=FAILED`) and are not referenced by other security groups (`is_referenced_by_another_sg=True`) (ready to be removed):
```sh
./metahub --list-findings --sh-filters Title="EC2.22 Unused EC2 security groups should be removed" RecordState=ACTIVE ComplianceStatus=FAILED --meta-checks --mh-filters-new is_referenced_by_another_sg=False
```

You can list all available MetaChecks using `--list-metachecks`

# Updating Findings

You can use **MetaHub** to update your AWS Security Findings in bulk. 

Think again in the first example. We have 1 MetaHub resource non-compliant, based on 4 AWS Security Hub findings. 

You can update those 4 AWS Security Findings in one single command with **MetaHub**: `--update-findings.`

For example, you can update the Workflow Status of those findings in one shot: `--update-findings Workflow=NOTIFIED.`

**MetaHub** supports KEY=VALUE parameters for updating AWS Security Hub findings, the same way you would using AWS CLI. 

Filters are defined as key=value. If a value contains spaces, you should define it with double quotes: KeyToUpdate="this is a value."

AWS Security Hub API is limited to 100 findings per update, Metahub will split your findings into 100 items chucks to avoid this limitation and update your findings all together besides the amount of them.

Examples:

- Update all Worflow Status to RESOLVED for findings with RecordState ARCHIVED and Workflow Status NEW
```sh
./metahub --list-findings --sh-filters RecordState=ARCHIVED WorkflowStatus=NEW --update-findings Workflow=RESOLVED Note="Resolving Findings that are ARCHIVED"
```