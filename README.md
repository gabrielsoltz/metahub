# MetaHub

<p align="center">
  <img src="metahub.png" alt="MetaHub"/>
</p>

MetaHub is a command line program for AWS Security Hub that lets you work with findings more practically.

MetaHub introduces a better way to organize the findings for the Security Analyst by avoiding Shadowing and Duplication. See [Findings Aggregation](#findings-aggregation)

MetaHub adds extra custom functionality and checks on top of findings, MetaChecks. See [MetaChecks](#MetaChecks)

MetaHub supports AWS Security Hub findings filtering the same way you would work with CLI utility using the option `--sh-filters`. In addition, it supports filtering on top of MetaChecks `--mh-filters` to get a much better valuable output based on your search. See [Filtering](#Filtering)

MetaHub lets you execute bulk updates to AWS Security Hub findings, like changing Workflow states. See [Updating Findings](#Updating-Findings)

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

MetaHub aggregates all findings under the affected resource. You have 2 possible outputs, the `short` one and the default one:

This is how MetaHub shows the previous example using the `--short` output:

```
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

```
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
    {
      "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports": {
        "SeverityLabel": "HIGH",
        "Security Standard": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
      }
    },
    {
      "EC2.19 Security groups should not allow unrestricted access to ports with high risk": {
        "SeverityLabel": "CRITICAL",
        "Security Standard": "Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"
      }
    },
    {
      "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389": {
        "SeverityLabel": "HIGH",
        "Security Standard": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"
      }
    },
    {
      "4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22": {
        "SeverityLabel": "HIGH",
        "Security Standard": "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"
      }
    }
  ],
  "AwsAccountId": "01234567890"
}
```

Your findings are combined under the ARN of the resource affected, ending in only one result or one non-compliant resource.

You can now work in MetaHub with all these four findings together as if they were only one. For example you can update these four findings using only one command, See [Updating Findings](#Updating-Findings)

## MetaChecks

On top of the AWS Security Hub findings, MetaHub can run additional checks. We call these, MetaChecks. 

Think again about that SG. Let's assume it's attached to something, so we have three AWS Security Hub findings combined in one MetaHub result:

```
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

```
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
    "tag_Owner": "Gabriel"
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

`./metahub --list-findings --sh-filters <KEY=VALUE>` 

Default Filters (without passing any): `RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub"`

Passing filters using this option resets the default filters, so if you want to add filters to the defaults one, you need to add them to your filter. 

For example, adding SeverityLabel to the defaults filters:

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" SeverityLabel=CRITICAL` 

Filters are defined as key=value. If a value contains spaces, you should use it with double quotes: KeyToFilter="this is a value."

Use cases examples:

- Filter by Severity:

`./metaHub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" SeverityLabel=CRITICAL`

- Filter by AWS Account:

`./metaHub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" SeverityLabel=CRITICAL AwsAccountId=1234567890`

- Filter by Check Title:

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" Title="EC2.22 Unused EC2 security groups should be removed"`

- Filter by AWS Resource Type:

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" ResourceType=AwsEc2SecurityGroup`

- Filter by Resource Id:

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" ResourceId="arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890"`

You can check available filters in [AWS Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html#SecurityHub.Client.get_findings)

## MetaChecks Filtering

MetaHub supports filtering for MetaChecks in the form of a list. You can use how many filters you want and separate them using spaces. If you specify more than one check, you will get all resources that match at least one of the checks. 

The MetaCheck filters are applied to the output of the MetaCheck that executes over your AWS Resources. 

This is the workflow:

1. MetaHub fetches AWS Security Findings based on the filters you specifi using `--sh-filters` (or the default ones).
2. MetaHub executes MetaChecks for the AWS affected resources based on the previous list of findings
3. MetaHub only shows you the resources that matches your `--mh-filters`, so it's a subset of the resources from point 1.

Use cases examples:

- Get all Security Groups (`ResourceType=AwsEc2SecurityGroup`) affected by AWS Security Hub findings that are ACTIVE and NEW (`RecordState=ACTIVE WorkflowStatus=NEW`) only if they are attached to Network Interfaces (`is_attached_to_network_interfaces`)

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ResourceType=AwsEc2SecurityGroup --mh-filters is_attached_to_network_interfaces`

You can list all available MetaChecks using `--list-metachecks`

# Updating Findings

You can use MetaHub to update your AWS Security Findings in bulk. 

Think again in the first example. We have 1 MetaHub resource non-compliant, based on 4 AWS Security Hub findings. 

You can update those 4 AWS Security Findings in one single command with Meta Hub: `--update-findings.`

For example, you can update the Workflow Status of those findings in one shot: `--update-findings Workflow=NOTIFIED.`

MetaHub supports KEY=VALUE parameters for updating AWS Security Hub findings, the same way you would using AWS CLI. 

Filters are defined as key=value. If a value contains spaces, you should define it with double quotes: KeyToUpdate="this is a value."

Use case examples:

- Update Workflow Status to `RESOLVED` for all findings with `RecordState=ARCHIVED` and `WorkflowStatus=NEW`: 

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ----update-findings Workflow=RESOLVED`

# Running the program

## Python Virtual Environment

This is a python program. Requirements are defined in the file `requirements.txt`; you can install those requirements in your system or use a Python virtual environment.

Using a Python virtual environment:

```
cd metahub
python3 -m venv venv/metahub
source venv/metahub/bin/activate
pip3 install -r requirements.txt
```

## Run and list findings

List all AWS Security Findings using the default filters. See [Filtering](#Filtering)

- `./metahub --list-findings`

## Run and list findings with MetaChecks enabled

List all AWS Security Findings using the default filters and running MetaChecks. See [Filtering](#Filtering)

- `./metahub --list-findings --meta-checks`

## Run using help

You can list all available commands using `--help`

- `./metahub --help`