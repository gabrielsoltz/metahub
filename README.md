# MetaHub

<p align="center">
  <img src="metahub.png" alt="MetaHub"/>
</p>

MetaHub is a command line program for AWS Security Hub that let you work with findings in a more practical way.

MetaHub introduces a better way to organize the findings for the Security Analyst by avoiding Shadowing and Duplication.

MetaHub adds extra custom functionality on top of findings, MetaChecks.

MetaHub let you excecute bulk actions like changing Workflow states using the command line.

MetaHub supports filtering the same way you would work with `--sh-filters` CLI utility, and also fitering on top of MetaChecks `--mh-filters` to get a much better valuable output based on your search. 

## Findings Aggregation

When I started working with AWS Security Hub, one of the issues I found that I didn't like, was what I called findings Shadowing and Duplication. You work with a bunch of checks, but there is no logic behind to combine those findings.

Shadowing is when two checks are referring to the same issue but one in a more generic way than the other one.

Duplication is when you are using multiple standards and you are getting the same problem from different standards.

Think of a Security Group with port 3389/TCP open to 0.0.0.0/0.

If you are using one of the default Security Standards like `AWS-Foundational-Security-Best-Practices`, you will get two findings for the same issue:

  - `EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports`
  - `EC2.19 Security groups should not allow unrestricted access to ports with high risk`

If you are also using standard CIS AWS Foundations Benchmark, you will also get an extra finding:

  - `4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389`

Now imagine that SG is not in-use. In that case, Security Hub will show an additional 4th finding for your resource!

  - `EC2.22 Unused EC2 security groups should be removed`

So now you have in your dashboard four findings for one resource !

If you are working with multi-account setups and many resources, this could result in many findings that refer to the same thing without adding any extra value to your analyze. 

This is how MetaHub shows the previous example using the `--short` output:

```
"<ARN>>": {
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
"<ARN>>": {
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

Your findings are now combined under the ARN of the resource affected ending in only 1 finding, or 1 non-compliant resource. Much better?

You can now work in MetaHub with all these four findings together as if they were only one. 

## MetaChecks

On top of Security Hub findings, MetaHub can run additional checks. We call these, MetaChecks. 

Think again on that SG. Let's assume it's attached to something, so we will have 3 findings, instead of 4. 

```
"arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
  "findings": [
    "EC2.19 Security groups should not allow unrestricted access to ports with high risk",
    "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports",
    "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
  ]
}
```

The check `EC2.19` it's classified as Critical severity by the Security Standard. Is it really a Critical finding?

What if we can go further based on the findings and get more information, for example, check what is this SG attached to, if it's public or not, for how long, who did it, and getting all this information in the same simple output that MetaHub provides and even filtering on top of that information. 

MetaChecks are defined by ResourceType. For the previous example, the resource type is AwsEc2SecurityGroup.

Let's run MetaHub again for the previous finding:

```
{
  "arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890": {
    "findings": [
    ...
    ],
    "AwsAccountId": "01234567890",
    "metachecks": {
      "is_attached_to_ec2_instance": "['i-01234567890', 'i-01234567891', 'i-01234567892', 'i-01234567893', 'i-01234567894']",
      "is_attached_to_ec2_instance_with_public_ip": "False",
      "is_attached_to_network_interfaces": "['eni-01234567890', 'eni-01234567891', 'eni-01234567892', 'eni-01234567892']",
      "GroupName": "SGGRroupName",
      "tags_owner": null
    }
  }
}
```

Now you have in addition to the findings, extra information that you can programtically combine to make decistions. 

Use cases examples:
- Trigger an alert when you find a SG open for port 3389/TCP and it's attached to a Public resource. 
- Change severity for a finding that is related with port 3389/TCP from Critical to High when is NOT attached to a public resource.


# Update Findings

You can use MetaHub to update your AWS Security Findings in bulk. 

Think again in the first example, we have 1 MetaHub resource non-comnpliant, based on 4 AWS Security Hub findings. 

You can udpate those 4 AWS Security Findings in one single-command with Meta Hub: `--update-findings`

For example, you can update the Worflow Status of those findings in one shot: `--update-findings Workflow=NOTIFIED`

MetaHub supports KEY=VALUE parameters for updating AWS Security Hub findings, the same way you would do it using AWS CLI. 

Filters are defined as key=value, if a value contains spaces, you should define it with double quotes: KeyToUpdate="this is a value"

Use case examples:

- Update Workflow Status to `RESOLVED` for all findings with `RecordState=ARCHIVED` and `WorkflowStatus=NEW`: 

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW --update Workflow=RESOLVED`


# Filtering

## Security Hub Filtering

MetaHub supports KEY=VALUE filtering for AWS Security Hub, the same way you would filter using AWS cli. 

- `./metahub --list-findings --sh-filters <KEY=VALUE>` 

The default filters (without passing any filter): `RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub"`

Passing filters using this option resets the default filters, so if you want to add filters to the default one you need to add them as well to your filter. 

Filters are defined as key=value, if a value contains spaces, you should define it with double quotes: KeyToFilter="this is a value"

Use cases examples:

- Severity:

`./metaHub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" SeverityLabel=CRITICAL`

- Account:

`./metaHub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" SeverityLabel=CRITICAL AwsAccountId=1234567890`

- Check Title:

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" Title="EC2.22 Unused EC2 security groups should be removed"`

- Resource Type:

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" ResourceType=AwsEc2SecurityGroup`

- Resource Id:

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" ResourceId="arn:aws:ec2:eu-west-1:01234567890:security-group/sg-01234567890"`

You can check available filters in [AWS Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html#SecurityHub.Client.get_findings)

## MetaChecks Filtering

MetaHub supports filtering for MetaChecks in the form of list. You speficy each metacheck separeten them using spaces. If you speficy more than one check, you will get all resources that matches at least one of the checks. 

When you pass a filter for MetaCheck, you will only get resources that matchs the filter you speficied.

Use cases examples:

`./metahub --list-findings --sh-filters RecordState=ACTIVE WorkflowStatus=NEW ProductName="Security Hub" ResourceType=AwsEc2SecurityGroup --mh-filters is_attached_to_network_interfaces`

From the rerources with findings found by your Security Hub filters, you will only get resources that also matchs your MetaHub filters. If the resource matchs the Security Hub filters but it doesn't match the MetaHub filter, you will not get it as a finding. 

You can list all MetaChecks by resources using `--list-metachecks`


# Running the program

## Python Virtual Environment

This is a python program, requirements are defined in the file `requirements.txt`, you can install those requirements in your system or use a Python virtual environment.

Python virtual environment:

```
cd metahub
python3 -m venv venv/metahub
source venv/metahub/bin/activate
pip3 install -r requirements.txt
```

## Run and list findings

List all AWS Security Findings using the default filters:

- `./metahub --list-findings`

## Run and list findings with MetaChecks enabled

List all AWS Security Findings using the default filters and running MetaChecks:

- `./metahub --list-findings --meta-checks`

## Run using help

You can list all available commands using `--help`

- `./metahub --help`