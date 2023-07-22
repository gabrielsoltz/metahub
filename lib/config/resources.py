MetaHubResourcesConfig = {
    "AwsEc2Instance": {
        "metatrails_events": ["RunInstances"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": 1},
    },
    "AwsEc2SecurityGroup": {
        "metatrails_events": ["CreateSecurityGroup", "AuthorizeSecurityGroupIngress"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": 1},
    },
    "AwsEc2Volume": {
        "metatrails_events": ["CreateVolume"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": 1},
    },
    "AwsAutoScalingLaunchConfiguration": {
        "metatrails_events": ["CreateLaunchConfiguration"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": 1},
    },
    "AwsEc2LaunchTemplate": {
        "metatrails_events": ["CreateLaunchTemplate"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": 1},
    },
    "AwsEc2NetworkAcl": {
        "metatrails_events": ["CreateNetworkAcl"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": 1},
    },
    "AwsElasticsearchDomain": {
        "metatrails_events": ["CreateDomain"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsLambdaFunction": {
        "metatrails_events": ["CreateFunction", "CreateFunction20150331"],
        "ResourceName": {"parsing_char": ":", "parsing_pos": -1},
    },
    "AwsS3Bucket": {
        "metatrails_events": ["CreateBucket"],
        "ResourceName": {"parsing_char": ":", "parsing_pos": -1},
    },
    "AwsElastiCacheCacheCluster": {
        "metatrails_events": ["CreateCacheCluster"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsSqsQueue": {
        "metatrails_events": ["CreateQueue"],
        "ResourceName": {"parsing_char": ":", "parsing_pos": -1},
    },
    "AwsSnsTopic": {
        "metatrails_events": ["CreateTopic"],
        "ResourceName": {"parsing_char": ":", "parsing_pos": -1},
    },
    "AwsIamPolicy": {
        "metatrails_events": ["CreatePolicyVersion", "CreatePolicy"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsRdsDbInstance": {
        "metatrails_events": ["CreateDBInstance"],
        "ResourceName": {"parsing_char": ":", "parsing_pos": -1},
    },
    "AwsRedshiftCluster": {
        "metatrails_events": ["CreateCluster"],
        "ResourceName": {"parsing_char": ":", "parsing_pos": -1},
    },
    "AwsDynamoDbTable": {
        "metatrails_events": ["CreateTable"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsKinesisStream": {
        "metatrails_events": ["CreateStream"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsKinesisFirehoseDeliveryStream": {
        "metatrails_events": ["CreateDeliveryStream"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsEcsCluster": {
        "metatrails_events": ["CreateCluster"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsEcsTaskDefinition": {
        "metatrails_events": ["RegisterTaskDefinition"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsEksCluster": {
        "metatrails_events": ["CreateCluster"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsStepFunctionsStateMachine": {
        "metatrails_events": ["CreateStateMachine"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsApiGatewayRestApi": {
        "metatrails_events": ["CreateRestApi"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsApiGatewayV2Api": {
        "metatrails_events": ["CreateApi"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsAppStreamFleet": {
        "metatrails_events": ["CreateFleet"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsCloudFormationStack": {
        "metatrails_events": ["CreateStack"],
        "ResourceName": {"parsing_char": None, "parsing_pos": None},
    },
    "AwsRoute53HostedZone": {
        "metatrails_events": ["CreateHostedZone"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsCloudFrontDistribution": {
        "metatrails_events": ["CreateDistribution"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsIamRole": {
        "metatrails_events": ["CreateRole"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsIamUser": {
        "metatrails_events": ["CreateUser"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsIamGroup": {
        "metatrails_events": ["CreateGroup"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsCloudTrailTrail": {
        "metatrails_events": ["CreateTrail"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsCodePipeline": {
        "metatrails_events": ["CreatePipeline"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsCodeCommitRepository": {
        "metatrails_events": ["CreateRepository"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsCodeBuildProject": {
        "metatrails_events": ["CreateProject"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsCodeDeployApplication": {
        "metatrails_events": ["CreateApplication"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsCodeDeployDeploymentGroup": {
        "metatrails_events": ["CreateDeploymentGroup"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsWafWebAcl": {
        "metatrails_events": ["CreateWebAcl"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsWafv2WebAcl": {
        "metatrails_events": ["CreateWebAcl"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsEc2Vpc": {
        "metatrails_events": ["CreateVpc"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": 1},
    },
    "AwsElasticBeanstalkEnvironment": {
        "metatrails_events": ["CreateEnvironment"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsElasticBeanstalkApplication": {
        "metatrails_events": ["CreateApplication"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsCloudWatchLogsLogGroup": {
        "metatrails_events": ["CreateLogGroup"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    },
    "AwsEc2Subnet": {
        "metatrails_events": ["CreateSubnet"],
        "ResourceName": {"parsing_char": "/", "parsing_pos": -1},
    }
}
