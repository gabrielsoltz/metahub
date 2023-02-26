MetaHubResourcesConfig = {
    "AwsEc2Instance": {
        "metatrails_events": ["RunInstances"],
        "ResourceName": {
            "parsing_char": "/",
            "parsing_pos": 1
        }
    },
    "AwsEc2SecurityGroup": {
        "metatrails_events": ["CreateSecurityGroup", "AuthorizeSecurityGroupIngress"],
        "ResourceName": {
            "parsing_char": "/",
            "parsing_pos": 1
        }
    },
    "AwsAutoScalingLaunchConfiguration": {
        "metatrails_events": [],
        "ResourceName": {
            "parsing_char": "/",
            "parsing_pos": 1
        }
    },
    "AwsEc2LaunchTemplate": {
        "metatrails_events": [],
        "ResourceName": {
            "parsing_char": "/",
            "parsing_pos": 1
        }
    },
    "AwsEc2NetworkAcl": {
        "metatrails_events": [],
        "ResourceName": {
            "parsing_char": "/",
            "parsing_pos": 1
        }
    },
    "AwsElasticsearchDomain": {
        "metatrails_events": ["CreateDomain"],
        "ResourceName": {
            "parsing_char": "/",
            "parsing_pos": -1
        }
    },
    "AwsLambdaFunction": {
        "metatrails_events": ["CreateFunction"],
        "ResourceName": {
            "parsing_char": "/",
            "parsing_pos": -1
        }
    },
    "AwsS3Bucket": {
        "metatrails_events": ["CreateBucket"],
        "ResourceName": {
            "parsing_char": "/",
            "parsing_pos": -1
        }
    }    
}