'''MetaCheck: AwsEc2SecurityGroup'''

import boto3

class Metacheck:

    def __init__(self, logger, finding, mh_filters, sess):
        self.logger = logger
        if not sess:
            self.client = boto3.client('ec2')
        else:
            self.client = sess.client(service_name='ec2')
        if finding:
            self.resource_id = finding["Resources"][0]["Id"].split('/')[1]
            self.network_interfaces = self._describle_network_interfaces()
            self.mh_filters = mh_filters
            self.tags = self._tags()
            self.tag_Owner = self._find_tag('Owner')
            self.tag_Name = self._find_tag('Name')
            self.tag_Environment = self._find_tag('Environment')

    def _describle_network_interfaces(self):
        response = self.client.describe_network_interfaces(
            Filters=[
                {
                    'Name': 'group-id',
                    'Values': [
                        self.resource_id,
                    ]
                },
            ],
        )
        return response['NetworkInterfaces']

    def _tags(self):
        response = self.client.describe_tags(
            Filters=[
                {
                    'Name': 'resource-id',
                    'Values': [
                        self.resource_id,
                    ]
                },
            ],
        )
        return response["Tags"]

    def _find_tag(self, tag):
        if self.tags:
            for _tag in self.tags:
                if _tag['Key'] == tag:
                    return _tag['Value']
        return False
    
    def is_attached_to_network_interfaces(self):
        NetworkInterfaces = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                NetworkInterfaces.append(NetworkInterface['NetworkInterfaceId'])
            return NetworkInterfaces
        return False
    
    def is_attached_to_ec2_instances(self):
        Ec2Instances = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                try:
                    Ec2Instances.append(NetworkInterface['Attachment']['InstanceId'])
                except KeyError:
                    continue
            if Ec2Instances: return Ec2Instances
        return False

    def is_attached_to_managed_services(self):
        ManagedServices = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                try:
                    RequesterId = NetworkInterface['RequesterManaged']
                    if RequesterId == True:
                        ManagedServices.append(NetworkInterface['Description'])
                except KeyError:
                    continue
            if ManagedServices: return ManagedServices
        return False

    def is_attached_to_public_ips(self):
        PublicIPs = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                try:
                    PublicIPs.append(NetworkInterface['Association']['PublicIp'])
                except KeyError:
                    continue
            if PublicIPs: return PublicIPs
        return False
    
    def is_public(self):
        if self.is_attached_to_public_ips():
            return True
        return False

    def checks(self):
        checks = [
            'is_attached_to_network_interfaces',
            'is_attached_to_ec2_instances',
            'is_attached_to_public_ips',
            'is_attached_to_managed_services',
            'is_public'
            ]
        return checks

    def output(self):
        mh_values = {}
        mh_matched = False if self.mh_filters else True

        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values.update({check: hndl})
            if check in self.mh_filters and hndl:
                mh_matched = True
        
        # Tags
        mh_values.update({'tag_Name': self.tag_Name})
        mh_values.update({'tag_Owner': self.tag_Owner})
        mh_values.update({'tag_Environment': self.tag_Environment})
                
        return mh_values, mh_matched