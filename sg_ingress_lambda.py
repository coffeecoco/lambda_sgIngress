import boto3

s = boto3.Session()
ec2_client = s.client('ec2')

# Add ingress rule for SSH TCP/22 to the designated SG
def sg_add_ingress(pub_ip, sg):
    response = ec2_client.authorize_security_group_ingress(
        GroupId=sg,
        IpProtocol='tcp',
        FromPort=22,
        ToPort=22,
        CidrIp=pub_ip
    )
    return response

# Remove any existing rules in the SG provided the current CIDR doesn't match
def remove_old_rule(r, sg, ip):
    rules = r['SecurityGroups'][0]
    if len(rules['IpPermissions']) > 0:
        curr_ip = r['SecurityGroups'][0]['IpPermissions'][0]['IpRanges'][0]['CidrIp']
        if str(ip) == str(curr_ip):
            print('Public IP already exists')
            return False
        else:
            ec2_client.revoke_security_group_ingress(GroupId=sg, IpPermissions=rules['IpPermissions'])
            return True
            
    else:
        print('No security group rules for ' + sg)
        return True

# Return EC2 SG object based on filters defined by provided VPCID/SGID
def run_call(ip, sg, vpc):
    sgrules = ec2_client.describe_security_groups(Filters=
    [
        {
            'Name': 'vpc-id',
            'Values': [vpc]
        },
        {
            'Name': 'group-id',
            'Values': [sg]
        }
    ]
    )
    r = remove_old_rule(sgrules, sg, ip)
    if r is True:
        sg_add_ingress(ip, sg)
        return True
    elif r is False:
        return False


# Lambda Handler
# Populate sgid and vpcid variables from API Gateway context object mappings
def handler(event, context):

    vpcid = event['vpcid']
    secgrp = event['sgid']
    pub_ip = event['pub_ip'] + '/32'
    c = run_call(pub_ip, secgrp, vpcid)
    if c is True:
        return "Public IP address added: " + pub_ip
    elif c is False:
        return "Rule for Public IP already exists: " + pub_ip
