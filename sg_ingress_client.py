import sys, datetime, hashlib, hmac
import requests
import boto3

sts_client = boto3.client('sts')


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(key, datestamp, regionname, servicename):
    kdate = sign(('AWS4' + key).encode('utf-8'), datestamp)
    kregion = sign(kdate, regionname)
    kservice = sign(kregion, servicename)
    ksigning = sign(kservice, 'aws4_request')
    return ksigning


def get_creds(o):
    # Accepts: otp
    temp_creds = sts_client.assume_role(
        RoleArn='arn:aws:iam::<aws_account_id>:role/<apigateway_invoke_role>',
        RoleSessionName='<descriptive session name>',
        DurationSeconds=900,
        SerialNumber='arn:aws:iam::<aws_account_id>:mfa/<iam_user_name>',
        TokenCode=o
    )
    l = list()
    for key, value in temp_creds['Credentials'].iteritems():
        l.append(value)
    if l[0] is None or l[3] is None:
        print "No access key returned"
        sys.exit()
    return l


def build_canonical(rp, h, r, s, ak, sk, st, ep, m):
    # Accepts: request_url, region, service, access_key, secret_key, session_token, endpoint, method

    t = datetime.datetime.utcnow()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    canonical_uri = '/prod/sgIngress/sg'
    canonical_querystring = rp
    canonical_headers = 'host:' + h + '\n' + 'x-amz-date:' + amzdate + '\n'

    signed_headers = 'host;x-amz-date'
    payload_hash = hashlib.sha256('').hexdigest()
    canonical_request = m + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' \
                        + signed_headers + '\n' + payload_hash

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + r + '/' + s + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + amzdate + '\n' + credential_scope + '\n' + hashlib.sha256(
        canonical_request).hexdigest()

    signing_key = get_signature_key(sk, datestamp, r, s)
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
    authorization_header = algorithm + ' ' + 'Credential=' + ak + '/' + credential_scope + ', ' + 'SignedHeaders=' \
                           + signed_headers + ', ' + 'Signature=' + signature
    # all headers
    hs = {'x-amz-date': amzdate, 'Authorization': authorization_header, 'X-Amz-Security-Token': st}
    # request url
    ru = ep + '?' + canonical_querystring
    # add request url, headers to list
    l = [ru, hs]

    return l


if __name__ == '__main__':
    vpcid = 'vpc-xxxxxxxx'  # VPC ID containing security group
    sgid = 'sg-xxxxxxxx'  # Security Group ID dedicated for "remote access" ingress rules
    method = 'GET'
    service = 'execute-api'
    host = '123.myapi.456.execute-api.<region>.amazonaws.com'
    region = '<region>'
    endpoint = 'https://123myapi456.execute-api.<region>.amazonaws.com/prod/sgIngress/sg'
    request_parameters = 'sgid=' + sgid + '&vpcid=' + vpcid
    otp = raw_input("OTP: ")
    credentials = get_creds(otp)
    access_key = credentials[3]
    secret_key = credentials[0]
    session_token = credentials[1]
    request = build_canonical(request_parameters, host, region, service, access_key, secret_key, session_token,
                              endpoint, method)
    url_request = request[0]
    headers = request[1]
    r = requests.get(url_request, headers=headers)
    print r.text
