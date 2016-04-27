#Updating EC2 security groups with Lambda

##sg_ingress_lambda.py

The Lambda function that integrates with API Gateway. Inherits VPC and Security Group IDs from URL query string parameters via API Gateway context object mapping:

```
{
"pub_ip": "$context.identity.sourceIp",
"vpcid": "$input.params('vpcid')",
"sgid": "$input.params('sgid')"
}
```

##sg_ingress_client.py

Local script used to assume an IAM role with API Gateway invocation permissions. Uses IAM MFA for initial assume role request. Inherits temporary credentials from assumed role, which are used to sign a GET request sent to the API Gateway endpoint that fires off the Lambda function above.

More information available on [my blog](http://natemitchell.co.za/modifying-ec2-security-groups-with-lambda-using-iam-mfa/)
