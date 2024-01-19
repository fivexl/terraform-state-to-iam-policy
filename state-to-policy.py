#!/usr/bin/env python3

import sys
import json
import argparse
import logging
import boto3

ignore_list = [
    'aws_iam_policy_document',
    'aws_caller_identity',
    'aws_region',
    'aws_canonical_user_id',
    'aws_partition',
]

ignore_replace_list_actions = {
    "appmesh:GetMesh*": None,
    "appautoscaling:*Policy*": "autoscaling:*Policy*",
    "appautoscaling:*Target*": "autoscaling:*Target*",
    "ecs:GetCluster*": None,
    "s3:DescribeBucket*": None,
    "secretsmanager:GetSecretVersion*": "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecretVersion*": None,
    "vpc:Get*": "ec2:Get*",
    "vpc:List*": "ec2:List*",
    "vpc:Describe*": "ec2:Describe*",
    "vpc:GetEndpoint*": None,
    "vpc:ListEndpoint*": None,
    "vpc:DescribeEndpoint*": "ec2:DescribeVpcEndpoint*",
    "security:GetGroup*": "ec2:GetSecurityGroup*",
    "security:ListGroup*": None,
    "security:DescribeGroup*": "ec2:DescribeSecurityGroup*",
    "security:*Group*": "ec2:*SecurityGroup*",
    "subnet:Get*": None,
    "subnet:List*": None,
    "subnet:Describe*": "ec2:DescribeSubnets",
    "subnets:Get*": None,
    "subnets:List*": None,
    "subnets:Describe*": "ec2:DescribeSubnets",
    "service:GetDiscoveryDnsNamespace*": "servicediscovery:Get*",
    "service:ListDiscoveryDnsNamespace*": "servicediscovery:List*",
    "service:DescribeDiscoveryDnsNamespace*": None,
    "service:*DiscoveryService*": "servicediscovery:*",  # need to investigate
    "iam:DescribeRole*": None,
    "elasticsearch:GetDomain*": None,
    "elasticsearch:ListDomain*": None,
    "elasticsearch:DescribeDomain*": "es:DescribeElasticsearchDomain*",
    "kms:GetAlias*": None,
    "kms:DescribeAlias*": None,
    "sns:DescribeTopic*": None,
    "ssm:ListParameter*": None,
    "cloudwatch:*LogGroup*": "logs:*LogGroup*",
    "cloudwatch:*LogStream*": "logs:*LogStream*",
    "kinesis:*FirehoseDeliveryStream*": "firehose:*DeliveryStream*",
    "s3:ListObject*": None,
    "s3:DescribeObject*": None,
    "s3:*BucketEncryption*": "s3:*EncryptionConfiguration*",
    "s3:*BucketServerSideEncryptionConfiguration*": "s3:*BucketEncryption*",
    "s3:*BucketLifecycleConfiguration*": "s3:*LifecycleConfiguration*",
    "iam:*RolePolicyAttachment*": "iam:*RolePolic*",
}


def check_action_candidate(action_candidate):
    if action_candidate not in ignore_replace_list_actions.keys():
        return action_candidate
    elif ignore_replace_list_actions[action_candidate] is not None:
        return ignore_replace_list_actions[action_candidate]
    else:
        return None


def get_policy_document(statements):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": statements
    }, indent=2)


def validate_statement(logger, client, statement):
    policy_document = get_policy_document([statement])
    try:
        findings = client.validate_policy(
            policyDocument=policy_document,
            policyType='IDENTITY_POLICY'
        )
        if len(findings['findings']) > 0:
            logger.error(
                f"Invalid policy statement:\n{policy_document}\n{json.dumps(findings['findings'], indent=4)}")
            # sys.exit(1)
    except Exception as e:
        logger.error(
            f"Invalid policy statement:\n{policy_document}")
        raise e


def prepare_policy_statement(logger, type, service, resource, arns):

    if len(arns) == 0:
        arns = "*"

    action = []
    if type == 'data':
        for verb in ['Get', 'List', 'Describe']:
            action_candidate = check_action_candidate(
                f"{service}:{verb}{resource}*")
            if action_candidate is not None:
                action.append(action_candidate)
    else:
        action_candidate = check_action_candidate(f"{service}:*{resource}*")
        action.append(action_candidate)

    return {
        "Sid": f"Allow{service.capitalize()}{resource}",
        "Action": action,
        "Effect": "Allow",
        "Resource": arns
    }


def prepare_wildcard_policy_statement(sid, actions):

    approved_actions = []
    for action in actions:
        if check_action_candidate(action) is not None:
            approved_actions.append(check_action_candidate(action))

    return {
        "Sid": sid,
        "Action": approved_actions,
        "Effect": "Allow",
        "Resource": "*"
    }


def parse_resource_name(name):
    # drop AWS prefix
    name = name.replace('aws_', '')
    # split by underscore
    name_parts = name.split('_')
    # first part is service
    service = name_parts[0]
    name_parts = name_parts[1:]

    # capitalize each word
    name_parts = [part.capitalize() for part in name_parts]
    # join back together
    resource = ''.join(name_parts)

    return service, resource


def get_args():
    parser = argparse.ArgumentParser(
        description="Update workflow files in all repos.")
    parser.add_argument("state_file", default="terraform.tfstate",
                        help="Path to terraform state file. Defaults to terraform.tfstate.")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="Enable debug logging.")
    return parser.parse_args()


def parse_state_file(logger, state_file, ignore_list):
    data_sources = dict()
    resources = dict()

    for resource in state_file['resources']:
        # skip non-aws resources
        if not resource['type'].startswith('aws_'):
            continue
        if resource['type'] in ignore_list:
            continue
        if resource['mode'] == 'data':
            if not resource['type'] in data_sources:
                data_sources[resource['type']] = []
            for instance in resource['instances']:
                if 'attributes' in instance and 'arn' in instance['attributes']:
                    data_sources[resource['type']].append(
                        instance['attributes']['arn'])
        if resource['mode'] == 'managed':
            if not resource['type'] in resources:
                resources[resource['type']] = []
            for instance in resource['instances']:
                if 'attributes' in instance and 'arn' in instance['attributes']:
                    resources[resource['type']].append(
                        instance['attributes']['arn'])

    logger.debug(f'Data Sources: {json.dumps(data_sources, indent=4)}')
    logger.debug(f'Resources: {json.dumps(resources, indent=4)}')

    wildcard_data_sources = {}
    wildcard_resources = {}
    scoped_data_sources = {}
    scoped_resources = {}

    for data_source in data_sources.keys():
        if len(data_sources[data_source]) == 0:
            wildcard_data_sources[data_source] = data_sources[data_source]
        else:
            # dedupe
            scoped_data_sources[data_source] = list(
                set(data_sources[data_source]))
    for resource in resources.keys():
        if len(resources[resource]) == 0:
            wildcard_resources[resource] = resources[resource]
        else:
            # dedupe
            scoped_resources[resource] = list(set(resources[resource]))

    return wildcard_data_sources, scoped_data_sources, wildcard_resources, scoped_resources


def main():
    args = get_args()

    logging.basicConfig()
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    with open(args.state_file) as f:
        data = json.load(f)

    wildcard_data_sources, scoped_data_sources, wildcard_resources, scoped_resources = parse_state_file(
        logger, data, ignore_list
    )

    client = boto3.client('accessanalyzer')
    policy_statements = []
    for data_source in scoped_data_sources.keys():
        service, resource_name = parse_resource_name(data_source)
        statement = prepare_policy_statement(
            logger, 'data', service, resource_name, scoped_data_sources[data_source]
        )
        validate_statement(logger, client, statement)
        policy_statements.append(statement)
    for resource in scoped_resources.keys():
        service, resource_name = parse_resource_name(resource)
        statement = prepare_policy_statement(
            logger, 'resource', service, resource_name, scoped_resources[resource]
        )
        validate_statement(logger, client, statement)
        policy_statements.append(statement)

    wildcard_read_actions = list()
    for wildcard_data_source in wildcard_data_sources.keys():
        service, resource_name = parse_resource_name(wildcard_data_source)
        wildcard_read_actions.append(f"{service}:List{resource_name}*")
        wildcard_read_actions.append(f"{service}:Get{resource_name}*")
        wildcard_read_actions.append(f"{service}:Describe{resource_name}*")
    statement = prepare_wildcard_policy_statement(
        "AllowWildCardRead", wildcard_read_actions)
    validate_statement(logger, client, statement)
    policy_statements.append(statement)

    wildcard_manage_actions = list()
    for wildcard_resource in wildcard_resources.keys():
        service, resource_name = parse_resource_name(wildcard_resource)
        wildcard_manage_actions.append(f"{service}:*{resource_name}*")
    statement = prepare_wildcard_policy_statement(
        "AllowWildCardManage", wildcard_manage_actions)
    validate_statement(logger, client, statement)
    policy_statements.append(statement)

    print(get_policy_document(policy_statements))


if __name__ == "__main__":
    main()
