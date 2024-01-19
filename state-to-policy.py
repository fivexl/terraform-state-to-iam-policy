
#!/usr/bin/env python3

import json
import argparse
import logging
import boto3

ignore_list = [
    'aws_iam_policy_document',
    'aws_caller_identity'
]


def get_policy_document(statements):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": statements
    }, indent=2)


def validate_statement(logger, client, statement):
    policy_document = get_policy_document([statement])
    try:
        client.validate_policy(
            policyDocument=policy_document,
            policyType='IDENTITY_POLICY'
        )
    except Exception as e:
        logger.error(
            f"Invalid policy statement:\n{policy_document}")
        raise e


def prepare_policy_statement(logger, type, service, resource, arns):

    if len(arns) == 0:
        arns = "*"

    action = [f"{service}:*{resource}*"]
    if type == 'data':
        action = [
            f"{service}:Get{resource}*",
            f"{service}:List{resource}*",
            f"{service}:Describe{resource}*",
        ]

    return {
        "Sid": f"Allow{service.capitalize()}{resource}",
        "Action": action,
        "Effect": "Allow",
        "Resource": arns
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

    return data_sources, resources


def main():
    args = get_args()

    logging.basicConfig()
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    with open(args.state_file) as f:
        data = json.load(f)

    data_sources, resources = parse_state_file(logger, data, ignore_list)

    client = boto3.client('accessanalyzer')
    policy_statements = []
    for data_source in data_sources.keys():
        service, resource_name = parse_resource_name(data_source)
        statement = prepare_policy_statement(
            logger, 'data', service, resource_name, data_sources[data_source]
        )
        validate_statement(logger, client, statement)
        policy_statements.append(statement)
    for resource in resources.keys():
        service, resource_name = parse_resource_name(resource)
        statement = prepare_policy_statement(
            logger, 'resource', service, resource_name, resources[resource]
        )
        validate_statement(logger, client, statement)
        policy_statements.append(statement)
    print(get_policy_document(policy_statements))


if __name__ == "__main__":
    main()
