import json
import boto3
import botocore.exceptions
import requests
import sys
import os
from typing import Union, List, Dict, Any, Tuple


class NsLabs:
    def __init__(
        self,
        c1ns_account_name: str,
        infra_file_path: str = "infra.yaml",
        infra_stack_name: str = "c1ns-demo-infra",
        ns_role_stack_name: str = "NetworkSecurityRole",
        c1ns_stack_name: str = "c1ns-appliance",
    ):

        # set up API credentials & header
        self.ws_api_key = os.environ["C1_KEY"]
        self.headers = {
            "api-secret-key": self.ws_api_key,
            "api-version": "v1",
        }

        self.ssh_key_name = sys.argv[1]

        # get AWS region & account ID
        print("Getting AWS account details...")
        self.cfn = boto3.resource("cloudformation")
        self.region = boto3.session.Session().region_name
        self.account_id = boto3.client("sts").get_caller_identity().get("Account")
        print(f"Region: {self.region}, Account ID: {self.account_id}")

        # get Network Security account ID and external ID
        print("Getting Network Security details...")
        cross_account_iam_info = self.get_cross_account_iam_info()
        self.network_security_id = cross_account_iam_info["networkSecurityAccountId"]
        external_id = cross_account_iam_info["externalId"]
        print(
            f"Network Security Account ID: {self.network_security_id}, External ID: {external_id}"
        )

        # create cross account role & get Network Security role ARN
        print("Creating cross account role...")
        policy_document = cross_account_iam_info["crossAccountPolicyPermissions"]
        self.create_cross_account_role_stack(ns_role_stack_name, policy_document)
        network_security_role_arn = self._get_network_security_role_arn(
            ns_role_stack_name
        )

        # create Network Security AWS connector
        print("Creating Network Security AWS Connector...")
        self.create_aws_connector(
            c1ns_account_name, external_id, network_security_role_arn
        )
        print("Done")

        # Spin up lab environment (e.g vulnerable host(s))
        print("Spinning up vulnerable lab environment...")
        self.create_lab_infra(infra_file_path, infra_stack_name)
        print("Done")

        # Spin up C1NS appliance
        print("Spinning up C1NS appliance...")
        self.create_c1ns_appliance_stack(infra_stack_name, c1ns_stack_name)
        print("Done")

    def create_aws_connector(
        self, c1ns_account_name: str, external_id: str, network_security_role_arn: str
    ) -> None:
        conn_payload = {
            "accountName": c1ns_account_name,
            "crossAccountRole": network_security_role_arn,
            "externalId": external_id,
        }

        url = "https://cloudone.trendmicro.com/api/network/awsconnectors"
        requests.post(url, headers=self.headers, data=json.dumps(conn_payload))

    def create_lab_infra(
        self,
        infra_file_path: str,
        infra_stack_name: str,
        admin_ip: str = "0.0.0.0/0",
    ) -> None:
        parameters = [
            {
                "ParameterKey": "KeyName",
                "ParameterValue": self.ssh_key_name,
            },
            {
                "ParameterKey": "AdminIp",
                "ParameterValue": admin_ip,
            },
        ]

        with open(infra_file_path, "r") as f:
            cfn_template = f.read()

        self.create_cfn_stack(infra_stack_name, cfn_template, parameters)

    def create_c1ns_appliance_stack(
        self, infra_stack_name: str, c1ns_stack_name: str
    ) -> None:
        igw_id = self.get_cfn_output(infra_stack_name, "IgwId")
        print(f"IGW ID: {igw_id}")
        cfn = self._generate_c1ns_cfn(igw_id)

        print("Creating C1NS appliance stack...")
        self.create_cfn_stack(c1ns_stack_name, cfn, parameters=None)

    def _get_cfn_recommended_params(self, igw_id: str) -> Tuple[str, str]:
        rec_payload = {
            "accountId": self.account_id,
            "internetGatewayId": igw_id,
            "region": self.region,
        }

        url = "https://cloudone.trendmicro.com/api/network/recommendedcftparams"
        resp = requests.post(url, headers=self.headers, data=json.dumps(rec_payload))

        cfn_params = resp.json()
        inspection_subnets = cfn_params["inspectionSubnets"]
        management_subnets = cfn_params["managementSubnets"]
        return inspection_subnets, management_subnets

    def _generate_c1ns_cfn(self, igw_id: str) -> str:
        inspection_subnets, management_subnets = self._get_cfn_recommended_params(
            igw_id
        )

        cfn_payload = {
            "internetGatewayId": igw_id,
            "region": self.region,
            "sshKeypair": self.ssh_key_name,
            "inspectionSubnets": inspection_subnets,
            "managementSubnets": management_subnets,
            "apiKey": self.ws_api_key,
            "accountId": self.account_id,
            "scriptFormat": "json",
        }

        url = "https://cloudone.trendmicro.com/api/network/protectigwcfts"
        resp = requests.post(url, headers=self.headers, data=json.dumps(cfn_payload))
        str_cfn = resp.json()["output"]

        # reduce instance size
        updated_str_cfn = str_cfn.replace("c5n.4xlarge", "c5.xlarge")

        # add CloudWatch commands
        after_location = updated_str_cfn.find(',"# -- END VTPS CLI\\n",')
        before = updated_str_cfn[:after_location]
        after = updated_str_cfn[after_location:]
        cloudwatch_commands = '"edit\\n","log\\n","cloudwatch inspection-event enable\\n","cloudwatch ips-event enable\\n","commit\\n","exit\\n","save-config -y\\n"'
        final_str_cfn = f"{before},{cloudwatch_commands}{after}"

        print("Generated CFN stack")

        return final_str_cfn

    def get_cross_account_iam_info(self) -> Any:
        url = "https://cloudone.trendmicro.com/api/network/crossaccountroleiaminfo"
        resp = requests.get(url, headers=self.headers)
        output = resp.json()

        return output

    def get_cfn_output(self, stack_name: str, output_name: str) -> Any:
        cfn_stack = self.cfn.Stack(stack_name)

        for output in cfn_stack.outputs:
            if output["OutputKey"] != output_name:
                continue

            output_value = output["OutputValue"]

            return output_value

    def _get_network_security_role_arn(self, ns_role_stack_name: str) -> Any:
        cfn_stack = self.cfn.Stack(ns_role_stack_name)

        for output in cfn_stack.outputs:
            if output["OutputKey"] != "NetworkSecurityRoleArn":
                continue

            network_security_role_arn = output["OutputValue"]
            print(f"Network Security role ARN: {network_security_role_arn}")

            return network_security_role_arn

        sys.exit("Error: Could not find Network Security role ARN.")

    def create_cross_account_role_stack(
        self, ns_role_stack_name: str, policy_document: str
    ) -> None:
        cfn_dict = {
            "Resources": {
                "NetworkSecurityIamRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Principal": {
                                    "AWS": f"arn:aws:iam::{self.network_security_id}:root"
                                },
                            },
                        },
                        "ManagedPolicyArns": [{"Ref": "NetworkSecurityIamPolicy"}],
                        "RoleName": "NetworkSecurityRole",
                    },
                },
                "NetworkSecurityIamPolicy": {
                    "Type": "AWS::IAM::ManagedPolicy",
                    "Properties": {
                        "Description": "Trend Micro Network Security IAM policy",
                        "ManagedPolicyName": "NetworkSecurityPolicy",
                        "PolicyDocument": policy_document,
                    },
                },
            },
            "Outputs": {
                "NetworkSecurityRoleArn": {
                    "Description": "Network Security role ARN",
                    "Value": {
                        "Fn::GetAtt": ["NetworkSecurityIamRole", "Arn"],
                    },
                    "Export": {
                        "Name": {"Fn::Sub": "${AWS::StackName}-NetworkSecurityRoleArn"}
                    },
                }
            },
        }

        cfn_template = json.dumps(cfn_dict)
        self.create_cfn_stack(ns_role_stack_name, cfn_template, None)

    def create_cfn_stack(
        self,
        stack_name: str,
        cfn_template: str,
        parameters: Union[None, List[Dict[str, str]]],
    ) -> None:
        if not isinstance(cfn_template, str):
            cfn_template = json.dumps(cfn_template)

        parameters = parameters or []

        try:
            self.cfn.create_stack(
                StackName=stack_name,
                TemplateBody=cfn_template,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Parameters=parameters,
            )

            waiter = self.cfn.meta.client.get_waiter("stack_create_complete")
            waiter.wait(StackName=stack_name)

            print(f"Created stack: {stack_name}")

        except botocore.exceptions.ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code != "AlreadyExistsException":
                sys.exit(f"Error: {e}")

            print(f'Stack "{stack_name}" already exists')


def main() -> None:  # noqa: D103
    NsLabs(c1ns_account_name="C1nsDemo")


if __name__ == "__main__":
    main()
