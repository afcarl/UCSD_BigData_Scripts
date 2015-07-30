#!/usr/bin/env python

import os
import sys
import json
from ucsd_bigdata_scripts.vault import Vault


class Credentials:

    def __init__(self):
        vault = Vault()
        self.credentials_json_file = "%s/credentials.json" % vault.path

        self.aws_user_name = None
        self.aws_access_key_id = None
        self.aws_secret_access_key = None
        self.ec2_ssh_key_name = None
        self.ec2_ssh_key_pair_file = None
        self.s3_bucket = None
        self.emr_ssh_key_pair_file = None

        Credentials.get(self)

    def get(self, json_object_name="student"):
        if os.path.isfile(self.credentials_json_file):
            try:
                with open(self.credentials_json_file, 'r') as f:
                    credentials_json = json.load(f)
            except ValueError:
                print "%s is not valid json" % self.credentials_json_file
                sys.exit()

            if "aws_user_name" in credentials_json[json_object_name]:
                self.aws_user_name = credentials_json[json_object_name]["aws_user_name"]
            if "aws_access_key_id" in credentials_json[json_object_name]:
                self.aws_access_key_id = credentials_json[json_object_name]["aws_access_key_id"]
            if "aws_secret_access_key" in credentials_json[json_object_name]:
                self.aws_secret_access_key = credentials_json[json_object_name]["aws_secret_access_key"]
            if "ec2_ssh_key_name" in credentials_json[json_object_name]:
                self.ec2_ssh_key_name = credentials_json[json_object_name]["ec2_ssh_key_name"]
            if "ec2_ssh_key_pair_file" in credentials_json[json_object_name]:
                self.ec2_ssh_key_pair_file = credentials_json[json_object_name]["ec2_ssh_key_pair_file"]
            if "s3_bucket" in credentials_json[json_object_name]:
                self.s3_bucket = credentials_json[json_object_name]["s3_bucket"]
            if "emr_ssh_key_pair_file" in credentials_json[json_object_name]:
                self.emr_ssh_key_pair_file = credentials_json[json_object_name]["emr_ssh_key_pair_file"]
