#!/usr/bin/env python

import sys
import os
from glob import glob
import csv
import json
from os.path import expanduser
import boto.ec2
from boto.s3.connection import S3Connection
import socket
import time
import logging
import argparse
import shutil

credentials_file_name = "credentials.json"
emr_ssh_key_pair_name = "emr-shared-key"
emr_ssh_key_pair_file_name = "emr-shared-key.pem"


def test_aws_credentials(aws_access_key_id, aws_secret_access_key):
    s3_conn = S3Connection(aws_access_key_id, aws_secret_access_key)

    try:
        s3_conn.get_all_buckets()
        logging.info("AWS Access Key ID and Access Key are correct: %s" % aws_access_key_id)
        s3_conn.close()
        return True
    except boto.exception.S3ResponseError:
        s3_conn.close()
        logging.info("WARN: AWS Access Key ID and Access Key are incorrect: %s" % aws_access_key_id)
        return False


def get_ec2_ssh_key_pair(aws_user_name, aws_access_key_id, aws_secret_access_key, region):
    try:
        ec2_conn = boto.ec2.connect_to_region(region,
                                              aws_access_key_id=aws_access_key_id,
                                              aws_secret_access_key=aws_secret_access_key)
    except Exception, e:
        logging.info("There was an error connecting to EC2: %s" % e)
        return None, None

    # Generate or specify the SSH key pair
    need_ssh_key_pair = True
    ec2_ssh_key_name = None
    ec2_ssh_key_pair_file = None
    pem_files = glob(vault + '/*.pem')

    # Log the pem files found in the vault directory
    for pem_file in pem_files:
        logging.info("Found pem file: %s" % pem_file)

        # Remove the emr_ssh_key_pair_file from this list of pem files
        if emr_ssh_key_pair_file_name in pem_file:
            logging.info("Removing pem file from the list: %s" % pem_file)
            pem_files.remove(pem_file)

    while need_ssh_key_pair:
        # If no pem_files exist in the vault then create one
        if len(pem_files) is 0:
            logging.info("No pem files found, generating a new SSH key pair")
            ec2_ssh_key_name = "%s_%s_%s" % (str(aws_user_name),
                                             str(socket.gethostname()),
                                             str(int(time.time())))
            try:
                key = ec2_conn.create_key_pair(key_name=ec2_ssh_key_name)
                key.save(vault)
            except Exception, e:
                ec2_conn.close()
                logging.info("There was an error creating a new SSH key pair: %s" % e)
                return None, None

            ec2_ssh_key_pair_file = vault + "/" + ec2_ssh_key_name + ".pem"

            if os.path.isfile(ec2_ssh_key_pair_file):
                print "SSH key pair created..."
                logging.info("SSH key pair created: %s : %s" % (ec2_ssh_key_name,
                                                                ec2_ssh_key_pair_file))
                need_ssh_key_pair = False
            else:
                logging.info("Error creating SSH key pair")
                sys.exit("Error creating SSH key pair")
        # If pem_files exist in the vault then select the first pem file that matches the name
        # of a ssh key pair on AWS
        else:
            try:
                aws_key_pairs = ec2_conn.get_all_key_pairs()
            except Exception, e:
                ec2_conn.close()
                logging.info("There was an error getting the key pairs from AWS: %s" % e)
                return None, None

            for pem_file in pem_files:
                logging.info("Checking %s for a match on AWS" % pem_file)
                ec2_ssh_key_name = os.path.splitext(os.path.basename(str(pem_file)))[0]
                ec2_ssh_key_pair_file = pem_file

                # Verify the ec2_ssh_key_name matches a ssh_key on AWS
                if any(ec2_ssh_key_name in k.name for k in aws_key_pairs):
                    logging.info("Found matching SSH key pair: %s :  %s" % (ec2_ssh_key_name,
                                                                            ec2_ssh_key_pair_file))
                    print "Found matching SSH key pair..."
                    need_ssh_key_pair = False
                    break
                else:
                    # If the pem_file is not in EC2 then remove it from pem_files to get
                    # len(pem_files) to 0 trigger the creation of a new ssh key pair
                    pem_files.remove(pem_file)
    ec2_conn.close()

    return ec2_ssh_key_name, ec2_ssh_key_pair_file


def get_s3_bucket(aws_user_name, aws_access_key_id, aws_secret_access_key):
    logging.info("Looking for the student's S3 Bucket")

    s3_bucket_prefix_list = ["dse-", "cse-"]
    s3_bucket = None

    s3_conn = S3Connection(aws_access_key_id, aws_secret_access_key)

    for s3_bucket_prefix in s3_bucket_prefix_list:
        logging.info("Checking Student S3 Bucket: %s%s" % (s3_bucket_prefix, aws_user_name))
        try:
            s3_conn.get_bucket("%s%s" % (s3_bucket_prefix, aws_user_name))
            s3_bucket = "s3://%s%s/" % (s3_bucket_prefix, aws_user_name)
            print "Student S3 Bucket found: %s" % s3_bucket
            break
        except boto.exception.S3ResponseError:
            logging.info("Student S3 Bucket NOT found: %s" % s3_bucket)
            continue

    s3_conn.close()

    return s3_bucket


def get_emr_ssh_key_pair(aws_access_key_id, aws_secret_access_key):
    logging.info("Looking for EMR S3 Bucket")

    s3_bucket_list = ["mas-dse-emr", "cse-emr"]
    emr_ssh_key_pair_file = None

    s3_conn = S3Connection(aws_access_key_id, aws_secret_access_key)

    for s3_bucket in s3_bucket_list:
        logging.info("Checking EMR S3 Bucket: %s" % s3_bucket)
        try:
            emr_bucket = s3_conn.get_bucket("%s" % s3_bucket)
            logging.info("EMR S3 Bucket found: %s" % s3_bucket)
            key = emr_bucket.get_key(emr_ssh_key_pair_file_name)
            logging.info("EMR SSH Key Found in S3 Bucket: %s/%s" % (s3_bucket,
                                                                    emr_ssh_key_pair_file_name))
            key.get_contents_to_filename("%s/%s" % (vault, emr_ssh_key_pair_file_name))
            logging.info("EMR SSH Key downloaded to: %s/%s" % (vault, emr_ssh_key_pair_file_name))

            if os.path.isfile("%s/%s" % (vault, emr_ssh_key_pair_file_name)):
                emr_ssh_key_pair_file = "%s/%s" % (vault, emr_ssh_key_pair_file_name)
                logging.info("EMR SSH Key found at: %s" % emr_ssh_key_pair_file)
            break
        except boto.exception.S3ResponseError, emr_error:
            logging.info("EMR S3 Error: %s" % emr_error)
            continue

    s3_conn.close()

    return emr_ssh_key_pair_file


def collect_credentials():
    credentials = []

    # Log the csv files found in the vault directory
    for csv_file in glob(vault + '/*.csv'):
        logging.info("Found csv file: %s" % csv_file)

        if os.path.isfile(csv_file):
            with open(csv_file, 'r') as f:
                reader = csv.reader(f)
                aws_credentials_list = list(reader)

                for aws_credentials in aws_credentials_list:
                    # Skip the csv column header
                    if not aws_credentials[1] == "Access Key Id":
                        if test_aws_credentials(aws_credentials[1], aws_credentials[2]):
                            credentials.append({'user_name': aws_credentials[0],
                                                'access_key_id': aws_credentials[1],
                                                'secret_access_key': aws_credentials[2]})

    # If there is more than one AWS key pair then display them using a menu,
    # otherwise just select the one
    if len(credentials) > 1:
        # Log the valid AWS credentials that are found
        logging.info("Multiple AWS credentials found:")

        print "You have multiple AWS credentials in your vault. The user names are listed below:\n"

        for position, credential in enumerate(credentials):
            logging.info("AWS credential found: %s : %s" %
                         (credential["user_name"], credential["access_key_id"]))

            print "\t%s. %s (%s)" % (position + 1,
                                     credential["user_name"],
                                     credential["access_key_id"])

        # Make sure user_input is value
        selected_credentials = None
        while selected_credentials is None:
            user_input = raw_input("\nEnter the number next to the credentials that "
                                   "you would like to use: ")
            try:
                if 0 < int(user_input) <= len(credentials):
                    selected_credentials = int(user_input) - 1
            except ValueError:
                continue

        logging.info("AWS credential selected: %s : %s" %
                     (credentials[selected_credentials]["user_name"],
                      credentials[selected_credentials]["access_key_id"]))
    elif len(credentials) == 1:
        selected_credentials = 0
        logging.info("One AWS credential found and selected: %s : %s" %
                     (credentials[selected_credentials]["user_name"],
                      credentials[selected_credentials]["access_key_id"]))
    else:
        logging.info("No AWS credentials found")
        sys.exit("No AWS credentials found.")

    return credentials[selected_credentials]["user_name"], \
        credentials[selected_credentials]["access_key_id"], \
        credentials[selected_credentials]["secret_access_key"]


def save_credentials_json(json_object_name, aws_user_name, aws_access_key_id, aws_secret_access_key,
                          ec2_ssh_key_name, ec2_ssh_key_pair_file, s3_bucket,
                          emr_ssh_key_pair_file):
    # Make sure all of the variables exist before trying to write them to
    # vault/credentials_file_name
    if ((aws_user_name is not None) and (aws_access_key_id is not None) and
            (aws_secret_access_key is not None)):
        print "ID: %s, key_id: %s" % (aws_user_name, aws_access_key_id)
        print "ec2_ssh_key_name: %s, ec2_ssh_key_pair_file: %s" % (ec2_ssh_key_name,
                                                                   ec2_ssh_key_pair_file)
        print "s3_bucket: %s, emr_ssh_key_pair_file: %s" % (s3_bucket, emr_ssh_key_pair_file)
    else:
        logging.info("Undefined variable: user_id: %s, key_id: %s ec2_ssh_key_name: %s, "
                     "ec2_ssh_key_pair_file: %s" % (aws_user_name, aws_access_key_id,
                                                    ec2_ssh_key_name, ec2_ssh_key_pair_file))
        sys.exit("Undefined variable")

    credentials_json = dict()

    # If credentials_file_name already exists then make a copy of the file and copy the
    # credentials that are not json_object_name credentials into the new credentials_file_name
    if os.path.isfile("%s/%s" % (vault, credentials_file_name)):
        logging.info("Found existing %s/%s" % (vault, credentials_file_name))
        # Make a copy of vault/credentials_file_name before making any changes
        credentials_file_copy = "%s/%s-%s" % (vault, credentials_file_name, str(int(time.time())))
        try:
            shutil.copyfile("%s/%s" % (vault, credentials_file_name), credentials_file_copy)
            logging.info("Copied %s/%s to %s" % (vault, credentials_file_name,
                                                 credentials_file_copy))
        except (IOError, EOFError):
            logging.info("Error copying %s/%s to %s" % (vault, credentials_file_name,
                                                        credentials_file_copy))
            sys.exit("Error copying %s/%s to %s" % (vault, credentials_file_name,
                                                    credentials_file_copy))

        # Read the contents of vault/credentials_file_name
        old_credentials_json = dict()
        try:
            with open("%s/%s" % (vault, credentials_file_name)) as old_credentials:
                old_credentials_json = json.load(old_credentials)
            logging.info("Reading old credentials in %s/%s" % (vault, credentials_file_name))
        except (IOError, EOFError):
            logging.info("Error reading %s/%s" % (vault, credentials_file_name))
            print "Error reading %s/%s" % (vault, credentials_file_name)

        # Add all the top level keys to credentials_json that are not json_object_name
        for top_level_key in old_credentials_json:
            if not top_level_key == json_object_name:
                credentials_json[top_level_key] = old_credentials_json[top_level_key]
    else:
        logging.info("Creating a new %s/%s" % (vault, credentials_file_name))
        print "Creating a new %s/%s" % (vault, credentials_file_name)

    # Add the new credentials
    logging.info("Adding json_object_name: %s, aws_user_name: %s, aws_access_key_id: %s, "
                 "ec2_ssh_key_name: %s, ec2_ssh_key_pair_file: %s s3_bucket: %s, "
                 "emr_ssh_key_pair_file: %s to %s"
                 % (json_object_name, aws_user_name, aws_access_key_id, ec2_ssh_key_name,
                    ec2_ssh_key_pair_file, s3_bucket, emr_ssh_key_pair_file, credentials_file_name))

    credentials_json[json_object_name] = dict()
    credentials_json[json_object_name]["aws_user_name"] = aws_user_name
    credentials_json[json_object_name]["aws_access_key_id"] = aws_access_key_id
    credentials_json[json_object_name]["aws_secret_access_key"] = aws_secret_access_key
    credentials_json[json_object_name]["ec2_ssh_key_name"] = ec2_ssh_key_name
    credentials_json[json_object_name]["ec2_ssh_key_pair_file"] = ec2_ssh_key_pair_file
    credentials_json[json_object_name]["s3_bucket"] = s3_bucket
    credentials_json[json_object_name]["emr_ssh_key_pair_file"] = emr_ssh_key_pair_file

    # Write the new vault/credentials_file_name
    with open("%s/%s" % (vault, credentials_file_name), 'w') as json_outfile:
        json.dump(credentials_json, json_outfile, sort_keys=True, indent=4, separators=(',', ': '))
    json_outfile.close()

    logging.info("Saved %s/%s" % (vault, credentials_file_name))


def create_mrjob_conf(aws_user_name, aws_access_key_id, aws_secret_access_key, s3_bucket,
                      emr_ssh_key_pair_file):
    # Create ~/.mrjob.conf with AWS credentials
    s3_scratch_uri = "%stmp/" % s3_bucket
    s3_log_uri = "%slog/" % s3_bucket

    logging.info("Creating ~/.mrjob.conf")
    template = open('mrjob.conf.template').read()

    filled_template = template % (aws_user_name, aws_user_name, aws_access_key_id,
                                  aws_secret_access_key, s3_scratch_uri, s3_log_uri,
                                  emr_ssh_key_pair_name, emr_ssh_key_pair_file)
    logging.info("~/.mrjob.conf template filled")

    home = os.environ['HOME']
    mrjob_outfile = "%s/.mrjob.conf" % home

    try:
        open(mrjob_outfile, 'wb').write(filled_template)
        logging.info("Wrote: %s" % mrjob_outfile)
        print "Wrote: %s" % mrjob_outfile
    except (IOError, EOFError):
        logging.info("Error writing to %s" % mrjob_outfile)
        sys.exit("Error writing to %s" % mrjob_outfile)


def clear_vault():
    backup_directory = "%s/Vault_%s" % (vault, str(int(time.time())))

    os.makedirs(backup_directory)
    logging.info("Clearing Vault to %s" % backup_directory)

    # Move all of the non .csv files into the backup_directory
    for clear_vault_file in glob(vault+'/*'):
        if os.path.isfile(clear_vault_file):
            if os.path.splitext(clear_vault_file)[1] == ".csv":
                logging.info("Leaving Vault file: %s" % clear_vault_file)
            else:
                logging.info("Moving Vault file: %s" % clear_vault_file)
                os.rename(clear_vault_file,
                          backup_directory + "/" + os.path.basename(str(clear_vault_file)))
    logging.info("Clearing Complete")


if __name__ == "__main__":
    # If the EC2_VAULT environ var is set then use it, otherwise default to ~/Vault/
    try:
        os.environ['EC2_VAULT']
    except KeyError:
        vault = expanduser("~") + '/Vault'
    else:
        vault = os.environ['EC2_VAULT']

    # Exit if no vault directory is found
    if not os.path.isdir(vault):
        sys.exit("Vault directory not found.")

    # Create a logs directory in the vault directory if one does not exist
    if not os.path.exists(vault + "/logs"):
        os.makedirs(vault + "/logs")

    # Save a log to vault/logs/setup.log
    logging.basicConfig(filename=vault + "/logs/setup.log",
                        format='%(asctime)s %(message)s',
                        level=logging.INFO)

    logging.info("setup.py started")
    logging.info("Vault: %s" % vault)

    # Log all of the files in the Vault directory
    for vault_file in glob(vault+'/*'):
        logging.info("Found Vault file: %s" % vault_file)

    # Commandline Parameters
    parser = argparse.ArgumentParser(description="setup.py: Collects the AWS credentials and "
                                                 "stores them in json file.")
    parser.add_argument('-c', dest='clear', action='store_true', default=False,
                        help='Clear the Vault directory before running')
    parser.add_argument('-r', dest='region', action='store', type=str, default="us-east-1",
                        help='The AWS region where the EC2 ssh key pair is created in')
    parser.add_argument('-o', dest='json_object_name', action='store', type=str, default="student",
                        help='The name of the JSON object used to store the credentials')

    args = vars(parser.parse_args())

    if args['clear']:
        clear_vault()

    # Collect the AWS credentials stored in the Vault
    user_id, key_id, secret_key = collect_credentials()

    # Get the EC2 ssh key pair from the Vault or generate a new ssh key pair
    ec2_key_name, ec2_key_pair_file = get_ec2_ssh_key_pair(user_id, key_id, secret_key,
                                                           args['region'])

    # Check S3 for valid student bucket
    student_bucket = get_s3_bucket(user_id, key_id, secret_key)

    # Download the shared EMR ssh key
    emr_key_pair_file = get_emr_ssh_key_pair(key_id, secret_key)

    # Save the credentials to the user's Vault
    save_credentials_json(args['json_object_name'], user_id, key_id, secret_key, ec2_key_name,
                          ec2_key_pair_file, student_bucket, emr_key_pair_file)

    # Save the credentials to the user's ~/.mrjob.conf
    create_mrjob_conf(user_id, key_id, secret_key, student_bucket, emr_key_pair_file)

    logging.info("setup.py finished")
