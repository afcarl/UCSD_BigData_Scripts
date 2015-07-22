#!/usr/bin/env python
""" This is a script for collecting the credentials, 
choosing one of them, and creating a pickle file to hold them """

import sys
import os
from glob import glob
import csv
import pickle
from os.path import expanduser
import boto.ec2
import socket
import time
import logging
import argparse
import shutil


def test_aws_credentials(aws_access_key_id, aws_secret_access_key):
    conn = boto.ec2.connect_to_region("us-east-1",
                                      aws_access_key_id=aws_access_key_id,
                                      aws_secret_access_key=aws_secret_access_key)
    try:
        conn.get_all_regions()
        conn.close()
        logging.info("AWS Access Key ID and Access Key are correct: %s" % aws_access_key_id)
        return True
    except boto.ec2.EC2Connection.ResponseError:
        conn.close()
        logging.info("WARN: AWS Access Key ID and Access Key are incorrect: %s" % aws_access_key_id)
        return False


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
                    # skip the csv column header
                    if not aws_credentials[1] == "Access Key Id":
                        if test_aws_credentials(aws_credentials[1], aws_credentials[2]):
                            credentials.append({'user_name': aws_credentials[0],
                                                'access_key_id': aws_credentials[1],
                                                'secret_access_key': aws_credentials[2]})

    # If there is more than one AWS key pair then display them using a menu,
    # otherwise just select the one
    if len(credentials) > 1:
        credential_count = 1

        # Log the valid AWS credentials that are found
        logging.info("Multiple AWS credentials found:")

        print "You have multiple AWS credentials in your vault. The user names are listed below:\n"

        for credential in credentials:
            logging.info("AWS credential found: %s : %s" %
                         (credential["user_name"], credential["access_key_id"]))

            print "\t%s. %s (%s)" % (credential_count,
                                     credential["user_name"],
                                     credential["access_key_id"])
            credential_count += 1

        # make sure user_input is value
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

    user_id = credentials[selected_credentials]["user_name"]
    key_id = credentials[selected_credentials]["access_key_id"]
    secret_key = credentials[selected_credentials]["secret_access_key"]

    try:
        # TODO: make us-east-1 variable
        conn = boto.ec2.connect_to_region("us-east-1",
                                          aws_access_key_id=key_id,
                                          aws_secret_access_key=secret_key)
    except Exception, e:
        logging.info("There was an error connecting to AWS: %s" % e)
        sys.exit("There was an error connecting to AWS: %s" % e)

    # Generate or specify the SSH key pair
    need_ssh_key_pair = True
    ssh_key_name = None
    ssh_key_pair_file = None
    pem_files = glob(vault+'/*.pem')

    # Log the pem files found in the vault directory
    for pem_file in pem_files:
        logging.info("Found pem file: %s" % pem_file)

    while need_ssh_key_pair:
        # If no pem_files exist in the vault then create one
        if len(pem_files) is 0:
                logging.info("No pem files found, generating a new SSH key pair")
                ssh_key_name = str(user_id) + "_" + str(socket.gethostname()) + "_" + str(int(time.time()))
                try:
                    key = conn.create_key_pair(key_name=ssh_key_name)
                    key.save(vault)
                except Exception, e:
                    logging.info("There was an error generating and saving a new SSH key pair: %s" % e)
                    sys.exit("There was an error generating and saving a new SSH key pair: %s" % e)
                ssh_key_pair_file = vault + "/" + ssh_key_name + ".pem"

                if os.path.isfile(ssh_key_pair_file):
                    print "SSH key pair created..."
                    logging.info("SSH key pair created: %s : %s" % (ssh_key_name, ssh_key_pair_file))
                    need_ssh_key_pair = False
                else:
                    logging.info("Error creating SSH key pair")
                    sys.exit("Error creating SSH key pair")
        # If pem_files exist in the vault the select the first one that matches the name of a ssh key pair on AWS
        else:
            try:
                aws_key_pairs = conn.get_all_key_pairs()
            except Exception, e:
                logging.info("There was an error getting the key pairs from AWS: %s" % e)
                sys.exit("There was an error getting the key pairs from AWS: %s" % e)

            for pem_file in pem_files:
                logging.info("Checking %s for a match on AWS" % pem_file)
                ssh_key_name = os.path.splitext(os.path.basename(str(pem_file)))[0]
                ssh_key_pair_file = pem_file

                # Verify the ssh_key_name matches a ssh_key on AWS
                if any(ssh_key_name in k.name for k in aws_key_pairs):
                    logging.info("Found matching SSH key pair: %s :  %s" % (ssh_key_name, ssh_key_pair_file))
                    print "Found matching SSH key pair..."
                    need_ssh_key_pair = False
                    break

    # Make sure all of the variables exist before trying to write them to vault/Creds.pkl
    if ((not user_id is None) and (not key_id is None) and (not secret_key is None) and (not ssh_key_name is None) and
            (not ssh_key_pair_file is None)):
        print 'ID: %s, key_id: %s' % (user_id, key_id)
        print 'ssh_key_name: %s, ssh_key_pair_file: %s' % (ssh_key_name, ssh_key_pair_file)
    else:
        logging.info("Undefined variable: user_id: %s, key_id: %s ssh_key_name: %s, ssh_key_pair_file: %s" %
                     (user_id, key_id, ssh_key_name, ssh_key_pair_file))
        sys.exit("Undefined variable")

    new_credentials = {}
    # If a Creds.pkl file already exists, make a copy, read the non 'launcher' credentials
    if os.path.isfile(vault + "/Creds.pkl"):
        logging.info("Found existing %s/Creds.pkl" % vault)
        # Make a copy of vault/Creds.pkl before making any changes
        old_credentials = vault + "/Creds_%s.pkl" % str(int(time.time()))
        try:
            shutil.copyfile(vault + "/Creds.pkl", old_credentials)
            logging.info("Copied %s/Creds.pkl to %s" % (vault, old_credentials))
        except (IOError, EOFError):
            logging.info("Error copying %s/Creds.pkl to %s" % (vault, old_credentials))
            sys.exit("Error copying %s/Creds.pkl to %s" % (vault, old_credentials))

        # Read the contents of vault/Creds.pkl
        try:
            pickle_file = open(vault + '/Creds.pkl', 'rb')
            saved_credentials = pickle.load(pickle_file)
            pickle_file.close()
            logging.info("Reading %s/Creds.pkl" % vault)
            print "Updating %s/Creds.pkl" % vault
        except (IOError, EOFError):
            saved_credentials = {}
            logging.info("Error reading %s/Creds.pkl" % vault)
            print "Error reading %s/Creds.pkl" % vault

        # Add all the top level keys that are not launcher
        for c in saved_credentials:
            logging.info("Found top level key in Creds.pkl: %s" % c)
            if not c == "launcher":
                logging.info("Saving %s to Creds.pkl unchanged" % c)
                new_credentials.update({c: saved_credentials[c]})
    else:
        logging.info("Creating a new %s/Creds.pkl" % vault)
        print "Creating a new %s/Creds.pkl" % vault

    # Add the new launcher credentials
    logging.info("Adding ID: %s, key_id: %s, ssh_key_name: %s, ssh_key_pair_file: %s to Creds.pkl" %
                 (user_id, key_id, ssh_key_name, ssh_key_pair_file))
    new_credentials.update({'launcher': {'ID': user_id,
                            'key_id': key_id,
                            'secret_key': secret_key,
                            'ssh_key_name': ssh_key_name,
                            'ssh_key_pair_file': ssh_key_pair_file}})

    # Write the new vault/Creds.pkl
    pickle_file = open(vault + '/Creds.pkl', 'wb')
    pickle.dump(new_credentials, pickle_file)
    pickle_file.close()
    logging.info("Saved %s/Creds.pkl" % vault)
    conn.close()


def clear_vault():
    backup_directory = vault + "/" + "Vault_" + str(int(time.time()))

    os.makedirs(backup_directory)
    logging.info("Clearing Vault to %s" % backup_directory)

    # Move all of the non .csv files into the backup_directory
    for clear_vault_file in glob(vault+'/*'):
        if os.path.isfile(clear_vault_file):
            if os.path.splitext(clear_vault_file)[1] == ".csv":
                logging.info("Leaving Vault file: %s" % clear_vault_file)
            else:
                logging.info("Moving Vault file: %s" % clear_vault_file)
                os.rename(clear_vault_file, backup_directory + "/" + os.path.basename(str(clear_vault_file)))

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
    logging.basicConfig(filename=vault + "/logs/setup.log", format='%(asctime)s %(message)s', level=logging.INFO)

    logging.info("setup.py started")
    logging.info("Vault: %s" % vault)

    # Log all of the files in the Vault directory
    for vault_file in glob(vault+'/*'):
        logging.info("Found Vault file: %s" % vault_file)

    # Commandline Parameters
    parser = argparse.ArgumentParser(description="This is a script for collecting the AWS credentials and creating " +
                                                 "a pickle file to hold them ")
    parser.add_argument('-c', dest='clear', action='store_true', default=False,
                        help='Clear the Vault directory before running')

    args = vars(parser.parse_args())

    if args['clear']:
        clear_vault()

    collect_credentials()

    logging.info("setup.py finished")
