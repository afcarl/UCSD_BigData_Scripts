#!/usr/bin/env python
import os
from os.path import expanduser
import sys
import datetime
import logging
import subprocess
import select
import time
import getpass


def empty_call_back(line):
    return False


def run_command(command, stderr_call_back=empty_call_back, stdout_call_back=empty_call_back, display=True):
    return_variable = False

    command_output = subprocess.Popen(command,
                                      shell=False,
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)

    def data_waiting(source):
        return select.select([source], [], [], 0) == ([source], [], [])

    while True:
        # Read from stderr and print any errors
        if data_waiting(command_output.stderr):
            command_stderr = command_output.stderr.readline()
            if len(command_stderr) > 0:
                if display:
                    print command_stderr,
                # Run custom stderr_call_back routine
                return_variable |= stderr_call_back(command_stderr)

        # Read from stdout
        if data_waiting(command_output.stdout):
            command_stdout = command_output.stdout.readline()
            # Stop if the end of stdout has been reached
            if not command_stdout:
                break
            else:
                if display:
                    print command_stdout,
                # Run custom stdout_call_back routine
                return_variable |= stdout_call_back(command_stdout)

        time.sleep(0.1)

    return return_variable


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

    # Save a log to vault/logs/github_add_ssh_key.log
    logging.basicConfig(filename=vault + "/logs/github_add_ssh_key.log", format='%(asctime)s %(message)s',
                        level=logging.INFO)

    logging.info("github_add_ssh_key.py started")
    logging.info("Vault: %s" % vault)

    # Generate new SSH keys if github_id_rsa or github_id_rsa.pub don't exist
    if not os.path.isfile(vault + "/github_id_rsa") or not os.path.isfile(vault + "/github_id_rsa.pub"):
        # If one of the two files exists, delete it
        if os.path.isfile(vault + "/github_id_rsa"):
            os.remove(vault + "/github_id_rsa")
        if os.path.isfile(vault + "/github_id_rsa.pub"):
            os.remove(vault + "/github_id_rsa.pub")

        # Function to parse the output of the ssh_keygen command
        def parse_ssh_keygen_response(response):
            logging.info("(PSKR) %s" % response.strip())

            # If the public key is saved then return true
            if not response.find("Your public key has been saved") == -1:
                logging.info("(PSKR) Found saved public key: %s" % response.strip())
                return True

            return False

        # Generate the SSH keys
        ssh_keygen = ["ssh-keygen", "-t", "rsa", "-f", "%s/github_id_rsa" % vault, "-P", ""]
        logging.info("Generating new SSH keys: %s" % ' '.join(ssh_keygen))
        print "Generating new SSH keys: %s" % ' '.join(ssh_keygen)

        if run_command(ssh_keygen, stdout_call_back=parse_ssh_keygen_response, display=False):
            logging.info("Generating new SSH keys successful")
        else:
            logging.info("Generating new SSH keys failed!")
            logging.info("github_add_ssh_key.py finished")
            sys.exit("Generating new SSH keys failed!")
    else:
        logging.info("Skipping ssh-keygen: %s/github_id_rsa and %s/github_id_rsa.pub already exist" % (vault, vault))

    # Read vault/github_id_rsa.pub
    ssh_public_key = None
    if os.path.isfile(vault + "/github_id_rsa.pub"):
        logging.info("Reading %s/github_id_rsa.pub" % vault)
        f = open(vault + "/github_id_rsa.pub", "r")
        ssh_public_key = f.read().rstrip()
        logging.info("github_id_rsa.pub: %s" % ssh_public_key)
        f.close()
    else:
        logging.info("Error reading %s/github_id_rsa.pub" % vault)
        logging.info("github_add_ssh_key.py finished")
        sys.exit("Error reading %s/github_id_rsa.pub" % vault)

    # Get the users GitHub username and password
    print "This script does not support GitHub accounts with two-factor authentication enabled. " \
          "Please disable it before continuing.\n\n"
    github_username = raw_input("Enter your GitHub username: ")
    github_password = getpass.getpass("Enter your GitHub password, input will not be shown: ")

    logging.info("GitHub username: %s password length: %s" % (github_username, len(github_password)))

    curl = None

    # Due to a CA Cert issues with Ubuntu, include the --cacert switch if /etc/ssl/certs/ca-certificates.crt exists
    if os.path.isfile("/etc/ssl/certs/ca-certificates.crt"):
        logging.info("Found /etc/ssl/certs/ca-certificates.crt : %s" % sys.platform)
        curl = ["curl",  "--cacert", "/etc/ssl/certs/ca-certificates.crt", "-s", "-i", "-u", "%s:%s"
                % (github_username, github_password), "-H", "Content-Type: application/json", "-d",
                "{\"title\":\"Source: github_add_ssh_key.py (%s)\",\"key\":\"%s\"}" %
                (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ssh_public_key),
                "https://api.github.com/user/keys"]
    else:
        logging.info("Did not find /etc/ssl/certs/ca-certificates.crt : %s" % sys.platform)
        curl = ["curl", "-s", "-i", "-u", "%s:%s" % (github_username, github_password), "-H",
                "Content-Type: application/json", "-d",
                "{\"title\":\"Source: github_add_ssh_key.py (%s)\",\"key\":\"%s\"}" %
                (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ssh_public_key),
                "https://api.github.com/user/keys"]

    logging.info("GitHub CURL Command: %s" % ' '.join(curl).replace(github_password, "PASS"))

    # Function to parse the output of the curl command
    def parse_github_response(response):
        logging.info("(PGR) %s" % response.strip())

        response_split = response.split(":")

        # Display the message to the user
        if response_split[0].strip() == "\"message\"":
            print response_split[1].strip().replace("\"", "").replace(",", "")

        # Return true if HTTP Status 201 is returned
        if response_split[0].strip() == "Status":
            if response_split[1].strip() == "201 Created":
                logging.info("(PGR) Got Created: %s" % response.strip())
                return True

        return False

    # Issue the API call to GitHub to add the SSH key
    if run_command(curl, stdout_call_back=parse_github_response, display=False):
        logging.info("SSH key added to GitHub successfully")
        print "SSH Key added to GitHub successfully! You should receive a conformation email from GitHub shortly"
    else:
        logging.info("SSH key failed to be added to GitHub!")
        logging.info("github_add_ssh_key.py finished")
        sys.exit("SSH key failed to be added to GitHub!")

    # Start the ssh agent
    logging.info("Starting ssh-agent")
    ssh_agent = ["ssh-agent", "-s"]
    run_command(ssh_agent, display=False)

    # Add the ssh key to the ssh agent
    logging.info("Adding SSH key: %s/github_id_rsa" % vault)
    ssh_add = ["ssh-add", "%s/github_id_rsa" % vault]
    run_command(ssh_add, display=False)

    # Function to parse the output of the verify_ssh command
    def parse_verify_ssh_response(response):
        logging.info("(PVSR) %s" % response.strip())

        # If the authentication is successful then return true
        if not response.find("successfully authenticated") == -1:
            logging.info("(PVSR) Successful authentication: %s" % response.strip())
            return True

        return False

    # SSH to github.com to verify the SSH key was successfully added to github.com
    logging.info("Verifying SSH keys by sshing to github.com")
    verify_ssh = ["ssh", "-T", "git@github.com", "-o", "StrictHostKeyChecking=no"]
    if run_command(verify_ssh, stdout_call_back=parse_verify_ssh_response, stderr_call_back=parse_verify_ssh_response,
                   display=False):
        logging.info("SSH test to github.com successful!")
        print "SSH test to github.com successful!"
    else:
        logging.info("SSH test to github.com failed!")
        logging.info("github_add_ssh_key.py finished")
        sys.exit("SSH test to github.com failed!")

    # Add the ssh-agent and ssh-add to the login scripts
    bash = None

    if sys.platform == "darwin":
        bash = expanduser("~") + '/.bash_profile'
    else:
        bash = expanduser("~") + '/.bashrc'

    if os.path.isfile(bash):
        # Check if the ssh-agent and the ssh-add commands have been added to the login script
        bash_ssh_agent = False
        bash_ssh_add = False

        # Look for ssh-agent and ssh-add in login script
        if 'ssh-agent' in open(bash).read():
            logging.info("Found ssh-agent in %s" % bash)
            bash_ssh_agent = True
        else:
            logging.info("Didn't find ssh-agent in %s" % bash)

        if 'ssh-add' in open(bash).read():
            logging.info("Found ssh-add in %s" % bash)
            bash_ssh_add = True
        else:
            logging.info("Didn't find ssh-add in %s" % bash)

        # If the ssh-agent or the ssh-add command isn't in the login script then add them
        if not bash_ssh_agent and not bash_ssh_add:
            logging.info("Updating %s" % bash)

            # Append `eval "$(ssh-agent -s)"` and `ssh-add ~/Vault/github_id_rsa` to login script
            f = open(bash, "a")
            f.write("\n\n# Added by github_add_ssh_key.py\neval \"$(ssh-agent -s)\"\nssh-add ~/Vault/github_id_rsa\n")
            f.close()

            logging.info("Updated %s" % bash)
    else:
        logging.info("Did not find %s" % bash)

        # Create login script with `eval "$(ssh-agent -s)"` and `ssh-add ~/Vault/github_id_rsa`
        f = open(bash, "w")
        f.write("\n\n# Added by github_add_ssh_key.py\neval \"$(ssh-agent -s)\"\nssh-add ~/Vault/github_id_rsa\n")
        f.close()

        logging.info("Created %s" % bash)

        logging.info("github_add_ssh_key.py finished")