#!/usr/bin/env python

import os
import sys
import json


class Vault:

    def __init__(self, check_dir=True):
        self.vault_config = "%s/.vault" % os.environ['HOME']
        self.path = Vault.get(self, check_dir=check_dir)

    def get(self, check_dir=True):
        path = "%s/Vault" % os.environ['HOME']

        if os.path.isfile(self.vault_config):
            try:
                with open(self.vault_config, 'r') as f:
                    vault_config_json = json.load(f)
                    path = vault_config_json["vault"]
            except ValueError:
                print "%s is not valid json" % self.vault_config
                sys.exit()

        if check_dir:
            # Exit if no vault directory is found
            if not os.path.isdir(path):
                sys.exit("Vault directory not found. Path: %s" % path)

        return path

    def set(self, path):
        vault_config_json = dict()

        if os.path.isfile(self.vault_config):
            try:
                with open(self.vault_config, 'r') as f:
                    vault_config_json = json.load(f)
            except ValueError:
                print "%s is not valid json" % self.vault_config
                sys.exit()

        vault_config_json["vault"] = path

        if "history" in vault_config_json:
            if path not in vault_config_json["history"]:
                vault_config_json["history"].append(path)
        else:
            vault_config_json["history"] = []
            vault_config_json["history"].append(path)

        with open(self.vault_config, 'w') as f:
            json.dump(vault_config_json, f, sort_keys=True, indent=4, separators=(',', ': '))

        if not os.path.isdir(path):
            try:
                os.makedirs(path)
            except Exception, e:
                print "Error creating vault: %s : %s" % (path, e)
                sys.exit()

        self.path = Vault.get(self)

    def history(self):
        vault_config_json = dict()
        history = []

        if os.path.isfile(self.vault_config):
            try:
                with open(self.vault_config, 'r') as f:
                    vault_config_json = json.load(f)
            except ValueError:
                print "%s is not valid json" % self.vault_config
                sys.exit()

        if "history" in vault_config_json:
            history = vault_config_json["history"]

        return history
