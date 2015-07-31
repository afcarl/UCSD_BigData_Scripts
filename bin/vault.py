#!/usr/bin/env python

import argparse
from ucsd_bigdata.vault import Vault

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Script to manage the system credentials vault.")
    parser.add_argument('--set', dest='set', action='store', type=str, default=None,
                        help='Enter the path to the vault you would like to use.')
    parser.add_argument('--history', dest='history', action='store_true', default=False,
                        help='Select a vault from your vault history.')

    args = vars(parser.parse_args())

    vault = Vault()

    if args["set"] is not None:
        vault.set(args["set"])
    elif args["history"]:
        vault_history = vault.history()

        if len(vault_history) > 0:
            for position, history_path in enumerate(vault_history):
                print "\t%s. %s" % (position + 1, history_path)

            # Make sure user_input is valid
            selected_vault = None
            while selected_vault is None:
                user_input = raw_input("\nEnter the number next to the vault that you "
                                       "would like to use: ")
                try:
                    if 0 < int(user_input) <= len(vault_history):
                        selected_vault = int(user_input) - 1
                except ValueError:
                    continue

            vault.set(vault_history[selected_vault])
        else:
            print "\nVault history is empty."

    print "\nThe Vault directory is: %s" % vault.path
