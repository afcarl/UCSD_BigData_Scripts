#!/usr/bin/env python

from ucsd_bigdata.credentials import Credentials
from ucsd_bigdata.find_waiting_flow import find_waiting_flow


if __name__ == "__main__":

    credentials = Credentials()
    print find_waiting_flow()
