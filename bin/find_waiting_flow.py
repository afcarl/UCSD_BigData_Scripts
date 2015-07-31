#!/usr/bin/env python

import os
import sys
from mrjob.emr import EMRJobRunner
from operator import itemgetter
from ucsd_bigdata.credentials import Credentials


def find_waiting_flow(aws_access_key_id=None, aws_secret_access_key=None, s3_scratch_uri=None,
                      s3_log_uri=None, ec2_key_pair=None, ec2_key_pair_file=None):
    # If the options are specified then ignore the options in ~/.mrjob.conf
    if aws_access_key_id is not None and aws_secret_access_key is not None and \
       s3_scratch_uri is not None and s3_log_uri is not None and ec2_key_pair is not None and \
       ec2_key_pair_file is not None:

        emr_conn = EMRJobRunner(aws_access_key_id=aws_access_key_id,
                                aws_secret_access_key=aws_secret_access_key,
                                s3_scratch_uri=s3_scratch_uri, s3_log_uri=s3_log_uri,
                                ec2_key_pair=ec2_key_pair,
                                ec2_key_pair_file=ec2_key_pair_file).make_emr_conn()
    # If options are not specified then use the options in ~/.mrjob.conf
    else:
        if not os.path.isfile("%s/.mrjob.conf" % os.environ['HOME']):
            sys.exit("%s/.mrjob.conf no found" % os.environ['HOME'])

        emr_conn = EMRJobRunner().make_emr_conn()

    job_flows = emr_conn.describe_jobflows()
    d = {'WAITING': 0, 'STARTING': 1, 'RUNNING': 2}
    waiting_flows = []

    for flow in job_flows:
        try:
            if flow.state in d.keys():
                job_id = flow.jobflowid
                ip_address = flow.masterpublicdnsname
                waiting_flows.append([d[flow.state], job_id, ip_address, flow.state])
                if ec2_key_pair_file != '':
                    print 'ssh -i %s hadoop@%s' % (ec2_key_pair_file, ip_address)
                    job_id = flow.jobflowid
        except Exception:
            continue

    waiting_flows = sorted(waiting_flows, key=itemgetter(0))
    # An index was added at the beginning for the sorting. Removing that index in this step
    waiting_flows = [i[1:] for i in waiting_flows]
    # Converting a list of lists to a list of dicts
    waiting_flows_dict = [{'flow_id': i[0], 'node': i[1], 'flow_state':i[2]} for i in waiting_flows]

    # Printing
    index = 0
    for flow_dict in waiting_flows_dict:
        print index, flow_dict['flow_id'], flow_dict['node'], flow_dict['flow_state']
        index += 1
    
    return waiting_flows_dict

if __name__ == "__main__":
    credentials = Credentials()
    credentials.get(json_object_name="admin")

    print find_waiting_flow(aws_access_key_id=credentials.aws_access_key_id,
                            aws_secret_access_key=credentials.aws_secret_access_key,
                            s3_scratch_uri="%stmp/" % credentials.s3_bucket,
                            s3_log_uri="%slog/" % credentials.s3_bucket,
                            ec2_key_pair="emr-shared-key",
                            ec2_key_pair_file=credentials.emr_ssh_key_pair_file)
