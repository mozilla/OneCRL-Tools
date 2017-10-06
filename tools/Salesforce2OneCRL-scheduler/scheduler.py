#!/usr/bin/env python

import os, sys
import subprocess


EXCEPTIONS_URL = 'https://raw.githubusercontent.com/mozilla/OneCRL-Tools/master/salesforce2OneCRL/data/exceptions.json'

def ccadb_import(event, context):
    lambda_task_root = "."
    binary_args = [
            '--exceptions',
            EXCEPTIONS_URL
            ]
    if 'LAMBDA_TASK_ROOT' in os.environ:
        lambda_task_root = os.environ['LAMBDA_TASK_ROOT']
    variables = 'PATH="%s" LAMBDA_TASK_ROOT="%s"' % (os.environ['PATH'], lambda_task_root)
    subprocess_call_args = [lambda_task_root + '/salesforce2OneCRL']
    subprocess_call_args.extend(binary_args)
    print("Calling CCADB import client using: %s and args %s" % (variables, " ".join(subprocess_call_args)))
    exit_code = subprocess.call(subprocess_call_args, env=os.environ.copy())
    if exit_code > 0:
        raise ValueError("CCADB import failed! Check the logs for more information.")

if __name__ == '__main__':
    ccadb_import(None, None)
