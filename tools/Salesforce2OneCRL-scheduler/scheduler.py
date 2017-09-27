#!/usr/bin/env python

import os, sys
import subprocess

def ccadb_import(event, context):
    lambda_task_root = "."
    if 'LAMBDA_TASK_ROOT' in os.environ:
        lambda_task_root = os.environ['LAMBDA_TASK_ROOT']
    command = 'PATH="%s" LAMBDA_TASK_ROOT="%s" %s/salesforce2OneCRL' % (os.environ['PATH'], lambda_task_root, lambda_task_root)
    print("Calling CCADB import client using: %s" % (command))
    exit_code = subprocess.call([lambda_task_root + '/salesforce2OneCRL'], env=os.environ.copy())
    if exit_code > 0:
        raise ValueError("CCADB import failed! Check the logs for more information.")

if __name__ == '__main__':
    ccadb_import(None, None)
