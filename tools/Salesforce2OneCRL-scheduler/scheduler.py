#!/usr/bin/env python

from base64 import b64decode
import os, sys
import subprocess


EXCEPTIONS_URL = 'https://raw.githubusercontent.com/mozilla/OneCRL-Tools/master/salesforce2OneCRL/data/exceptions.json'

def kms_decrypt(encrypted_data):
    """Decrypt KMS variables"""
    res = boto3.client("kms").decrypt(
        CiphertextBlob=encrypted_data,
    )
    return res["Plaintext"].decode("utf-8")

def kms_decrypt_env(key):
    """Decrypt environment variable"""
    return kms_decrypt(b64decode(os.environ[key]))

def ccadb_import(event, context):
    lambda_task_root = "."
    binary_args = [
            '--exceptions',
            EXCEPTIONS_URL
            ]

    env = os.environ.copy()

    if 'LAMBDA_TASK_ROOT' in os.environ:
        lambda_task_root = os.environ['LAMBDA_TASK_ROOT']

    if 'PROTECTED_KINTO_USER' in os.environ:
        kinto_user = str(kms_decrypt_env("PROTECTED_KINTO_USER"))
        env['kintouser'] = kinto_user

    if 'PROTECTED_KINTO_PASS' in os.environ:
        kinto_pass =  str(kms_decrypt_env("PROTECTED_KINTO_PASS"))
        env['kintopass'] = kinto_pass

    if 'PROTECTED_BUGZILLA_KEY' in os.environ:
        bugzilla_key =  str(kms_decrypt_env("PROTECTED_BUGZILLA_KEY"))
        env['bzapikey'] = bugzilla_key

    variables = 'PATH="%s" LAMBDA_TASK_ROOT="%s"' % (os.environ['PATH'], lambda_task_root)
    subprocess_call_args = [lambda_task_root + '/salesforce2OneCRL']
    subprocess_call_args.extend(binary_args)
    print("Calling CCADB import client using: %s and args %s" % (variables, " ".join(subprocess_call_args)))
    exit_code = subprocess.call(subprocess_call_args, env=env)
    if exit_code > 0:
        raise ValueError("CCADB import failed! Check the logs for more information.")

if __name__ == '__main__':
    ccadb_import(None, None)
