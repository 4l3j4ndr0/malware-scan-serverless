# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
import botocore
import json
import logging
import os
import pwd
import re
import subprocess
from aws_lambda_powertools import Logger


logger = Logger()


s3_resource = boto3.resource("s3")


class ClamAVException(Exception):
    """Raise when ClamAV returns an unexpected exit code"""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return str(self.message)


@logger.inject_lambda_context(log_event=True)
def lambda_handler(event, context):
    """Updates the cvd files in the S3 Bucket"""
    print(json.dumps(event))
    mount_path = os.environ["EFS_MOUNT_PATH"]
    definitions_path = f"{mount_path}/{os.environ['EFS_DEF_PATH']}"
    freshclam_update(definitions_path)

def freshclam_update(download_path):
    """Points freshclam to the local database files. Downloads
    the latest database files"""
    conf = "/tmp/freshclam.conf"
    # will already exist when Lambdas are running in same execution context
    # or downloaded from the Virus Defs bucket
    if not os.path.exists(conf):
        with open(conf, "a") as f:
            f.write("\nDNSDatabaseInfo current.cvd.clamav.net")
            f.write("\nDatabaseMirror  database.clamav.net")
            f.write("\nReceiveTimeout  0")
            f.write("\nCompressLocalDatabase  true")
    try:
        command = [
            "freshclam",
            f"--config-file={conf}",
            "--stdout",
            "-u",
            f"{pwd.getpwuid(os.getuid()).pw_name}",
            f"--datadir={download_path}",
        ]
        update_summary = subprocess.run(
            command,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
        )
        if update_summary.returncode != 0:
            raise ClamAVException(
                f"FreshClam exited with unexpected code: {update_summary.returncode}"
                f"\nOutput: {update_summary.stdout}"
            )
    except subprocess.CalledProcessError as e:
        report_failure(str(e.stderr))
    except ClamAVException as e:
        report_failure(e.message)
    return


def report_failure(message):
    """Raise an error formatted for the POWERTOOLS namespace"""
    exception_json = {
        "source": "serverless-clamscan-update",
        "message": message,
    }
    raise Exception(json.dumps(exception_json))
