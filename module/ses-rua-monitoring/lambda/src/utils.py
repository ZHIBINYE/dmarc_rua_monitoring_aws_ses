import logging
import os
import zipfile
from datetime import datetime
from config import Config
import boto3
import botocore.config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def extract_zip(file: str, output: str) -> list:
    zfile = zipfile.ZipFile(file)
    fileListInZip = zfile.namelist()
    zfile.extractall(output)
    zfile.close()
    # delete zip file
    os.remove(file)
    return [os.path.join(output, f) for f in fileListInZip]

def analysis_report(fileListInZip: list[str]) -> list:
    reports = []
    for f in fileListInZip:
        with open(f) as fd:
            report = fd.read()
        logger.info("{0}\n".format(report))
        reports.append(report)
        # delete report
        os.remove(f)
    return reports

def timestamp_to_human(timestamp, format=None):
    """
    Converts a UNIX/DMARC timestamp to a human-readable string

    Args:
        timestamp: The timestamp
        format: The converted timestamp in  format, default: ``YYYY-MM-DD HH:MM:SS``

    Returns:
        str: The converted timestamp in format
    """
    if format is None:
        return timestamp_to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    else:
               return timestamp_to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S") 

def timestamp_to_datetime(timestamp):
    """
    Converts a UNIX/DMARC timestamp to a Python ``datetime`` object

    Args:
        timestamp (int): The timestamp

    Returns:
        datetime: The converted timestamp as a Python ``datetime`` object
    """
    return datetime.fromtimestamp(int(timestamp))

def get_s3_client(config: Config):
    if config.image_presigned_url_access_key_id and config.image_presigned_url_secret_access_key:
        return boto3.client("s3",
            config=botocore.config.Config(signature_version="s3v4"),
            aws_access_key_id=config.image_presigned_url_access_key_id,
            aws_secret_access_key=config.image_presigned_url_secret_access_key
        )
    else:
        return boto3.client('s3')
