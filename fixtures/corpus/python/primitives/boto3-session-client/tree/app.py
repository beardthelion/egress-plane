import boto3


def probe():
    s = boto3.Session()
    return s.client()
