import boto3


def probe():
    return boto3.client()
