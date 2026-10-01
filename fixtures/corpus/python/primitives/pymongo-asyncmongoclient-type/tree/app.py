import pymongo


def probe(target):
    return pymongo.AsyncMongoClient(target)
