import pymongo


def probe(target):
    return pymongo.MongoClient(target)
