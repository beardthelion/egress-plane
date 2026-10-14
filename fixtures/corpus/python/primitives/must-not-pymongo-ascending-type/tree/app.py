from pymongo import ASCENDING, DESCENDING, DeleteMany, DeleteOne, GEOSPHERE, HASHED, IndexModel, InsertOne, ReadPreference, ReplaceOne, ReturnDocument, TEXT, UpdateMany, UpdateOne, WriteConcern, version

def probe():
    return (
        ASCENDING,
        DESCENDING,
        DeleteMany,
        DeleteOne,
        GEOSPHERE,
        HASHED,
        IndexModel,
        InsertOne,
        ReadPreference,
        ReplaceOne,
        ReturnDocument,
        TEXT,
        UpdateMany,
        UpdateOne,
        WriteConcern,
        version,
    )
