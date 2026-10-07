from pymongo import ASCENDING, DESCENDING, DeleteMany, DeleteOne, GEOSPHERE, HASHED, IndexModel, InsertOne, ReadPreference, ReplaceOne, ReturnDocument, TEXT, UpdateMany, UpdateOne, WriteConcern, version

def probe():
    return (
        ASCENDING,
        DESCENDING,
        GEOSPHERE,
        HASHED,
        TEXT,
        ReturnDocument,
        InsertOne,
        UpdateOne,
        UpdateMany,
        DeleteOne,
        DeleteMany,
        ReplaceOne,
        IndexModel,
        WriteConcern,
        ReadPreference,
        version,
    )
