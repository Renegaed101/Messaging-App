from pymongo import MongoClient


def initializeConnection():
    try:
        conn = MongoClient(
            "mongodb+srv: // admin: abcd@cluster0.waeehl7.mongodb.net /?retryWrites=true & w=majority")
        print("Connected successfully!!!")
    except:
        print("Could not connect to MongoDB")

    # database name: chatdb
    db = conn.chatdb
    return db
