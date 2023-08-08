from pymongo import MongoClient


def initializeConnection():
    try:
        conn = MongoClient(
            "mongodb+srv://admin:abcd@cluster0.nkofpby.mongodb.net/?retryWrites=true&w=majority")
        print("Connected successfully!!!")
    except:
        print("Could not connect to MongoDB")

    # database name: chatdb
    db = conn.Messaging_App
    return db
