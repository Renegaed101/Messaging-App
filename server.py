import socket
import time
import mongoconfig
from threading import Thread
from passwordManagement import encrypt, check_password
import keyexchange

# Mongo DB initialization
db = mongoconfig.initializeConnection()
users = db.users
messages = db.messages

# server's IP address
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5002  # port we want to use
separator_token = "<SEP>"  # we will use this to separate the client name & message

# initialize list/set of all connected client's sockets
client_sockets = set()

# Maps users after they log in to their sockets, allows multiple log-ins from a single client
#Format : {username:socket}
user_socket_Mapping = {}

# create a TCP socket
s = socket.socket()

# make the port as reusable port
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# bind the socket to the address we specified
s.bind((SERVER_HOST, SERVER_PORT))

# listen for upcoming connections
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")


def main():
    while True:
        # we keep listening for new connections all the time
        client_socket, client_address = s.accept()
        print(f"[+] {client_address} connected.")
        # add the new connected client to connected sockets
        client_sockets.add(client_socket)
        # start a new thread that listens for each client's messages
        t = Thread(target=listen_for_client, args=(client_socket,))
        # make the thread daemon so it ends whenever the main thread ends
        t.daemon = True
        # start the thread
        t.start()

# Handles when a verifyUser request is recieved from client


def verifyUser(user, cs):
    senderUsername = [k for k, v in user_socket_Mapping.items() if v == cs][0]
    if users.count_documents({"username": user}) > 0:
        messages.insert_many([{"username": senderUsername, "chat_with": user, "history": ""},
                             {"username":user, "chat_with":senderUsername, "history": ""}])
        cs.send("&1True".encode())
        return
    cs.send("&1False".encode())
    return

# Handles when a verifyLogin request is recieved from client

def verifyLogin(credentials, cs):

    parse = credentials.split("&-!&&")
    username = parse[0]
    password = parse[1]
    user = users.find_one({"username": username})
    try:
        if check_password(password, user.get("password")):
            print("\nWelcome %s!\n" % (username))
            cs.send(("&3True").encode())
            user_socket_Mapping[username] = cs
        else:
            print('\nError ~ Incorrect Password!\n')
            cs.send("&3FalsePassword".encode())
    except Exception as e:
        print('\nError ~ That username does not exist!\n')
        cs.send("&3FalseUsername".encode())


# Handles when a user wants to send a message to another user
def sendMessage(message, cs):

    def updateMsgHistory(receiver, sender, message):
        formattedMsg = "\n\t[%s]%s\n" % (sender, message)
        senderDoc = messages.find_one({"username": sender, "chat_with": receiver})
        receiverDoc = messages.find_one({"username": receiver, "chat_with": sender})

        messages.update_one({"username": sender, "chat_with": receiver},
                            {"$set": {"history":senderDoc.get("history")+formattedMsg}})
        messages.update_one({"username": receiver, "chat_with": sender},
                            {"$set": {"history":receiverDoc.get("history")+formattedMsg}})

    parse = message.split("&-!&&")
    rcvUsername = parse[0]
    payload = parse[1]

    senderUsername = [k for k, v in user_socket_Mapping.items() if v == cs][0]

    updateMsgHistory(rcvUsername, senderUsername, payload)

    try:
        user_socket_Mapping[rcvUsername].send(
            ("&2" + senderUsername + "&-!&&" + payload).encode())
    except Exception as e:
        # Case where an attempt is made to send someone a message that isn't online
        pass


# Handles request from client where user wants to make a new account
def createNewAccount(credentials, cs):
    parse = credentials.split("&-!&&")
    username = parse[0]
    password = parse[1]

    if users.count_documents({"username": username}) == 0:
        print("\nWelcome %s!\n" % (username))
        cs.send("&4True".encode())
        user_socket_Mapping[username] = cs
        encryptedPassword = encrypt(password)
        users.insert_one({"username": username, "password": encryptedPassword})
    else:
        print('\nError ~ Username already exists!\n')
        cs.send("&4FalsePassword".encode())


# Handles request from user to log them out
def logOut(username, cs):
    del user_socket_Mapping[username]
    cs.send("&5True".encode())


# Handles request from user to delete their account
def deleteAccount(username, cs):
    del user_socket_Mapping[username]
    users.delete_one({"username": username})
    messages.delete_one({"username":username})
    messages.update_many({"chat_with":username},
                         {"$set": {"chat_with":"[deleted] "+username}})
    cs.send("&6True".encode())

# Handles request from user to view chat history


def retrieveHistory(user, cs):
    senderUsername = [k for k, v in user_socket_Mapping.items() if v == cs][0]
    doc = messages.find_one({"username":senderUsername, "chat_with":user})
    cs.send(("&7"+doc.get("history")).encode())

# Handles request from user to view their active chats


def retrieveChat(user, cs):
    response = "&8"
    for msg_history in messages.find({"username": user}):
            response += "&-!&&" + msg_history.get("chat_with")
    cs.send(response.encode())

# Handles request from user to delete a chat's history (will only delete their copy)


def deleteChatHistory(user, cs):
    senderUsername = [k for k, v in user_socket_Mapping.items() if v == cs][0]
    messages.update_one({"username":senderUsername, "chat_with":user},
                        {"$set":{"history":""}})
    cs.send("&9True".encode())

def exchangeKeys(key, cs):
    if key:
        secret, serverKey = keyexchange.create_public_key()
        print(secret)
        cs.send(("&0").encode())
        #sharedKey = keyexchange.gen_shared_key(key, secret)
        #print(sharedKey)



# Mapping of request commands to functions
Requests = {"&1": verifyUser, "&2": sendMessage, "&3": verifyLogin, "&4": createNewAccount,
            "&5": logOut, "&6": deleteAccount, "&7": retrieveHistory, "&8": retrieveChat,
            "&9": deleteChatHistory, "&0": exchangeKeys}


def listen_for_client(cs):
    """
    This function keep listening for a message from `cs` socket
    Whenever a message is received, broadcast it to all other connected clients
    """
    while True:
        try:
            # keep listening for a message from `cs` socket
            msg = cs.recv(1024).decode()
            # pull out request code
            requestCode = msg[:2]
            # launch function for request
            Requests[requestCode](msg[2:], cs)

        except Exception as e:
            # client no longer connected
            # remove it from the set
            #print(f"[!] Error: {e}")
            print("A client disconnected")
            client_sockets.remove(cs)
            return


if __name__ == "__main__":
    main()
