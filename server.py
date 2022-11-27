import socket
import time
import mongoconfig
from threading import Thread

# Mongo DB initialization
db = mongoconfig.initializeConnection()
users = db.users

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

# Placeholder accounts to test functionality while database is not set up
#Format : {username:password}
Accounts = {'Alice': '123', 'Bob': '123', 'Sam': '123'}

# Placeholder message history to test functionality while databse is not set up
#Format : {user:{otherUser:history}}
message_history = {"Alice": {}, "Bob": {}, "Sam": {}}


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
        message_history[senderUsername][user] = ""
        cs.send("&1True".encode())
        return
    cs.send("&1False".encode())
    return

# Handles when a verifyLogin request is recieved from client


def verifyLogin(credentials, cs):

    parse = credentials.split("&-!&&")
    username = parse[0]
    password = parse[1]

    try:
        if users.count_documents({"username": username, "password": password}) == 1:
            print("\nWelcome %s!\n" % (username))
            cs.send("&3True".encode())
            user_socket_Mapping[username] = cs
        else:
            print('\nError ~ Incorrect Password!\n')
            cs.send("&3FalsePassword".encode())
    except Exception as e:
        print('\nError ~ That username does not exist!\n')
        cs.send("&3FalseUsername".encode())


# Handles when a user wants to send a message to another user
def sendMessage(message, cs):

    def updateMsgHistory(rcvr, sndr, msg):
        formattedMsg = "\n\t[%s]%s\n" % (sndr, msg)
        try:
            message_history[sndr][rcvr] += formattedMsg
            message_history[rcvr][sndr] += formattedMsg
        except Exception as e:
            # This is the case where no message history yet exists for the two users
            message_history[sndr][rcvr] = formattedMsg
            message_history[rcvr][sndr] = formattedMsg

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
        Accounts[username] = password
        print("\nWelcome %s!\n" % (username))
        cs.send("&4True".encode())
        user_socket_Mapping[username] = cs
        message_history[username] = {}
        users.insert_one({"username": username, "password": password})
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
    del message_history[username]
    cs.send("&6True".encode())

# Handles request from user to view chat history


def retrieveHistory(user, cs):
    senderUsername = [k for k, v in user_socket_Mapping.items() if v == cs][0]
    cs.send(("&7"+message_history[senderUsername][user]).encode())

# Handles request from user to view their active chats


def retrieveChat(user, cs):
    response = "&8"
    for chat in message_history[user].keys():
        response += "&-!&&" + chat
    cs.send(response.encode())

# Handles request from user to delete a chat's history (will only delete their copy)


def deleteChatHistory(user, cs):
    senderUsername = [k for k, v in user_socket_Mapping.items() if v == cs][0]
    message_history[senderUsername][user] = ""
    cs.send("&9True".encode())


# Mapping of request commands to functions
Requests = {"&1": verifyUser, "&2": sendMessage, "&3": verifyLogin, "&4": createNewAccount,
            "&5": logOut, "&6": deleteAccount, "&7": retrieveHistory, "&8": retrieveChat,
            "&9": deleteChatHistory}


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
