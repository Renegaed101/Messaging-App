import socket
import threading
from threading import Thread
from datetime import datetime
import keyexchange
from Crypto.Cipher import AES

# server's IP address
# if the server is not on this machine,
# put the private (network) IP address (e.g 192.168.1.2)
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5002  # server's port
separator_token = "<SEP>"  # we will use this to separate the client name & message

# A condition variable to synchronize timings for sending and receiving requests/responses from the server
responseWait = threading.Condition()

# Request Responses from server are stored here
requestResponse = None

# Keeps track of currently logged in user
activeUser = None

# Keeps track of which active conversation is currently open
activeConv = None

# List of active chats
Chats = []

# initialize TCP socket
s = socket.socket()
print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
# connect to the server
s.connect((SERVER_HOST, SERVER_PORT))
print("[+] Connected.")


def main():

    # This thread handles all data recieved from server
    t = Thread(target=responseHandlerThread)
    t.daemon = True
    t.start()

    # Client start up menu
    while True:
        selection = input(
            "\nPlease select an option\n1.Log in\n2.Create New Account\n3.Exit Client\n")
        if selection == '1':
            if verifyLogin():
                enterHomePage()
        elif selection == '2':
            if createNewAccount():
                enterHomePage()
        elif selection == '3':
            s.close()
            exit()
        else:
            print(
                "\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")


# Function that handles data sent in from server
def responseHandlerThread():
    global requestResponse

    # Handles when a message is sent from another user
    def handleMessage(msg):
        parse = msg.split("&-!&&")
        username = parse[0]
        message = parse[1]

        if activeConv == username:
            formattedMsg = "\n\t[%s]%s\n" % (username, message)
            print(formattedMsg)

    while True:
        msg = s.recv(1024).decode()
        requestCode = msg[:2]

        if requestCode == "&2" and activeConv != None:
            handleMessage(msg[2:])
        else:
            responseWait.acquire()
            requestResponse = msg
            responseWait.notify()
            responseWait.release()


# Function that verifies login form server
def verifyLogin():
    global activeUser

    username = input('Username: ')
    password = input('Password: ')

    response = sync_send(("&3" + username + "&-!&&" + password).encode())

    if response[2:] == "True":
        activeUser = username
        secret, clientKey = keyexchange.create_public_key()
        response = sync_send(("&0" + str(clientKey)).encode())
        serverKey = int(response[2:])
        sharedKey = keyexchange.gen_shared_key(serverKey, secret)
        print(sharedKey)

        return True

    elif response[2:] == "FalsePassword":
        print('\nError ~ Incorrect Password!\n')
        return False
    else:
        print('\nError ~ That username does not exist!\n')
        return False


# Function that synchronizes with responseHandlerThread to send/receive a request/response from server
def sync_send(rqst):
    responseWait.acquire()

    s.send(rqst)

    responseWait.wait()
    response = requestResponse
    responseWait.release()
    return response


# Client home page (after log-in)
def enterHomePage():
    while True:
        selection = input(
            "\nPlease select an option\n1.Chats\n2.Account Settings\n3.Logout\n")
        if selection == '1':
            openChats()
        elif selection == '2':
            try:
                openSettings()
            # In case the user deleted their account
            except Exception as e:
                break
        elif selection == "3":
            logOut()
            return
        else:
            print(
                "\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")

# Sends logOut signal to server


def logOut():
    global activeUser

    sync_send(("&5"+activeUser).encode())
    activeUser = None


# Prototype function that creates a new account for testing menu functionality
def createNewAccount():
    global activeUser

    username = input('Username: ')
    password = input('Password: ')

    response = sync_send(("&4" + username + "&-!&&" + password).encode())

    if response[2:] == "True":
        print("\nWelcome %s!" % (username))
        activeUser = username
        return True
    else:
        print('\nError ~ Username already exists!\n')
        return False


# Opens active conversations menu
def openChats():

    def retrieveChats():
        global Chats

        response = sync_send(("&8"+activeUser).encode())
        newChats = response[7:].split("&-!&&")
        if newChats == [""]:
            Chats = []
        else:
            Chats = newChats

    # Generates the selection menu for active conversations

    def generateSelectionMenu():
        i = 1
        optionMaps = {}
        print("\nOpen a chat")

        for conv in Chats:
            print("%d.%s" % (i, conv))
            optionMaps[i] = conv
            i += 1
        selection = input("%d.Start a new conversation\nq.Go Back\n" % (i))

        if selection == "q":
            return False

        try:
            selection = int(selection)

            if selection == i:
                startNewChat()
            else:
                enterChatRoom(optionMaps[selection])
        except Exception as e:
            print(
                "\nError ~ Incorrect input.\n Please enter a number corresponding to a conversation\n")

    while True:
        retrieveChats()
        if len(Chats) == 0:
            print("\nYou have no active conversations!\n")
            selection = input("1.Start a new conversation\nq.Go Back\n")
            if selection == "1":
                startNewChat()
            elif selection == "q":
                break
            else:
                print(
                    "\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")

        else:
            if generateSelectionMenu() == False:
                break


# Function that authenticates a user exists to start a new conversation with them
def startNewChat():

    def verifyUser(user):

        response = sync_send(("&1"+user).encode())

        if response[2:] == "True":
            return True
        return False

    user = input("\nPlease enter a user's username to chat with: ")
    if verifyUser(user):
        print("\nYou started a new conversation with %s!\n" % (user))
    else:
        print("\nError ~ User does not exists.\n")


# Opens an active chat with a user
def enterChatRoom(user):
    global activeConv

    def retrieveHistory():
        response = sync_send(("&7"+user).encode())
        hist = response[2:]
        if hist == "":
            print("\nNo message History\n")
        else:
            print(response[2:])

    retrieveHistory()
    if "[deleted] " in user:
        print("This user has deleted their account, press any key return")
        input()
    else:
        print("(Enter q to exit): ")
        activeConv = user
        while True:
            to_send = input()
            if to_send.lower() == 'q':
                break

            # add the datetime, name & the color of the sender
            date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            to_send = date_now + ": " + to_send
            s.send(("&2" + user + "&-!&&" + to_send).encode())
            formattedMsg = "\n\t[%s]%s\n" % (activeUser, to_send)
            print(formattedMsg)

        activeConv = None


# encrypts message before being sent
def encryptMessage(message, sharedKey):

    cipher = AES.new(sharedKey, AES.MODE_EAX)
    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(message.encode('ascii'))

    return ciphertext, tag, nonce


# Decrypts recieved message

def decryptMessage(ciphertext, tag, nonce, sharedKey):
    cipher = AES.new(sharedKey, AES.MODE_EAX, nonce=nonce)

    message = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return message.decode('ascii')
    except:
        return false


# Opens user settings menu
def openSettings():

    def deleteChatHistory(chat):
        sync_send(("&9"+chat).encode())

    # Sends a signal to server to delete activeUser's account
    def deleteAccount():
        global activeUser

        sync_send(("&6"+activeUser).encode())
        activeUser = None

    # Generates menu that allows user to delete currently active chats, history and all (locally for now)
    def generateSelectionMenu():
        i = 1
        optionMaps = {}
        print("\nSelect a chat to delete it's history\nNote ~ this will only delete" +
              " your copy\n")

        for conv in Chats:
            print("%d.%s" % (i, conv))
            optionMaps[i] = conv
            i += 1
        selection = input("q.Go Back\n")

        if selection == "q":
            return False

        selection = int(selection)

        try:
            deleteChatHistory(optionMaps[selection])
        except Exception as e:
            print(
                "\nError ~ Incorrect input.\n Please enter a number corresponding to a conversation\n")

    while True:
        selection = input(
            "\nPlease select an option\n1.Delete Message History\n2.Delete Account\nq.Go back\n")
        if selection == '1':
            if len(Chats) == 0:
                print("\nYou have no active conversations!\n")
                continue
            if generateSelectionMenu() == False:
                break
        elif selection == '2':
            if (input("\nAre you sure?[y/n]: ")) == "y":
                deleteAccount()
                raise Exception("Account deleted")
            else:
                continue
        elif selection == "q":
            break
        else:
            print(
                "\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")


if __name__ == "__main__":
    main()
