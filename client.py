import socket
import random
from threading import Thread
from datetime import datetime
from colorama import Fore, init, Back

# init colors
init()

# set the available colors
colors = [Fore.BLUE, Fore.CYAN, Fore.GREEN, Fore.LIGHTBLACK_EX,
          Fore.LIGHTBLUE_EX, Fore.LIGHTCYAN_EX, Fore.LIGHTGREEN_EX,
          Fore.LIGHTMAGENTA_EX, Fore.LIGHTRED_EX, Fore.LIGHTWHITE_EX,
          Fore.LIGHTYELLOW_EX, Fore.MAGENTA, Fore.RED, Fore.WHITE, Fore.YELLOW
          ]

# choose a random color for the client
client_color = random.choice(colors)

# server's IP address
# if the server is not on this machine,
# put the private (network) IP address (e.g 192.168.1.2)
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5002  # server's port
separator_token = "<SEP>"  # we will use this to separate the client name & message

#Temporary placeholder accounts to test prototype menu/messaging functionality
Accounts = {'Alice':'123','Bob':'123','Sam':'123'}

#Temporary placeholder user chats to test prototype menu/messaging functionality
Chats = {}

# initialize TCP socket
s = socket.socket()
print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
# connect to the server
s.connect((SERVER_HOST, SERVER_PORT))
print("[+] Connected.\n")

#Prototype function that creates a new account for testing menu functionality
def createNewAccount():
    username = input('Username: ')
    password = input('Password: ')

    Accounts[username] = password
    print ("\nWelcome %s!\n" % (username))

#Prototype function that verifies login for testing menu functionality
def verifyLogin():
    username = input('Username: ')
    password = input('Password: ')
    
    try: 
        if Accounts[username] == password:
            print ("\nWelcome %s!\n" % (username))
            return True
        print ('\nError ~ Incorrect Password!\n')    
        return False
    except Exception as e:
        print ('\nError ~ That username does not exist!\n')
    

# Client start up menu
while True:
    selection = input("Please select an option\n1.Log in\n2.Create New Account\n")
    if selection == '1':
        if verifyLogin():
            break
    elif selection == '2':
        createNewAccount()
        break
    else:
        print("\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")


#Prototype function that authenticates a user exists from server
def verifyUser(user):
    s.send(("&1"+user).encode())
    response = s.recv(1024).decode()
    if response[2:] == "True":
        return True
    return False

#Function that attempts to establish a new conversation
def startNewChat():
    user = input ("\nPlease enter a user's username to chat with: ")
    if verifyUser(user):
        print("\nUser Exists!\n")
    else:
        print("\nError ~ User does not exists.\n")

#Opens active conversations menu 
def openChats():
    i = 1
    if len(Chats) == 0:
        print("\nYou have no active conversations!\n")
        startNewChat()
    else: 
        for conv in Chats:
            print("%d.%s" % (i,conv[0]))
            i+=1
        print("%d.")
    
#Client home page (after log-in)
while True: 
    selection = input("Please select an option\n1.Chats\n2.Account Settings\n")
    if selection == '1':
        openChats()
    elif selection == '2':
        createNewAccount()
        break
    else:
        print("\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")


def listen_for_messages():
    while True:
        message = s.recv(1024).decode()
        print("\n" + message)



# make a thread that listens for messages to this client & print them
t = Thread(target=listen_for_messages)
# make the thread daemon so it ends whenever the main thread ends
t.daemon = True
# start the thread
t.start()

while True:
    # input message we want to send to the server
    to_send = input()
    # a way to exit the program
    if to_send.lower() == 'q':
        break
    # add the datetime, name & the color of the sender
    date_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    to_send = f"{client_color}[{date_now}] {name}{separator_token}{to_send}{Fore.RESET}"
    # finally, send the message
    s.send(to_send.encode())

# close the socket
s.close()
