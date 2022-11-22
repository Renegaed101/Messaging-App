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
print("[+] Connected.")

def main():    
    # Client start up menu
    while True:
        selection = input("\nPlease select an option\n1.Log in\n2.Create New Account\n3.Exit Client\n")
        if selection == '1':
            if verifyLogin():
                enterHomePage()
        elif selection == '2':
            createNewAccount()
            break
        elif selection == '3':
            s.close()
            exit()
        else:
            print("\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")

#Prototype function that verifies login for testing menu functionality
def verifyLogin():
    username = input('Username: ')
    password = input('Password: ')

    s.send(("&3" + username + "&-!&&" + password).encode())
    response = s.recv(1024).decode()
    if response[2:] == "True":
        print ("\nWelcome %s!" % (username))
        return True
    elif response[2:] == "FalsePassword": 
        print ('\nError ~ Incorrect Password!\n')
        return False
    else: 
        print ('\nError ~ That username does not exist!\n')
        return False
    
#Client home page (after log-in)
def enterHomePage():
    while True: 
        selection = input("\nPlease select an option\n1.Chats\n2.Account Settings\n3.Logout\n")
        if selection == '1':
            openChats()
        elif selection == '2':
            openSettings()
        elif selection == "3":
            logOut()
            return
        else:
            print("\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")


#Prototype function that creates a new account for testing menu functionality
def createNewAccount():
    username = input('Username: ')
    password = input('Password: ')

    Accounts[username] = password
    print ("\nWelcome %s!\n" % (username))


#Opens active conversations menu 
def openChats():

    def generateSelectionMenu():
        i = 1
        optionMaps = {}
        print ("Open a chat")

        for conv in Chats.items():
            print("%d.%s" % (i,conv[0]))
            optionMaps[i] = conv[0]
            i+=1        
        selection = input("%d.Start a new conversation\nq.Go Back" % (i))
        
        if selection == "q":
            return False

        selection = int(selection)

        if selection == i:
            startNewChat()
        else:
            try:
                enterChatRoom(Chats[optionMaps[selection]],optionMaps[selection])
            except Exception as e:
                print("\nError ~ Incorrect input.\n Please enter a number corresponding to a conversation\n")

    while True:
        if len(Chats) == 0:
            print("\nYou have no active conversations!\n")
            selection = input("1.Start a new conversation\nq.Go Back\n")
            if selection == "1":
                startNewChat()
            elif selection == "q":
                break
            else:
                print("\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")
          
        else: 
            if generateSelectionMenu() == False:
                break

#Function that authenticates a user to start a new chat
def startNewChat():
    user = input ("\nPlease enter a user's username to chat with: ")
    if verifyUser(user):
        print("\nYou started a new conversation with %s!\n" % (user))
        Chats[user] = ""
    else:
        print("\nError ~ User does not exists.\n")


#Prototype function that authenticates a user exists from server
def verifyUser(user):
    s.send(("&1"+user).encode())
    response = s.recv(1024).decode()
    if response[2:] == "True":
        return True
    return False

def enterChatRoom(chat,user):
    print ("\nEnter q to exit\n")

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
        to_send = date_now + ": " + to_send
        # finally, send the message
        s.send(("&2" + user + "&-!&&" + to_send).encode())

#Function that will run in a thread when in a chat room to recieve messages
def listen_for_messages():
    while True:
        message = s.recv(1024).decode()
        print("\n" + message)

            
#Opens user settings menu
def openSettings():

    def deleteAccount():
        pass

    def generateSelectionMenu():
        i = 1
        optionMaps = {}
        print ("Open a chat")

        for conv in Chats.items():
            print("%d.%s" % (i,conv[0]))
            optionMaps[i] = conv[0]
            i+=1        
        print("%d.Start a new conversation" % (i))
        selection = int(input())

        if selection == i:
            startNewChat()
        else:
            try:
                enterChatRoom(Chats[optionMaps[selection]],optionMaps[selection])
            except Exception as e:
                print("\nError ~ Incorrect input.\n Please enter a number corresponding to a conversation\n")

    while True:
        selection = input("\nPlease select an option\n1.Delete Message History\n2.Delete Account\nq.Go back\n")
        if selection == '1':
            generateSelectionMenu()
        elif selection == '2':
            deleteAccount()
            break
        elif selection == "q":
            break
        else:
            print("\nError ~ Incorrect input.\n Please enter a number corresponding to a menu option\n")

def logOut():
    pass

if __name__ == "__main__":
    main()

""""
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
"""

