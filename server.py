import socket
from threading import Thread

# server's IP address
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5002  # port we want to use
separator_token = "<SEP>"  # we will use this to separate the client name & message

# initialize list/set of all connected client's sockets
client_sockets = set()
#Maps users after they log in to their sockets, allows multiple log-ins from a single client
#Format : (username:socket)
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

#Placeholder accounts to test functionality while database is not set up
#Format : (username:password)
Accounts = {'Alice':'123','Bob':'123','Sam':'123'}

#Handles when a verifyUser request is recieved from client
def verifyUser(user,cs):
        if user in Accounts.keys():
            cs.send("&1True".encode())
            return
        cs.send("&1False".encode())    
        return

#Handles when a verifyLogin request is recieved from client
def verifyLogin(credentials,cs):
    parse = credentials.split("&-!&&")
    username = parse[0]
    password = parse[1]
    
    try: 
        if Accounts[username] == password:
            print ("\nWelcome %s!\n" % (username))
            cs.send("&2True".encode())
            user_socket_Mapping[username] = cs
        else:
            print ('\nError ~ Incorrect Password!\n')    
            cs.send("&2FalsePassword".encode())
    except Exception as e:
        print ('\nError ~ That username does not exist!\n')
        cs.send("&2FalseUsername".encode())


#Handles when a client want to send a message to another client
def sendMessage(message,cs):
    parse = message.split("&-!&&")
    username = parse[0]
    payload = parse[1]

    user_socket_Mapping[username].send(payload.encode())
    
Requests = {"&1":verifyUser,"&2":sendMessage,"&3":verifyLogin}

def listen_for_client(cs):
    """
    This function keep listening for a message from `cs` socket
    Whenever a message is received, broadcast it to all other connected clients
    """
    while True:
        try:
            # keep listening for a message from `cs` socket
            msg = cs.recv(1024).decode() 
            requestCode = msg[:2]
            Requests[requestCode](msg[2:],cs)
                      
        except Exception as e:
            # client no longer connected
            # remove it from the set
            #print(f"[!] Error: {e}")
            print ("A client disconnected")
            client_sockets.remove(cs)
            return
        
            # if we received a message, replace the <SEP>
            # token with ": " for nice printing
            #msg = msg.replace(separator_token, ": ")
            
        # iterate over all connected sockets
        #for client_socket in client_sockets:
            # and send the message
            #client_socket.send(msg.encode())
  



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

# close client sockets
for cs in client_sockets:
    cs.close()
# close server socket
s.close()
