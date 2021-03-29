import ssl
from socket import *
import base64

username = 'your_postech_id@postech.ac.kr'
password = 'your_password'              # IMPORTANT NOTE!!!!!!!!!!: PLEASE REMOVE THIS FIELD WHEN YOU SUBMIT!!!!!

subject = 'Computer Network Assignment2 - Email Client'
from_ = 'your_postech_id@postech.ac.kr'
to_ = 'your_postech_id_or_your_friend\'s@postech.ac.kr'
content = 'It is so hard for me!!!'

# Message to send
endmsg = '\r\n.\r\n'

# Choose a mail server (e.g. Google mail server) and call it mailserver
mailserver = 'smtp.office365.com'
port = 587

# 1. Establish a TCP connection with a mail server [2pt]
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((mailserver, port))
received = clientSocket.recv(1024).decode()
print (received)

# 2. Dialogue with the mail server using the SMTP protocol. [2pt]
command = "EHLO\r\n"
clientSocket.send(command.encode())
received = clientSocket.recv(1024).decode()
print (received)

# 3. Login using SMTP authentication using your postech account. [5pt]

# HINT: Send STARTTLS
# HINT: Wrap socket using ssl.PROTOCOL_SSLv23
# HINT: Use base64.b64encode for the username and password
# HINT: Send EHLO

command = "STARTTLS\r\n"
clientSocket.send(command.encode())
received = clientSocket.recv(1024).decode()
print (received)

wrapSocket = ssl.wrap_socket(clientSocket, ssl_version=ssl.PROTOCOL_SSLv23)

command = "EHLO\r\n"
wrapSocket.send(command.encode())
received = wrapSocket.recv(1024).decode()
print (received)

command = "AUTH LOGIN\r\n"
wrapSocket.send(command.encode())
received = wrapSocket.recv(1024).decode()
print (received)

command = base64.b64encode(username.encode()) + "\r\n".encode()
wrapSocket.send(command)
received = wrapSocket.recv(1024).decode()
print (received)

command = base64.b64encode(password.encode()) + "\r\n".encode()
wrapSocket.send(command)
received = wrapSocket.recv(1024).decode()
print (received)

# 4. Send a e-mail to your POSTECH mailbox. [5pt]
command = "MAIL FROM:" + from_ + "\r\n"
wrapSocket.send(command.encode())
received = wrapSocket.recv(1024).decode()
print (received)

command = "RCPT TO:" + to_ + "\r\n"
wrapSocket.send(command.encode())
received = wrapSocket.recv(1024).decode()
print (received)

command = "DATA\r\n"
wrapSocket.send(command.encode())
received = wrapSocket.recv(1024).decode()
print (received)

command = "Subject:" + subject + "\r\n\r\n" + content + "\r\n" + endmsg
wrapSocket.send(command.encode())
received = wrapSocket.recv(1024).decode()
print (received)

command = "QUIT\r\n"
wrapSocket.send(command.encode())
received = wrapSocket.recv(1024).decode()
print (received)

# 5. Destroy the TCP connection [2pt]
wrapSocket.close()
clientSocket.close()