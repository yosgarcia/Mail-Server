# 📧 Email Server & Client Project (SMTP, IMAP)

This project implements a complete email communication system using Python and the Twisted library, designed to run on GNU/Linux environments.
It includes the development of servers and clients for the SMTP and IMAP protocols, with support for MIME attachments.

---
## Technical Requirements
- Language: Python
- Library: Twisted
- Operating System: GNU/Linux
- Standards: MIME for attachments
---
## SMTP Server
A mail server that implements the SMTP protocol using Twisted.
- Supports sending and receiving emails.
- Verifies accepted domains — only accepts messages addressed to configured domains.
- Handles email attachments through the MIME standard.

How to use:
```
$ python smtpserver.py -d <domains> -s <mail-storage> -p <port>
```
**Parameters**
- `-d`: the domains accepted by the server splits by a comma.
- `-s`: directory to storage all the mails.
- `-p`: port used for the communicaction.

## SMTP Client
A mail client that supports mass and personalized email sending.
- Reads a list of recipients from a CSV file.
- Sends emails via a specified SMTP mail server.
- Allows message personalization using variables (e.g., recipient’s name).
- Ideal for sending bulk or automated messages.

How to use:
```
$ python smtpclient.py -h <mail-server> -c <csv-file> -m <message-file>
$ python smtpclient.py -g
```

Parameters:
- `-h`: mail server address
- `-c`: CSV file with recipients (e.g., [csv file example](./mails.csv))
- `-m`: message file (e.g., [message file example](./message.txt))
- `-g`: To use the user interface to send the mail

Note: Consider that the smtp client is configured to use the port 2525. In case of wanting to use a different one, it has to be changed in the code.

## IMAP Server
An IMAP server that allows users to access and read their emails from any compatible mail client (e.g., Thunderbird) with user authentication.

How to use:
```
$ python IMAPserver.py -s <mail-storage> -p <port>
```

Parameters:
- `-s`: directory where the mails are storage.
- `-p`: port used for the communication.
