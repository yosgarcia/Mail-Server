import argparse
from twisted.mail import smtp
from twisted.internet import defer, reactor, ssl
import base64
from twisted.internet.defer import Deferred
import csv
from twisted.cred.portal import Portal
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword, UsernamePassword
from zope.interface import implementer
from twisted.cred.error import UnauthorizedLogin
import os
import time
from email import message_from_string
from email.header import decode_header
from email.utils import parseaddr



# Leer parametros de la linea de comandos
# y separar los dominios permitidos
def parse_arguments():
    parser = argparse.ArgumentParser(description="SMTP Server")
    parser.add_argument("-d", "--domains", required=True, help="List of allowed domains separated by commas")
    parser.add_argument("-s", "--mail-storage", required=True, help="Directory to store emails")
    parser.add_argument("-p", "--port", type=int, required=True, default=25, help="Port to listen on")
    
    args = parser.parse_args()

    # lista de dominios que se pueden aceptar
    allowed_domains = args.domains.split(",")

    return allowed_domains, args.mail_storage, args.port


# Clase para manejar los mensajes
@implementer(smtp.IMessage)
class FileMessage:
    def __init__(self, recipient, mail_storage):
        self.recipient = recipient
        self.mail_storage = mail_storage
        self.lines = []

    def lineReceived(self, line):
        if isinstance(line, bytes):
            self.lines.append(line.decode('utf-8'))  # Decodificar si es bytes
        else:
            self.lines.append(line) 


    def eomReceived(self):
        recipient_user, recipient_domain = self.recipient.split('@')
        recipient_dir = os.path.join(self.mail_storage, recipient_domain, recipient_user)
        os.makedirs(recipient_dir, exist_ok=True)

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        base_filename = f"mail_{timestamp}"
        email_filename = f"{base_filename}.eml"  # Guardaremos el correo en formato .eml
        email_file_path = os.path.join(recipient_dir, email_filename)

        # Juntar todas las líneas en un solo string (mensaje RAW)
        full_message = "\n".join(self.lines)

        # Guardar el mensaje RAW en formato .eml
        with open(email_file_path, 'w', encoding="utf-8") as f:
            f.write(full_message)
        print(f"Mail saved in: {email_file_path}")

        # Procesar el mensaje MIME para extraer adjuntos y asociarlos
        mime_msg = message_from_string(full_message)
        attachments = []
        if mime_msg.is_multipart():
            attachments_dir = os.path.join(recipient_dir, "attachments")
            os.makedirs(attachments_dir, exist_ok=True)
            for part in mime_msg.walk():
                # Ignorar contenedores multipart
                if part.get_content_maintype() == "multipart":
                    continue
                content_disp = part.get("Content-Disposition", "")
                if content_disp and "attachment" in content_disp.lower():
                    filename = part.get_filename()
                    if not filename:
                        filename = f"attachment_{timestamp}"
                    file_path = os.path.join(attachments_dir, filename)
                    with open(file_path, "wb") as af:
                        af.write(part.get_payload(decode=True))
                    attachments.append(filename)
                    print(f"Attachment saved in: {file_path}")

        # Guardar un archivo de metadatos si se encontraron adjuntos
        if attachments:
            meta_filename = f"{base_filename}.meta"
            meta_file_path = os.path.join(recipient_dir, meta_filename)
            with open(meta_file_path, 'w', encoding="utf-8") as mf:
                mf.write("Attachments:\n")
                for att in attachments:
                    mf.write(att + "\n")
            print(f"Metadata saved in: {meta_file_path}")

        return defer.succeed(None)


    def connectionLost(self):
        self.lines = None



@implementer(smtp.IMessageDelivery)
class FileMessageDelivery:
    def __init__(self, allowed_domains, mail_storage):
        self.allowed_domains = allowed_domains
        self.mail_storage = mail_storage
    
    def receivedHeader(self, helo, origin, recipients):
        return f""
    
    def validateFrom(self, helo, origin):
        return origin # Se acepta cualquier remitente
    
    def validateTo(self, user):
        recipient_domain = user.dest.domain.decode("utf-8")
        if recipient_domain in self.allowed_domains:
            return lambda: FileMessage(user.dest.local.decode("utf-8") + '@' + recipient_domain, self.mail_storage)
        raise smtp.SMTPBadRcpt(user)


# Clase para el servidor SMTP
class FileSMTPFactory(smtp.SMTPFactory):

    def __init__(self, allowed_domains, mail_storage):
        self.delivery = FileMessageDelivery(allowed_domains, mail_storage)

    def buildProtocol(self, addr):
        p = smtp.SMTPFactory.buildProtocol(self, addr)
        p.delivery = self.delivery
        return p



if __name__ == "__main__":
    domains, storage, port = parse_arguments()
    print(f"Allowed domains: {domains}")
    print(f"Mail storage: {storage}")
    print(f"Port: {port}")

    reactor.listenTCP(port, FileSMTPFactory(domains, storage))
    reactor.run()
