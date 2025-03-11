import argparse
from twisted.mail import smtp
from twisted.internet import defer, reactor
import base64
from twisted.internet.defer import Deferred


from twisted.cred import checkers, portal, credentials
from twisted.cred.checkers import ICredentialsChecker

from zope.interface import implementer
import os
import time



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
        email_filename = f"mail_{timestamp}.txt"
        email_file_path = os.path.join(recipient_dir, email_filename)

        # Convertir el mensaje en un string completo
        full_message = "\n".join(self.lines)
        if "Content-Transfer-Encoding: base64" in full_message:
                parts = full_message.split("\n\n", 1)  # Separar encabezados del cuerpo
                headers = parts[0]
                body = parts[1] if len(parts) > 1 else ""

                # Intentar decodificar el cuerpo en Base64
                try:
                    decoded_body = base64.b64decode(body).decode("utf-8")
                except Exception as e:
                    print(f"Error al decodificar Base64: {e}")
                    decoded_body = body  # Si hay error, dejarlo como está

                full_message = headers + "\n\n" + decoded_body  # Unir encabezados y mensaje

        # Filtrar encabezados redundantes
        filtered_lines = []
        ignore_headers = {"MIME-Version:", "Content-Type:", "Content-Transfer-Encoding:"}

        for line in full_message.split("\n"):
            if not any(line.startswith(header) for header in ignore_headers):
                filtered_lines.append(line)

        cleaned_message = "\n".join(filtered_lines)

        # Guardar el mensaje limpio
        with open(email_file_path, 'w', encoding="utf-8") as f:
            f.write(cleaned_message)  # Guardar solo el mensaje limpio
            print(f"Mail saved to {email_file_path}")
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
    protocol = smtp.ESMTP

    def __init__(self, allowed_domains, mail_storage):
        self.delivery = FileMessageDelivery(allowed_domains, mail_storage)

    def buildProtocol(self, addr):
        p = smtp.SMTPFactory.buildProtocol(self, addr)
        p.delivery = self.delivery
        return p


if __name__ == "__main__":
    domains, storage, port = parse_arguments()
    print(f"Dominios permitidos: {domains}")
    print(f"Almacenamiento de correos: {storage}")
    print(f"Puerto: {port}")


    reactor.listenTCP(port, FileSMTPFactory(domains, storage))
    reactor.run()
