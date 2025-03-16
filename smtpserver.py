import argparse, os, time, nntplib, json
from twisted.mail import smtp
from twisted.internet import defer, reactor
from twisted.internet.defer import Deferred
from twisted.internet import ssl
from zope.interface import implementer
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


def load_users_from_json(file_path):
    if not os.path.exists(file_path):
        print(f"[ERROR] Users file {file_path} not found")
        return {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            users = json.load(f)
            return users
    except Exception as e:
        print(f"[ERROR] No se pudo cargar el archivo JSON: {e}")
        return {}
    

# Configuración del servidor NNTP público
NNTP_SERVER = "news.aioe.org"  # Servidor NNTP público
NNTP_PORT = 119  # Puerto NNTP estándar
NNTP_GROUP = "alt.test"  # Grupo de prueba

def notify_nntp(user, subject):
    """Notifica a un servidor NNTP sobre un nuevo correo"""
    if user not in USERS or not USERS[user].get("nntp_enabled", False):
        return  

    nntp_server = USERS[user]["nntp_server"]
    nntp_group = USERS[user]["nntp_group"]

    try:
        print(f"[INFO] Conectando a NNTP {nntp_server} para notificar a {user}")

        with nntplib.NNTP(nntp_server) as nntp:
            # Construcción del mensaje NNTP
            message = f"""\
                Newsgroups: {nntp_group}
                Subject: Nuevo correo para {user}
                From: smtp-server@santa.com
                Date: {time.strftime("%a, %d %b %Y %H:%M:%S")}
                Message-ID: <{int(time.time())}@{nntp_server}>

                Se ha recibido un nuevo correo para {user}.
                Asunto: {subject}
                """

            response = nntp.post(message.split("\n"))  # Enviar mensaje NNTP
            print(f"[INFO] Notificación NNTP enviada: {response}")

    except Exception as e:
        print(f"[ERROR] No se pudo notificar NNTP para {user}: {e}")





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

# Carga los usuarios al iniciar el servidor
USERS_FILE = "users.json"
USERS = load_users_from_json(USERS_FILE)

if __name__ == "__main__":
    domains, storage, port = parse_arguments()
    print(f"Allowed domains: {domains}")
    print(f"Mail storage: {storage}")
    print(f"Port: {port}")
    
    reactor.listenTCP(port, FileSMTPFactory(domains, storage))
    reactor.run()


