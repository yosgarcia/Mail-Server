import argparse
import os
from twisted.internet import reactor
from twisted.mail.imap4 import IMAP4Server, IMAP4Client
from twisted.protocols.basic import LineReceiver
from twisted.cred import portal
from twisted.cred.checkers import FilePasswordDB
from twisted.cred.credentials import UsernamePassword
from twisted.internet.protocol import Protocol
from twisted.internet import defer



def parse_arguments():
    parser = argparse.ArgumentParser(description="IMAP Server")
    parser.add_argument("-s", "--mail-storage", required=True, help="Directory to store emails")
    parser.add_argument("-p", "--port", type=int, required=True, default=143, help="Port to listen on")

    args = parser.parse_args()

    return args.mail_storage, args.port



class IMAPServer(IMAP4Server):
    def connectionMade(self):
        super().connectionMade()
        print(f"Connection made from {self.transport.getPeer()}")
    
    def connectionLost(self, reason):
        super().conectionLost(reason)
        print(f"Connection lost: {reason}")



# Clase para manejar el almacenamiento de los correos
class Mailbox:
    def __init__(self, storage_dir):
        self.storage_dir = storage_dir
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)

    def list_emails(self):
        """Listar los correos disponibles en el directorio de almacenamiento"""
        emails = []
        for domain_dir in os.listdir(self.storage_dir):
            domain_path = os.path.join(self.storage_dir, domain_dir)
            if os.path.isdir(domain_path):
                for user_dir in os.listdir(domain_path):
                    user_path = os.path.join(domain_path, user_dir)
                    if os.path.isdir(user_path):
                        emails.extend(os.listdir(user_path))  # Asumimos que cada archivo es un correo
        return emails

    def get_email(self, email_filename):
        """Recuperar un correo específico por nombre de archivo"""
        for domain_dir in os.listdir(self.storage_dir):
            domain_path = os.path.join(self.storage_dir, domain_dir)
            if os.path.isdir(domain_path):
                for user_dir in os.listdir(domain_path):
                    user_path = os.path.join(domain_path, user_dir)
                    if os.path.isdir(user_path):
                        email_path = os.path.join(user_path, email_filename)
                        if os.path.exists(email_path):
                            with open(email_path, 'r', encoding='utf-8') as f:
                                return f.read()
        return None

    def delete_email(self, email_filename):
        """Eliminar un correo específico"""
        for domain_dir in os.listdir(self.storage_dir):
            domain_path = os.path.join(self.storage_dir, domain_dir)
            if os.path.isdir(domain_path):
                for user_dir in os.listdir(domain_path):
                    user_path = os.path.join(domain_path, user_dir)
                    if os.path.isdir(user_path):
                        email_path = os.path.join(user_path, email_filename)
                        if os.path.exists(email_path):
                            os.remove(email_path)
                            return True
        return False


class IMAPFactory(Protocol.ServerFactory):
    def __init__(self, storage_dir):
        self.storage = Mailbox(storage_dir)

    def buildProtocol(self, addr):
        return IMAPServer()
    


def main():
    storage_dir, port = parse_arguments()


    print(f"IMAP Server listening on port {port} with mail storage at {storage_dir}")

    reactor.listenTCP(port, IMAPFactory(storage_dir))
    reactor.run()

if __name__ == '__main__':
    main()

# ======== AUTENTICACIÓN DE USUARIOS ========
'''
@implementer(ICredentialsChecker)
class SMTPAuthChecker:
    """
    Verifica las credenciales de los usuarios.
    """
    credentialInterfaces = (IUsernamePassword,)

    def __init__(self, users_file):
        self.users = self.load_users(users_file)

    def load_users(self, users_file):
        """
        Cargar usuarios desde un archivo CSV.
        """
        users = {}
        try:
            with open(users_file, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    users[row["email"]] = row["password"]
        except Exception as e:
            print(f"Error loading users: {e}")
            exit(1)
        return users

    def requestAvatarId(self, credentials):
        """
        Validar credenciales.
        """
        if credentials.username in self.users and self.users[credentials.username] == credentials.password:
            print(f"Usuario autenticado: {credentials.username}")
            return defer.succeed(credentials.username)
        print(f"Fallo de autenticación: {credentials.username}")
        return defer.fail(UnauthorizedLogin())

'''