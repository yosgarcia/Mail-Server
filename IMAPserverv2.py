from twisted.internet import reactor, defer
from twisted.mail import imap4
from twisted.cred import portal, checkers, credentials
from twisted.mail.maildir import MaildirMailbox
import os

# Configuración de directorio donde se almacenarán los correos
MAILDIR_PATH = "var/mail"

# Clase que implementa un usuario IMAP
class IMAPUserAccount:
    def __init__(self, username):
        self.username = username
        self.mailbox_path = os.path.join(MAILDIR_PATH, username)
        os.makedirs(self.mailbox_path, exist_ok=True)

    def _getMailbox(self, name):
        path = os.path.join(self.mailbox_path, name)
        if not os.path.exists(path):
            os.makedirs(path)
        return defer.succeed(MaildirMailbox(path))

    def listMailboxes(self):
        return defer.succeed([b"INBOX"])

    def select(self, name, readOnly=True):
        return self._getMailbox(name)

# Implementación de un Realm para manejar autenticación de usuarios
class IMAPRealm:
    def requestAvatar(self, avatarId, mind, *interfaces):
        if imap4.IAccount not in interfaces:
            raise NotImplementedError("IMAPRealm solo soporta IAccount")
        return imap4.IAccount, IMAPUserAccount(avatarId), lambda: None

# Configuración del servidor IMAP
def main():
    # Configuración de autenticación: Usuarios y contraseñas
    checker = checkers.InMemoryUsernamePasswordDatabaseDontUse()
    checker.addUser("ianparedes@santa.com", "password123")  # Usuario y contraseña de prueba

    # Configurar el Portal de autenticación
    realm = IMAPRealm()
    p = portal.Portal(realm, [checker])

    # Iniciar el servidor IMAP en el puerto 143 (puedes cambiarlo)
    factory = imap4.IMAP4Server()
    factory.portal = p
    reactor.listenTCP(1430, factory)

    print("Servidor IMAP corriendo en el puerto 143...")
    reactor.run()

if __name__ == "__main__":
    main()
