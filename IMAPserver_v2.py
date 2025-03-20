import os
import random
import email
from io import BytesIO
from zope.interface import implementer
from twisted.internet import protocol, reactor
from twisted.cred import portal, checkers, credentials
from twisted.mail import imap4
from twisted.mail.imap4 import MessageSet
from email import message_from_file
from twisted.python import log
import argparse
import sys, json

# ----------------------------
# Gestión de Metadatos del Buzón
# ----------------------------

class MailboxMetadata:
    def __init__(self):
        self.messages = []  # Lista de mensajes con sus UID
        self.uidvalidity = random.randint(100000, 999999)
        self.uid_next = 1  # El siguiente UID que se asignará

    def add_message(self, filename):
        # Asignar un UID único a cada mensaje
        uid = self.uid_next
        self.messages.append({'uid': uid, 'filename': filename})
        self.uid_next += 1
        return uid

    def get_message_by_uid(self, uid):
        # Obtener mensaje por UID
        for message in self.messages:
            if message['uid'] == uid:
                return message['filename']
        return None

    def get_message_count(self):
        return len(self.messages)

    def getUIDValidity(self):
        return self.uidvalidity

    def getUIDNext(self):
        return self.uid_next

# ----------------------------
# Implementación del Buzón IMAP
# ----------------------------

@implementer(imap4.IMailbox)
class SimpleMailbox:
    def __init__(self, path):
        self.path = path
        self.metadata = MailboxMetadata()  # No se carga desde un archivo, se inicializa vacía
        self.listeners = []

        # Cargar los mensajes directamente del directorio
        self.load_messages()

    def load_messages(self):
        """Carga los correos directamente desde el directorio del usuario."""
        for f in os.listdir(self.path):
            if f.endswith('.eml'):
                uid = self.metadata.add_message(f)
                print(f"Cargado mensaje: {f}, UID: {uid}")
        print(f"Correos cargados: {self.metadata.messages}")

    def getFlags(self):
        return ['\\Seen', '\\Deleted', '\\Flagged']

    def getHierarchicalDelimiter(self):
        return '/'

    def getUIDValidity(self):
        return self.metadata.getUIDValidity()

    def getMessageCount(self):
        return self.metadata.get_message_count()

    def getRecentCount(self):
        return 0

    def isWriteable(self):
        return True

    def getUIDNext(self):
        return self.metadata.getUIDNext()

    def _seq_to_messages(self, messageSet):
        seq_map = {}
        for msg_num in messageSet:
            if msg_num <= 0 or msg_num > len(self.metadata.messages):
                continue
            seq_map[msg_num] = self.metadata.messages[msg_num - 1]['filename']
        return seq_map

    def fetch(self, msgnum, uid=False):

        # Si msgnum es un MessageSet, aseguramos que tenga su valor final
        if isinstance(msgnum, imap4.MessageSet):
            if hasattr(msgnum, 'last'):
                msgnum.last = self.metadata.get_message_count() # Asegura que `last` esté configurado
    # Ahora intenta convertir el MessageSet a una lista
            else:
                # Si no es callable, intentamos establecerlo manualmente (por ejemplo, en el atributo _last)
                msgnum._last = self.metadata.get_message_count() if not uid else (self.metadata.getUIDNext() - 1)
            try:
                msgnums = list(msgnum)
            except Exception as e:
                print(f"Error al convertir MessageSet a lista: {e}")
                return iter({})
        else:
            # Si msgnum es una cadena (por ejemplo, "1:*" o "1:5")
            msgnums = []
            for range_str in msgnum.split(','):
                if ':' in range_str:
                    start, end = range_str.split(':')
                    start = int(start)
                    if end == '*':
                        end = self.metadata.get_message_count()
                    else:
                        end = int(end)
                    msgnums.extend(range(start, end + 1))
                else:
                    msgnums.append(int(range_str))

        results = {}

        if uid:
            for m in msgnums:
                print(f"Buscando mensaje UID {m}")
                filename = self.metadata.get_message_by_uid(m)
                if filename:
                    file_path = os.path.join(self.path, filename)
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    message = SimpleMessage(data, m)
                    headers = message.getHeaders(False, 'From', 'To', 'Subject', 'Date', 'Message-ID', 'Content-Type')
                    header_str = "\r\n".join([f"{key}: {val}" for key, val in headers.items()])
                    size = message.getSize()


                    flags = message.getFlags()  # Asegúrate de que es una lista de banderas
                    if isinstance(flags, str):
                        flags = [flags]  # Convierte a lista si es una cadena
                    '''results[m] = (
                        f"* {m} FETCH (UID {m} RFC822.SIZE {size} FLAGS ({' '.join(flags)}) "
                        f"BODY.PEEK[HEADER.FIELDS (From To Subject Date Message-ID)] {{{size}}}\r\n{header_str})"
                    )'''
                    results[m] = message
                    print(f"Enviando mensaje UID {m} con el contenido:\n{header_str}\n")
        else:
            for idx, message_info in enumerate(self.metadata.messages, start=1):
                if idx in msgnums:
                    filename = message_info['filename']
                    file_path = os.path.join(self.path, filename)
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    message = SimpleMessage(data, idx)
                    headers = message.getHeaders(False, 'From', 'To', 'Subject', 'Date', 'Message-ID')
                    header_str = "\r\n".join([f"{key}: {val}" for key, val in headers.items()])
                    size = message.getSize()
                    flags = message.getFlags()  # Asegúrate de que es una lista de banderas
                    if isinstance(flags, str):
                        flags = [flags]  # Convierte a lista si es una cadena
                    '''results[idx] = (
                        f"* {idx} FETCH (UID {idx} RFC822.SIZE {size} FLAGS ({' '.join(flags)}) "
                        f"BODY.PEEK[HEADER.FIELDS (From To Subject Date Message-ID)] {{{size}}}\r\n{header_str})"
                    )'''
                    print(f"Enviando mensaje UID {idx} con el contenido:\n{header_str}\n")

        print(f"RESULTADOS: {results}")
        return iter(results.items())





    def addListener(self, listener):
        self.listeners.append(listener)

    def removeListener(self, listener):
        self.listeners.remove(listener)

    def expunge(self):
        return []

    def store(self, messages, flags, mode, uid):
        return {}

    def addMessage(self, message, flags=None, date=None):
        filename = f"mail_{random.randint(1000,9999)}.eml"
        filepath = os.path.join(self.path, filename)
        with open(filepath, 'wb') as f:
            f.write(message.getvalue())
        uid = self.metadata.add_message(filename)
        return len(self.metadata.messages), filename, uid
    
    def getMessage(self, uid):
        """Devuelve un SimpleMessage a partir de un UID solicitado por el cliente."""
        filename = self.metadata.get_message_by_uid(uid)
        if filename is None:
            return None  # Si no existe, Twisted manejará el error
        filepath = os.path.join(self.path, filename)
        with open(filepath, 'rb') as f:
            raw_data = f.read()
        return SimpleMessage(raw_data, uid)


# ----------------------------
# Implementación del Mensaje IMAP
# ----------------------------

@implementer(imap4.IMessage)
class SimpleMessage:
    def __init__(self, data, uid):
        self.email_obj = email.message_from_bytes(data)
        self.raw = data
        self.flags = ['\\Seen']  # Puedes ajustar las banderas como quieras
        self.uid = uid

    def getHeaders(self, negate, *names):
        headers = {}
        for key, val in self.email_obj.items():
            if (key.lower() in [n.lower() for n in names] and not negate) or (negate and key.lower() not in [n.lower() for n in names]):
                headers[key] = val

        # Asegúrate de que el 'Content-Type' y 'Content-Transfer-Encoding' estén bien configurados
        if 'Content-Type' in headers:
            content_type = headers['Content-Type']
            if 'charset' not in content_type:
                headers['Content-Type'] = content_type + "; charset=UTF-8"
        
        if 'Content-Transfer-Encoding' not in headers:
            headers['Content-Transfer-Encoding'] = 'base64'  # Asegúrate de que el mensaje esté en base64 si es necesario

        return headers

    def getBodyFile(self):
        payload = self.email_obj.get_payload(decode=True)
        print(f"Payload: {payload}")
        return BytesIO(payload if payload else b'')

    def isMultipart(self):
        return self.email_obj.is_multipart()
    
    def getFlags(self):
        return self.flags
    
    def getUID(self):
        return self.uid
    
    def getSize(self):
        return len(self.raw)

# ----------------------------
# Implementación de la Cuenta IMAP
# ----------------------------

import unicodedata
def sanitize_folder_name(name):
    return unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('ascii')


@implementer(imap4.IAccount)
class SimpleAccount:
    def __init__(self, user_path):
        self.user_path = user_path
        self.metadata = MailboxMetadata()
        self.load_messages()

    def load_messages(self):
        """Carga los correos directamente desde el directorio del usuario."""
        self.metadata.messages = [{'uid': i + 1, 'filename': f} for i, f in enumerate(os.listdir(self.user_path)) if f.endswith('.eml')]
        print(f"Mensajes cargados para la cuenta: {self.metadata.messages}")

    def listMailboxes(self, ref, wildcard):
        yield 'INBOX', self.select('INBOX')

    def select(self, path, rw=False):
        if path != 'INBOX':
            raise KeyError("Solo se admite INBOX.")
        return SimpleMailbox(self.user_path)

    def isSubscribed(self, mailbox_name):
        return True  # O personaliza según el comportamiento que desees
    
    def create(self, path):
        clean_path = sanitize_folder_name(path)
    # En este servidor simple, no soportamos crear nuevos buzones
    # Puedes simplemente devolver un error para indicar que no es soportado
        raise imap4.MailboxException(f"Creación de buzones no soportada: {clean_path}")

# ----------------------------
# Realm y Comprobador de Credenciales
# ----------------------------

@implementer(portal.IRealm)
class SimpleRealm:
    def __init__(self, base_dir):
        self.base_dir = base_dir

    def requestAvatar(self, avatarId, mind, *interfaces):
        if imap4.IAccount not in interfaces:
            raise NotImplementedError("Solo se admite imap4.IAccount.")
        username = avatarId
        local_part, domain = username.split('@')
        user_dir = os.path.join(self.base_dir, domain, local_part)
        if not os.path.exists(user_dir):
            raise KeyError("Usuario no encontrado.")
        return imap4.IAccount, SimpleAccount(user_dir), lambda: None

# ----------------------------
# Comprobador de Credenciales
# ----------------------------

class SimplePasswordChecker:
    # Implementa la interfaz ICredentialsChecker
    credentialInterfaces = [credentials.IUsernamePassword]

    def __init__(self, users_file):
        self.users = self.load_users(users_file)

    def load_users(self, users_file):
        with open(users_file, 'r') as f:
            return json.load(f)

    def requestAvatarId(self, credentials):
        username = credentials.username.decode('utf-8') if isinstance(credentials.username, bytes) else credentials.username
        password = credentials.password.decode('utf-8') if isinstance(credentials.password, bytes) else credentials.password

        if username not in self.users:
            raise KeyError("Usuario no encontrado.")
        if self.users[username]['password'] != password:
            raise ValueError("Contraseña incorrecta.")
        return username

# ----------------------------
# Creación del Servidor IMAP
# ----------------------------

class IMAPServerProtocol(imap4.IMAP4Server):
    def lineReceived(self, line):
        print("CLIENT:", line)
        imap4.IMAP4Server.lineReceived(self, line)

    def sendLine(self, line):
        imap4.IMAP4Server.sendLine(self, line)
        print("SERVER:", line)

class IMAPFactory(protocol.Factory):
    def __init__(self, portal):
        self.portal = portal

    def buildProtocol(self, addr):
        proto = IMAPServerProtocol()
        proto.portal = self.portal
        return proto

# ----------------------------
# Función principal para el arranque
# ----------------------------

def main():
    parser = argparse.ArgumentParser(description="Servidor IMAP simple")
    parser.add_argument('-s', '--storage', help="Directorio de almacenamiento de correos", required=True)
    parser.add_argument('-p', '--port', type=int, help="Puerto para el servidor IMAP", required=True)
    args = parser.parse_args()

    data_dir = args.storage
    port = args.port

    # Cargar el archivo JSON de usuarios
    users_file = 'users.json'

    # Crear el portal de autenticación
    realm = SimpleRealm(data_dir)
    checker = SimplePasswordChecker(users_file)
    portal_inst = portal.Portal(realm)
    portal_inst.registerChecker(checker)

    # Iniciar el servidor IMAP
    log.startLogging(sys.stdout)
    reactor.listenTCP(port, IMAPFactory(portal_inst))
    reactor.run()

if __name__ == "__main__":
    main()
