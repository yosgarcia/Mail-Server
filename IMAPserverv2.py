import base64
import os
import json
import random
import email
import argparse
from io import StringIO
from zope.interface import implementer

from twisted.cred import portal, checkers, credentials, error as credError
from twisted.internet import protocol, reactor
from twisted.mail import imap4, maildir
from twisted.python import log
import sys

# ========== Archivo de usuarios JSON ==========
USERS_FILE = "users.json"

# ========== Checker personalizado para leer el JSON ==========
@implementer(checkers.ICredentialsChecker)
class JSONPasswordChecker:
    credentialInterfaces = (credentials.IUsernamePassword,)

    def __init__(self, filename):
        with open(filename, "r") as f:
            self.users = json.load(f)

    def requestAvatarId(self, credentials):
        username = credentials.username.decode()
        password = credentials.password.decode()
        if username in self.users and self.users[username]["password"] == password:
            return username
        raise credError.UnauthorizedLogin("Usuario o contraseña inválidos")

# ========== Mailbox y cuenta IMAP ==========
@implementer(imap4.IAccount)
class IMAPUserAccount:
    def __init__(self, user_dir):
        self.dir = user_dir

    def _getMailbox(self, path):
        if not os.path.exists(self.dir):
            raise KeyError("No existe el mailbox")
        return IMAPMailbox(self.dir)

    def listMailboxes(self, ref, wildcard):
        for box in os.listdir(self.dir):
            yield box, self._getMailbox(box)

    def select(self, path, rw=False):
        return self._getMailbox(path)

class ExtendedMaildir(maildir.MaildirMailbox):
    def __iter__(self):
        return iter(self.list)

    def __len__(self):
        return len(self.list)

    def __getitem__(self, i):
        return self.list[i]

@implementer(imap4.IMailbox)
class IMAPMailbox(object):

    def __init__(self, path):
        self.maildir = self._getMessagesFromDir(path)
        self.listeners = []
        # Asignamos un UIDVALIDITY basado en el nombre del directorio o en un valor fijo
        self.uniqueValidityIdentifier = hash(path)  # Genera un UIDVALIDITY basado en la ruta del usuario


    def _getMessagesFromDir(self, path):
        """Método para leer los correos directamente del directorio del usuario"""
        messages = []
        uid = 1  # Empezamos con UID = 1
        for file_name in os.listdir(path):
            full_path = os.path.join(path, file_name)
            if os.path.isfile(full_path):
                with open(full_path, 'r') as f:
                    messages.append(MaildirMessage(f.read(), uid))  # Asignamos UID
                    uid += 1  # Incrementamos el UID para el siguiente mensaje
        return messages

    def getHierarchicalDelimiter(self):
        return "."

    def getFlags(self):
        return []

    def getMessageCount(self):
        return len(self.maildir)

    def getRecentCount(self):
        return 0

    def isWriteable(self):
        return False

    def getUIDValidity(self):
        return self.uniqueValidityIdentifier

    def _seqMessageSetToSeqDict(self, messageSet):
        """Método para convertir el conjunto de mensajes por secuencia"""
        if not messageSet.last:
            messageSet.last = self.getMessageCount()

        seqMap = {}
        for messageNum in messageSet:
            if messageNum >= 0 and messageNum <= self.getMessageCount():
                seqMap[messageNum] = self.maildir[messageNum - 1]
        return seqMap

    def fetch(self, messages, uid):
        """Método para obtener los correos, soporte tanto por número de secuencia como por UID."""
        
        # Si se solicita por UID (esto es lo que estás usando en tu caso)
        if uid:
            # Si el set de mensajes es de tipo rango 1:* o un conjunto de IDs.
            if '1:*' in str(messages):
                # Obtén todos los mensajes (conviértelo a una lista de secuencias)
                messages = list(range(1, self.getMessageCount() + 1))  # Todos los mensajes

            # Itera sobre el conjunto de mensajes (MessageSet) 
            for seq in messages:
                message = self.maildir[seq - 1]  # Accede al mensaje de acuerdo a la secuencia
                yield seq, message

        else:
            # Si no es por UID, usa la función de secuencias para buscar mensajes.
            # La secuencia de mensajes se pasa como una lista
            messagesToFetch = self._seqMessageSetToSeqDict(messages)
            for seq, message in messagesToFetch.items():
                yield seq, message


    def addListener(self, listener):
        self.listeners.append(listener)

    def removeListener(self, listener):
        self.listeners.remove(listener)

@implementer(imap4.IMessage)
class MaildirMessage(object):

    def __init__(self, messageData, uid):
        self.message = email.message_from_string(messageData)
        self.uid = uid  # Usar el número de UID directamente como un número único
        self.flags = []

    def getHeaders(self, negate, *names):
        
        # Convertir las claves de bytes a str si es necesario
        def decode_key(key):
            if isinstance(key, bytes):
                return key.decode('utf-8')  # Decodificar de bytes a str
            return key

        if not names:
            # Devolver todos los encabezados como diccionario de str
            return {decode_key(k): str(v) for k, v in self.message.items()}
        else:
            if negate:
                # Devolver encabezados que NO estén en names
                return {decode_key(k): str(v) for k, v in self.message.items() if k.upper() not in names}
            else:
                # Devolver solo los encabezados especificados
                return {decode_key(name): str(self.message.get(name, '')) for name in names}



    def getBodyFile(self):
        """Método para obtener el cuerpo del mensaje (soporta multipart)"""
        if self.message.is_multipart():
            parts = []
            # Iterar sobre todas las partes del mensaje MIME
            for part in self.message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Si es texto plano (text/plain) o HTML (text/html)
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    body = part.get_payload(decode=False)  # Obtener el cuerpo
                    charset = part.get_content_charset() or "utf-8"  # Codificación
                    body_text = body
                    parts.append(f"TEXT: {body_text}\r\n")

                elif content_type == "text/html" and "attachment" not in content_disposition:
                    body = part.get_payload(decode=False)  # Obtener el cuerpo HTML
                    charset = part.get_content_charset() or "utf-8"  # Codificación
                    body_html = body.decode(charset, errors="replace")  # Decodificar HTML
                    parts.append(f"HTML: {body_html}\r\n")

                # Si es un archivo adjunto
                elif "attachment" in content_disposition:
                    filename = part.get_filename()  # Obtener el nombre del archivo
                    if filename:
                        file_data = part.get_payload(decode=True)  # Decodificar el archivo (base64)
                        file_content = base64.b64encode(file_data).decode("utf-8")  # Codificar nuevamente en base64 para mostrar
                        parts.append(f"ATTACHMENT: {filename}\r\n")
                        parts.append(f"FILE DATA (Base64): {file_content}\r\n")
            
            return "\r\n".join(parts)
        else:
            # Si el mensaje no es multipart, solo devolvemos el contenido principal
            body = self.message.get_payload(decode=False)
            charset = self.message.get_content_charset() or "utf-8"
            return body.decode(charset, errors="replace")

    def isMultipart(self):
        return self.message.is_multipart()

    def getUID(self):
        """Método para obtener el UID único del mensaje (como un número)"""
        return self.uid
    
    def getFlags(self):
        # Devuelve los flags del mensaje (por ejemplo, si ya ha sido leído)
        return self.flags

    def setFlag(self, flag):
        # Método para establecer un flag (por ejemplo, \Seen)
        if flag not in self.flags:
            self.flags.append(flag)

    def removeFlag(self, flag):
        # Método para eliminar un flag
        if flag in self.flags:
            self.flags.remove(flag)
    
    def getSize(self):
        # Devuelve el tamaño del mensaje en bytes
        return len(self.message.as_string().encode('utf-8'))

# ========== Realm ==========
@implementer(portal.IRealm)
class MailUserRealm:
    def __init__(self, baseDir):
        self.baseDir = baseDir

    def requestAvatar(self, avatarId, mind, *interfaces):
        if imap4.IAccount not in interfaces:
            raise NotImplementedError("Este realm solo soporta imap4.IAccount.")

        # Dividir usuario@dominio
        try:
            user, domain = avatarId.split("@")
        except ValueError:
            raise KeyError("Formato de usuario inválido")

        userDir = os.path.join(self.baseDir, domain, user)
        if not os.path.exists(userDir):
            raise KeyError("Directorio de usuario no encontrado: {}".format(userDir))
        avatar = IMAPUserAccount(userDir)
        return imap4.IAccount, avatar, lambda: None

# ========== Protocolo con logging ==========
class IMAPServerProtocol(imap4.IMAP4Server):
    def lineReceived(self, line):
        print("CLIENT:", line)
        super().lineReceived(line)

    def sendLine(self, line):
        super().sendLine(line)
        print("SERVER:", line)

class IMAPFactory(protocol.Factory):
    def __init__(self, portal):
        self.portal = portal

    def buildProtocol(self, addr):
        proto = IMAPServerProtocol()
        proto.portal = self.portal
        return proto

# ========== Main ==========
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Servidor IMAP básico.")
    parser.add_argument("-s", "--storage", required=True, help="Ruta al directorio de almacenamiento de mail (/var/mail)")
    parser.add_argument("-p", "--port", required=True, type=int, help="Puerto para escuchar conexiones IMAP")

    args = parser.parse_args()

    log.startLogging(sys.stdout)

    mail_portal = portal.Portal(MailUserRealm(args.storage))
    mail_portal.registerChecker(JSONPasswordChecker(USERS_FILE))

    print(f"Servidor IMAP escuchando en puerto {args.port}, storage: {args.storage}")
    reactor.listenTCP(args.port, IMAPFactory(mail_portal))
    reactor.run()
