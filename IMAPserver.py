import base64
import os
import random
import email
from io import BytesIO
from zope.interface import implementer
from twisted.internet import protocol, reactor
from twisted.cred import portal, credentials
from email import policy
from twisted.mail import imap4
import argparse
import json
import unicodedata




class MailboxMetadata:
    """
    Clase que se encarga de manejar los metadatos del buzón, incluyendo
    la lista de los mensajes y los UID asignados.

    Atributos:
        messages (list): Lista de mensajes con sus UID.
        uidvalidity (int): Número aleatorio que representa la validez de los UID.
        uid_next (int): El siguiente UID que se asignará.
    """
    def __init__(self):
        self.messages = []  
        self.uidvalidity = random.randint(100000, 999999)
        self.uid_next = 1  

    def addMessage(self, filename):
        """
        Función para añadir un mensaje al buzón.

        Args:
            filename (str): Nombre del archivo del mensaje.
        
        Returns:
            int: UID asignado al mensaje.
        """
        # Asignar un UID único a cada mensaje
        uid = self.uid_next
        self.messages.append({'uid': uid, 'filename': filename})
        self.uid_next += 1
        return uid

    def getMessageByUid(self, uid):
        """
        Función para obtener el nombre del archivo de un mensaje a partir de su UID.

        Args:
            uid (int): UID del mensaje.

        Returns:
            str: Nombre del archivo del mensaje.
        """
        for message in self.messages:
            if message['uid'] == uid:
                return message['filename']
        return None

    def getMessageCount(self):
        """
        Función para obtener el número de mensajes en el buzón.

        Returns:
            int: Número de mensajes.
        """
        return len(self.messages)

    def getUIDValidity(self):
        """
        Obtiene el UIDVALIDITY del buzón.

        Returns:
            int: Valor UIDVALIDITY.
        """
        return self.uidvalidity

    def getUIDNext(self):
        """
        Obtiene el siguiente UID disponible.

        Returns:
            int: Valor UIDNEXT.
        """
        return self.uid_next



@implementer(imap4.IMailbox)
class SimpleMailbox:
    """
    Clase que implementa un buzón IMAP que se encargada de manejar los correos en
    el directorio del usuario.

    Atributos:
        path (str): Directorio del usuario.
        metadata (MailboxMetadata): Metadatos del buzón.
        listeners (list): Lista de listeners para eventos en el buzón.
    """
    def __init__(self, path):
        self.path = path
        self.metadata = MailboxMetadata()
        self.listeners = []
        self.deleted_messages = set() 
        # Cargar los mensajes directamente del directorio
        self.loadMessages()

    def loadMessages(self):
        """
        Carga los correos .eml directamente desde el directorio del usuario.
        
        """
        for f in os.listdir(self.path):
            if f.endswith('.eml'):
                uid = self.metadata.addMessage(f)
        print(f"Mails loaded: {self.metadata.messages}")

    def getFlags(self):
        """
        Define las banderas IMAP que va a soportar el buzón.

        Returns:
            list: Lista de banderas.
        """
        return ['\\Seen', '\\Deleted', '\\Flagged']

    def getHierarchicalDelimiter(self):
        """
        Define el delimitador jerárquico del buzón.

        Returns:
            str: Delimitador que en este caso es '/'.
        """
        return '/'

    def getUIDValidity(self):
        """
        Devuelve el UIDVALIDITY del buzón.

        Returns:
            int: Valor UIDVALIDITY.
        """
        return self.metadata.getUIDValidity()

    def getMessageCount(self):
        """
        Devuelve el número total de mensajes en el buzón.

        Returns:
            int: Número de mensajes.
        """
        return self.metadata.getMessageCount()

    def getRecentCount(self):
        """
        Devuelve el número de mensajes recientes.

        Returns:
            int: Siempre retorna 0 ya que no se tiene implementa una lógica para los mensajes
                recientes.
        """
        return 0

    def isWriteable(self):
        """
        Indica si el buzón es escribible.

        Returns:
            bool: True, ya que permite agregar mensajes nuevos.
        """
        return True

    def getUIDNext(self):
        """
        Obtiene el siguiente UID disponible.

        Returns:
            int: Valor UIDNEXT.
        """
        return self.metadata.getUIDNext()

    def _seqToMessages(self, messageSet):
        """
        Convierte un conjunto de secuencias (MessageSet) en un diccionario de mensajes válidos.

        Args:
            messageSet (MessageSet): Conjunto de secuencias.

        Returns:
            dict: Mapeo de número de mensaje a filename.
        """
        seq_map = {}
        for msg_num in messageSet:
            if msg_num <= 0 or msg_num > len(self.metadata.messages):
                continue
            seq_map[msg_num] = self.metadata.messages[msg_num - 1]['filename']
        return seq_map

    def fetch(self, msgnum, uid=False):
        """
        Método encargado de retornar los mensajes solicitados por el cliente de correo.

        Args:
            msgnum: Secuencia o cadena representando los mensajes solicitados.
            uid (bool): Si True, usa UID en lugar de número de secuencia.

        Returns:
            iterator: Iterador con los mensajes encontrados.
        """
        if isinstance(msgnum, imap4.MessageSet):
            # Para evitar errores, se asegura que tenga el atributo `last`
            if hasattr(msgnum, 'last'):
                msgnum.last = self.metadata.getMessageCount()
            else:
                # Si no es callable, intentamos establecerlo manualmente (por ejemplo, en el atributo _last)
                msgnum._last = self.metadata.getMessageCount() if not uid else (self.metadata.getUIDNext() - 1)
            try:
                msgnums = list(msgnum)
            except Exception as e:
                print(f"Error converting MessageSet to List: {e}")
                return iter({})
        else:
            # Si msgnum es una cadena por ejemplo "1:*" o "1:5"
            msgnums = []
            for range_str in msgnum.split(','):
                if ':' in range_str:
                    start, end = range_str.split(':')
                    start = int(start)
                    if end == '*':
                        end = self.metadata.getMessageCount()
                    else:
                        end = int(end)
                    msgnums.extend(range(start, end + 1))
                else:
                    msgnums.append(int(range_str))

        results = {}

        if uid:
            for m in msgnums:
                filename = self.metadata.getMessageByUid(m)
                if filename:
                    file_path = os.path.join(self.path, filename)
                    with open(file_path, 'rb') as f:
                        data = f.read() # Se obtiene el contenido del correo

                    message = SimpleMessage(data, m)
                    headers = message.getHeaders(False, 'From', 'To', 'Subject', 'Date', 'Message-ID', 'Content-Type')
                    header_str = "\r\n".join([f"{key}: {val}" for key, val in headers.items()])
                    size = message.getSize()
                    flags = message.getFlags()

                    sub_parts = message.getSubPart()

                    if sub_parts:
                        for part in sub_parts:
                            part_content = part['content']
                            part_filename = part['filename']
                            part_content_type = part['content_type']

                            # Aquí enviarías el adjunto como una respuesta adicional si lo deseas
                            # Puedes también agregar la codificación base64 para los adjuntos.
                            if part_filename:
                                encoded_content = base64.b64encode(part_content).decode('utf-8')
                                results[m] = f"Attachment: {part_filename}, Content-Type: {part_content_type}, Content: {encoded_content}"

                    if isinstance(flags, str):
                        flags = [flags] 
                    '''results[m] = (
                        f"* {m} FETCH (UID {m} RFC822.SIZE {size} FLAGS ({' '.join(flags)}) "
                        f"BODY.PEEK[HEADER.FIELDS (From To Subject Date Message-ID)] {{{size}}}\r\n{header_str})"
                    )'''
                    results[m] = message
                    print(f"Sending message UID {m} with content:\n{message.raw}\n")
                else:
                    print(f"Message with UID {m} not found.")
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
                    flags = message.getFlags() 

                    if isinstance(flags, str):
                        flags = [flags]  
                    '''results[idx] = (
                        f"* {idx} FETCH (UID {idx} RFC822.SIZE {size} FLAGS ({' '.join(flags)}) "
                        f"BODY.PEEK[HEADER.FIELDS (From To Subject Date Message-ID)] {{{size}}}\r\n{header_str})"
                    )'''

                    sub_parts = message.getSubParts()  # Obtener partes adicionales (como los adjuntos)

                    # Aquí puedes incluir los adjuntos
                    if sub_parts:
                        for part in sub_parts:
                            part_content = part['content']
                            part_filename = part['filename']
                            part_content_type = part['content_type']

                            # Puedes agregar los adjuntos como una respuesta si lo deseas
                            if part_filename:
                                encoded_content = base64.b64encode(part_content).decode('utf-8')
                                results[idx] = f"Attachment: {part_filename}, Content-Type: {part_content_type}, Content: {encoded_content}"

                    print(f"Sending message UID {idx} with content:\n{message.raw}\n")

        return iter(results.items())


    def addListener(self, listener):
        """
        Agrega un listener al buzón.

        Args:
            listener: Listener que se quiere agregar.
        """
        self.listeners.append(listener)

    def removeListener(self, listener):
        """
        Elimina un listener del buzón.

        Args:
            listener: Listener a eliminar.
        """
        self.listeners.remove(listener)

    def expunge(self):
        """
        Elimina permanentemente todos los mensajes marcados como eliminados (\Deleted).

        Returns:
            str: Mensaje de confirmación.
        """
        for msg_uid in self.deleted_messages:
            print(f"Expunging message {msg_uid} from the server.")
            filename = self.metadata.getMessageByUid(msg_uid, None)
            if filename:
                file_path = os.path.join(self.path, filename)
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        print(f"Deleted message with UID {msg_uid} at {file_path}")
                    else:
                        print(f"File for message UID {msg_uid} not found: {file_path}")
                except Exception as e:
                    print(f"Error deleting message {msg_uid}: {e}")

        self.deleted_messages.clear()

        return "OK EXPUNGE completed"
    
    def store(self, messages, flags, mode, uid):
        """
        Método dummy para almacenar banderas y no realiza cambios reales.

        Args:
            messages: Mensajes afectados.
            flags: Banderas a aplicar.
            mode: Modo de aplicación.
            uid: Si se aplica por UID.
        Returns:
            dict: Diccionario vacío.
        """
        return {}

    def addMessage(self, message, flags=None, date=None):
        """
        Añade un nuevo mensaje al buzón.

        Args:
            message: Contenido del mensaje.
            flags: Lista de banderas.
            date: Fecha del mensaje.

        Returns:
            tuple: Número total de mensajes, nombre del archivo, UID asignado al mensaje.
        """
        filename = f"mail_{random.randint(1000,9999)}.eml"
        filepath = os.path.join(self.path, filename)

        with open(filepath, 'wb') as f:
            f.write(message.getvalue())
        uid = self.metadata.addMessage(filename)

        return len(self.metadata.messages), filename, uid
    

    def getMessage(self, uid):
        """
        Obtiene un mensaje específico según UID.

        Args:
            uid (int): UID del mensaje solicitado.

        Returns:
            SimpleMessage: Objeto SimpleMessage correspondiente al UID de parámetro.
        """
        filename = self.metadata.getMessageByUid(uid)
        if filename is None:
            return None
        filepath = os.path.join(self.path, filename)
        with open(filepath, 'rb') as f:
            raw_data = f.read()
        return SimpleMessage(raw_data, uid)






@implementer(imap4.IMessage)
class SimpleMessage:
    """
    Clase que representa un mensaje IMAP de correo,
    parseado a partir del archivo .eml.

    Atributos:
        email_obj (email.message.Message): Objeto de mensaje de la librería email.
        raw (bytes): Contenido del mensaje en bytes.
        flags (list): Lista de banderas.
        uid (int): UID del mensaje.
    """
    def __init__(self, data, uid):
        self.email_obj = email.message_from_bytes(data)
        self.raw = data
        self.flags = ['\\Seen'] 
        self.uid = uid


    def getHeaders(self, negate, *names):
        """
        Función que retorna los headers del correo

        Args:
            negate (bool): En caso de que sea True, devuelve todos los headers excepto los especificados.
            names (str): Nombres de los headers a incluir o excluir.

        Returns:
            dict: Diccionario con los headers seleccionados.
        """
        headers = {}
        for key, val in self.email_obj.items():
            if (key.lower() in [n.lower() for n in names] and not negate) or (negate and key.lower() not in [n.lower() for n in names]):
                headers[key] = val

        if 'Content-Type' in headers:
            content_type = headers['Content-Type']
            if 'charset' not in content_type:
                headers['Content-Type'] = content_type + "; charset=UTF-8"
        
        if 'Content-Transfer-Encoding' not in headers:
            headers['Content-Transfer-Encoding'] = 'base64'  

        return headers

    def getBodyFile(self):
        """
        Extrae el cuerpo del correo como un objeto BytesIO.

        Returns:
            BytesIO: Contenido del cuerpo en formato bytes.
        """
        try:
            # En caso que sea un correo con un archivo adjunto
            if self.email_obj.is_multipart():
                # Recorrer todas las partes del mensaje y buscar la de tipo texto plano
                for part in self.email_obj.walk():
                    content_type = part.get_content_type()
                    content_disposition = part.get('Content-Disposition', '')

                    # Ignorar los adjuntos
                    if content_type == 'text/plain' and 'attachment' not in content_disposition:
                        payload = part.get_payload(decode=True)
                        if payload:
                            return BytesIO(payload)
                return BytesIO(b'')
            else:
                # Se extrae directamente
                payload = self.email_obj.get_payload(decode=True)
                return BytesIO(payload if payload else b'')
        except Exception as e:
            print(f"Error in getBodyFile: {e}")
            return BytesIO(b'')


    def getSubPart(self):
        """
        Esta función devuelve una subparte específica del mensaje 
        en caso de que sea multipart.

        Args:
            part (int): Índice de la subparte.

        Returns:
            BytesIO o None: Subparte en formato bytes, o None si no existe.
        """
        # Si el mensaje es multipart, devolver todas las partes, incluidas las de adjunto
        if self.email_obj.is_multipart():
            sub_parts = []
            for part in self.email_obj.walk():
                content_disposition = part.get('Content-Disposition', '')
                content_type = part.get_content_type()
                payload = part.get_payload(decode=True) or b''
                
                # Si es un adjunto, agregamos la parte
                if 'attachment' in content_disposition or content_type.startswith('application/'):
                    filename = part.get_filename()
                    sub_parts.append({
                        'filename': filename,
                        'content': payload,
                        'content_type': content_type
                    })
                # Para partes de texto, agregar también
                if content_type == 'text/plain':
                    sub_parts.append({
                        'filename': None,
                        'content': payload,
                        'content_type': content_type
                    })
            return sub_parts
        else:
            # Si no es multipart, solo devolver el contenido
            return [{
                'filename': None,
                'content': self.email_obj.get_payload(decode=True) or b'',
                'content_type': self.email_obj.get_content_type()
            }]


    def isMultipart(self):
        """
        Indica si el mensaje es multipart.

        Returns:
            bool: True si es multipart, False si no.
        """
        return self.email_obj.is_multipart()
    

    def getFlags(self):
        """
        Retorna la lista de banderas actuales del mensaje.

        Returns:
            list: Lista de banderas IMAP.
        """
        return self.flags
    
    def getUID(self):
        """
        Retorna el UID del mensaje.

        Returns:
            int: UID del mensaje.
        """
        return self.uid
    
    def getSize(self):
        """
        Retorna el tamaño total del mensaje.

        Returns:
            int: Tamaño en bytes.
        """
        return len(self.raw)





@implementer(imap4.IAccount)
class SimpleAccount:
    """
    Clase que representa una cuenta de usuario IMAP.

    Atributos:
        user_path (str): Ruta al directorio del usuario 
        donde se almacenan sus correos.
        metadata (MailboxMetadata): Metadatos del buzón.
    """
    def __init__(self, user_path):
        self.user_path = user_path
        self.metadata = MailboxMetadata()
        self.load_messages()

    def load_messages(self):
        """
        Carga los correos directamente desde el directorio del usuario.
        Lee todos los archivos .eml y los indexa con un UID.
        """
        self.metadata.messages = [{'uid': i + 1, 'filename': f} for i, f in enumerate(os.listdir(self.user_path)) if f.endswith('.eml')]
        print(f"Messages loaded for account: {self.metadata.messages}")

    def listMailboxes(self, ref, wildcard):
        """
        Lista los buzones disponibles. Solo soporta INBOX para este caso.

        Returns:
            generator: Yields una tupla con el nombre y objeto del buzón.
        """
        yield 'INBOX', self.select('INBOX')


    def select(self, path, rw=False):
        """
        Selecciona un buzón específico

        Args:
            path (str): Nombre del buzón.

        Returns:
            SimpleMailbox: Instancia del buzón seleccionado.
        """
        if path != 'INBOX':
            raise KeyError("INBOX valid only.")
        return SimpleMailbox(self.user_path)

    def isSubscribed(self, mailbox_name):
        # En este servidor no se manejan las suscripciones
        return True  
    
    def sanitizeFolderName(name):
        # Limpia eñ nombre del buzón
        return unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('ascii')

    def create(self, path):
        # No está implementado que se pueda crear nuevos buzones
        clean_path = self.sanitizeFolderName(path)
        raise imap4.MailboxException(f"New mailbox creation not suported: {clean_path}")



@implementer(portal.IRealm)
class SimpleRealm:
    """
    Realm para el portal de autenticación IMAP.

    Atributos:
        base_dir (str): Directorio base donde están los correos organizados por dominio y usuario.
    """
    def __init__(self, base_dir):
        self.base_dir = base_dir

    def requestAvatar(self, avatarId, mind, *interfaces):
        """
        Proporciona la cuenta correspondiente para el usuario que se 
        autentique.

        Args:
            avatarId (str): ID del avatar que vendría siendo el nombre de usuario.
            interfaces: Interfaces solicitadas.

        Returns:
            tuple: (interfaz, instancia de SimpleAccount, logout callable).

        """
        if imap4.IAccount not in interfaces:
            raise NotImplementedError("It's only admitted imap4.IAccount")
        username = avatarId
        local_part, domain = username.split('@')
        user_dir = os.path.join(self.base_dir, domain, local_part)
        if not os.path.exists(user_dir):
            raise KeyError("User not found.")
        return imap4.IAccount, SimpleAccount(user_dir), lambda: None




class SimplePasswordChecker:
    """
    Implementación del validador de credenciales que valida 
    usuario y contraseña desde un archivo JSON.

    Atributos:
        users (dict): Diccionario con usuarios y contraseñas.
    """
    credentialInterfaces = [credentials.IUsernamePassword]

    def __init__(self, users_file):
        self.users = self.load_users(users_file)

    def load_users(self, users_file):
        """
        Carga los usuarios desde el archivo JSON de usuarios.

        Args:
            users_file (str): Ruta del archivo JSON.

        Returns:
            dict: Usuarios y contraseñas.
        """
        with open(users_file, 'r') as f:
            return json.load(f) 

    def requestAvatarId(self, credentials):
        """
        Función que verifica si el usuario y contraseña ingresados son válidos

        Args:
            credentials (IUsernamePassword): Credenciales del cliente.

        Returns:
            str: Nombre de usuario validado.
        """
        username = credentials.username.decode('utf-8') if isinstance(credentials.username, bytes) else credentials.username
        password = credentials.password.decode('utf-8') if isinstance(credentials.password, bytes) else credentials.password

        if username not in self.users:
            raise KeyError("User not found.")
        if self.users[username]['password'] != password:
            raise ValueError("Invalid password.")
        return username




class IMAPServerProtocol(imap4.IMAP4Server):
    """
    Protocolo IMAP que se encarga de mandar y recibir la comunicación
    con el cliente de correos.
    """
    def lineReceived(self, line):

        print("CLIENT:", line)
        imap4.IMAP4Server.lineReceived(self, line)

    def sendLine(self, line):
        imap4.IMAP4Server.sendLine(self, line)
        print("SERVER:", line)

class IMAPFactory(protocol.Factory):
    """
    Clase para la fábrica para construir instancias del protocolo IMAP.

    Atributos:
        portal (Portal): Portal de autenticación.
    """

    def __init__(self, portal):
        self.portal = portal

    def buildProtocol(self, addr):
        proto = IMAPServerProtocol()
        proto.portal = self.portal
        return proto




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
    print(f"Starting IMAP server on port {port}...")

    reactor.listenTCP(port, IMAPFactory(portal_inst))
    reactor.run()

if __name__ == "__main__":
    main()
