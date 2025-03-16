import argparse
import os, sys, time, re, json
from twisted.internet import reactor, protocol, defer
from twisted.mail import imap4
from zope.interface import implementer

from twisted.protocols.basic import LineReceiver


import email
from email import policy


def parse_arguments():
    """
    Función para leer los argumentos de la línea de comandos.

    Returns:
        mail_storage: Directorio de correos almacenados.
        port: Puerto a usar.
    """
    parser = argparse.ArgumentParser(description="IMAP Server")
    parser.add_argument("-s", "--mail-storage", required=True, help="Directory to store emails")
    parser.add_argument("-p", "--port", type=int, required=True, default=143, help="Port to listen on")

    args = parser.parse_args()

    return args.mail_storage, args.port


def load_users_from_json(file_path):
    """
    Función para cargar los usuarios desde un archivo JSON.

    Args:  
        file_path: Ruta del archivo JSON.
    
    Returns:
        users: Diccionario con los usuarios.
    """
    if not os.path.exists(file_path):
        print(f"[ERROR] Users file {file_path} not found")
        return {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            users = json.load(f)
            return users
    except Exception as e:
        print(f"[ERROR] JSON file could not be loaded: {e}")
        return {}
    



class IMAPServer(LineReceiver):
    """
    Clase para implementar un servidor IMAP básico.
    Acepta comandos:
        - CAPABILITY
        - LOGIN
        - SELECT
        - FETCH
        - LOGOUT
        - NOOP
        - UID

    Atributos:  
        mail_storage: Directorio de almacenamiento de correos.
        state: Estado del servidor (NO_AUTENTICADO, AUTENTICADO, SELECCIONADO).
        username: Nombre de usuario autenticado.
        user_dir: Directorio del usuario autenticado.
        mailbox: Diccionario con los mensajes del usuario autenticado.
    """

    delimiter = b'\r\n'

    def __init__(self, mail_storage):
        self.mail_storage = mail_storage
        self.state = 'NOT_AUTHENTICATED'
        self.username = None
        self.user_dir = None
        self.mailbox = None  # Diccionario: clave = número de mensaje, valor = info (path, size, etc.)

    def connectionMade(self):
        """Método llamado cuando se establece una nueva conexión."""
        print("[INFO] New connection established from:", self.transport.getPeer())
        self.sendLine(b'* OK IMAP4rev1 Service Ready')


    def load_mailbox(self):
        """
        Recarga la lista de correos desde el disco para incluir nuevos mensajes
        que hayan llegado.
        """
        
        if not self.user_dir:
            return

        self.mailbox = {}  # Resetear el diccionario
        try:
            files = os.listdir(self.user_dir)
        except Exception as e:
            print(f"[ERROR] It could not access to the mailbox: {e}")
            return

        # Se itera a través de los archivos .eml
        eml_files = [f for f in files if f.endswith('.eml')]
        eml_files.sort()
        
        for i, filename in enumerate(eml_files, start=1):
            fullpath = os.path.join(self.user_dir, filename)
            size = os.path.getsize(fullpath)
            internal_date = time.strftime('%d-%b-%Y %H:%M:%S +0000', time.gmtime(os.path.getmtime(fullpath)))
            
            # Se actualiza el diccionario con la información del mensaje
            self.mailbox[i] = {
                'filename': filename,
                'path': fullpath,
                'size': size,
                'flags': [],
                'internal_date': internal_date
            }


    def lineReceived(self, line):
        """
        Función para gestionar los comandos que reciba el servidor IMAP de la conexión

        Args:
            line: Línea recibida del cliente.
        """
        
        try:
            line = line.decode('utf-8')
        except UnicodeDecodeError:
            self.sendLine(b'* BAD Invalid Encoding')
            return

        # Se espera que la línea tenga el formato: <tag> <COMANDO> [argumentos...]
        print(f"[DEBUG] Command received: {line}")
        parts = line.split()
        if not parts:
            return
        tag = parts[0]
        if len(parts) < 2:
            self.sendLine((tag + " BAD Commans are missing").encode())
            return

        command = parts[1].upper()
        args = parts[2:]

        if command == 'CAPABILITY':
            self.cmd_CAPABILITY(tag, args)
        elif command == 'LOGIN':
            self.cmd_LOGIN(tag, args)
        elif command == 'SELECT':
            self.cmd_SELECT(tag, args)
        elif command == 'FETCH':
            self.cmd_FETCH(tag, args)
        elif command == 'UID':
            if len(args) < 2 or args[0].upper() != 'FETCH':
                self.sendLine((tag + " BAD Invalid UID Command").encode())
            else:
                self.cmd_UID_FETCH(tag, args[1:])
        elif command == 'LOGOUT':
            self.cmd_LOGOUT(tag, args)
        elif command == 'NOOP':
            self.cmd_NOOP(tag, args) 
        else:
            self.sendLine((tag + " BAD Unknown command" + command).encode())


    def parse_uid_range(self, uid_range):
        """
        Función para parsear el rango de UIDs y convertirlo en una lista de UIDs.
        Si el rango tiene el formato "1:*" o "*", se considera como todos los UIDs.

        Args:
            uid_range: Rango de UIDs.

        Returns:
            uids: Lista de UIDs.
        """
        uids = []
        
        # Caso con * (todos los UIDs)
        if '*' in uid_range:
            if uid_range == "*":
                return list(self.mailbox.keys())
            else:
                # Si es algo como "1:*", lo convertimos en un rango "1:último UID"
                parts = uid_range.split(':')
                if len(parts) == 2 and parts[1] == "*":
                    start = int(parts[0])
                    end = len(self.mailbox) 
                    uids = list(range(start, end + 1))
        
        # Caso con rango específico "start:end"
        elif ':' in uid_range:
            start, end = uid_range.split(':')
            start = int(start)
            end = int(end)
            
            if start > end:
                start, end = end, start 

            uids = list(range(start, end + 1))
        
        # Caso de un solo UID
        else:
            try:
                uids = [int(uid_range)]
            except ValueError:
                return None

        return uids



    def cmd_UID_FETCH(self, tag, args):
        """
        Función para manejar el comando UID FETCH. 
        Se espera que se envíe un rango de UID y una solicitud compuesta,
        por ejemplo:
        UID FETCH 1:3 (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS 
        (From To Cc Bcc Subject Date Message-ID Priority X-Priority References 
        Newsgroups In-Reply-To Content-Type Reply-To)])

        Args:
            tag: Etiqueta del comando.
            args: Lista de argumentos.

        """

        self.load_mailbox()  # Actualizar antes de responder

        if len(args) < 2:
            self.sendLine(f"{tag} BAD UID FETCH requires UID and aditional data".encode())
            return

        uid_range = args[0]
        data_item_full = " ".join(args[1:]).strip()
        
        # Parseamos los UIDs
        uids = self.parse_uid_range(uid_range)
        if not uids:
            self.sendLine(f"{tag} BAD Invalid range of UID".encode())
            return

        # Procesamos la solicitud del cliente compuesta con una expresión regular
        pattern = r"^\(UID\s+RFC822\.SIZE\s+FLAGS\s+BODY\.PEEK\[HEADER\.FIELDS\s+\((?P<fields>.+)\)\]\)$"
        m = re.match(pattern, data_item_full, re.IGNORECASE)

        if m:
            fields_str = m.group("fields")
            fields = fields_str.split() 
            
            for uid in uids:
                msg = self.mailbox.get(uid)
                if not msg:
                    self.sendLine(f'* {uid} NO Message does not exist'.encode())
                    continue
                try:
                    with open(msg['path'], 'rb') as f:
                        content = f.read()

                    msg_obj = email.message_from_bytes(content, policy=policy.default)
                except Exception:
                    self.sendLine(f"{tag} NO Error reading message".encode())
                    return

                
                flags = msg.get('flags', [])
                flags_str = ' '.join(flags) if flags else []#'\\Seen'
                
                
                header_fields = []
                for field in fields:
                    header_value = msg_obj.get(field, '')
                    if header_value:  # Solo añadimos los campos que realmente existen
                        header_fields.append(f"{field}: {header_value}")
                
                
                if not header_fields:
                    self.sendLine(f"{tag} NO Requested headings not found".encode())
                    return

                headers_str = "\r\n".join(header_fields)
                
                literal = f'{{{len(headers_str.encode())}}}'
                self.sendLine(f'* {uid} FETCH (UID {uid} RFC822.SIZE {len(content)} FLAGS ({flags_str}) BODY.PEEK[HEADER.FIELDS ({", ".join(fields)})] {literal})'.encode())
                self.transport.write(headers_str.encode() + b'\r\n')
                self.sendLine(f"{tag} OK UID FETCH completed".encode())


                """body_literal = f'{{{len(content)}}}'
                self.sendLine(f'* {uid} FETCH (BODY[] {body_literal})'.encode())
                self.transport.write(content + b'\r\n')"""

            self.sendLine(f"{tag} OK UID FETCH completed".encode())
            return

        
        elif data_item_full.upper() == "(FLAGS)":
            for uid in uids:
                msg = self.mailbox.get(uid)
                if msg:
                    flags = msg.get('flags', [])
                    flags_str = ' '.join(flags) if flags else '\\Seen'
                    self.sendLine(f'* {uid} FETCH (UID {uid} FLAGS ({flags_str}))'.encode())
                else:
                    self.sendLine(f'* {uid} NO Message does not exist'.encode())
            self.sendLine(f"{tag} OK UID FETCH completed".encode())
            return

        elif data_item_full.upper() == "(BODY[])":
            for uid in uids:
                msg = self.mailbox.get(uid)
                if not msg:
                    self.sendLine(f'* {uid} NO Message does not exist'.encode())
                    continue
                try:
                    with open(msg['path'], 'rb') as f:
                        content = f.read()
                except Exception:
                    self.sendLine(f"{tag} NO Error reading message".encode())
                    return

                literal = f'{{{len(content)}}}'
                flags = msg.get('flags', [])
                flags_str = ' '.join(flags) if flags else '\\Seen'
                self.sendLine(f'* {uid} FETCH (UID {uid} FLAGS ({flags_str}) BODY[] {literal})'.encode())
                self.transport.write(content + b'\r\n')

            self.sendLine(f"{tag} OK UID FETCH completed".encode())
            return

        else:
            self.sendLine(f"{tag} BAD It only admits (FLAGS), (BODY[]) or compound request (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (...)])".encode())
            return
        
    
    def cmd_NOOP(self, tag, args):
        """
        Función para responder al comando NOOP.
        Se devuele un mensaje de éxito OK
        """
        self.sendLine((tag + " OK NOOP completed").encode())

    def cmd_CAPABILITY(self, tag, args):
        """
        Función para responder al comando CAPABILITY.
        """
        self.sendLine(b'* CAPABILITY IMAP4rev1 LITERAL+')
        self.sendLine((tag + " OK CAPABILITY completed").encode())

    def cmd_LOGIN(self, tag, args):
        """
        Función para manejar el comando LOGIN.
        Aqui se maneja el inicio de sesión de un usuario.
        
        Args:
            tag: Etiqueta del comando.
            args: Lista de argumentos.
        """
        if len(args) < 2:
            self.sendLine((tag + " BAD LOGIN requires user and password").encode())
            return

        username = args[0].strip('"')
        password = args[1].strip('"')
        
        if '@' not in username:
            self.sendLine((tag + " NO Invalida user format").encode())
            return
        user, domain = username.split('@', 1)
        user_dir = os.path.join(self.mail_storage, domain, user)

        if username not in USERS:
            self.sendLine((tag + " NO User not found").encode())
            return

        if USERS[username]["password"] != password:
            self.sendLine((tag + " NO Wrong password").encode())
            return

        print(f"[INFO] Succesful login for: {username}")

        self.username = username
        self.user_dir = user_dir
        self.state = 'AUTHENTICATED'
        self.sendLine((tag + " OK LOGIN completed").encode())

    def cmd_SELECT(self, tag, args):
        """
        Función para manejar el comando SELECT.
        
        Args:
            tag: Etiqueta del comando.
            args: Lista de argumentos.

        """
        # Solo se admite SELECT INBOX
        if self.state != 'AUTHENTICATED':
            self.sendLine((tag + " NO No authenticated").encode())
            return

        if len(args) < 1:
            self.sendLine((tag + " NO A mailbox is expected").encode())
            return

        # Eliminar comillas en torno al nombre del buzón
        mailbox_name = args[0].strip('"') 
        
        if mailbox_name.upper() != 'INBOX':
            self.sendLine((tag + " NO INBOX is only allowed").encode())
            return

        
        self.mailbox = {}
        try:
            files = os.listdir(self.user_dir)
        except Exception as e:
            self.sendLine((tag + " NO Error accediendo al buzón").encode())
            return

        # Se filtran los archivos .eml
        eml_files = [f for f in files if f.endswith('.eml')]
        eml_files.sort()  # Ordenamos (por ejemplo alfabéticamente)
        for i, filename in enumerate(eml_files, start=1):
            fullpath = os.path.join(self.user_dir, filename)
            size = os.path.getsize(fullpath)
            # Se utiliza la fecha de modificación como fecha interna (internal date)
            internal_date = time.strftime('%d-%b-%Y %H:%M:%S +0000', time.gmtime(os.path.getmtime(fullpath)))
            self.mailbox[i] = {'filename': filename,
                               'path': fullpath,
                               'size': size,
                               'flags': [],
                               'internal_date': internal_date}
        
        message_count = len(self.mailbox)
        self.state = 'SELECTED'
        
        self.sendLine((f'* {message_count} EXISTS').encode())
        self.sendLine(b'* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)')
        self.sendLine((tag + " OK [READ-WRITE] SELECT completed").encode())

    def cmd_FETCH(self, tag, args):
        """
        Función para manejar el comando FETCH.
        Se espera que se envíe un número de mensaje y la solicitud de datos.
        Por ejemplo: FETCH 1 (BODY[])

        Args:
            tag: Etiqueta del comando.
            args: Lista de argumentos.
        """

        self.load_mailbox() 

        if self.state != 'SELECTED':
            self.sendLine((tag + " NO Mailbox not selected").encode())
            return
        
        if len(args) < 2:
            self.sendLine((tag + " BAD FETCH requires number of messages and data item").encode())
            return
        
        msg_set = args[0]
        data_item = args[1]
        
        
        if data_item.upper() not in ['(BODY[])', 'BODY[]']:
            self.sendLine((tag + " BAD BODY[] only allowed").encode())
            return

        # rango de mensajes
        if msg_set == "1:*":
            uids = list(self.mailbox.keys())
        else:
            # Analizar un único número de mensaje
            try:
                msg_nums = [int(num) for num in msg_set.split(",")]
            except ValueError:
                self.sendLine((tag + " BAD Invalid message number").encode())
                return
            
            uids = []
            for num in msg_nums:
                if num in self.mailbox:
                    uids.append(num)
            
            if not uids:
                self.sendLine((tag + " NO There are no messages for the indicated numbers").encode())
                return

        # Obtener los mensajes solicitados
        for uid in uids:
            msg = self.mailbox[uid]
            try:
                with open(msg['path'], 'rb') as f:
                    content = f.read()
            except Exception as e:
                self.sendLine((tag + " NO Error reading message").encode())
                return
            
            
            literal = b'{%d+}' % (len(content),)
            self.sendLine((f'* {uid} FETCH (BODY[] {literal.decode()})').encode())
            self.transport.write(content + b'\r\n')


        self.sendLine((tag + " OK FETCH completed").encode())

        # Se elimina el mensaje del disco
        '''try:
            os.remove(msg['path'])
        except Exception as e:
            pass

        # Se elimina el mensaje del buzón en memoria
        del self.mailbox[msg_num]'''
        #self.sendLine((tag + " OK FETCH completado").encode())

    def cmd_LOGOUT(self, tag, args):
        """
        Función para manejar el comando LOGOUT.
        Se cierra la conexión con el cliente.

        Args:
            tag: Etiqueta del comando.
            args: Lista de argumentos.
        
        """
        self.sendLine(b'* BYE IMAP4rev1 Server closing session')
        self.sendLine((tag + " OK LOGOUT completed").encode())
        self.transport.loseConnection()


class IMAPFactory(protocol.Factory):
    """
    Clase para crear instancias de IMAP Server.

    Atributos:
        mail_storage: Directorio de almacenamiento de correo
    """
    def __init__(self, mail_storage):
        self.mail_storage = mail_storage

    def buildProtocol(self, addr):
        """
        Función para construir un protocolo IMAP.
        """
        return IMAPServer(self.mail_storage)


# Cargar los usuarios desde el archivo JSON
USERS_FILE = "users.json"
USERS = load_users_from_json(USERS_FILE)

if __name__ == '__main__':
    mail_storage, port = parse_arguments()

    factory = IMAPFactory(mail_storage)
    print(f"[INFO] Running IMAP server in port: {port} with storage in {mail_storage}")
    reactor.listenTCP(port, factory)
    reactor.run()

