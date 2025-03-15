import argparse
import os, sys, time, re, json
from twisted.internet import reactor, protocol, defer
from twisted.mail import imap4
from zope.interface import implementer

from twisted.protocols.basic import LineReceiver


import email
from email import policy

# Función para parsear los argumentos
def parse_arguments():
    parser = argparse.ArgumentParser(description="IMAP Server")
    parser.add_argument("-s", "--mail-storage", required=True, help="Directory to store emails")
    parser.add_argument("-p", "--port", type=int, required=True, default=143, help="Port to listen on")

    args = parser.parse_args()

    return args.mail_storage, args.port


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
    
# Carga los usuarios al iniciar el servidor
USERS_FILE = "users.json"
USERS = load_users_from_json(USERS_FILE)


class IMAPServer(LineReceiver):
    """
    Implementación básica de un servidor IMAP.
    Se soportan los comandos:
      - CAPABILITY: Responde con la lista de capacidades.
      - LOGIN: Autentica al usuario (se espera un formato usuario@dominio).
      - SELECT: Sólo se admite INBOX, se listan todos los .eml del directorio del usuario.
      - FETCH: Soporta obtener el cuerpo del mensaje (BODY[]) de un mensaje individual.
               Una vez enviado el mensaje se elimina el archivo.
      - LOGOUT: Cierra la conexión.
    """
    delimiter = b'\r\n'

    def __init__(self, mail_storage):
        self.mail_storage = mail_storage
        self.state = 'NOT_AUTHENTICATED'
        self.username = None
        self.user_dir = None
        self.mailbox = None  # Diccionario: clave = número de mensaje, valor = info (path, size, etc.)

    def connectionMade(self):
        print("[INFO] Nueva conexión establecida desde:", self.transport.getPeer())
        self.sendLine(b'* OK IMAP4rev1 Service Ready')


    def load_mailbox(self):
        """Recarga la lista de correos desde el disco para incluir nuevos mensajes."""
        if not self.user_dir:
            return

        self.mailbox = {}  # Resetear el diccionario
        try:
            files = os.listdir(self.user_dir)
        except Exception as e:
            print(f"[ERROR] No se pudo acceder al buzón: {e}")
            return

        eml_files = [f for f in files if f.endswith('.eml')]
        eml_files.sort()
        
        for i, filename in enumerate(eml_files, start=1):
            fullpath = os.path.join(self.user_dir, filename)
            size = os.path.getsize(fullpath)
            internal_date = time.strftime('%d-%b-%Y %H:%M:%S +0000', time.gmtime(os.path.getmtime(fullpath)))
            
            self.mailbox[i] = {
                'filename': filename,
                'path': fullpath,
                'size': size,
                'flags': [],
                'internal_date': internal_date
            }


    def lineReceived(self, line):
        print(f"[DEBUG] Comando recibido: {line}")
        try:
            line = line.decode('utf-8')
        except UnicodeDecodeError:
            self.sendLine(b'* BAD Encoding invalido')
            return

        # Se espera que la línea tenga el formato: <tag> <COMANDO> [argumentos...]
        parts = line.split()
        if not parts:
            return
        tag = parts[0]
        if len(parts) < 2:
            self.sendLine((tag + " BAD Faltan comando").encode())
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
                self.sendLine((tag + " BAD Comando UID inválido").encode())
            else:
                self.cmd_UID_FETCH(tag, args[1:])  # Llamamos a UID FETCH
        elif command == 'LOGOUT':
            self.cmd_LOGOUT(tag, args)
        elif command == 'NOOP':
            self.cmd_NOOP(tag, args)  # Manejo del comando NOOP
        else:
            print(f"[DEBUG] Comando recibido: {command}")

            self.sendLine((tag + " BAD Comando desconocido" + command).encode())


    def parse_uid_range(self, uid_range):
        """
        Parseamos el rango de UIDs y lo convertimos a una lista de UIDs.
        Si el rango tiene el formato "1:*" o "*", se considera como todos los UIDs.
        Si es un rango como "1:5" o "5:1", se lo invierte y genera el rango adecuado.
        Ejemplo:
            "1:5" -> [1, 2, 3, 4, 5]
            "5:1" -> [1, 2, 3, 4, 5] (invertido)
            "*": Considera todos los UIDs disponibles.
        """
        uids = []
        
        # Caso con * (todos los UIDs)
        if '*' in uid_range:
            if uid_range == "*":
                # Si el rango es solo *, devolvemos todos los UIDs posibles
                return list(self.mailbox.keys())
            else:
                # Si es algo como "1:*", lo convertimos en un rango "1:último UID"
                parts = uid_range.split(':')
                if len(parts) == 2 and parts[1] == "*":
                    start = int(parts[0])
                    end = len(self.mailbox)  # Usamos el último UID
                    uids = list(range(start, end + 1))
        
        # Caso con rango específico "start:end"
        elif ':' in uid_range:
            start, end = uid_range.split(':')
            start = int(start)
            end = int(end)
            
            # Aseguramos que el rango esté ordenado correctamente (menor a mayor)
            if start > end:
                start, end = end, start  # Invertimos el rango si está en orden incorrecto
                
            uids = list(range(start, end + 1))  # Creamos el rango de UIDs
        
        # Caso de un solo UID
        else:
            try:
                uids = [int(uid_range)]
            except ValueError:
                return None

        return uids



    def cmd_UID_FETCH(self, tag, args):
        """
        Manejamos el comando UID FETCH. Se espera que se envíe un rango de UID y una solicitud compuesta,
        por ejemplo:
        UID FETCH 1:3 (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date Message-ID Priority X-Priority References Newsgroups In-Reply-To Content-Type Reply-To)])
        """
        self.load_mailbox()  # Actualizar antes de responder

        if len(args) < 2:
            self.sendLine(f"{tag} BAD UID FETCH requiere UID y datos adicionales".encode())
            return

        uid_range = args[0]
        data_item_full = " ".join(args[1:]).strip()
        print(f"Comando recibido: {uid_range}")
        print(f"Parámetros completos: {data_item_full}")
        
        # Parseamos los UIDs (rango o comodín "*")
        uids = self.parse_uid_range(uid_range)
        if not uids:
            self.sendLine(f"{tag} BAD Rango de UID inválido".encode())
            return

        # Procesamos la solicitud compuesta con una expresión regular
        pattern = r"^\(UID\s+RFC822\.SIZE\s+FLAGS\s+BODY\.PEEK\[HEADER\.FIELDS\s+\((?P<fields>.+)\)\]\)$"
        m = re.match(pattern, data_item_full, re.IGNORECASE)

        if m:
            fields_str = m.group("fields")
            fields = fields_str.split()  # Dividir los campos solicitados
            
            # Preparamos la respuesta para cada UID
            for uid in uids:
                msg = self.mailbox.get(uid)
                if not msg:
                    self.sendLine(f'* {uid} NO No existe el mensaje'.encode())
                    continue

                try:
                    with open(msg['path'], 'rb') as f:
                        content = f.read()

                    msg_obj = email.message_from_bytes(content, policy=policy.default)
                except Exception:
                    self.sendLine(f"{tag} NO Error leyendo el mensaje".encode())
                    return

                # Obtenemos las flags
                flags = msg.get('flags', [])
                flags_str = ' '.join(flags) if flags else '\\Seen'
                
                # Preparamos los encabezados solicitados
                header_fields = []
                for field in fields:
                    header_value = msg_obj.get(field, '')
                    if header_value:  # Solo añadimos los campos que realmente existen
                        header_fields.append(f"{field}: {header_value}")
                
                # Si no hay encabezados solicitados, enviamos un campo vacío
                if not header_fields:
                    self.sendLine(f"{tag} NO No se encontraron los encabezados solicitados".encode())
                    return

                # Unimos todos los encabezados
                headers_str = "\r\n".join(header_fields)
                
                # Enviamos el literal de los encabezados
                literal = f'{{{len(headers_str.encode())}}}'
                self.sendLine(f'* {uid} FETCH (UID {uid} RFC822.SIZE {len(content)} FLAGS ({flags_str}) BODY.PEEK[HEADER.FIELDS ({", ".join(fields)})] {literal})'.encode())
                self.transport.write(headers_str.encode() + b'\r\n')
                self.sendLine(f"{tag} OK UID FETCH completado".encode())

                print("[DEBUG] Enviando encabezados:", headers_str)

                # Enviamos el cuerpo completo (BODY[])
                body_literal = f'{{{len(content)}}}'
                self.sendLine(f'* {uid} FETCH (BODY[] {body_literal})'.encode())
                self.transport.write(content + b'\r\n')

            self.sendLine(f"{tag} OK UID FETCH completado".encode())
            return

        # Si la solicitud no es la compuesta, se manejan otros casos (FLAGS, BODY[])
        elif data_item_full.upper() == "(FLAGS)":
            for uid in uids:
                msg = self.mailbox.get(uid)
                if msg:
                    flags = msg.get('flags', [])
                    flags_str = ' '.join(flags) if flags else '\\Seen'
                    self.sendLine(f'* {uid} FETCH (UID {uid} FLAGS ({flags_str}))'.encode())
                else:
                    self.sendLine(f'* {uid} NO No existe el mensaje'.encode())
            self.sendLine(f"{tag} OK UID FETCH completado".encode())
            return

        elif data_item_full.upper() == "(BODY[])":
            for uid in uids:
                msg = self.mailbox.get(uid)
                if not msg:
                    self.sendLine(f'* {uid} NO No existe el mensaje'.encode())
                    continue

                try:
                    with open(msg['path'], 'rb') as f:
                        content = f.read()
                except Exception:
                    self.sendLine(f"{tag} NO Error leyendo el mensaje".encode())
                    return

                literal = f'{{{len(content)}}}'
                flags = msg.get('flags', [])
                flags_str = ' '.join(flags) if flags else '\\Seen'
                self.sendLine(f'* {uid} FETCH (UID {uid} FLAGS ({flags_str}) BODY[] {literal})'.encode())
                self.transport.write(content + b'\r\n')

            self.sendLine(f"{tag} OK UID FETCH completado".encode())
            return

        else:
            self.sendLine(f"{tag} BAD Solo se admite (FLAGS), (BODY[]) o la solicitud compuesta (UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (...)])".encode())
            return
        
    
    def cmd_NOOP(self, tag, args):
        # El comando NOOP no hace nada, simplemente respondemos con OK
        self.sendLine((tag + " OK NOOP completado").encode())

    def cmd_CAPABILITY(self, tag, args):
        # Respuesta a la capacidad. Se podría ampliar si se desean otras extensiones.
        self.sendLine(b'* CAPABILITY IMAP4rev1 LITERAL+')
        self.sendLine((tag + " OK CAPABILITY completado").encode())

    def cmd_LOGIN(self, tag, args):
        # Se esperan dos argumentos: username y password.
        if len(args) < 2:
            self.sendLine((tag + " BAD LOGIN requiere usuario y contraseña").encode())
            return

        username = args[0].strip('"')
        password = args[1].strip('"')
        # Para este ejemplo se acepta cualquier contraseña si el directorio existe.
        if '@' not in username:
            self.sendLine((tag + " NO Formato de usuario inválido").encode())
            print(f"[DEBUG] no tiene arroba: {username} y contraseña: {password}")
            return
        user, domain = username.split('@', 1)
        user_dir = os.path.join(self.mail_storage, domain, user)
        if not os.path.isdir(user_dir):
            self.sendLine((tag + " NO Usuario no tiene directorio").encode())
            return
        print(f"[DEBUG] Intentando login con usuario: {username}")

        if username not in USERS:
            self.sendLine((tag + " NO Usuario no encontrado").encode())
            return

        if USERS[username]["password"] != password:
            self.sendLine((tag + " NO Contraseña incorrecta").encode())
            return

        print(f"[INFO] Login exitoso para {username}")

        self.username = username
        self.user_dir = user_dir
        self.state = 'AUTHENTICATED'
        self.sendLine((tag + " OK LOGIN completado").encode())

    def cmd_SELECT(self, tag, args):
        # Solo se admite SELECT INBOX
        if self.state != 'AUTHENTICATED':
            self.sendLine((tag + " NO No autenticado").encode())
            return

        if len(args) < 1:
            self.sendLine((tag + " NO Se espera un buzón").encode())
            return

        # Eliminar comillas en torno al nombre del buzón (si existen)
        mailbox_name = args[0].strip('"')  # Esto elimina las comillas alrededor de "INBOX"
        
        if mailbox_name.upper() != 'INBOX':
            self.sendLine((tag + " NO Solo se admite INBOX").encode())
            return

        # Se carga la lista de mensajes (archivos .eml) del directorio del usuario
        print(f"[INFO] Login exitoso para {self.user_dir}")

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
        # Se envían respuestas untagged según el protocolo IMAP
        self.sendLine((f'* {message_count} EXISTS').encode())
        self.sendLine(b'* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)')
        self.sendLine((tag + " OK [READ-WRITE] SELECT completado").encode())

    def cmd_FETCH(self, tag, args):

        self.load_mailbox()  # Actualizar antes de responder

        # Se espera el formato: FETCH <num_msg> (BODY[])
        if self.state != 'SELECTED':
            self.sendLine((tag + " NO Buzón no seleccionado").encode())
            return
        
        if len(args) < 2:
            self.sendLine((tag + " BAD FETCH requiere número de mensaje y data item").encode())
            return
        
        msg_set = args[0]
        data_item = args[1]
        
        # Verificar que solo se está solicitando BODY[]
        if data_item.upper() not in ['(BODY[])', 'BODY[]']:
            self.sendLine((tag + " BAD Solo se admite BODY[]").encode())
            return

        # Si el comando FETCH tiene un rango de mensajes, procesamos el rango
        if msg_set == "1:*":
            # Devolvemos todos los mensajes del buzón
            uids = list(self.mailbox.keys())
            print("[DEBUG] Enviando todos los mensajes")
        else:
            # Analizar un único número de mensaje
            try:
                msg_nums = [int(num) for num in msg_set.split(",")]
            except ValueError:
                self.sendLine((tag + " BAD Número de mensaje inválido").encode())
                return
            
            uids = []
            for num in msg_nums:
                if num in self.mailbox:
                    uids.append(num)
            
            if not uids:
                self.sendLine((tag + " NO No existen mensajes para los números indicados").encode())
                return

        # Obtener los mensajes solicitados
        for uid in uids:
            msg = self.mailbox[uid]
            try:
                with open(msg['path'], 'rb') as f:
                    content = f.read()
            except Exception as e:
                self.sendLine((tag + " NO Error leyendo el mensaje").encode())
                return
            print("[DEBUG] Enviando mensaje:", msg['filename'])
            # Se indica el literal (la cantidad de bytes)
            literal = b'{%d+}' % (len(content),)
            # Respuesta FETCH untagged (para simplificar, se envía en una sola respuesta)
            self.sendLine((f'* {uid} FETCH (BODY[] {literal.decode()})').encode())
            # Enviamos el literal (contenido) y terminamos con CRLF
            self.transport.write(content + b'\r\n')

        # Finalizamos la respuesta del comando FETCH
        self.sendLine((tag + " OK FETCH completado").encode())

        # Se elimina el mensaje del disco (cumpliendo que se borre al descargarse)
        '''try:
            os.remove(msg['path'])
        except Exception as e:
            pass

        # Se elimina el mensaje del buzón en memoria
        del self.mailbox[msg_num]'''
        #self.sendLine((tag + " OK FETCH completado").encode())

    def cmd_LOGOUT(self, tag, args):
        self.sendLine(b'* BYE IMAP4rev1 Server cerrando sesion')
        self.sendLine((tag + " OK LOGOUT completado").encode())
        self.transport.loseConnection()


class IMAPFactory(protocol.Factory):
    def __init__(self, mail_storage):
        self.mail_storage = mail_storage

    def buildProtocol(self, addr):
        return IMAPServer(self.mail_storage)


def main():
    
    mail_storage, port = parse_arguments()

    factory = IMAPFactory(mail_storage)
    print(f"[INFO] Running IMAP server in port: {port} with storage in {mail_storage}")
    reactor.listenTCP(port, factory)
    reactor.run()


if __name__ == '__main__':
    main()






'''@implementer(imap4.IAccount)
class IMAPUserAccount:
    """ Clase que representa la cuenta de un usuario IMAP """
    def __init__(self, user_dir):
        self.user_dir = user_dir
        self.mailbox = IMAPMailbox(user_dir)

    def listMailboxes(self, request, reference):
        """ Retorna un solo mailbox llamado INBOX """
        return defer.succeed([("INBOX", self.mailbox)])

    def select(self, path, rw=True):
        """ Retorna el mailbox de INBOX si el cliente lo selecciona """
        if path.upper() == "INBOX":
            return defer.succeed(self.mailbox)
        return defer.fail(imap4.MailboxException("No such mailbox"))

    def logout(self):
        """ Método que se llama cuando el usuario cierra sesión """
        pass  # No es necesario hacer nada especial aquí


class IMAPMessage:
    def __init__(self, content):
        self.content = content
        self.flags = []  # Puedes agregar flags como \Seen, \Deleted, etc.

    def getFlags(self):
        return self.flags

    def getInternalDate(self):
        return "01-Jan-2024 12:00:00 +0000"  # Ajusta con la fecha real del correo

    def getSize(self):
        return len(self.content)

    def getBodyFile(self):
        from io import BytesIO
        return BytesIO(self.content)

    def getHeaders(self, negate):
        """
        Devuelve los encabezados del correo.
        :param negate: Si es True, devuelve solo las cabeceras especificadas en una lista.
        """
        headers = {}
        try:
            from email import message_from_bytes
            email_obj = message_from_bytes(self.content)
            for key, value in email_obj.items():
                headers[key] = value
        except Exception as e:
            print(f"Error parsing headers: {e}")
        return headers

@implementer(imap4.IMailbox)
class IMAPMailbox(object):
    def __init__(self, user_dir):
        self.user_dir = user_dir
        self.messages = self.load_messages()
        self.listeners = []

    def load_messages(self):
        # Cargar los correos con extensión .eml en el directorio del usuario
        emails = []
        for filename in os.listdir(self.user_dir):
            if filename.endswith(".eml"):
                emails.append(filename)
        return emails

    def listMessages(self, index=None):
        # Ignoramos el índice para esta implementación básica.
        return defer.succeed(self.messages)

    def getMessage(self, index):
        # Retorna el contenido de un correo específico.
        try:
            filename = self.messages[index]
            with open(os.path.join(self.user_dir, filename), "r", encoding="utf-8") as f:
                content = f.read().encode("utf-8")
            return defer.succeed(content)
        except IndexError:
            return defer.fail(imap4.MailboxException("Invalid message index"))

    def deleteMessages(self, indices):
        # Elimina los correos indicados por sus índices (en orden descendente)
        for index in sorted(indices, reverse=True):
            try:
                filename = self.messages[index]
                os.remove(os.path.join(self.user_dir, filename))
                del self.messages[index]
            except IndexError:
                continue
        return defer.succeed(None)

    def getFlags(self):
        """ Retorna una lista vacía de flags, ya que no estamos manejando flags """
        return []

    def getMessageCount(self):
        return len(self.messages)

    def getRecentCount(self):
        # Para esta implementación básica, siempre devolvemos 0       
        return 0

    def getUnseenCount(self):
        # Para esta implementación básica, siempre devolvemos 0
        return 0

    def requestStatus(self, names):
        """ Retorna el estado del buzón """
        status = {}
        if b'MESSAGES' in names:
            status[b'MESSAGES'] = len(self.messages)
        if b'RECENT' in names:
            status[b'RECENT'] = 0
        if b'UNSEEN' in names:
            status[b'UNSEEN'] = 0
        return defer.succeed(status)

    def getHierarchicalDelimiter(self):
        """ Retorna el delimitador de jerarquía de carpetas ('/') para compatibilidad con clientes IMAP """
        return "/"

    def expunge(self):
        # Para esta implementación básica, devolvemos una lista vacía
        return defer.succeed([])

    def getUIDValidity(self):
        # Retornamos un valor constante, por ejemplo 1
        return 1

    def isWriteable(self):
        return True 

    def addListener(self, listener):
        """Registra un listener para notificar cambios en la bandeja."""
        self.listeners.append(listener)
    
    def fetch(self, messages, uid):
        # Convertimos la función en un generador
        for index in messages:
            try:
                # Los índices IMAP inician en 1; las listas Python en 0.
                filename = self.messages[index - 1]
                with open(os.path.join(self.user_dir, filename), "r", encoding="utf-8") as f:
                    content = f.read().encode("utf-8")
                # Enviar un mensaje por vez, como un generador
                yield (index, IMAPMessage(content))
            except IndexError:
                continue


class IMAPServerProtocol(imap4.IMAP4Server):
    def __init__(self, mail_storage):
        super().__init__()
        self.mail_storage = mail_storage

    def authenticateLogin(self, username, password):
        username = username.decode("utf-8")
        password = password.decode("utf-8")

        if username in USERS and USERS[username] == password:
            # Extraer usuario y dominio
            if "@" not in username:
                return defer.fail(imap4.error.LoginDenied("Invalid email format"))

            user, domain = username.split("@")
            user_dir = os.path.join(mail_storage, domain, user)

            if not os.path.exists(user_dir):
                return defer.fail(imap4.error.LoginDenied("Mailbox not found"))

            account = IMAPUserAccount(user_dir)
            return defer.succeed((imap4.IAccount, account, account.logout))
        
        return defer.fail(imap4.error.LoginDenied("Invalid credentials"))


class IMAPServerFactory(protocol.Factory):
    def __init__(self, mail_storage):
        self.mail_storage = mail_storage

    def buildProtocol(self, addr):
        return IMAPServerProtocol(self.mail_storage)
    


if __name__ == '__main__':
    mail_storage, port = parse_arguments()
    print(f"[INFO] Running IMAP server in port: {port} with storage in {mail_storage}")
    reactor.listenTCP(port, IMAPServerFactory(mail_storage))
    reactor.run()'''

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