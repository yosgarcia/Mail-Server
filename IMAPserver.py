import argparse
import os, sys, time
from twisted.internet import reactor, protocol, defer
from twisted.mail import imap4
from zope.interface import implementer

from twisted.protocols.basic import LineReceiver


# Función para parsear los argumentos
def parse_arguments():
    parser = argparse.ArgumentParser(description="IMAP Server")
    parser.add_argument("-s", "--mail-storage", required=True, help="Directory to store emails")
    parser.add_argument("-p", "--port", type=int, required=True, default=143, help="Port to listen on")

    args = parser.parse_args()

    return args.mail_storage, args.port

USERS = {
    "ianparedes@santa.com": "password123",
    "leochacon@northpole.com" : "1234"
}

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
        Analiza el rango de UIDs y devuelve una lista de UIDs válidos.
        Soporta rangos como '1:*' (todos los UIDs) o '1,2,3' (UIDs específicos).
        """
        uids = []
        if uid_range == '1:*':
            uids = list(self.mailbox.keys())  # Devolvemos todos los UIDs
        else:
            # Analizamos un rango específico
            try:
                for part in uid_range.split(','):
                    uid = int(part)
                    if uid in self.mailbox:
                        uids.append(uid)
            except ValueError:
                return []  # Si no podemos analizar el rango, devolvemos una lista vacía

        return uids



    def cmd_UID_FETCH(self, tag, args):
        """
        Manejamos el comando UID FETCH.
        Esperamos un rango de UID y el parámetro (FLAGS o BODY[]).
        Ejemplo: UID FETCH 1:* (FLAGS)
                UID FETCH 1:* (BODY[])
        """
        # Verificamos que el comando esté bien formado
        if len(args) < 2:
            self.sendLine((tag + " BAD UID FETCH requiere UID y datos adicionales").encode())
            return
        print("HOLLLSAA" + args[0])
        print("HOLLLSAA" + args[1])
        uid_range = args[0]
        data_item = args[1].upper()

        # Parseamos los UIDs, pueden ser un rango como "1:*" o una lista de UIDs específicos
        uids = self.parse_uid_range(uid_range)  # Parseamos el rango de UIDs

        if not uids:
            self.sendLine((tag + " BAD Rango de UID inválido").encode())
            return

        if data_item == "(FLAGS)":  # Solo devuelve las flags
            # Respondemos con las banderas para cada UID
            for uid in uids:
                if uid in self.mailbox:
                    flags = self.mailbox[uid].get('flags', [])
                    flags_str = ' '.join(flags) if flags else '\\Seen'  # Por ejemplo, solo \\Seen si no hay banderas
                    self.sendLine(f'* {uid} FETCH (FLAGS ({flags_str}))'.encode())
                else:
                    self.sendLine(f'* {uid} NO No existe el mensaje').encode()

        #elif data_item == "(BODY[])":  # Devuelve el cuerpo del mensaje
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

        else:
            self.sendLine((tag + " BAD Solo se admite (FLAGS) o (BODY[])").encode())

        # Finalizamos la respuesta del comando UID FETCH
        self.sendLine((tag + " OK UID FETCH completado").encode())


    def cmd_NOOP(self, tag, args):
        # El comando NOOP no hace nada, simplemente respondemos con OK
        self.sendLine((tag + " OK NOOP completado").encode())

    def cmd_CAPABILITY(self, tag, args):
        # Respuesta a la capacidad. Se podría ampliar si se desean otras extensiones.
        self.sendLine(b'* CAPABILITY IMAP4rev1')
        self.sendLine((tag + " OK CAPABILITY completado").encode())

    def cmd_LOGIN(self, tag, args):
        # Se esperan dos argumentos: username y password.
        if len(args) < 2:
            self.sendLine((tag + " BAD LOGIN requiere usuario y contraseña").encode())
            return

        username = args[0].strip('"')
        password = args[1].strip('"')
        print(f"[DEBUG] Intentando login con usuario: {username} y contraseña: {password}")

        # Para este ejemplo se acepta cualquier contraseña si el directorio existe.
        if '@' not in username:
            self.sendLine((tag + " NO Formato de usuario inválido").encode())
            print(f"[DEBUG] no tiene arroba: {username} y contraseña: {password}")

            return
        user, domain = username.split('@', 1)
        user_dir = os.path.join(self.mail_storage, domain, user)
        print(f"[DEBUG] user_dir: {user_dir}")
        if not os.path.isdir(user_dir):
            self.sendLine((tag + " NO Usuario no encontrado").encode())
            return


        # Validación de usuario y contraseña
        if username not in USERS:
            self.sendLine((tag + " NO Usuario no encontrado").encode())
            print(f"[DEBUG] usuario not in users: {username} y contraseña: {password}")

            return
        
        if USERS[username] != password:
            self.sendLine((tag + " NO Contraseña incorrecta").encode())
            print(f"[DEBUG] contraseña erronea: {username} y contraseña: {password}")

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
        # Se espera el formato: FETCH <num_msg> (BODY[])
        if self.state != 'SELECTED':
            self.sendLine((tag + " NO Buzón no seleccionado").encode())
            return
        
        if len(args) < 2:
            self.sendLine((tag + " BAD FETCH requiere número de mensaje y data item").encode())
            return
        print("AQUIIIIIIII")
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