import argparse, os, time, json
from twisted.mail import smtp
from twisted.internet import defer, reactor
from twisted.internet.defer import Deferred
from twisted.internet import ssl
from zope.interface import implementer



def parse_arguments():
    """
    Función encargada para leer los argumentos de la línea de comandos.

    Returns:
        allowed_domains (list): Lista de dominios permitidos.
        mail_storage (str): Directorio de almacenamiento.
        port (int): Puerto a escuchar.
    
    """
    parser = argparse.ArgumentParser(description="SMTP Server")
    parser.add_argument("-d", "--domains", required=True, help="List of allowed domains separated by commas")
    parser.add_argument("-s", "--mail-storage", required=True, help="Directory to store emails")
    parser.add_argument("-p", "--port", type=int, required=True, default=25, help="Port to listen on")
    
    args = parser.parse_args()

    allowed_domains = args.domains.split(",")

    return allowed_domains, args.mail_storage, args.port




@implementer(smtp.IMessage)
class FileMessage:
    """
    Clase encargada de recibir y guardar los mensaje de correo que lleguen al servidor SMTP.

    Atributos:
        recipient (str): Dirección de correo del destinatario.
        mail_storage (str): Directorio de almacenamiento para los correos.
        lines (list): Lista de líneas del mensaje.
    """

    def __init__(self, recipient, mail_storage):
        self.recipient = recipient
        self.mail_storage = mail_storage
        self.lines = []

    def lineReceived(self, line):
        """
        Método para recibir una línea del mensaje y definir si necesita ser decodificada.
        
        Args:
            line (bytes/str): Línea del mensaje a evaluar.
        """
        # En caso de que sea bytes
        if isinstance(line, bytes):
            self.lines.append(line.decode('utf-8'))  
        else:
            self.lines.append(line) 


    def eomReceived(self):
        """
        Método para crear el archivo .eml unas vez recibidad todas las líneas del mensaje.
        
        Returns:
            defer.succeed(None): Promesa de que el archivo fue creado exitosamente.
        
        """
        recipient_user, recipient_domain = self.recipient.split('@')
        recipient_dir = os.path.join(self.mail_storage, recipient_domain, recipient_user)
        os.makedirs(recipient_dir, exist_ok=True) # Se crea el directorio en caso de que no exista

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        base_filename = f"mail_{timestamp}"
        email_filename = f"{base_filename}.eml" # Se guarda el archivo con extensión .eml
        email_file_path = os.path.join(recipient_dir, email_filename)

        # Juntar todas las líneas del mensaje en un solo string
        full_message = "\n".join(self.lines)

        
        with open(email_file_path, 'w', encoding="utf-8") as f:
            f.write(full_message)
        print(f"Mail saved in: {email_file_path}")

        
        return defer.succeed(None)


    def connectionLost(self):
        self.lines = None



@implementer(smtp.IMessageDelivery)
class FileMessageDelivery:
    """
    Clase encargada de validar los destinatarios y remitentes de cada correo.

    Atributos:
        allowed_domains (list): Lista de dominios permitidos por el servidor.
        mail_storage (str): Directorio de almacenamiento para almacenar los correos.

    """
    def __init__(self, allowed_domains, mail_storage):
        self.allowed_domains = allowed_domains
        self.mail_storage = mail_storage
    
    def receivedHeader(self, helo, origin, recipients):
        """
        Método para crear el encabezado del correo

        Args:
            helo (str): Nombre del servidor de origen.
            origin (str): Dirección de correo del remitente.
            recipients (list): Lista de destinatarios.

        Returns:
            str: Encabezado del correo
        """
        return f"" # No se agrega el encabezado ya que el mensaje ya viene con el encabezado
    
    def validateFrom(self, helo, origin):
        """
        Método para validar el remitente del correo.
        
        Args:
            helo (str): Nombre del servidor de origen.
            origin (str): Dirección de correo del remitente.
        
        Returns:
            str: Dirección de correo del remitente.
        """
        # En este caso no hay ninguna restricción de remitente
        return origin 
    

    def validateTo(self, user):
        """
        Método para validar el destinatario del correo.

        Args:
            user: Dirección de correo del destinatario.
        
        Returns:
            FileMessage: Objeto FileMessage para recibir el mensaje.
        """
        recipient_domain = user.dest.domain.decode("utf-8") 
        if recipient_domain in self.allowed_domains:
            # Se verifica si el dominio el destinatario debe ser aceptado por el servidor
            return lambda: FileMessage(user.dest.local.decode("utf-8") + '@' + recipient_domain, self.mail_storage)
        raise smtp.SMTPBadRcpt(user) # Se rechaza el correo indicando que el destinatario no es válido



class FileSMTPFactory(smtp.SMTPFactory):
    """
    Clase para crear el servidor SMTP y generar el protocolo.

    Atributos:
        delivery: Objeto FileMessageDelivery encargado de validar los destinatarios y remitentes.
    """
    def __init__(self, allowed_domains, mail_storage):
        self.delivery = FileMessageDelivery(allowed_domains, mail_storage)

    def buildProtocol(self, addr):
        """
        Método para construir el protocolo del servidor SMTP.

        Args:
            addr: Dirección del cliente.

        Returns:
            protocol: Protocolo del servidor SMTP.
        """
        protocol = smtp.SMTPFactory.buildProtocol(self, addr)
        protocol.delivery = self.delivery
        return protocol



if __name__ == "__main__":
    domains, storage, port = parse_arguments()
    print(f"Allowed domains: {domains}")
    print(f"Mail storage: {storage}")
    print(f"Port: {port}")
    
    reactor.listenTCP(port, FileSMTPFactory(domains, storage))
    reactor.run()


