import argparse
from twisted.mail import smtp
from twisted.internet import defer, reactor
import os


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

def validate_email_sender(helo, origin, allowed_domains):
    domain = origin.domain.decode()

    if domain in allowed_domains:
        print(f"Email allowed from: {origin}")
        return origin
    else:
        print(f"Email denied: {origin} does not belong to allowed domains")
        raise smtp.SMTPBadSender(f"Email not allowed from {origin}")


def save_email(mail_storage, mailfrom, rcptto, message):
    try:
        os.makedirs(mail_storage, exist_ok=True)  # Asegurar que la carpeta existe
        
        # Tomar solo el primer destinatario para nombrar el archivo
        destinatario = rcptto[0].decode()
        filepath = os.path.join(mail_storage, f"{destinatario}.txt")

        # Guardar el correo en el archivo
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(f"De: {mailfrom}\n")
            f.write(f"Para: {destinatario}\n\n")
            f.write(message.decode())
            f.write("\n" + "-" * 40 + "\n")  # Separador entre correos

        print(f"Correo guardado en {filepath}")
        return defer.succeed(None)  # Retorna una promesa de éxito

    except Exception as e:
        print(f"Error guardando correo: {e}")
        return defer.fail(e)  # Retorna un error para que Twisted lo maneje

def validate_email_recipient(user):
    """Función para validar y gestionar el almacenamiento de correos para destinatarios"""
    return lambda: save_email(user.dest)


def smtp_protocol_factory(allowed_domains, mail_storage):
    protocol = smtp.SMTP()

    protocol.validateFrom = lambda helo, origin: validate_email_sender(helo, origin, allowed_domains)

    protocol.validateTo = lambda user: validate_email_recipient(user)



    return protocol


def start_smtp_server(allowed_domains, mail_storage, port):
    """Iniciar el servidor SMTP"""
    print(f"Iniciando servidor SMTP en el puerto {port}...")
    reactor.listenTCP(port, smtp.SMTPFactory(lambda: smtp_protocol_factory(allowed_domains, mail_storage)))  # Iniciar el servidor
    reactor.run()  # Mantener el servidor corriendo

if __name__ == "__main__":
    domains, storage, port = parse_arguments()
    print(f"Dominios permitidos: {domains}")
    print(f"Almacenamiento de correos: {storage}")
    print(f"Puerto: {port}")

    start_smtp_server(domains, storage, port)