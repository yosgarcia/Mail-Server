import csv
import sys
import re
from twisted.mail.smtp import sendmail
from twisted.internet import reactor, defer
from email.mime.text import MIMEText

from twisted.python.failure import Failure

def is_valid_email(email):
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None


def read_csv(file_path):
    mail_data = []

    try:
        with open(file_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            if reader.fieldnames is None:
                raise ValueError("File is empty or is not a valid CSV file")
            
            for row in reader:
                if "name" not in row or "sender_email" not in row or "recipient_email" not in row:
                    raise ValueError("CSV must contain columns: name, sender_email, recipient_email.")
                if not is_valid_email(row["sender_email"]) or not is_valid_email(row["recipient_email"]):
                    print(f"Wrong email detected: {row} - It will be omitted.")
                    continue  # Omitir correos inválidos
                mail_data.append(row)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error in csv: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading csv: {e}")
        sys.exit(1)

    return mail_data


def handle_send_error(err, recipient):
    if isinstance(err, Failure):
        print(f"Error sendind email to {recipient}: {err.getErrorMessage()}")
    else:
        print(f"Error with email {recipient}: {err}")


def send_mail(smtp_host, smtp_port, sender, recipient, message):
    # Mensaje en fromato MIME
    msg = MIMEText(message, "plain", "utf-8")
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = "Correo de prueba con Twisted"

    # Convertir a bytes para SMTP
    msg_data = msg.as_string()

    # Enviar correo
    d = sendmail(
        smtp_host,
        sender,
        recipient,
        msg_data.encode("utf-8"),
        port=smtp_port,
        requireAuthentication=False,
        requireTransportSecurity=False  # Cambiar a True si se usa TLS
    )
    
    # Manejar la respuesta
    d.addCallbacks(lambda _: print(f"Mail sent to {recipient}!"), lambda err: handle_send_error(err, recipient))
    

    return d



def change_message(mail_data, name, sender_email, recipient_email):
    changed_data = mail_data.replace("{name}", name)
    changed_data = changed_data.replace("{sender_email}", sender_email)
    changed_data = changed_data.replace("{recipient_email}", recipient_email)
    return changed_data


def read_message(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1) 
    except Exception as e:
        print(f"Error reading message file: {e}")
        sys.exit(1) 





def main():
    """
    Función principal que procesa los parámetros y envía correos.
    """
    if len(sys.argv) != 7 or sys.argv[1] != "-h" or sys.argv[3] != "-c" or sys.argv[5] != "-m":
        print("Use: python smtpclient.py -h <mail-server> -c <csv-file> -m <message-file>")
        sys.exit(1)

    smtp_host = sys.argv[2]
    csv_file = sys.argv[4]
    message_file = sys.argv[6]
    smtp_port = 2525  # Cambia esto si tu servidor usa otro puerto

    contactos = read_csv(csv_file)
    mensaje_template = read_message(message_file)

    if not contactos:
        print("There are not valid emails on CSV file. Stopping program...")
        sys.exit(1)

    deferreds = []
    for contacto in contactos:
        mensaje_personalizado = change_message(mensaje_template, contacto["name"], contacto["sender_email"], contacto["recipient_email"])
        d = send_mail(smtp_host, smtp_port, contacto["sender_email"], contacto["recipient_email"], mensaje_personalizado)
        deferreds.append(d)

    defer.DeferredList(deferreds).addCallback(lambda _: reactor.stop())
    reactor.run()





if __name__ == '__main__':
    main()
