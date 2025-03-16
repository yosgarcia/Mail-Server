import csv
import sys
import re
import argparse
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, scrolledtext
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from twisted.mail.smtp import sendmail
from twisted.internet import reactor, defer
from email.mime.text import MIMEText

from twisted.python.failure import Failure




def is_valid_email(email):
    """
    Función para validar el formato de un correo electrónico
    siga la estructura de los correos.

    Args:
        email (str): Correo a verificar.
    
    Returns:
        bool: True si el correo es válido, False en caso contrario.
    """
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(regex, email) is not None


def read_csv(file_path):
    """
    Función para leer un archivo CSV y obtener los datos de los correos.

    Args:   
        file_path (str): Ruta del archivo CSV a leer.

    Returns:
        list: Lista de diccionarios con los datos de los correos válidos.
    """
    mail_data = []

    try:
        with open(file_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            if reader.fieldnames is None:
                raise ValueError("File is empty or is not a valid CSV file")
            
            for row in reader:
                # En caso que se ingrese un CSV con un formato diferente
                if "name" not in row or "sender_email" not in row or "recipient_email" not in row or "subject" not in row:
                    raise ValueError("CSV must contain columns: name, sender_email, recipient_email, subject.")
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
    """
    Función para manejar los errores al enviar un correo.
    """
    if isinstance(err, Failure):
        print(f"Error sendind email to {recipient}: {err.getErrorMessage()}")
    else:
        print(f"Error with email {recipient}: {err}")


def send_mail(smtp_host, smtp_port, sender, recipient, message, subject):
    """
    Función para enviar un correo electrónico usando SMTP en el formato MIME.

    Args:
        smtp_host (str): Servidor SMTP.
        smtp_port (int): Puerto por el cual se va a hacer la comunicación.
        sender (str): Correo del remitente.
        recipient (str): Correo del destinatario.
        message (str): Cuerpo del mensaje.
        subject (str): Asunto del correo.
    """

    # Mensaje en fromato MIME
    msg = MIMEText(message, "plain", "utf-8")
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject

    # Convertir a bytes para SMTP
    msg_data = msg.as_string()

    
    deferred = sendmail(
        smtp_host,
        sender,
        recipient,
        msg_data.encode("utf-8"),
        port=smtp_port,
        requireAuthentication=False,
        requireTransportSecurity=False  # False ya que no se está usando SSL
    )
    
    deferred.addCallbacks(lambda _: print(f"Mail sent to {recipient}!"), lambda err: handle_send_error(err, recipient))
    
    return deferred


def send_emails(smtp_host, smtp_port, csv_file, message_file):
    """
    Función para enviar cada una de los correos electrónicos del archivo csv.

    Args:
        smtp_host: Servidor SMTP.
        smtp_port: Puerto por el cual se va a hacer la comunicación.
        csv_file: Ruta del archivo CSV de donde se van a extraer la información de los correos
        message_file: Ruta del archivo con el mensaje a enviar.
    
    Returns:
        defer.DeferredList: Lista de deferreds con el estado de cada envío.
    """

    contactos = read_csv(csv_file)
    mensaje_template = read_message(message_file)

    if not contactos:
        print("There are no valid emails in the CSV file. Stopping program...")
        sys.exit(1)

    deferreds = []
    # Se itera por cada correo valido del csv
    for contacto in contactos:
        # Se remplaza el mensaje del correo con los datos del contacto
        # de manera que sea personalizado el mensaje
        mensaje_personalizado = change_message(mensaje_template, contacto["name"], contacto["sender_email"], contacto["recipient_email"])
        
        d = send_mail(smtp_host, smtp_port, contacto["sender_email"], contacto["recipient_email"], mensaje_personalizado, contacto["subject"])
        
        deferreds.append(d)

    return defer.DeferredList(deferreds)

def change_message(mail_data, name, sender_email, recipient_email):
    """
    Función para cambiar los datos del mensaje con los datos del contacto
    para personalizar el correo.

    Args:
        mail_data: Mensaje a enviar.
        name: Nombre del destinatario.
        sender_email: Correo del remitente.
        recipient_email: Correo del destinatario.
    """
    changed_data = mail_data.replace("{name}", name)
    changed_data = changed_data.replace("{sender_email}", sender_email)
    changed_data = changed_data.replace("{recipient_email}", recipient_email)
    return changed_data


def read_message(file_path):
    """
    Función para leer el archivo de mensaje y obtener el contenido del mensaje,

    Args:
        file_path: Ruta del archivo de mensaje.
    
    Returns:
        str: Contenido del mensaje en formato de string
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1) 
    except Exception as e:
        print(f"Error reading message file: {e}")
        sys.exit(1) 


def open_gui():
    """
    Función para abrir la interfaz gráfica del cliente SMTP.
    Se diseña la ventan a desplegar y administra las diferentes
    opciones que tiene el cliente para enviar correos.
    """
    def send_batch():
        """
        Función local para enviar a través de la interfaz los correos de manera 
        masiva con el archivo csv 
        """
        # Se obtiene los datos de los campos
        smtp_host = smtp_host_entry.get()
        smtp_port = smtp_port_entry.get()
        csv_file = csv_file_entry.get()
        message_file = message_file_entry.get()

        if not smtp_host or not smtp_port or not csv_file or not message_file:
            messagebox.showerror("Error", "Every field must be completed.")
            return
        
        try:
            smtp_port = int(smtp_port)
            d_list = send_emails(smtp_host, smtp_port, csv_file, message_file)
            d_list.addCallback(lambda _: on_success())
            d_list.addErrback(lambda err: on_error(err))
            reactor.run() 

        except Exception as e:
            messagebox.showerror("Error", f"There was an error sending emails: {e}")

    def send_manual():
        """
        Función local para enviar un correo de manera manual a través de la interfaz.
        """
        smtp_host = smtp_host_manual_entry.get()
        smtp_port = smtp_port_manual_entry.get()
        sender = sender_manual_entry.get()
        recipient = recipient_manual_entry.get()
        subject = subject_manual_entry.get()
        message = message_text.get("1.0", "end").strip()

        if not all([smtp_host, smtp_port, sender, recipient, subject, message]):
            messagebox.showerror("Error", "Every field must be completed.")
            return

        if not is_valid_email(sender) or not is_valid_email(recipient):
            messagebox.showerror("Error", "One fo the emails is not valid.")
            return

        try:
            smtp_port = int(smtp_port)
            d = send_mail(smtp_host, smtp_port, sender, recipient, message, subject)
            d.addCallback(lambda _: on_success())
            d.addErrback(lambda err: on_error(err))
            reactor.run()
        except Exception as e:
            messagebox.showerror("Error", f"There was an error sending email: {e}")
    
    def on_success():
        messagebox.showinfo("Success", "Email(s) sent successfully!")
        root.destroy()
        reactor.stop()

    def on_error(err):
        messagebox.showerror("Error", f"Failed: {err}")
        root.destroy()
        reactor.stop()

   
    root = ttk.Window(themename="flatly")
    root.title("Client SMTP")
    root.geometry("800x700")

    
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=20, pady=20)

    # Pestaña 1: Envío desde CSV 
    batch_tab = ttk.Frame(notebook)
    notebook.add(batch_tab, text="Send from CSV")

    ttk.Label(batch_tab, text="SMTP Server:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    smtp_host_entry = ttk.Entry(batch_tab, width=50, font=("Arial", 12))
    smtp_host_entry.pack(pady=5)

    ttk.Label(batch_tab, text="SMTP Port:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    smtp_port_entry = ttk.Entry(batch_tab, width=50, font=("Arial", 12))
    smtp_port_entry.insert(0, "2525")
    smtp_port_entry.pack(pady=5)

    ttk.Label(batch_tab, text="CSV file:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    csv_file_entry = ttk.Entry(batch_tab, width=50, font=("Arial", 12))
    csv_file_entry.pack(pady=5)
    ttk.Button(batch_tab, text="Select CSV", bootstyle=SUCCESS, width=20,
               command=lambda: csv_file_entry.insert(0, filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])))\
        .pack(pady=5)

    ttk.Label(batch_tab, text="Message file:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    message_file_entry = ttk.Entry(batch_tab, width=50, font=("Arial", 12))
    message_file_entry.pack(pady=5)
    ttk.Button(batch_tab, text="Select message", bootstyle=SUCCESS, width=20,
               command=lambda: message_file_entry.insert(0, filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])))\
        .pack(pady=5)

    ttk.Button(batch_tab, text="Send Emails", bootstyle=PRIMARY, width=25, command=send_batch)\
        .pack(pady=30)

    # Pestaña 2: Envío Manual
    manual_tab = ttk.Frame(notebook)
    notebook.add(manual_tab, text="Send Manually")

    ttk.Button(manual_tab, text="Send Email", bootstyle=PRIMARY, width=25, command=send_manual)\
        .pack(pady=30)

    ttk.Label(manual_tab, text="SMTP Server:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    smtp_host_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    smtp_host_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="SMTP Port:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    smtp_port_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    smtp_port_manual_entry.insert(0, "2525")
    smtp_port_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="From:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    sender_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    sender_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="To:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    recipient_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    recipient_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="Subject:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    subject_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    subject_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="Message:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    message_text = scrolledtext.ScrolledText(manual_tab, width=60, height=10, font=("Arial", 12))
    message_text.pack(pady=5)

    
    root.mainloop()



if __name__ == '__main__':
    """
    Lectura de argumentos de consola y ejecución del programa.
    """
    print(sys.argv)
    if len(sys.argv) == 2 and sys.argv[1] == "-g":
        open_gui()
    elif len(sys.argv) == 7 and sys.argv[1] != "-g":
        if sys.argv[1] != "-h" or sys.argv[3] != "-c" or sys.argv[5] != "-m":
            print("Uso: python smtpclient.py -h <servidor-smtp> -c <archivo-csv> -m <archivo-mensaje>")
            sys.exit(1)

        # Configuración de los argumentos
        smtp_host = sys.argv[2]
        csv_file = sys.argv[4]
        message_file = sys.argv[6]
        smtp_port = 2525  

        d = send_emails(smtp_host, smtp_port, csv_file, message_file)
        d.addCallback(lambda _: reactor.stop())
        reactor.run()
