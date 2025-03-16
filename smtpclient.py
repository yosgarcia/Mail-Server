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


def parse_arguments():
    parser = argparse.ArgumentParser(description="SMTP Client")

    # Definir los parámetros que quieres aceptar
    parser.add_argument("-h", "--host", required=True, help="SMTP server address")
    parser.add_argument("-c", "--csv", required=True, help="Path to the CSV file containing email data")
    parser.add_argument("-m", "--message", required=True, help="Path to the message file")
    #parser.add_argument("-p", "--port", type=int, default=2525, help="SMTP port (default is 2525)")
    parser.add_argument("-gui", "--gui", action="store_true", help="Run in graphical interface mode")

    # Parsear los argumentos
    args = parser.parse_args()

    # Retornar los valores de los parámetros
    return args.host, args.csv, args.message, args.gui


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
    if isinstance(err, Failure):
        print(f"Error sendind email to {recipient}: {err.getErrorMessage()}")
    else:
        print(f"Error with email {recipient}: {err}")


def send_mail(smtp_host, smtp_port, sender, recipient, message, subject):

    # Mensaje en fromato MIME
    msg = MIMEText(message, "plain", "utf-8")
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject

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

def send_emails(smtp_host, smtp_port, csv_file, message_file):
    contactos = read_csv(csv_file)
    mensaje_template = read_message(message_file)

    if not contactos:
        print("There are no valid emails in the CSV file. Stopping program...")
        sys.exit(1)

    deferreds = []
    for contacto in contactos:
        mensaje_personalizado = change_message(mensaje_template, contacto["name"], contacto["sender_email"], contacto["recipient_email"])
        d = send_mail(smtp_host, smtp_port, contacto["sender_email"], contacto["recipient_email"], mensaje_personalizado, contacto["subject"])
        deferreds.append(d)

    return defer.DeferredList(deferreds)

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


def open_gui():
    def send_batch():
        smtp_host = smtp_host_entry.get()
        smtp_port = smtp_port_entry.get()
        csv_file = csv_file_entry.get()
        message_file = message_file_entry.get()

        if not smtp_host or not smtp_port or not csv_file or not message_file:
            messagebox.showerror("Error", "Todos los campos deben ser completados.")
            return
        
        try:
            smtp_port = int(smtp_port)
            d_list = send_emails(smtp_host, smtp_port, csv_file, message_file)
            d_list.addCallback(lambda _: on_success())
            d_list.addErrback(lambda err: on_error(err))
            reactor.run()

        except Exception as e:
            messagebox.showerror("Error", f"Hubo un error al enviar los correos: {e}")

    def send_manual():
        smtp_host = smtp_host_manual_entry.get()
        smtp_port = smtp_port_manual_entry.get()
        sender = sender_manual_entry.get()
        recipient = recipient_manual_entry.get()
        subject = subject_manual_entry.get()
        message = message_text.get("1.0", "end").strip()

        if not all([smtp_host, smtp_port, sender, recipient, subject, message]):
            messagebox.showerror("Error", "Todos los campos deben ser completados.")
            return

        if not is_valid_email(sender) or not is_valid_email(recipient):
            messagebox.showerror("Error", "Uno de los correos no es válido.")
            return

        try:
            smtp_port = int(smtp_port)
            d = send_mail(smtp_host, smtp_port, sender, recipient, message, subject)
            d.addCallback(lambda _: on_success())
            d.addErrback(lambda err: on_error(err))
            reactor.run()
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error: {e}")
    
    def on_success():
        messagebox.showinfo("Success", "Email(s) sent successfully!")
        root.destroy()
        reactor.stop()

    def on_error(err):
        messagebox.showerror("Error", f"Failed: {err}")
        root.destroy()
        reactor.stop()

    # Crear ventana principal
    root = ttk.Window(themename="flatly")
    root.title("Cliente SMTP - Interfaz Moderna")
    root.geometry("800x700")

    # Crear pestañas
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=20, pady=20)

    # --------- TAB 1: Envío desde CSV ---------
    batch_tab = ttk.Frame(notebook)
    notebook.add(batch_tab, text="Enviar desde CSV")

    ttk.Label(batch_tab, text="Servidor SMTP:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    smtp_host_entry = ttk.Entry(batch_tab, width=50, font=("Arial", 12))
    smtp_host_entry.pack(pady=5)

    ttk.Label(batch_tab, text="Puerto SMTP:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    smtp_port_entry = ttk.Entry(batch_tab, width=50, font=("Arial", 12))
    smtp_port_entry.insert(0, "2525")
    smtp_port_entry.pack(pady=5)

    ttk.Label(batch_tab, text="Archivo CSV:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    csv_file_entry = ttk.Entry(batch_tab, width=50, font=("Arial", 12))
    csv_file_entry.pack(pady=5)
    ttk.Button(batch_tab, text="Seleccionar CSV", bootstyle=SUCCESS, width=20,
               command=lambda: csv_file_entry.insert(0, filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])))\
        .pack(pady=5)

    ttk.Label(batch_tab, text="Archivo de mensaje:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    message_file_entry = ttk.Entry(batch_tab, width=50, font=("Arial", 12))
    message_file_entry.pack(pady=5)
    ttk.Button(batch_tab, text="Seleccionar Mensaje", bootstyle=SUCCESS, width=20,
               command=lambda: message_file_entry.insert(0, filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])))\
        .pack(pady=5)

    ttk.Button(batch_tab, text="Enviar Correos", bootstyle=PRIMARY, width=25, command=send_batch)\
        .pack(pady=30)

    # --------- TAB 2: Envío Manual ---------
    manual_tab = ttk.Frame(notebook)
    notebook.add(manual_tab, text="Enviar Manualmente")

    ttk.Button(manual_tab, text="Enviar Correo", bootstyle=PRIMARY, width=25, command=send_manual)\
        .pack(pady=30)

    ttk.Label(manual_tab, text="Servidor SMTP:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    smtp_host_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    smtp_host_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="Puerto SMTP:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    smtp_port_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    smtp_port_manual_entry.insert(0, "2525")
    smtp_port_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="Remitente (Tu Email):", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    sender_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    sender_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="Destinatario:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    recipient_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    recipient_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="Asunto:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    subject_manual_entry = ttk.Entry(manual_tab, width=50, font=("Arial", 12))
    subject_manual_entry.pack(pady=5)

    ttk.Label(manual_tab, text="Mensaje:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 0))
    message_text = scrolledtext.ScrolledText(manual_tab, width=60, height=10, font=("Arial", 12))
    message_text.pack(pady=5)

    


    root.mainloop()


def main():
    """
    Función principal que procesa los parámetros y envía correos.
    """
    print(sys.argv)
    if len(sys.argv) == 2 and sys.argv[1] == "-g":
        open_gui()
    elif len(sys.argv) == 7 and sys.argv[1] != "-g":
        if sys.argv[1] != "-h" or sys.argv[3] != "-c" or sys.argv[5] != "-m":
            print("Uso: python smtpclient.py -h <servidor-smtp> -c <archivo-csv> -m <archivo-mensaje>")
            sys.exit(1)

        smtp_host = sys.argv[2]
        csv_file = sys.argv[4]
        message_file = sys.argv[6]
        smtp_port = 2525  

        d = send_emails(smtp_host, smtp_port, csv_file, message_file)
        d.addCallback(lambda _: reactor.stop())
        reactor.run()




if __name__ == '__main__':
    main()
