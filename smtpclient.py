import csv
from twisted.mail.smtp import sendmail
from twisted.internet import reactor, defer
from email.mime.text import MIMEText


def read_csv(file_path):
    mail_data = []
    with open(file_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            mail_data.append(row)
    return mail_data


def change_message(mail_data, name, sender_email, recipient_email):
    changed_data = mail_data.replace("{name}", name)
    changed_data = changed_data.replace("{sender_email}", sender_email)
    changed_data = changed_data.replace("{recipient_email}", recipient_email)
    return changed_data


def read_message(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read().strip()  


if __name__ == '__main__':
    csv_file = "mails.csv"
    mails = read_csv(csv_file)
    print(mails)
    archivo_mensaje = "message.txt"
    mensaje_base = read_message(archivo_mensaje)
    print(mensaje_base)

    for mail in mails:
        changed_message = change_message(mensaje_base, mail["name"], mail["sender_email"], mail["recipient_email"])
        print(f"From: {mail['sender_email']}")
        print(f"To: {mail['recipient_email']}")
        print(f"Mensaje:\n{changed_message}\n")

