import os
from datetime import datetime
from virus_total_apis import PublicApi as VirusTotalPublicApi
import hashlib
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys

######################_____FUNCIONES CORREO_____##########################################

email_recipient = "recipient@mail.com"

def send_email(subject, body, to_email):
    # Set up the email details
    from_email = 'sender@mail.com'
    password = 'Password2024'

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Set up the SMTP server
    try:
        server = smtplib.SMTP('smtp-mail.outlook.com', 587)  # Replace with your SMTP server and port
        server.starttls()  # Enable TLS
        server.login(from_email, password)
        server.send_message(msg)
        server.quit()
        print("Email enviado exitosamente.")
    except Exception as e:
        print(f"Failed to send email. Error: {e}")

#########################################____LISTADO____#####################################   

directorio = r"C:\Users\user\Downloads"
nombre_archivo_inicial = "First_scan.txt"

def listainicial():
    """Genera el archivo inicial con la lista de todos los archivos en el directorio."""
    original_file = os.listdir(directorio)
    with open(os.path.join(directorio, nombre_archivo_inicial), "w", encoding="utf-8") as file:
        file.write("\n".join(original_file))

def lista_actualizada():
    """Genera un archivo de lista actualizado con la fecha y hora actuales."""
    global new_file
    new_file = os.listdir(directorio)
    hora_actual = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nombre_archivo_actualizado = f"last_scan_{hora_actual}.txt"
    with open(os.path.join(directorio, nombre_archivo_actualizado), "w", encoding="utf-8") as file:
        file.write("\n".join(new_file))
    return nombre_archivo_actualizado

# Inicializar la variable comparacion
comparacion = []

if not os.path.exists(os.path.join(directorio, nombre_archivo_inicial)):
    listainicial()
else:
    lista_actualizada()
    with open(os.path.join(directorio, nombre_archivo_inicial), "r", encoding="utf-8") as file2:
        lista_comparativa = [line.strip() for line in file2]  # Quitar los saltos de línea
        comparacion = list(set(new_file) - set(lista_comparativa))
        archivos_last_scan = [line for line in comparacion if line.startswith("last_scan")]

    # Eliminar el archivo inicial después de cerrar todas las operaciones de archivo
    try:
        os.remove(os.path.join(directorio, nombre_archivo_inicial))
    except PermissionError as e:
        print(f"No se puede eliminar el archivo {nombre_archivo_inicial}: {e}")

    # Encontrar el último archivo de escaneo
    ayuda = [archivo for archivo in os.listdir(directorio) if archivo.startswith("last_scan")]
    if ayuda:
        # Selecciona el archivo más reciente (el último añadido)
        archivo_renombrar = ayuda[-1]
        os.rename(os.path.join(directorio, archivo_renombrar), os.path.join(directorio, nombre_archivo_inicial))

print(f"Archivos nuevos encontrados: {comparacion}")

#####################_____ANTIVIRUS________###################

API_KEY = 'API KEY TAKEN FROM THE VIRUSTOTAL USER PROFILE'
vt = VirusTotalPublicApi(API_KEY)

for iterador in comparacion:
    if iterador != "First_scan.txt" and iterador:
        print (iterador)
        with open ((os.path.join(directorio, iterador)),"rb") as f:
            archivo=f.read()
            archivomd5=hashlib.md5(archivo).hexdigest()
            response = vt.get_file_report(archivomd5)
            time.sleep(300)
            returncode=response["response_code"]
            positivos=response["results"]["positives"]
            AVtotales=response["results"]["total"]
            if returncode == 200:
                if positivos == 0:
                    print(f"El archivo {iterador} no fue detectado como una amenaza por {AVtotales} bases de datos")
                elif 0< positivos <30 :
                    print(f"El archivo {iterador} fue detectado como una posible amenaza por {positivos} bases de datos, potencialmente malicioso")
                    subject = "Potencial Archivo Malicioso Encontrado. RIESGO MEDIO"
                    body = f"El archivo {iterador} fue encontrado como potencialmente malicioso"
                    send_email(subject, body, email_recipient) 

                else:
                    print(f"El archivo {iterador} fue detectado como una amenaza por {positivos} bases de datos. El archivo es malicioso. Enviando notificacion...")
                    #enviando email
                    subject = "Archivo Malicioso Encontrado. RIESGO ALTO"
                    body = f"El archivo {iterador} fue encontrado como malware"
                    send_email(subject, body, email_recipient)                 
                
            else:
                print ("Hubo un problema al intentarse conectarse a VirusTotal")

sys.exit()