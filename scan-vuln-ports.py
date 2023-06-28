import nmap
import smtplib
from email.mime.text import MIMEText
import argparse
import time

PUERTOS_VULNERABLES = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    53: "DNS",
    161: "SNMP",
    445: "SMB",
    3389: "RDP",
    21: "FTP",
    3306: "MySQL",
    69: "TFTP",
    123: "NTP"
}

# Configuración del servidor SMTP
smtp_server = 'smtp.test.com'
smtp_port = 587
remitente = 'test@test.cl'
contraseña = 'test'

def enviar_correo(ip, puerto, servicio, destinatario):
    # Configura los detalles del correo electrónico
    asunto = 'Puerto vulnerable detectado'
    cuerpo = f"Se encontró el puerto {puerto} ({servicio}) abierto en la IP {ip}."

    # Crea el objeto MIMEText para el correo electrónico
    mensaje = MIMEText(cuerpo)
    mensaje['Subject'] = asunto
    mensaje['From'] = remitente
    mensaje['To'] = destinatario

    # Envía el correo electrónico a través del servidor SMTP
    servidor_smtp = smtplib.SMTP(smtp_server, smtp_port)
    servidor_smtp.starttls()
    servidor_smtp.login(remitente, contraseña)
    servidor_smtp.sendmail(remitente, destinatario, mensaje.as_string())
    servidor_smtp.quit()

def escanear_puertos(segmentos_ips, destinatario):
    # Crea un objeto de escaneo Nmap
    nm = nmap.PortScanner()

    while True:
        # Realiza el escaneo de puertos en los segmentos de IP especificados
        for segmento_ip in segmentos_ips:
            nm.scan(hosts=segmento_ip, arguments='-p 22,23,80,53,161,445,3389,21,3306,69,123 --open')

            # Itera sobre los resultados del escaneo
            for host in nm.all_hosts():
                for protocolo in nm[host].all_protocols():
                    puertos = nm[host][protocolo].keys()
                    for puerto in puertos:
                        # Verifica si el puerto está abierto y es vulnerable
                        if puerto in PUERTOS_VULNERABLES and nm[host][protocolo][puerto]['state'] == 'open':
                            servicio = PUERTOS_VULNERABLES[puerto]
                            print(f"Se encontró el puerto {puerto} ({servicio}) abierto en la IP {host}.")
                            enviar_correo(host, puerto, servicio, destinatario)

        # Espera 1 minuto antes de realizar el próximo escaneo
        time.sleep(60)

if __name__ == "__main__":
    # Configura los argumentos de la línea de comandos
    parser = argparse.ArgumentParser(description='Script para escanear puertos y detectar vulnerabilidades.')
    parser.add_argument('segmentos_ips', nargs='+', help='Segmentos de IP o IPs)
    parser.add_argument('--destinatario', required=True, help='Dirección de correo electrónico del destinatario')
    args = parser.parse_args()

    # Ejecuta el escaneo de puertos con los segmentos de IP proporcionados como argumento
    escanear_puertos(args.segmentos_ips, args.destinatario)
