Este script en python te permitirá escanear costantemente tus segmentos IPs publicos cada un minuto para detectar cualquier puerto vulnerable expuesto. Adicionalmente te enviara un correo al destinatario indicado si detecta un puerto vulnerable expuesto.

Para utilizarlo debes editar el script y proporcionar el servidor SMTP deseado, junto con el usuario y contraseña.

Finalmente par autilizarlo debes indicar el o los segmentos IPs publicos a escanear y el destinario del correo a quien les llegaran las notificaciones. Por ejemplo:

python3 scan-vuln-ports.py 8.8.8.8 8.8.8.0/29 --destinatario test@test.cl


Raúl Herrera P.
Ingeniero en ciberseguridad
