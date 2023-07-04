# Información previa

- Herramienta simple y accesible para escanear puertos y sus correspondientes servicios.
- Se puede usar tanto de manera remota (siempre que esten ambos dispositivos en la misma red logicamente) como desde el propio localhost.
- Recomendable no usar la herramienta con una VPN de por medio, ya que el escaneo se ralentizará bastante.
- Si alguien quiere modificar el script a su gusto es totalmente libre.
- Tiene disponible proporcionarle tanto IPv4 como IPv6 sobre el protocolo TCP.
- Es posible que si lo intentas ejecutar hacia una maquina Windows, el propio Firewall haga que se ralentice el escaneo.

## Uso
Primero nos clonamos el repositorio:

`$ git clone https://github.com/n3v3rm1nd8/BitMap-Python`

Nos instalamos las dependencias en el caso de que no las tengamos:

`$ pip install -r requirements.txt`

Hecho esto, ya podemos usar el script:

`$ python bitmap.py --help`

## Posible error
> **WARNING: No libpcap provider available ! pcap wont be used.**

Es posible que si ejecutamos el script en Windows, al inicio nos salga este error, esto solo afectaría a la hora de utilizar el metodo por IPv6, ya que necesita de esta libreria, para ello nos podemos ir a https://npcap.com/ y nos descargamos en la pestaña *Download* el binario correspondiente para Windows, lo ejecutamos para instalarlo (es recomendable reiniciar despues de la instalación) y ya estaría solucionado.

## Posible advertencia
> **WARNING: Mac address to reach destination not found. Using broadcast.**

Esto se consideraria mas como una advertencia a tener en cuenta que sale en algunos casos, es posible que cuando ejecutemos el script en una maquina Windows utilizando IPv6 salga el mensaje de arriba, esto en resumen indica que la libreria *Scapy* que usa el script, en algunos momentos no encuentra la MAC para comunicarse con el target proporcionado, pero no afecta como tal al escaneo, se realizará sin problemas.