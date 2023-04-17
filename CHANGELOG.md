Jediné omezení na které jsem narazil při testování bylo při testování na fakultou poskytnutém
virtuálním stroji s OS NIX, kde bylo potřeba spouštět program společně s příkazem `sudo`, jinak 
se neotevřelo rozhraní.

Problém je i se zachytáváním packetů protokolu MLD.

ip[40] ve filtru pro MLD je 130, 131, 132 pro MLD a 143 pro MLDv2, ale nebere ani jedno.