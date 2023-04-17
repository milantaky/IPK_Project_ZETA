IPK - Projekt ZETA: Network sniffer
===
**Autor:** Milan Takac - xtakac09

2BIT FIT VUT 

O Projektu:
---
Náplní tohoto projektu bylo vytvořit program, který chytá síťový provoz na určitém rozhraní.
Přesněji tedy zachytává packety protokolů `TCP, UDP, ICMPv4, ICMPv6, ARP, NDP, IGMP, MLD`.
Pro TCP/UDP packety se dá také přepínačem nastavit požadovaný port. Tento port se může objevit jako
zdrojový i jako cílový.

Spouštění:
---
Po přeložení souboru **ipk-sniffer.c** příkazem `make` dostanete spustitelný soubor.
Toto je příkaz ke spuštění s přepínači:
`./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}`
Kde:
* `-i eth0` (sniffuje se pouze jedno rozhraní) nebo `--interface`. Není-li tento parametr zadán (a ostatní parametry rovněž) nebo je-li zadáno pouze `-i/--interface` bez hodnoty (a ostatní parametry nejsou zadány), vypíše se seznam aktivních rozhraní (další informace nad rámec seznamu rozhraní jsou vítány, ale nejsou vyžadovány).
* `-t` nebo` --tcp` (zobrazí segmenty TCP a je volitelně doplněn funkcí -p).
* `-u` nebo `--udp` (zobrazí datagramy UDP a je volitelně doplněn funkcí-p).
* `-p 23` (rozšiřuje předchozí dva parametry o filtrování TCP/UDP na základě čísla portu; pokud tento parametr není přítomen, k filtrování podle čísla portu nedochází, pokud je parametr zadán, může se daný port vyskytovat jak ve zdrojové, tak v cílové části hlaviček TCP/UDP).
* `--icmp4` (zobrazí pouze pakety ICMPv4).
* `--icmp6` (zobrazí pouze ICMPv6 echo request/response).
* `--arp` (zobrazí pouze rámce ARP).
* `--ndp` (zobrazí pouze pakety ICMPv6 NDP).
* `--igmp` (zobrazí pouze pakety IGMP).
* `--mld` (zobrazí pouze pakety MLD).
Pokud nejsou protokoly výslovně zadány, jsou pro tisk brány v úvahu všechny (tj. veškerý obsah bez ohledu na protokol).
* `-n 10` (určuje počet paketů, které se mají zobrazit, tj. "dobu", po kterou program běží; není-li zadáno, uvažuje se zobrazení pouze jednoho paketu, tj. jako při -n 1).
Všechny argumenty mohou být v libovolném pořadí.

**Teorie na pozadí**
===
Program k zachycení packetu využívá knihovny `libpcap`.
Nejprve se zpracují zadané přepínače. 
Funkcí `pcap_open_live` se otevře nastavený interface pro sniffing s módem promiscuous, který zajišťuje čtení všech packetů procházejících tímto rozhraním.
Podle nich se vytvoří filtr, a funkcemi `pcap_compile` a `pcap_setfilter` se přeloží a aplikuje.
Funkcí `pcap_loop` předá chycený packet funkci `packetCallback`, která zkontroluje zda je packet typu `LINKTYPE_ETHERNET`, a případně ho zahodí.
Následně se packet zpracuje podle funkce v její hlavičce. Pak vytiskne základní informace z hlavičky, jako:
* Časovou známku
* Zdrojovou a cílovou MAC adresu 
* Délku packetu
* Zdrojovou a cílovou IP adresu
* Obsah packetu

Jakmile je zpracován požadovaný počet packetů, uvolní se filtr, interface se uzavře, a program se ukončí.
Když nastane při běhu programu nějaká chyba, program se ukončí a vztiskne se příslušná chybová hláška.
Program je připraven i na přijmutí `C-c` (interrupt) signálu.

**Omezení**
---
Jediné s čím má program problém jsou `MLD` packety, nechce je zachytávat.

**Doporučení k testování**
---
* Nejvíce se mi osvedčilo spouštět s programem WireShark a následně kontrolovat vypsané packety
* Dobré k testování konkrétních protokolů je stažení pcap souboru a "odeslání" aplikací `tcpreplay`.

**Zdroje**
===
Práce s pcap funkcemi - [tcpdump](https://www.tcpdump.org).
