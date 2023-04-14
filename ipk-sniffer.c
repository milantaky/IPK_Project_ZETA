#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>   // pro praci s hlavickami -> ether_header

#define MAX_PACKET_SIZE 65535

int zkontrolujPrepinace(int pocet, char** prepinace);
int vypisAktivniRozhrani();
void packetCallback(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body);

int main(int argc, char** argv){
    char interface[20];
    int pocetPacketu = 1;                   // Defaultne
    char filteros[100] = "";
    int pocetProtokolu = 0;
    int port = -1;      
    int interfaceSet = 0;    
    
// Zpracovani prepinacu ---------------------------------------------------------------------
    if(argc == 1) {
        return 0;
    } else {
        if(argc == 2 && (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--interface") == 0)){
            if(!vypisAktivniRozhrani()){
                return 1;
            }
            printf("\njen interface\n");
            return 0;
        } 

        int argN = 1;
        while(argv[argN] != NULL){

            // -i / --interface s hodnotou - predpokladam ze je prikaz spravne
            if(strcmp(argv[argN], "-i") == 0 || strcmp(argv[argN], "--interface") == 0){
                if(argv[argN + 1] != NULL){
                    argN++;
                    strcpy(interface, argv[argN]);
                    interfaceSet = 1;
                    argN++;
                    continue;
                } // netreba else
            }
            
            if(interfaceSet){
                // -p 
                if(strcmp(argv[argN], "-p") == 0){
                    if(argv[argN + 1] != NULL){
                        argN++;
                        if((port = atoi(argv[argN])) == 0){
                            fprintf(stderr, "CHYBA: Neplatny argument za -p: %s\n", argv[argN]);
                            return 1;
                        }
                        //continue;
                    } else {
                        fprintf(stderr, "CHYBA: Chybi argument za -p.\n");
                        return 1;
                    }    
                } 
                else if(strcmp(argv[argN], "-n") == 0){                  // -n
                    if(argv[argN + 1] != NULL){
                        argN++;
                        if((pocetPacketu = atoi(argv[argN])) == 0){
                            fprintf(stderr, "CHYBA: Neplatny argument za -n: %s - musi byt cislo.\n", argv[argN]);
                            return 1;
                        }    
                        //continue; 
                    } else {
                        fprintf(stderr, "CHYBA: Chybi argument za -n.\n");
                        return 1;
                    }
                }                               // PROTOKOLY --------------------------------------------------------------
                else if(strcmp(argv[argN], "-t") == 0 || strcmp(argv[argN], "--tcp") == 0){      // TCP -t --tcp
                    if(!pocetProtokolu){
                        strcat(filteros, "tcp");
                    } else {
                        strcat(filteros, " or tcp");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "-u") == 0 || strcmp(argv[argN], "--udp") == 0){          // UDP -u --udp
                    if(!pocetProtokolu){
                        strcat(filteros, "udp");
                    } else {
                        strcat(filteros, " or udp");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--icmp4") == 0){                                          // ICMPv4 --icmp4             
                    if(!pocetProtokolu){
                        strcat(filteros, "icmp");
                    } else {
                        strcat(filteros, " or icmp");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--icmp6") == 0){                                             // ICMPv6 --icmp6
                    if(!pocetProtokolu){
                        strcat(filteros, "icmp6");
                    } else {
                        strcat(filteros, " or icmp6");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--arp") == 0){                                                   // ARP --arp
                    if(!pocetProtokolu){
                        strcat(filteros, "arp");
                    } else {
                        strcat(filteros, " or arp");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--ndp") == 0){                                       // NDP --ndp
                    if(!pocetProtokolu){
                        strcat(filteros, "ndp");
                    } else {
                        strcat(filteros, " or ndp");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--igmp") == 0){                                          // IGMP --igmp
                    if(!pocetProtokolu){
                        strcat(filteros, "igmp");
                    } else {
                        strcat(filteros, " or igmp");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--mld") == 0){                                                   // MLD --mld
                    if(!pocetProtokolu){
                        strcat(filteros, "mld");
                    } else {
                        strcat(filteros, " or mld");
                    }
                        pocetProtokolu++;
                    //continue;
                } 
                else {                                      // Pokud to doslo az sem, je to neplatny argument
                    fprintf(stderr, "CHYBA: neplatny argument: %s\n", argv[argN]);
                    return 1;
                }

            } else {
                fprintf(stderr, "CHYBA: Je potreba nastavit interface\n");
                return 1;
            }

            argN++;
        }

    }      

    printf("\n------------- MOJE INFO --------------\n");
    printf("Interface: %s\n", interface);
    printf("Filter: %s\n", filteros);
    printf("Port %d\n", port);
    printf("N %d\n", pocetPacketu);
    printf("pocetProtokolu %d\n", pocetProtokolu);
    printf("--------------------------------------\n\n");


    /*
    nastavene protokoly?
        -> nastav filter
        -> zkompiluj
        -> set filter
    otevri interface pro live           pcap_open_live

    nacti packet        |   pcap_loop
    zpracuj             |
        -> procti hlavicku
            -> vypis info
        -> napis offset: hexa zprava  -  normal zprava (netiskutelny znak = .)
    chytej dalsi
    */

    //       pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
    int timeout = 10000;                            // v ms - 10s
    char errBuff[PCAP_ERRBUF_SIZE];
    memset(errBuff, 0, PCAP_ERRBUF_SIZE);
    pcap_t *handle;                                 // kam se bude chytat

    // https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
    if((handle = pcap_open_live(interface, MAX_PACKET_SIZE, 1, timeout, errBuff)) == NULL){
        fprintf(stderr, "CHYBA: Nastala chyba pri otevreni interface pro sniffing:\n       %s\n",errBuff);
        return 1;
    }

    // TODO: Filtr
    // compile
    // setfilter


    if(pcap_loop(handle, pocetPacketu, packetCallback, (u_char*)handle) != 0){
        fprintf(stderr, "CHYBA: Nastala chyba pri prijimani nebo zpracovani packetu.\n");
        return 1;
    }

    pcap_close(handle);

    return 0;
}

/*
Pokud je jen -i nebo --interface, vypis aktivni rozhrani
Pokud je jen -i nebo --interface a hodnota, ber vsechno co na nej jde
-p doplnuje TCP/UDP, ale nemusi. muze byt jako src i dest
    -t --tcp
    -u --udp
-n pocet packetu - default 1


--icmp4 (will display only ICMPv4 packets).
--icmp6 (will display only ICMPv6 echo request/response).
--arp (will display only ARP frames).
--ndp (will display only ICMPv6 NDP packets).
--igmp (will display only IGMP packets).
--mld (will display only MLD packets).
*/






// Zkontroluje prepinace, a vraci 1, pokud je vse v poradku, jinak 0
// Predpokladane spusteni: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
int zkontrolujPrepinace(int pocet, char** prepinace){
    printf("pocet: %d\n", pocet);
    printf("arg: %s\n", prepinace[1]);




    return 1;
}

// Vypise seznam aktivnich rozhrani
// Vraci 1 pri chybe, jinak 0
// ZDROJ: https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html
int vypisAktivniRozhrani(){

    char errbuff[PCAP_ERRBUF_SIZE];
    memset(errbuff, 0 , PCAP_ERRBUF_SIZE);      // vynuluje buffer pred pouzitim

    pcap_if_t *devs;

    if(pcap_findalldevs(&devs, errbuff) == -1){
        fprintf(stderr, "CHYBA: Nastala chyba pri hledani aktivnich rozhrani:\n     %s\n", errbuff);
        return 1;
    }

    printf("\n");
    while(devs->next != NULL){
        printf("%s\n",devs->name);
        devs = devs->next;
    }
    printf("\n");

    pcap_freealldevs(devs);
    return 0;
}

void packetCallback(u_char *user, const struct pcap_pkthdr *packetHeader, const u_char *packetBody){

    // Zkontroluje jestli je packet typu LINKTYPE_ETHERNET (DLT_EN10MB)
    // ZDROJ: https://www.tcpdump.org/manpages/pcap_datalink.3pcap.html
    int linkType = pcap_datalink((pcap_t *) user);
    if(linkType != DLT_EN10MB) return;

    // TODO: Timestamp


    // Zjisteni src/dest MAC adresy - mozna hodit do fce
    // ZDROJ: https://linux.die.net/man/3/ether_ntoa
    struct ether_header *ethHeader = (struct ether_header *) packetHeader;
    struct ether_addr *srcMAC  = (struct ether_addr *) ethHeader->ether_shost;
    struct ether_addr *destMAC = (struct ether_addr *) ethHeader->ether_dhost;

    // TODO: upravit vypsani podle toho pojebanyho RFC
    printf("src MAC: %s\n", ether_ntoa(srcMAC));
    printf("dst MAC: %s\n", ether_ntoa(destMAC));

    printf("frame length: %d bytes\n", packetHeader->len);
    
    // TODO: IP adresy
    // TODO: porty

    // Vypis obsahu packetu
    printf("\n");
    int delkaZpravy = packetHeader->caplen;
    int zbyvaDopsat = (delkaZpravy) % 16;
    for (int i = 0; i < delkaZpravy; i++) {
        // byte_offset - vymyslet lip
        if(i % 16 == 0 && i == 0) printf("0x%05x: ", i);

        if(i != 0 && i % 16 == 0){              // Je to posledni pismeno na radku? (krom 1.)
            for(int j = i - 16; j < i; j++){
                if(packetBody[j] > 32 && packetBody[j] < 127)
                    printf("%c", packetBody[j]);
                else 
                    printf(".");
                
                if(j == i - 9) printf(" ");
            }
            printf("\n");
            printf("0x%05x: ", i);
        }

        printf("%02x ", packetBody[i]);

        // TODO: opravit aby to tu nebylo 3x
        // Tisknutelne/netisknutelne znaky
        if(i == delkaZpravy - 1){                       // Konec vypsane zpravy - dopsat zbyle znaky
            if(zbyvaDopsat != 0){                       // Je posledni radek plny?
                for(int k = 0; k < 48 - zbyvaDopsat * 3; k++){
                    printf(" ");
                }

                for(int j = delkaZpravy - zbyvaDopsat; j < delkaZpravy; j++){
                    if(packetBody[j] > 32 && packetBody[j] < 127)
                        printf("%c", packetBody[j]);
                    else 
                        printf(".");
                        
                    if(j == delkaZpravy - zbyvaDopsat + 7) printf(" ");
                }
            } else {                                    // Je plny, dopis ho
                for(int j = 0; j < 16; j++){
                    if(packetBody[j] > 32 && packetBody[j] < 127)
                        printf("%c", packetBody[j]);
                    else 
                        printf(".");

                    if(j == 8) printf(" ");
                }
            }
        }
    }

    printf("\n\n");
    
}











//Promiscuous mode is set with pcap_set_promisc().  ZDROJ - https://www.tcpdump.org/manpages/pcap.3pcap.html

// useful linky
// https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html - otevreni ke cmuchu
