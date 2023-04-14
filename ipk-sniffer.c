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
void vypisPacket(const u_char *packetos, int delka);

// TODO: interrupt signal

int main(int argc, char** argv){
    char interface[20];
    int pocetPacketu = 1;                   // Defaultne
    char filteros[512] = "";                // 512 protoze nejdelsi retezec muze byt 506
    int pocetProtokolu = 0;
    int port = -1;      
    int interfaceSet = 0;    
    // int tcpSet = 0;
    // int udpSet = 0;
    
// Zpracovani prepinacu ---------------------------------------------------------------------
    if(argc == 1) {
        return 0;
    } else {
        // Zadan pouze interface -> vypis aktivnich rozhrani 
        if(argc == 2 && (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--interface") == 0)){
            if(!vypisAktivniRozhrani()){
                return 1;
            }
            return 0;
        } 

        int argN = 1;           
        while(argv[argN] != NULL){
            if(strcmp(argv[argN], "-i") == 0 || strcmp(argv[argN], "--interface") == 0){     // -i / --interface s hodnotou - predpokladam ze je prikaz spravne
                if(argv[argN + 1] != NULL){
                    argN++;
                    if((argv[argN][0] > 64 && argv[argN][0] < 91) || (argv[argN][0] > 97 && argv[argN][0] < 123)){
                        strcpy(interface, argv[argN]);
                    } else {
                        fprintf(stderr, "CHYBA: Neplatny nazev rozhrani: %s\n", argv[argN]);
                        return 1;
                    }
                    interfaceSet = 1;
                    argN++;
                    continue;
                }
            }
            
            if(interfaceSet){
                if(strcmp(argv[argN], "-p") == 0){       // -p 
                    if(argv[argN + 1] != NULL){
                        argN++;
                        if(argv[argN][0] < 47 || argv[argN][0] > 58 || (port = atoi(argv[argN])) == 0 || port < 1){
                            fprintf(stderr, "CHYBA: Neplatny argument za -p (musi byt cislo vetsi 0): %s\n", argv[argN]);
                            return 1;
                        }
                        //continue;
                    } else {
                        fprintf(stderr, "CHYBA: Chybi argument za -p.\n");
                        return 1;
                    }    
                } 
                else if(strcmp(argv[argN], "-n") == 0){  // -n
                    if(argv[argN + 1] != NULL){
                        argN++;
                        if(argv[argN][0] < 47 || argv[argN][0] > 58 || (pocetPacketu = atoi(argv[argN])) == 0 || pocetPacketu < 1){
                            fprintf(stderr, "CHYBA: Neplatny argument za -n (musi byt cislo vetsi 0): %s\n", argv[argN]);
                            return 1;
                        }    
                        //continue; 
                    } else {
                        fprintf(stderr, "CHYBA: Chybi argument za -n.\n");
                        return 1;
                    }
                }
                // PROTOKOLY --------------------------------------------------------------
                else if(strcmp(argv[argN], "-t") == 0 || strcmp(argv[argN], "--tcp") == 0){   // TCP -t --tcp
                    if(!pocetProtokolu){
                        if(port > 0){  // Je nastaveny port, muze byt u src i dest
                            char port_str[10];
                            sprintf(port_str, "%d", port);
                            strcat(filteros, "(tcp and src port ");
                            strcat(filteros, port_str);
                            strcat(filteros, ") or (tcp and dest port ");
                            strcat(filteros, port_str);
                            strcat(filteros, ")");
                        } else {
                            strcat(filteros, "tcp");
                        }
                    } else {
                        if(port > 0){
                            char port_str[10];
                            sprintf(port_str, "%d", port);
                            strcat(filteros, " or (tcp and src port ");
                            strcat(filteros, port_str);
                            strcat(filteros, ") or (tcp and dest port ");
                            strcat(filteros, port_str);
                            strcat(filteros, ")");
                        } else {
                            strcat(filteros, " or tcp");
                        }
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "-u") == 0 || strcmp(argv[argN], "--udp") == 0){   // UDP -u --udp
                    if(!pocetProtokolu){
                        if(port > 0){  // Je nastaveny port, muze byt u src i dest
                            char port_str[10];
                            sprintf(port_str, "%d", port);
                            strcat(filteros, "(udp and src port ");
                            strcat(filteros, port_str);
                            strcat(filteros, ") or (udp and dest port ");
                            strcat(filteros, port_str);
                            strcat(filteros, ")");
                        } else {
                            strcat(filteros, "udp");
                        }
                    } else {
                        if(port > 0){
                            char port_str[10];
                            sprintf(port_str, "%d", port);
                            strcat(filteros, " or (udp and src port ");
                            strcat(filteros, port_str);
                            strcat(filteros, ") or (udp and dest port ");
                            strcat(filteros, port_str);
                            strcat(filteros, ")");
                        } else {
                            strcat(filteros, " or udp");
                        }
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--icmp4") == 0){    // ICMPv4 --icmp4             
                    if(!pocetProtokolu){
                        strcat(filteros, "icmp");
                    } else {
                        strcat(filteros, " or icmp");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--icmp6") == 0){    // ICMPv6 --icmp6
                    if(!pocetProtokolu){
                        strcat(filteros, "icmp6");
                    } else {
                        strcat(filteros, " or icmp6");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--arp") == 0){      // ARP --arp
                    if(!pocetProtokolu){
                        strcat(filteros, "arp");
                    } else {
                        strcat(filteros, " or arp");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--ndp") == 0){      // NDP --ndp
                    if(!pocetProtokolu){
                        strcat(filteros, "(icmp6 and (ip6[40] = 133 or ip6[40] = 134 or ip6[40] = 135 or ip6[40] = 136 or ip6[40] = 137))");
                    } else {
                        strcat(filteros, " or (icmp6 and (ip6[40] = 133 or ip6[40] = 134 or ip6[40] = 135 or ip6[40] = 136 or ip6[40] = 137))");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--igmp") == 0){     // IGMP --igmp
                    if(!pocetProtokolu){
                        strcat(filteros, "igmp");
                    } else {
                        strcat(filteros, " or igmp");
                    }
                        pocetProtokolu++;
                    //continue;
                }
                else if(strcmp(argv[argN], "--mld") == 0){      // MLD --mld
                    if(!pocetProtokolu){
                        strcat(filteros, "(icmp6 and (ip6[40] = 143))");
                    } else {
                        strcat(filteros, " or (icmp6 and (ip6[40] = 143))");
                    }
                        pocetProtokolu++;
                    //continue;
                } 
                else {        // Pokud to doslo az sem, je to neplatny argument
                    fprintf(stderr, "CHYBA: neplatny argument: %s\n", argv[argN]);
                    return 1;
                }

            } else {
                fprintf(stderr, "CHYBA: Je potreba nastavit interface\n");
                return 1;
            }

            if(pocetProtokolu > 8){
                fprintf(stderr, "CHYBA: prilis mnoho zadanych protokolu\n");
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
    nastavene protokoly?                                                            DONE
        -> nastav filter                                                            DONE
        -> zkompiluj                                                                DONE
        -> set filter                                                               DONE
        -> test
    otevri interface pro live           pcap_open_live                              DONE
    nacti packet        |   pcap_loop                                               DONE
    zpracuj             |
        -> procti hlavicku
            -> vypis info
        -> napis offset: hexa zprava  -  normal zprava (netiskutelny znak = .)      DONE
    chytej dalsi                                                                    DONE
    */


    int timeout = 10000;                            // v ms - 10s
    char errBuff[PCAP_ERRBUF_SIZE];
    memset(errBuff, 0, PCAP_ERRBUF_SIZE);
    pcap_t *handle;                                 // kam se bude chytat

    // ZDROJ: https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
    if((handle = pcap_open_live(interface, MAX_PACKET_SIZE, 1, timeout, errBuff)) == NULL){
        fprintf(stderr, "CHYBA: Nastala chyba pri otevreni interface pro sniffing:\n       %s\n",errBuff);
        return 1;
    }

    // Filtr  --------------------------------------------------------------------------
    // ZDROJ: https://www.tcpdump.org/manpages/pcap_compile.3pcap.html

    if(pocetProtokolu){
        printf("Nastavuji filter\n");
        struct bpf_program pFilter; 
        if(pcap_compile(handle, &pFilter, filteros, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR){
            fprintf(stderr, "CHYBA: Prelozeni filtru:\n       %s\n", pcap_geterr(handle));
            return 1;
        }
        
        if(pcap_setfilter(handle, &pFilter) == PCAP_ERROR){
            fprintf(stderr, "CHYBA: Nastaveni filtru:\n       %s\n", pcap_geterr(handle));
            return 1;
        }
    }                           //      igmp, arp, icmp6 (jeho soucasti je MLD)

    // Sbirani packetu
    if(pcap_loop(handle, pocetPacketu, packetCallback, (u_char*)handle) != 0){
        fprintf(stderr, "CHYBA: Nastala chyba pri prijimani nebo zpracovani packetu.\n");
        return 1;
    }

    pcap_close(handle);

    return 0;
}

/*
Pokud je jen -i nebo --interface, vypis aktivni rozhrani                DONE
Pokud je jen -i nebo --interface a hodnota, ber vsechno co na nej jde   DONE
-p doplnuje TCP/UDP, ale nemusi. muze byt jako src i dest               
    -t --tcp
    -u --udp
-n pocet packetu - default 1                                            DONE

// ---------------- TEST
// bere to :
    // ARP, IGMP, NDP
// melo by :
    // mld (neprisel zadny), TCP - bere to i TLS, ale to bezi na TCP

--icmp4 (will display only ICMPv4 packets).
--icmp6 (will display only ICMPv6 echo request/response).
    -- request - 128, reply - 129 
                                                            // --arp (will display only ARP frames).                                   
                                                            // --ndp (will display only ICMPv6 NDP packets).
                                                            //     -- types 133-137 u icmpv6
                                                            // --igmp (will display only IGMP packets).
--mld (will display only MLD packets).
    -- icmpv6 type 143
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

// Callback funkce pro zpracovani packetu
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
    // TODO: porty - jen u udp, tcp

    // Vypis obsahu packetu
    vypisPacket(packetBody, packetHeader->caplen);

    printf("\n\n");
    
}

// Vypise obsah celeho packetu
void vypisPacket(const u_char *packetos, int delka){

    printf("\n");
    int zbyvaDopsat = (delka) % 16;
    for (int i = 0; i < delka; i++) {
        // byte_offset - vymyslet lip
        if(i % 16 == 0 && i == 0) printf("0x%05x: ", i);

        if(i != 0 && i % 16 == 0){              // Je to posledni pismeno na radku? (krom 1.)
            for(int j = i - 16; j < i; j++){
                if(packetos[j] > 32 && packetos[j] < 127)
                    printf("%c", packetos[j]);
                else 
                    printf(".");
                
                if(j == i - 9) printf(" ");
            }
            printf("\n");
            printf("0x%05x: ", i);
        }

        printf("%02x ", packetos[i]);

        // TODO: opravit aby to tu nebylo 3x
        // Tisknutelne/netisknutelne znaky
        if(i == delka - 1){                       // Konec vypsane zpravy - dopsat zbyle znaky
            if(zbyvaDopsat != 0){                       // Je posledni radek plny?
                for(int k = 0; k < 48 - zbyvaDopsat * 3; k++){
                    printf(" ");
                }

                for(int j = delka - zbyvaDopsat; j < delka; j++){
                    if(packetos[j] > 32 && packetos[j] < 127)
                        printf("%c", packetos[j]);
                    else 
                        printf(".");
                        
                    if(j == delka - zbyvaDopsat + 7) printf(" ");
                }
            } else {                                    // Je plny, dopis ho
                for(int j = 0; j < 16; j++){
                    if(packetos[j] > 32 && packetos[j] < 127)
                        printf("%c", packetos[j]);
                    else 
                        printf(".");

                    if(j == 8) printf(" ");
                }
            }
        }
    }

}
