typedef unsigned char u_char;
typedef unsigned int  u_int;
typedef unsigned short u_short;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>   
#include <netinet/if_ether.h>
#include <time.h>

#define MAX_PACKET_SIZE 65535

int vypisAktivniRozhrani();
void packetCallback(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body);
void vypisInfoOPacketu(const struct pcap_pkthdr *header, const u_char *body);
void vytiskniTimestamp();
void vytiskniMAC(const u_char *body);
void vytiskniIPv4(const u_char *packet ,int src, int dest);
void vytiskniIPv6(const u_char *packet ,int src, int dest);
void zpracujIPv6(const u_char *packet, int src);
void vypisPorty(const u_char *packet, int src, int dst);
void vytiskniObsah(const u_char *packetos, int delka);

// TODO : interrupt signal
// TODO : timestamp doladit

int main(int argc, char** argv){
    char interface[20] = "";
    int pocetPacketu = 1;                   // Defaultne
    char filteros[2048] = "";               
    int pocetProtokolu = 0;
    int port = -1;      
    int interfaceSet = 0;    
    
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
                        if(argv[argN][0] < 47 || argv[argN][0] > 58 || (port = atoi(argv[argN])) == 0 || port < 1 || port > 65535){
                            fprintf(stderr, "CHYBA: Neplatny argument za -p (musi byt cislo mezi 0(reserved) - 65535): %s\n", argv[argN]);
                            return 1;
                        }

                    } else {
                        fprintf(stderr, "CHYBA: Chybi argument za -p.\n");
                        return 1;
                    }    

                    // All arguments can be in any order -> {-p port [--tcp|-t] [--udp|-u]} - tohle chapu jako ze p musi byt vzdy pred tcp/udp
                } 
                else if(strcmp(argv[argN], "-n") == 0){  // -n
                    if(argv[argN + 1] != NULL){
                        argN++;
                        if(argv[argN][0] < 47 || argv[argN][0] > 58 || (pocetPacketu = atoi(argv[argN])) == 0 || pocetPacketu < 1){
                            fprintf(stderr, "CHYBA: Neplatny argument za -n (musi byt cislo vetsi 0): %s\n", argv[argN]);
                            return 1;
                        }    
                    } else {
                        fprintf(stderr, "CHYBA: Chybi argument za -n.\n");
                        return 1;
                    }
                }
                // PROTOKOLY --------------------------------------------------------------
                else if(strcmp(argv[argN], "-t") == 0 || strcmp(argv[argN], "--tcp") == 0){   // TCP -t --tcp
                    if(!pocetProtokolu){
                        if(port > 0){  // Je nastaveny port, muze byt u src i dest
                            char port_str[11];
                            sprintf(port_str, "%d", port);
                            strcat(filteros, "tcp port ");
                            strcat(filteros, port_str);
                        } else {
                            strcat(filteros, "tcp");
                        }
                    } else {
                        if(port > 0){
                            char port_str[11];
                            sprintf(port_str, "%d", port);    
                            strcat(filteros, " or tcp port ");;
                            strcat(filteros, port_str);
                        } else {
                            strcat(filteros, " or tcp");
                        }
                    }
                    pocetProtokolu++;
                }
                else if(strcmp(argv[argN], "-u") == 0 || strcmp(argv[argN], "--udp") == 0){   // UDP -u --udp
                    if(!pocetProtokolu){
                        if(port > 0){  // Je nastaveny port, muze byt u src i dest
                            char port_str[11];
                            sprintf(port_str, "%d", port);
                            strcat(filteros, "udp port ");
                            strcat(filteros, port_str);
                        } else {
                            strcat(filteros, "udp");
                        }
                    } else {
                        if(port > 0){
                            char port_str[11];     
                            sprintf(port_str, "%d", port);
                            strcat(filteros, " or udp port ");
                            strcat(filteros, port_str);
                        } else {
                            strcat(filteros, " or udp");
                        }
                    }
                    pocetProtokolu++;
                }
                else if(strcmp(argv[argN], "--icmp4") == 0){    // ICMPv4 --icmp4             
                    if(!pocetProtokolu){
                        strcat(filteros, "icmp");
                    } else {
                        strcat(filteros, " or icmp");
                    }
                    pocetProtokolu++;
                }
                else if(strcmp(argv[argN], "--icmp6") == 0){    // ICMPv6 --icmp6 -> jenom request/reply
                    if(!pocetProtokolu){
                        strcat(filteros, "(icmp6 and (ip6[40] = 128 or ip6[40] = 129))");
                    } else {
                        strcat(filteros, " or (icmp6 and (ip6[40] = 128 or ip6[40] = 129))");
                    }
                    pocetProtokolu++;
                }
                else if(strcmp(argv[argN], "--arp") == 0){      // ARP --arp
                    if(!pocetProtokolu){
                        strcat(filteros, "arp");
                    } else {
                        strcat(filteros, " or arp");
                    }
                    pocetProtokolu++;
                }
                else if(strcmp(argv[argN], "--ndp") == 0){      // NDP --ndp
                    if(!pocetProtokolu){
                        strcat(filteros, "(icmp6 and (ip6[40] = 133 or ip6[40] = 134 or ip6[40] = 135 or ip6[40] = 136 or ip6[40] = 137))");
                    } else {
                        strcat(filteros, " or (icmp6 and (ip6[40] = 133 or ip6[40] = 134 or ip6[40] = 135 or ip6[40] = 136 or ip6[40] = 137))");
                    }
                    pocetProtokolu++;
                }
                else if(strcmp(argv[argN], "--igmp") == 0){     // IGMP --igmp
                    if(!pocetProtokolu){
                        strcat(filteros, "igmp");
                    } else {
                        strcat(filteros, " or igmp");
                    }
                    pocetProtokolu++;
                }
                else if(strcmp(argv[argN], "--mld") == 0){      // MLD --mld
                    if(!pocetProtokolu){
                        strcat(filteros, "(icmp6 and (ip6[40] = 143))");
                    } else {
                        strcat(filteros, " or (icmp6 and (ip6[40] = 143))");
                    }
                    pocetProtokolu++;
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

    // printf("\n------------- MOJE INFO --------------\n");
    // printf("Interface: %s\n", interface);
    // printf("Filter: %s\n", filteros);
    // printf("Port %d\n", port);
    // printf("N %d\n", pocetPacketu);
    // printf("pocetProtokolu %d\n", pocetProtokolu);
    // printf("--------------------------------------\n\n");

    char errBuff[PCAP_ERRBUF_SIZE];
    memset(errBuff, 0, PCAP_ERRBUF_SIZE);
    pcap_t *handle;     // kam se bude chytat

    // ZDROJ: https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
    if((handle = pcap_open_live(interface, MAX_PACKET_SIZE, 1, 1000, errBuff)) == NULL){
        fprintf(stderr, "CHYBA: Nastala chyba pri otevreni interface pro sniffing:\n       %s\n",errBuff);
        return 1;
    }

    // Filtr  --------------------------------------------------------------------------
    // ZDROJ: https://www.tcpdump.org/manpages/pcap_compile.3pcap.html

    if(pocetProtokolu){
        struct bpf_program pFilter; 
        if(pcap_compile(handle, &pFilter, filteros, 0, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR){
            fprintf(stderr, "CHYBA: Prelozeni filtru:\n       %s\n", pcap_geterr(handle));
            return 1;
        }
        
        if(pcap_setfilter(handle, &pFilter) == PCAP_ERROR){
            fprintf(stderr, "CHYBA: Nastaveni filtru:\n       %s\n", pcap_geterr(handle));
            return 1;
        }
    }                      

    // Chytani packetu -----------------------------------------------------------------
    if(pcap_loop(handle, pocetPacketu, packetCallback, (u_char*)handle) != 0){
        fprintf(stderr, "CHYBA: Nastala chyba pri prijimani nebo zpracovani packetu.\n");
        return 1;
    }

    pcap_close(handle);

    return 0;
}

// ---------------- TEST
// bere to :
    // ARP, IGMP, NDP, UDP, UDP s portem, TCP, TCP s portem, ICMPv6
// melo by :
    //snad icmpv4, mld (neprisel zadny),

// TCP
// UDP
// ARP
// ICMPv6
    // NDP
    // MLD
// ICMPv4
// IGMP


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
    
    vytiskniTimestamp();
    vytiskniMAC(packetBody);
    printf("frame length: %d bytes\n", packetHeader->len);

    // ROZDELENI PACKETU --------------------------------------------
        // int protocolType = ntohs(ethHeader->ether_type);      NEFUNGUJE
        // Proto se to deli podle manualniho nalezeni ether_type v packetu - jsou to jen LINKTYPE_ETHERNET, takze jine typy mi sem neprijdou (filtr)

    unsigned char type[3] = "";
    memcpy(type, &packetBody[12], 2);
    type[2] = '\0';

    // Type ARP : 08 06
    if(type[0] == 8 && type[1] == 6) {
        vytiskniIPv4(packetBody, 28, 38);   // arp src 28-31 dst 38-41  
    }

    // Type IPv4: 08 00 -> TCP, UDP, ICMPv4, IGMP
    if(type[0] == 8 && type[1] == 0){
        vytiskniIPv4(packetBody, 26, 30);   // ipv4 src indexy 26-29 dst 30-33

        // Je to TCP/UDP ?
        unsigned char portyTaky[2];
        portyTaky[0] = packetBody[23];      // tam je typ ipv4 protokolu
        portyTaky[1] = '\0';

        // Porty u TCP a UDP vypisuji vzdy
        if(portyTaky[0] == 6 || portyTaky[0] == 17){
            vypisPorty(packetBody, 34, 36); // TCP/UDP porty src 34-35 dst 36-37
        }
    }

    // Type IPv6: 86 dd -> ICMPv6, MLD, NDP 
    if(type[0] == 134 && type[1] == 221){
        vytiskniIPv6(packetBody, 22, 38); // ipv6 src 22-37 dst 38-53
    }

    // Type: resit REVARP? Ne

    vytiskniObsah(packetBody, packetHeader->caplen);

    printf("\n\n");
    
}

// Vypise zdrojovou a cilovou MAC adresu
void vytiskniMAC(const u_char *body){
    // DST indexy 0-5
    // SRC indexy 6-11

    printf("src MAC: ");
    for(int i = 6; i < 11; i++){
        printf("%02x:", body[i]);
    }
    printf("%02x\n", body[11]);


    printf("dst MAC: ");
    for(int i = 0; i < 5; i++){
        printf("%02x:", body[i]);
    }
    printf("%02x\n", body[5]);

}

// Vytiskne timestamp
void vytiskniTimestamp(){

    char timestamp[30];
    time_t now = time(NULL);
    struct tm *tm_now = gmtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", tm_now);

    //.xxx za casem nespecifikovano

    char timeMod[50] = "";
    strncpy(timeMod, timestamp, sizeof(timestamp));

    for(int i = (int) strlen(timestamp) + 1; i > (int) strlen(timestamp) - 2; i--){
        timeMod[i] =  timeMod[i - 1];
    }
    timeMod[22] = ':';

    printf("timestamp: %s\n", timeMod);

}

// Vypise obsah celeho packetu
void vytiskniObsah(const u_char *packetos, int delka){

    printf("\n");
    int zbyvaDopsat = (delka) % 16;
    for (int i = 0; i < delka; i++) {
        if(i % 16 == 0 && i == 0) printf("0x%04x: ", i);

        if(i != 0 && i % 16 == 0){              // Je to posledni pismeno na radku? (krom 1.)
            for(int j = i - 16; j < i; j++){
                if(packetos[j] > 32 && packetos[j] < 127)
                    printf("%c", packetos[j]);
                else 
                    printf(".");
                
                if(j == i - 9) printf(" ");
            }
            printf("\n");
            printf("0x%04x: ", i);
        }

        printf("%02x ", packetos[i]);

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

// Vypise zdrojovou a cilovou IPv4 adresu
void vytiskniIPv4(const u_char *packet ,int src, int dest){
    
    u_char srcAddress[5];
    u_char destAddress[5];
    memcpy(srcAddress, &packet[src], 4);
    memcpy(destAddress, &packet[dest], 4);
    srcAddress[4] = '\0';
    destAddress[4] = '\0';
    
    printf("src IP: ");
    for(int i = 0; i < 4; i++){
        if(i != 3)
            printf("%u.", srcAddress[i]);
        else
            printf("%u", srcAddress[i]);
    }

    printf("\ndst IP: ");
    for(int i = 0; i < 4; i++){
        if(i != 3)
            printf("%u.", destAddress[i]);
        else
            printf("%u", destAddress[i]);
    }
    printf("\n");

}

// Vypise zdrojovou a cilovou IPv6 adresu
void vytiskniIPv6(const u_char *packet ,int src, int dest){
    printf("src IP: ");
    zpracujIPv6(packet, src);
    printf("\ndst IP: ");
    zpracujIPv6(packet, dest);
    printf("\n");
}

// Zpracuje najde v packetu IPv6 adresu a zpracuje podle RFC 5952
void zpracujIPv6(const u_char *packet, int src){
    // delka ipv6 adresy je 16 indexu

    // Nacteni IPv6 adresy
    int dest = src + 16;
    char sourceRaw[16] = "";
    int z = 0;
    for(int i = src; i < dest; i++){
        sourceRaw[z] = packet[i];
        z++;
    }

    // Pridani dvojtecek
    char source[23];
    int k = 0;
    for(int i = 0; i < 16; i++){
        source[k] = sourceRaw[i];
        if((i+1) % 2 == 0 && i != 15){
            k++;
            source[k] = 58;
        }
        k++;
    }

    // Nalezeni indexu nejdelsiho retezce 0
    int delkaPole = 16;
    int start = -1;
    int nejdelsiVyskyt = 0;
    int aktualniVyskyt = 0;
    int aktualniIndex = -1;
    for(int i = 0; i < delkaPole - 1; i +=2){
        if(sourceRaw[i] == 0 && sourceRaw[i + 1] == 0){     // je tohle 0?
            if(aktualniVyskyt == 0){                // nasla se alespon jedna 0
                aktualniIndex = i;
            }
            aktualniVyskyt++;
            if(aktualniVyskyt > nejdelsiVyskyt){    // je to zatim delsi jak max?
                nejdelsiVyskyt = aktualniVyskyt;
                start = aktualniIndex;
            }
        } else {
            aktualniIndex = 0;
            aktualniVyskyt = 0;
        }
    }       

    char finalSource[23];
    // Zacatek
    for(int i = 0; i < start + start/2; i++){
        finalSource[i] = source[i];
    }


    // Zbytek
    char help[23];
    int kolik = 23 - start - 3*nejdelsiVyskyt;
    int odkud = start + 3*nejdelsiVyskyt ;

    for(int i = 0; i < kolik; i++){
        help[i] = source[odkud + i];
    }
    
    int temp = 0;
    for(int i = start + start/2; i < 23 - 2*nejdelsiVyskyt - start; i++){
        finalSource[i] = help[temp];
        temp++;
    }

    for(int i = 0; i < start + 1 + 23 - odkud; i++){
        if(finalSource[i] != 58){
            if((unsigned char) finalSource[i] < 16){      // je tohle < 16
                if(i == 0){             // je to prvni znak
                    if((unsigned char) finalSource[i ] != 0)
                        printf("%x", (unsigned char)finalSource[i]);
                    continue;
                } else {                
                    if((unsigned char) finalSource[i - 1] == 0){    // predesly znak je 0
                        printf("%x", (unsigned char)finalSource[i]); 
                        continue;
                    } else {
                        if((unsigned char) finalSource[i - 1] == 58){
                            if((unsigned char) finalSource[i ] != 0)
                                printf("%x", (unsigned char)finalSource[i]);
                            continue;
                        } else {
                            printf("%02x", (unsigned char)finalSource[i]); 
                            continue;
                        }
                    }
                }
            }
            printf("%02x", (unsigned char)finalSource[i]);
        } else {
            printf(":");
        } 
    }

}

// Pro TCP/UDP - vypis src/dest portu
void vypisPorty(const u_char *packet, int src, int dst){
    
    char sPort[3] = "";
    char dPort[3] = "";

    // Nacteni ASCII portu
    sPort[0] = packet[src];
    sPort[1] = packet[src + 1];
    dPort[0] = packet[dst];
    dPort[1] = packet[dst + 1];

    // Prevod na int
    int sourceFirst  = (int) sPort[0];
    int sourceSecond = (int) sPort[1];

    int destFirst  = (int) dPort[0];
    int destSecond = (int) dPort[1];

    // Uprava a bitovy posun
    sourceFirst  = sourceFirst & 255;
    sourceFirst  = sourceFirst << 8;
    sourceSecond = sourceSecond & 255;

    destFirst  = destFirst & 255;
    destFirst  = destFirst << 8;
    destSecond = destSecond & 255;

    int source = sourceFirst + sourceSecond;
    int destination = destFirst + destSecond;
    
    printf("src port: %d\n", source);
    printf("dst port: %d\n", destination);

}
