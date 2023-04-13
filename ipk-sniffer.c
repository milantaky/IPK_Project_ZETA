#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>

int zkontrolujPrepinace(int pocet, char** prepinace);
int vypisAktivniRozhrani();

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

    printf("\nInterface: %s\n", interface);
    printf("Filter: %s\n", filteros);
    printf("Port %d\n", port);
    printf("N %d\n", pocetPacketu);
    printf("pocetProtokolu %d\n\n", pocetProtokolu);

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













//Promiscuous mode is set with pcap_set_promisc().  ZDROJ - https://www.tcpdump.org/manpages/pcap.3pcap.html

// useful linky
// https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html - otevreni ke cmuchu
