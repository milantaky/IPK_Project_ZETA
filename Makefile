# Project 2 - Zeta
# Author: Milan Takac - xtakac09
# 2BIT VUT FIT (BUT)

cc=GCC
CFLAGS= -std=c99 -pedantic -Wall -Wextra -Werror

ipk-sniffer: ipk-sniffer.c
	$(CC) $(CFLAGS) ipk-sniffer.c -o ipk-sniffer