# td-gossip
Projeto de mensageiro Udp para disciplina transmissão de dados da UnB

José G. H. Cavalcanti - 11/0125011

Utiliza as bibliotecas libnet e libpcap

Comando para compilação:
g++ -std=c++11 -ggdb 110125011_gossip.cpp -o gossip -lpcap -lncurses -pthread `libnet-config --defines` `libnet-config --libs`

Executar como usuário root.
