#include <iostream>
#include "pcap_engine.hpp"
int main() {
    pcap_engine pcap_eng;
    if (pcap_eng.init()) {
        std::cout << "pcap engine init ok." << std::endl;
    }
    if (!pcap_eng.load_pcap_process()) {
        std::cerr << "load pcap process threads failed." << std::endl;
    }

    return 0;
}