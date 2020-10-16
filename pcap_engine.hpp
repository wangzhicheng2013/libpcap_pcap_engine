#pragma once
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <pcap.h>
#include <iostream>
#include <thread>
#include <functional>
#include <atomic>
#include "net_utility.hpp"
std::atomic<uint64_t>total_packets_size;
class pcap_engine {
public:
    pcap_engine() = default;
    ~pcap_engine() {
        close_pcap_handlers();
        join_pcap_threads();
    }
public:
    bool init() {
        if (!load_netcards() || !load_pcap_handlers()) {
            return false;
        }
    }
    inline void set_filter(const char *exp) {
        FILTER = exp;
        is_filter_ = true;
    }
    inline void set_stat_interval(int m) {
        stat_interval_ = m;
    }
    bool load_netcards() {
        pcap_if_t *all_devs = nullptr;
        char err_buf[PCAP_ERRBUF_SIZE] = "";
        if (pcap_findalldevs(&all_devs, err_buf) < 0) {
            std::cerr << "pcap engine find devs failed error:" << err_buf << std::endl;
            if (all_devs) {
                pcap_freealldevs(all_devs);
            }
            return false;
        }
        for (pcap_if_t *p = all_devs;p;p = p->next) {
            if (0 == strcmp(p->name, "lo")) {       // filter loopback
                continue;
            }
            if ((NETCARD_STATUS::UP == G_NET_UTILITY.get_netcard_status(p->name)) &&
                        G_NET_UTILITY.netcard_link_detected(p->name)) {
                
                netcards_.emplace_back(p->name);
                std::cout << "card:" << p->name << " is valid." << std::endl;
            }
            else {
                std::cerr << "card:" << p->name << " invalid." << std::endl;
            }
        }
        pcap_freealldevs(all_devs);
        return !netcards_.empty();
    }
    bool load_pcap_handlers() {
        for (auto &netcard : netcards_) {
            pcap_t *handler = open_pcap_handlers(netcard.c_str());
            if (!handler) {
                continue;
            }
            pcap_handlers_.push_back(handler);
        }
        return !pcap_handlers_.empty();
    }
    bool load_pcap_process() {
        threads_.resize(pcap_handlers_.size());
        try {
            for (int i = 0;i < threads_.size();i++) {
                threads_[i] = std::thread(std::bind(&pcap_engine::process, this, pcap_handlers_[i]));
            }
            stat_thread_ = std::thread(std::bind(&pcap_engine::pcap_stat_thread, this));
        }
        catch (...) {
            return false;
        }
        while (true) {      // let pcap to run otherwise will coredump
            sleep(10);
        }
        return true;
    }
    void process(void *arg) {
        pcap_t *handler = static_cast<pcap_t *>(arg);
        if (!handler) {
            return;
        }
        int pkts_read = -1;
        pcap_loop(handler, pkts_read, (pcap_handler)process_packet, nullptr);
    }
    static void process_packet(u_char *user, struct pcap_pkthdr *pHeadr, u_char *pkt_data) {
        total_packets_size += pHeadr->caplen;
        // to save packet or other transaction
    }
private:
    pcap_t *open_pcap_handlers(const char *netcard) {
        char err_buf[PCAP_ERRBUF_SIZE] = "";
        pcap_t *handler = pcap_open_live(netcard, SNAP_LEN, 1, PCAP_TIMEOUT, err_buf);
        if (!handler) {
            std::cerr << "pcap open live failed error:" << err_buf << std::endl;
            return nullptr;
        }
        struct bpf_program filter = { 0 };
        if (pcap_compile(handler, &filter, FILTER, 1, MASK) < 0 ) {
            std::cerr << "pcap compile failed for filter:" << FILTER << " optimized:1" << " netmask:" << MASK << std::endl;
            std::cerr << "pcap compile failed error:" << pcap_geterr(handler) << std::endl;
            pcap_freecode(&filter);
            pcap_close(handler);
            return nullptr;
        }
        if (is_filter_) {
            if (pcap_setfilter(handler, &filter) < 0) {
                std::cerr << "pcap setfilter failed for filter:" << FILTER << " optimized:1" << " netmask:" << MASK << std::endl;
                std::cerr << "pcap setfilter failed error:" << pcap_geterr(handler) << std::endl;
                pcap_freecode(&filter);
                pcap_close(handler);
                return nullptr;
            }
        }
        pcap_freecode(&filter);
        // pcap_setnonblock is related with pcap_dispatch here do not use pcap_setnonblock
        return handler;
    }
    void close_pcap_handlers() {
        for (auto &handler : pcap_handlers_) {
            if (handler) {
                pcap_close(handler);
            }
        }
    }
    void join_pcap_threads() {
        for (auto &th : threads_) {
            if (th.joinable()) {
                th.join();
            }
        }
        if (stat_thread_.joinable()) {
            stat_thread_.join();
        }
    }
    void pcap_stat_thread() {
        time_t cur_time_stamp = time(nullptr);
        uint64_t last_total_packets_size = 0;
        while (true) {
            if (time(nullptr) - cur_time_stamp < stat_interval_) {
                sleep(1);       // should sleep otherwise cpu will be very high
                continue;
            }
            uint64_t val = total_packets_size.load();
            uint64_t current_total_packets_size =  val - last_total_packets_size;
            std::cout << "current total packets size = " << current_total_packets_size << std::endl;
            std::cout << "total packets size = " << val << std::endl;
            stat_netcards_drop_packet_num();
            std::cout << "total netcards drop packets num = " << all_netcards_drop_packet_num << std::endl;
            for (int i = 0;i < netcards_drop_packet_num.size();i++) {
                std::cout << "netcard index:" << i << " drop packets num = " << netcards_drop_packet_num[i] << std::endl;
            }
            cur_time_stamp = time(nullptr);
            last_total_packets_size = val;
        }
    }
    void stat_netcards_drop_packet_num() {
        struct pcap_stat pstat = { 0 };
        int i = 0;
        int size = pcap_handlers_.size();
        netcards_drop_packet_num.resize(size);
        pcap_t *handler = nullptr;
        for (;i < size;i++) {
            handler = pcap_handlers_[i];
            if (!handler) {
                continue;
            }
            if (pcap_stats(handler, &pstat) < 0) {
                std::cerr << "pcap stat failed. card index:" << i << std::endl;
                continue;
            }
            all_netcards_drop_packet_num += pstat.ps_drop;
            netcards_drop_packet_num[i] += pstat.ps_drop;
        }
    }
private:
    bool is_filter_ = false;
    int stat_interval_ = 60;
private:
    uint64_t all_netcards_drop_packet_num = 0;
private:
    std::vector<std::string>netcards_;
    std::vector<pcap_t *>pcap_handlers_;
    std::vector<uint64_t>netcards_drop_packet_num;

    std::vector<std::thread>threads_;
    std::thread stat_thread_;
private:
    const int SNAP_LEN = 2048;
    const int PCAP_TIMEOUT = 30;    // 30s
    const char *FILTER = "(tcp)";
    uint32_t MASK = 0xFFFFFF00;
};