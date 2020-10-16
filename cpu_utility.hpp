#pragma once
#include <stdio.h>
#include <string>
#include <sched.h>
#include <thread>
#include "single_instance.hpp"
class cpu_utility {
public:
    inline bool bind_cpu(unsigned cpu_no) {
        cpu_set_t mask = { 0 };
        CPU_SET(cpu_no, &mask);
        return sched_setaffinity(0, sizeof(mask), &mask) >= 0;
    }
    inline int get_cpu_num() {
        return std::thread::hardware_concurrency();
    }
};

#define  G_CPU_UTILITY single_instance<cpu_utility>::instance()