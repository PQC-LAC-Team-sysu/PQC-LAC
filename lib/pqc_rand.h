//
// Created by 22126 on 2026/9/8.
//

#ifndef PQC_PQC_RAND_H
#define PQC_PQC_RAND_H
#include <cstdint>
using namespace std;
class pqc_rand {
    private:
    // 随机算法的编码，0为真随机，1为均匀分布采样，2为中心二项分布采样
    uint8_t  algorithm;
    // 随机算法的种子
    uint32_t  seed;
    
};


#endif //PQC_PQC_RAND_H
