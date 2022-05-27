#ifndef HW_MNGT_H_
#define HW_MNGT_H_

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

//#include "../../../../SudoPPA/sdk/api/api.h"
//#include "../../../../SudoPPA/sdk/cap/cap.h"
#include "../../../../SudoPPA/library/sdf/sdf.h"


typedef struct devmngt_
{
    void * hdev[128];
    void * hsess[128];
    int algo;
    int api_mode;
    int process_num;
    int thread_num;
    int test_time; /* per minute*/
    uint64_t size;
    uint64_t loop;
    uint8_t key_mode;
    uint8_t dev;
    uint8_t check_rst;
    uint8_t check_perf;
    uint8_t dev_type;
    uint32_t handle_cnt;
} devmngt_t;

typedef struct benchmark_
{
    void *hdev;
    int algo;
    int api_mode;
    int process_num;
    int thread_num;
    int test_time; /* per minute*/
    uint64_t size;
    uint64_t loop;
    uint8_t key_mode;
    uint8_t dev;
    uint8_t check_rst;
    uint8_t check_perf;
    uint8_t dev_type;
    uint32_t handle_cnt;
} benchmark_t;


#endif
