#ifndef HW_MNGT_H_
#define HW_MNGT_H_

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "../../../../SudoPPA/sdk/api/api.h"
#include "../../../../SudoPPA/sdk/cap/cap.h"


#define SDR_OK                      0x0
#define SDR_BASE                    0x01000000
#define SDR_UNKNOWERR               (SDR_BASE + 0x00000001) /* 未知错误 */
#define SDR_NOTSUPPORT              (SDR_BASE + 0x00000002) /* 不支持 */
#define SDR_COMMFAIL                (SDR_BASE + 0x00000003) /* 通信错误 */
#define SDR_HARDFAIL                (SDR_BASE + 0x00000004) /* 硬件错误 */
#define SDR_OPENDEVICE              (SDR_BASE + 0x00000005) /* 打开设备错误 */
#define SDR_OPENSESSION             (SDR_BASE + 0x00000006) /* 打开会话句柄错误 */
#define SDR_PARDENY                 (SDR_BASE + 0x00000007) /* 权限不满足 */
#define SDR_KEYNOTEXIST             (SDR_BASE + 0x00000008) /* 密钥不存在 */
#define SDR_ALGNOTSUPPORT           (SDR_BASE + 0x00000009) /* 不支持的算法 */
#define SDR_ALGMODNOTSUPPORT        (SDR_BASE + 0x0000000A) /* 不支持的算法模式 */
#define SDR_PKOPERR                 (SDR_BASE + 0x0000000B) /* 公钥运算错误 */
#define SDR_SKOPERR                 (SDR_BASE + 0x0000000C) /* 私钥运算错误 */
#define SDR_SIGNERR                 (SDR_BASE + 0x0000000D) /* 签名错误 */
#define SDR_VERIFYERR               (SDR_BASE + 0x0000000E) /* 验证错误 */
#define SDR_SYMOPERR                (SDR_BASE + 0x0000000F) /* 对称运算错误 */
#define SDR_STEPERR                 (SDR_BASE + 0x00000010) /* 步骤错误 */
#define SDR_FILESIZEERR             (SDR_BASE + 0x00000011) /* 文件大小错误或输入数据长度非法 */
#define SDR_FILENOEXIST             (SDR_BASE + 0x00000012) /* 文件不存在 */
#define SDR_FILEOFSERR              (SDR_BASE + 0x00000013) /* 文件操作偏移量错误 */
#define SDR_KEYTYPEERR              (SDR_BASE + 0x00000014) /* 密钥类型错误 */
#define SDR_KEYERR                  (SDR_BASE + 0x00000015) /* 密钥错误 */
#define SDR_ENCDATAERR              (SDR_BASE + 0x00000016) /* 加密数据错误 */
#define SDR_RANDERR                 (SDR_BASE + 0x00000017) /* 随机数产生失败 */
#define SDR_PRKRERR                 (SDR_BASE + 0x00000018) /* 私钥使用权限获取失败 */
#define SDR_MACERR                  (SDR_BASE + 0x00000019) /* MAC 运算失败 */
#define SDR_FILEEXISTS              (SDR_BASE + 0x0000001A) /* 指定文件已存在 */
#define SDR_FILEWERR                (SDR_BASE + 0x0000001B) /* 文件写入失败 */
#define SDR_NOBUFFER                (SDR_BASE + 0x0000001C) /* 存储空间不足 */
#define SDR_INARGERR                (SDR_BASE + 0x0000001D) /* 输入参数错误 */
#define SDR_OUTARGERR               (SDR_BASE + 0x0000001E) /* 输出参数错误 */
#define SDR_UKEYERR                 (SDR_BASE + 0x0000001F) /* Ukey错误 */
#define SDR_GENKEYERR               (SDR_BASE + 0x00000020) /* 密钥生成错误 */
#define SDR_STATEERR                (SDR_BASE + 0x00000021) /* 状态错误 */
#define SDR_RETRYERR                (SDR_BASE + 0x00000022) /* 重试超过次数 */
#define SDR_DEVICE_BUSY             (SDR_BASE + 0x00000023) /* 设备忙 */

#define SDR_NOMANAGEMENTAUTH        (SDR_BASE + 0x0000001F)
#define SDR_NOOPERATIONAUTH         (SDR_BASE + 0x00000020)
#define SDR_MALLOCERR               (SDR_BASE + 0x00000021)
#define SDR_HANDLENULL              (SDR_BASE + 0x00000022)
#define SDR_PARAMETERSERR           (SDR_BASE + 0x00000023)
#define SDR_DEVICEERR               (SDR_BASE + 0x00000024)
#define SDR_CREATEFILEERR           (SDR_BASE + 0x00000025)
#define SDR_PRIVATEERR              (SDR_BASE + 0x00000026)
#define SDR_LENGTH_ERROR            (SDR_BASE + 0x00000027)
#define SDR_INDEX_ERROR             (SDR_BASE + 0x00000028)
#define SDR_KEYLENGTHERROR          (SDR_BASE + 0x00000029)


typedef struct SDF_Session
{
    void *hDeviceHandle;
    void *private;
#if SDF_ENABLE_SESS_PRIKEY_RIGHT_MODE
    sdf_sess_prikey_right_t key_right;
#endif    
} SDF_Session_t;


//
int SDF_OpenDevice(
    void **phDeviceHandle);

int SDF_CloseDevice(
    void *hDeviceHandle);

int SDF_OpenSession(
    void *hDeviceHandle,
    void **phSessionHandle);

int SDF_CloseSession(
    void *hSessionHandle);


typedef struct devmngt_
{
    void * hdev[128];
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
