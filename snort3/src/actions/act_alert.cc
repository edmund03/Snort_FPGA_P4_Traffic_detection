//--------------------------------------------------------------------------
// Copyright (C) 2021-2023 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// act_alert.cc author Bhagya Tholpady <bbantwal@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_action.h"
#include "framework/module.h"
#include "protocols/packet.h"

#include "actions.h"
#include <iostream>

#include <zmq.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <thread>
#include <mutex>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <string.h>
#include <arpa/inet.h>
#include "protocols/tcp.h"
#include "json.hpp"
std::mutex fpga_mutex;
std::mutex p4_read_mutex;

#define INTEL_FPGA_PCIE_IOCTL_MAGIC 0x70
#define INTEL_FPGA_PCIE_IOCTL_CHR_SEL_BAR _IOW(INTEL_FPGA_PCIE_IOCTL_MAGIC, \
                                               2, unsigned int)

#define MatchLengthField "length"
#define UdfTablePriority "priority"
#define ServerAddr "tcp://240.127.1.1:9669"
#define ServerAddrHost "tcp://127.0.0.1:9669"
#define P4RT_USER_TABLE_ADD "add"
#define P4RT_USER_TABLE_GET "get"
#define P4RT_USER_TABLE_DEL "del"
#define APP_P4RT_UDF_PORTCLASSIFICATION_NAME "FIXED_ACL"
#define ZMQ_RESPONSE_UDF_BUFFER_SIZE (4 * 1024 * 1024)

#define P4_RULE_MAX 500

const int version_major = 2;
const int version_minor = 0;

#define OPCODE_WRITE_HASH 1
#define OPCODE_DELETE_HASH 2
#define OPCODE_READ_SINGLE_HASH 3
#define OPCODE_READ_ALL_HASH 4

struct pcl_fpga_pcie_cmd
{
    // hash to write
    unsigned int hashvalue;
    unsigned int opcode; // 1 - add 2 - del 3- read one 4- read all
    // user_addr to read.
    void *user_addr;
} __attribute__((packed));

struct Fpga_array_ipv4
{
    uint8_t protocol;
    uint32_t source_ip;
    uint32_t destination_ip;
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t payload4B;
    uint32_t hash;
};
Fpga_array_ipv4 *fpga_data_ipv4_array = (struct Fpga_array_ipv4 *)malloc((1 << 16) * sizeof(struct Fpga_array_ipv4));
int fpga_data_ipv4_count = 0;

struct Fpga_array_ipv6
{
    uint8_t protocol;
    uint32_t source_ip[4];
    uint32_t destination_ip[4];
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t payload4B;
    uint32_t hash;
};
Fpga_array_ipv6 fpga_data_ipv6_array[10000];
int fpga_data_ipv6_count = 0;

struct P4_array_ipv4
{
    uint8_t protocol;
    uint32_t source_ip;
    uint32_t destination_ip;
    // uint16_t source_port;
    uint16_t destination_port;
    uint32_t payload4B;
};
P4_array_ipv4 p4_data_ipv4_array[10000];
int p4_data_ipv4_count = 0;

struct P4_array_ipv6
{
    uint8_t protocol;
    uint32_t source_ip[4];
    uint32_t destination_ip[4];
    // uint16_t source_port;
    uint16_t destination_port;
    uint32_t payload4B;
};
P4_array_ipv6 p4_data_ipv6_array[10000];
int p4_data_ipv6_count = 0;

typedef uint32_t sai_uint32_t;
typedef std::pair<std::string, std::string> FieldValueTuple;
#define fvField std::get<0>
#define fvValue std::get<1>

using namespace snort;
using namespace std;

#define s_name "alert"

#define s_help \
    "generate alert on the current packet"

//-------------------------------------------------------------------------
class AlertAction : public IpsAction
{
public:
    AlertAction() : IpsAction(s_name, nullptr) {}

    void exec(Packet *, const OptTreeNode *otn) override;
};

// crc32tab
static const unsigned int crc32tab[] = {
    0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
    0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
    0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
    0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
    0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
    0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
    0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
    0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
    0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
    0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
    0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
    0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
    0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
    0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
    0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
    0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
    0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
    0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
    0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
    0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
    0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
    0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
    0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
    0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
    0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
    0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
    0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
    0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
    0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
    0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
    0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
    0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
    0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
    0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
    0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
    0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
    0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
    0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
    0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
    0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
    0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
    0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
    0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
    0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
    0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
    0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
    0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
    0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
    0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
    0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
    0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
    0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
    0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
    0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
    0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
    0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
    0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
    0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
    0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
    0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
    0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
    0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
    0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
    0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL};

// crc32计算hash
unsigned int crc32(const unsigned char *buf, unsigned int size)
{
    unsigned int i, crc;
    crc = 0xFFFFFFFF;

    for (i = 0; i < size; i++)
        crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);

    return crc;
}

// 合并ipv4参与计算hash的值
uint32_t packet_ipv4_hash(uint8_t protocol, uint32_t source_ip, uint32_t destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B)
{
    uint8_t buf[] = {
        protocol,
        source_ip >> 24,
        (source_ip >> 16) & 0xff,
        (source_ip >> 8) & 0xff,
        source_ip & 0xff,
        destination_ip >> 24,
        (destination_ip >> 16) & 0xff,
        (destination_ip >> 8) & 0xff,
        destination_ip & 0xff,
        source_port >> 8,
        source_port & 0xff,
        destination_port >> 8,
        destination_port & 0xff,
        payload4B >> 24,
        (payload4B >> 16) & 0xff,
        (payload4B >> 8) & 0xff,
        payload4B & 0xff,
    };
    return crc32(buf, 17);
}

// 合并ipv6参与计算hash的值
uint32_t packet_ipv6_hash(uint8_t protocol, uint32_t *source_ip, uint32_t *destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B)
{
    uint8_t buf[] = {
        protocol,
        source_ip[0] >> 24,
        (source_ip[0] >> 16) & 0xff,
        (source_ip[0] >> 8) & 0xff,
        source_ip[0] & 0xff,
        source_ip[1] >> 24,
        (source_ip[1] >> 16) & 0xff,
        (source_ip[1] >> 8) & 0xff,
        source_ip[1] & 0xff,
        source_ip[2] >> 24,
        (source_ip[2] >> 16) & 0xff,
        (source_ip[2] >> 8) & 0xff,
        source_ip[2] & 0xff,
        source_ip[3] >> 24,
        (source_ip[3] >> 16) & 0xff,
        (source_ip[3] >> 8) & 0xff,
        source_ip[3] & 0xff,
        destination_ip[0] >> 24,
        (destination_ip[0] >> 16) & 0xff,
        (destination_ip[0] >> 8) & 0xff,
        destination_ip[0] & 0xff,
        destination_ip[1] >> 24,
        (destination_ip[1] >> 16) & 0xff,
        (destination_ip[1] >> 8) & 0xff,
        destination_ip[1] & 0xff,
        destination_ip[2] >> 24,
        (destination_ip[2] >> 16) & 0xff,
        (destination_ip[2] >> 8) & 0xff,
        destination_ip[2] & 0xff,
        destination_ip[3] >> 24,
        (destination_ip[3] >> 16) & 0xff,
        (destination_ip[3] >> 8) & 0xff,
        destination_ip[3] & 0xff,
        source_port >> 8,
        source_port & 0xff,
        destination_port >> 8,
        destination_port & 0xff,
        payload4B >> 24,
        (payload4B >> 16) & 0xff,
        (payload4B >> 8) & 0xff,
        payload4B & 0xff,
    };
    return crc32(buf, 41);
}

// 写入fpga驱动
int write_fpga(unsigned int opcode, uint32_t hash_value)
{
    // fpga_mutex.lock();
    ssize_t fd;
    int result;
    // fd = open("/dev/smartips_fpga", O_RDWR | O_CLOEXEC);
    fd = open("/dev/pcl_fpga_pcie_drv", O_RDWR | O_CLOEXEC);
    if (fd == -1)
    {
        std::cout << "failed to open /dev/pcl_fpga_pcie_drv";
        return -1;
    }
    else
    {
        struct pcl_fpga_pcie_cmd kcmd;
        std::cout << "write hash" << std::endl;
        memset(&kcmd, 0, sizeof(struct pcl_fpga_pcie_cmd));
        kcmd.opcode = opcode;
        kcmd.hashvalue = hash_value;
        kcmd.user_addr = NULL;
        result = write(fd, &kcmd, sizeof(struct pcl_fpga_pcie_cmd));
        if (result < 0)
        {
            std::cout << "write hash failed" << std::endl;
            close(fd);
            return -1;
        }
    }
    close(fd);
    // fpga_mutex.unlock();
    return 0;
}

// 生成fpga ipv4 hash表 （五元组 payload4b hash值（32b））
void write_fpga_ipv4_hash(uint8_t protocol, uint32_t source_ip, uint32_t destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B, uint32_t hash_value)
{
    bool flag = false;
    int result = 0;
    unsigned int hash_value_0_15 = hash_value & 0xffff;
    for (int i = 0; i < fpga_data_ipv4_count; i++)
    {
        if ((fpga_data_ipv4_array[i].hash & 0xffff) == hash_value_0_15)
            flag = true;
    }
    if (flag == false)
    {
        result = write_fpga(OPCODE_WRITE_HASH, hash_value);
        if (result)
            return;
        fpga_data_ipv4_array[fpga_data_ipv4_count].protocol = protocol;
        fpga_data_ipv4_array[fpga_data_ipv4_count].source_ip = source_ip;
        fpga_data_ipv4_array[fpga_data_ipv4_count].destination_ip = destination_ip;
        fpga_data_ipv4_array[fpga_data_ipv4_count].source_port = source_port;
        fpga_data_ipv4_array[fpga_data_ipv4_count].destination_port = destination_port;
        fpga_data_ipv4_array[fpga_data_ipv4_count].payload4B = payload4B;
        fpga_data_ipv4_array[fpga_data_ipv4_count].hash = hash_value;
        fpga_data_ipv4_count++;
    }
}

/**
 * @brief 删除fpga ipv4规则
 * @author yifei.zhou
 */
void del_fpga_ipv4_hash()
{
    bool flag = false;
    for (int i = 0; i < fpga_data_ipv4_count; i++)
    {
        write_fpga(OPCODE_DELETE_HASH, fpga_data_ipv4_array[i].hash);
    }
    // 清除数组
    memset(fpga_data_ipv4_array, 0, sizeof(struct Fpga_array_ipv4) * fpga_data_ipv4_count);
    fpga_data_ipv4_count = 0;
}

// 生成fpga ipv4 hash表 （五元组 payload4b hash值（32b））
void write_fpga_ipv6_hash(uint8_t protocol, uint32_t *source_ip, uint32_t *destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B, uint32_t hash_value)
{
    bool flag = false;
    for (int i = 0; i < fpga_data_ipv6_count; i++)
    {
        if (fpga_data_ipv6_array[i].hash == hash_value)
            flag = true;
    }
    if (flag == false)
    {
        fpga_data_ipv6_array[fpga_data_ipv6_count].protocol = protocol;
        fpga_data_ipv6_array[fpga_data_ipv6_count].source_ip[0] = source_ip[0];
        fpga_data_ipv6_array[fpga_data_ipv6_count].source_ip[1] = source_ip[1];
        fpga_data_ipv6_array[fpga_data_ipv6_count].source_ip[2] = source_ip[2];
        fpga_data_ipv6_array[fpga_data_ipv6_count].source_ip[3] = source_ip[3];
        fpga_data_ipv6_array[fpga_data_ipv6_count].destination_ip[0] = destination_ip[0];
        fpga_data_ipv6_array[fpga_data_ipv6_count].destination_ip[1] = destination_ip[1];
        fpga_data_ipv6_array[fpga_data_ipv6_count].destination_ip[2] = destination_ip[2];
        fpga_data_ipv6_array[fpga_data_ipv6_count].destination_ip[3] = destination_ip[3];
        fpga_data_ipv6_array[fpga_data_ipv6_count].source_port = source_port;
        fpga_data_ipv6_array[fpga_data_ipv6_count].destination_port = destination_port;
        fpga_data_ipv6_array[fpga_data_ipv6_count].payload4B = payload4B;
        fpga_data_ipv6_array[fpga_data_ipv6_count].hash = hash_value;
        write_fpga(OPCODE_WRITE_HASH, hash_value);
        fpga_data_ipv6_count++;
    }
}

/**
 * @brief 删除fpga ipv6规则
 * @author yifei.zhou
 */
void del_fpga_ipv6_hash()
{
    bool flag = false;
    for (int i = 0; i < fpga_data_ipv6_count; i++)
    {
        write_fpga(OPCODE_DELETE_HASH, fpga_data_ipv6_array[i].hash);
    }
    // 清除数组
    memset(fpga_data_ipv6_array, 0, sizeof(struct Fpga_array_ipv6) * fpga_data_ipv6_count);
    fpga_data_ipv6_count = 0;
}

// 处理ipv4的alert数据包
void packet_ipv4_hash_crc32(Packet *p, string pro)
{
    if (pro == std::string("TCP"))
    {
        SfIpString src_addr, dst_addr;
        uint16_t source_port = 0, destination_port = 0;
        uint8_t protocol = 6;
        source_port = p->ptrs.sp;
        destination_port = p->ptrs.dp;
        if (p->ptrs.tcph == nullptr || p->ptrs.ip_api.ip_data() == nullptr)
            return;
        const uint16_t tcph_len = p->ptrs.tcph->hlen();
        const uint8_t *tcp_data = p->ptrs.ip_api.ip_data() + tcph_len;
        const uint16_t ip_header_len = p->ptrs.ip_api.dgram_len() - p->ptrs.ip_api.pay_len();
        // make suer first 512bits has 4 bytes payload. -- byhs
        // if (ip_header_len + tcph_len + 14 > 60)
        //     return;
        uint32_t payload4B = (tcp_data[0] << 24) | (tcp_data[1] << 16) | (tcp_data[2] << 8) | tcp_data[3];
        string sip = p->ptrs.ip_api.get_src()->ntop(src_addr);
        string dip = p->ptrs.ip_api.get_dst()->ntop(dst_addr);
        if (sip.length() <= 16 && dip.length() <= 16)
        {
            struct in_addr sp, dp;
            u_int32_t source_ip, destination_ip;
            inet_pton(AF_INET, sip.c_str(), (void *)&sp);
            inet_pton(AF_INET, dip.c_str(), (void *)&dp);
            source_ip = sp.s_addr;
            destination_ip = dp.s_addr;
            source_ip = ntohl(source_ip);
            destination_ip = ntohl(destination_ip);
            uint32_t result = packet_ipv4_hash(protocol, source_ip, destination_ip, source_port, destination_port, payload4B);
            write_fpga_ipv4_hash(protocol, source_ip, destination_ip, source_port, destination_port, payload4B, result);
        }
    }
    else
    {
        const ip::IP4Hdr *const ip4h = p->ptrs.ip_api.get_ip4h();
        IpProtocol proto = ip4h->proto();
        uint8_t protocol = (uint8_t)proto;
        uint32_t source_ip = ntohl(ip4h->get_src());
        uint32_t destination_ip = ntohl(ip4h->get_dst());
        uint16_t source_port = p->ptrs.sp;
        uint16_t destination_port = p->ptrs.dp;
        uint32_t payload4B = (p->data[0] << 24) | (p->data[1] << 16) | (p->data[2] << 8) | p->data[3];
        uint32_t result = packet_ipv4_hash(protocol, source_ip, destination_ip, source_port, destination_port, payload4B);
        write_fpga_ipv4_hash(protocol, source_ip, destination_ip, source_port, destination_port, payload4B, result);
    }
}

// 处理ipv6的alert数据包
void packet_ipv6_hash_crc32(Packet *p)
{
    if (p->ptrs.ip_api.get_ip6h() == nullptr)
        return;
    const ip::IP6Hdr *const ip6h = p->ptrs.ip_api.get_ip6h();
    IpProtocol proto = ip6h->proto();
    uint8_t protocol = (uint8_t)proto;
    uint32_t source_ip[4] = {ip6h->get_src()->u6_addr32[0], ip6h->get_src()->u6_addr32[1], ip6h->get_src()->u6_addr32[2], ip6h->get_src()->u6_addr32[3]};
    uint32_t destination_ip[4] = {ip6h->get_dst()->u6_addr32[0], ip6h->get_dst()->u6_addr32[1], ip6h->get_dst()->u6_addr32[2], ip6h->get_dst()->u6_addr32[3]};
    uint16_t source_port = p->ptrs.sp;
    uint16_t destination_port = p->ptrs.dp;
    uint32_t payload4B = (p->data[0] << 24) | (p->data[1] << 16) | (p->data[2] << 8) | p->data[3];
    uint32_t result = packet_ipv6_hash(protocol, source_ip, destination_ip, source_port, destination_port, payload4B);
    write_fpga_ipv6_hash(protocol, source_ip, destination_ip, source_port, destination_port, payload4B, result);
}

// 获取当前时间
string get_time()
{
    auto now = std::chrono::system_clock::now();
    uint64_t dis_millseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() - std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() * 1000;
    time_t tt = std::chrono::system_clock::to_time_t(now);
    auto time_tm = localtime(&tt);
    char strTime[25] = {0};
    sprintf(strTime, "%d-%02d-%02d %02d:%02d:%02d %03d", time_tm->tm_year + 1900,
            time_tm->tm_mon + 1, time_tm->tm_mday, time_tm->tm_hour,
            time_tm->tm_min, time_tm->tm_sec, (int)dis_millseconds);
    return strTime;
}

/**
 * @brief 清除日志信息
 *
 */
void write_log_boundary()
{
    p4_read_mutex.lock();
    const char *dir1 = "/home/edmund/log/ips_log.txt";
    const char *boundary1 = "ips-log----------------------------------------";
    const char *dir2 = "/home/edmund/log/p4_log.txt";
    const char *boundary2 = "p4-log----------------------------------------";
    const char *dir3 = "/home/edmund/log/fpga_log.txt";
    const char *boundary3 = "fpga-log----------------------------------------";
    const char *dir;
    const char *boundary;
    fstream file;
    if (distribution_path == 1)
    {
        dir = dir1;
        boundary = boundary1;
    }
    else if (distribution_path == 2)
    {
        dir = dir2;
        boundary = boundary2;
    }
    else if (distribution_path == 3)
    {
        dir = dir3;
        boundary = boundary3;
    }
    file.open(dir, ios::in);
    if (!file)
    {
        ofstream fout(dir);
    }
    file.close();
    file.open(dir, ios::ate | ios::app);
    file << boundary << endl;
    file.close();
    p4_read_mutex.unlock();
}

// 读取fpga ipv4 日志
int read_fpga_log_ipv4(ssize_t fd, uint8_t protocol, uint32_t source_ip, uint32_t destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B, uint32_t hash)
{
    // fpga_mutex.lock();

    int result;
    struct pcl_fpga_pcie_cmd kcmd;
    // std::cout << "read hash" << std::endl;
    uint32_t *count = (uint32_t *)malloc(sizeof(uint32_t));
    memset(count, 0, sizeof(uint32_t));
    memset(&kcmd, 0, sizeof(struct pcl_fpga_pcie_cmd));
    kcmd.opcode = OPCODE_READ_SINGLE_HASH;
    kcmd.hashvalue = hash;
    kcmd.user_addr = count;
    result = read(fd, &kcmd, sizeof(struct pcl_fpga_pcie_cmd));
    if (result < 0)
    {
        std::cout << "read hash failed" << std::endl;
        close(fd);
        return -1;
    }
    const char *dir = "/home/edmund/log/fpga_log.txt";
    string time = get_time();
    struct in_addr addr1, addr2;
    char ipaddr_S[16];
    char ipaddr_D[16];
    addr1.s_addr = htonl(source_ip);
    addr2.s_addr = htonl(destination_ip);
    inet_ntop(AF_INET, (void *)&addr1, ipaddr_S, (socklen_t)sizeof(ipaddr_S));
    inet_ntop(AF_INET, (void *)&addr2, ipaddr_D, (socklen_t)sizeof(ipaddr_D));
    fstream file;
    file.open(dir, ios::in);
    if (!file)
    {
        ofstream fout(dir);
    }
    file.close();
    file.open(dir, ios::out | ios::app);
    int p_num;
    string p = std::to_string(protocol);
    std::istringstream pp(p);
    pp >> p_num;

    if (p_num == 17)
    {
        file << time << " hash:" << hex << hash << " count:" << dec << *count << "  UDP  " << ipaddr_S << ":" << dec << source_port << "->" << ipaddr_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << endl;
    }
    else if (p_num == 6)
    {
        file << time << "hash:" << hex << hash << " count:" << dec << *count << "  TCP  " << ipaddr_S << ":" << dec << source_port << "->" << ipaddr_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << endl;
    }
    else
    {
        file << time << "hash:" << hex << hash << " count:" << dec << *count << "  " << p_num << "  " << ipaddr_S << ":" << dec << source_port << "->" << ipaddr_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << endl;
    }
    file.close();

    // fpga_mutex.unlock();
}

// 读取fpga ipv6 日志
void read_fpga_log_ipv6(uint8_t protocol, uint32_t *source_ip, uint32_t *destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B, uint32_t hash)
{
    ssize_t fd;
    fd = open("/dev/pcl_fpga_pcie_drv", O_RDWR | O_CLOEXEC);
    if (fd == -1)
    {
        throw std::runtime_error("could not open character device; "
                                 "ensure that Intel FPGA kernel driver "
                                 "has been loaded");
    }
    else
    {
        // fpga_mutex.lock();
        uint32_t hash_value = hash;
        uint32_t index = 0x40000000 + (hash_value & 0xff);
        uint64_t hash_addr = 0xc074;
        int result = ioctl(fd, INTEL_FPGA_PCIE_IOCTL_CHR_SEL_BAR, 2);
        pwrite(fd, &index, sizeof(index), hash_addr);
        uint32_t count;
        pread(fd, &count, sizeof(count), hash_addr);
        const char *dir = "/home/edmund/log/fpga_log.txt";
        string time = get_time();
        struct in6_addr addr1, addr2;
        char ipaddr6_S[INET6_ADDRSTRLEN];
        char ipaddr6_D[INET6_ADDRSTRLEN];
        addr1.__in6_u.__u6_addr32[0] = source_ip[0];
        addr1.__in6_u.__u6_addr32[1] = source_ip[1];
        addr1.__in6_u.__u6_addr32[2] = source_ip[2];
        addr1.__in6_u.__u6_addr32[3] = source_ip[3];
        addr2.__in6_u.__u6_addr32[0] = destination_ip[0];
        addr2.__in6_u.__u6_addr32[1] = destination_ip[1];
        addr2.__in6_u.__u6_addr32[2] = destination_ip[2];
        addr2.__in6_u.__u6_addr32[3] = destination_ip[3];
        inet_ntop(AF_INET6, (void *)&addr1, ipaddr6_S, (socklen_t)sizeof(ipaddr6_S));
        inet_ntop(AF_INET6, (void *)&addr2, ipaddr6_D, (socklen_t)sizeof(ipaddr6_D));
        fstream file;
        file.open(dir, ios::in);
        if (!file)
        {
            ofstream fout(dir);
        }
        file.close();
        file.open(dir, ios::out | ios::app);

        int p_num;
        string p = std::to_string(protocol);
        std::istringstream pp(p);
        pp >> p_num;

        if (p_num == 17)
        {
            file << time << " hash:" << hex << hash << " count:" << count << "  UDP  " << ipaddr6_S << ":" << dec << source_port << "->" << ipaddr6_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << endl;
        }
        else if (p_num == 6)
        {
            file << time << " hash:" << hex << hash << " count:" << count << "  TCP  " << ipaddr6_S << ":" << dec << source_port << "->" << ipaddr6_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << endl;
        }
        else
        {
            file << time << " hash:" << hex << hash << " count:" << count << "  " << p_num << "  " << ipaddr6_S << ":" << dec << source_port << "->" << ipaddr6_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << endl;
        }
        file.close();
        // fpga_mutex.unlock();
    }
}

// 读取fpga日志
void read_fpga_log()
{

    int result = 0;
    ssize_t fd;
    fd = open("/dev/pcl_fpga_pcie_drv", O_RDWR | O_CLOEXEC);
    if (fd == -1)
    {
        std::cout << "failed to open /dev/pcl_fpga_pcie_drv";
        return;
    }

    for (int i = 0; i < fpga_data_ipv4_count; i++)
    {
        // printf("debug: packet is captured\n");
        if (i == 0)
            write_log_boundary();
        result = read_fpga_log_ipv4(fd, fpga_data_ipv4_array[i].protocol, fpga_data_ipv4_array[i].source_ip, fpga_data_ipv4_array[i].destination_ip, fpga_data_ipv4_array[i].source_port, fpga_data_ipv4_array[i].destination_port, fpga_data_ipv4_array[i].payload4B, fpga_data_ipv4_array[i].hash);
        if (result)
            return;
    }

    close(fd);
    /*
    for (int j = 0; j < fpga_data_ipv6_count; j++)
    {
        read_fpga_log_ipv6(fpga_data_ipv6_array[j].protocol, fpga_data_ipv6_array[j].source_ip, fpga_data_ipv6_array[j].destination_ip, fpga_data_ipv6_array[j].source_port, fpga_data_ipv6_array[j].destination_port, fpga_data_ipv6_array[j].payload4B, fpga_data_ipv6_array[i].hash);
    }
    */
}
string buildJson(const vector<FieldValueTuple> &fv)
{
    nlohmann::json j = nlohmann::json::array();

    // we use array to save order
    for (const auto &i : fv)
    {
        j.push_back(fvField(i));
        j.push_back(fvValue(i));
    }

    return j.dump();
}

void readJson(const string &jsonstr, vector<FieldValueTuple> &fv)
{
    nlohmann::json j = nlohmann::json::parse(jsonstr);

    FieldValueTuple e;

    for (size_t i = 0; i < j.size(); i += 2)
    {
        fvField(e) = j[i];
        fvValue(e) = j[i + 1];
        fv.push_back(e);
    }
}

std::vector<FieldValueTuple> zmqSendRequest(const std::string &msg, std::string key, std::string command)
{
    void *zmqctx = NULL;
    void *zmqsock;
    std::vector<uint8_t> m_buffer;
    zmqctx = zmq_ctx_new();
    zmqsock = zmq_socket(zmqctx, ZMQ_REQ);
    const char *addr;
    if (running_mode == 0)
    {
        addr = ServerAddr;
    }
    else
    {
        addr = ServerAddrHost;
    }
    if (zmq_connect(zmqsock, addr))
    {
        printf("zmq_connect failed\n");
    }
    m_buffer.resize(ZMQ_RESPONSE_UDF_BUFFER_SIZE);
    int rc = zmq_send(zmqsock, msg.c_str(), msg.length(), 0);
    std::vector<FieldValueTuple> values;
    if (rc <= 0)
    {
        printf("Failed to create UDF entry in table\n");
    }
    else
    {
        zmq_pollitem_t items[1] = {};
        items[0].socket = zmqsock;
        items[0].events = ZMQ_POLLIN;
        int rd = zmq_poll(items, 1, 5000);
        if (rd == 0)
        {
            if (command == "get")
            {
                printf("Read ZMQ POLL time out for interface response\n");
            }
            else
            {
                printf("ZMQ POLL time out for interface response\n");
            }
        }
        if (rd < 0)
        {
            printf("ZMQ POLL failed for interface response\n");
        }
        rd = zmq_recv(zmqsock, m_buffer.data(), ZMQ_RESPONSE_UDF_BUFFER_SIZE, 0);
        if (rd < 0)
        {
            printf("ZMQ RECV failed for interface response\n");
        }
        if (rd > ZMQ_RESPONSE_UDF_BUFFER_SIZE)
        {
            printf("ZMQ RECV overflow  for interface response\n");
        }
        m_buffer.at(rc) = 0;
        readJson((char *)m_buffer.data(), values);
        FieldValueTuple fvt = values.at(0);
        const std::string &opkey = fvField(fvt);
        const std::string &op = fvValue(fvt);
        values.erase(values.begin());
        if (op == command && key == opkey)
        {
            FieldValueTuple ret = values.at(0);
            const std::string &retvalue = fvValue(ret);
            if (retvalue != std::string("0"))
            {
                printf("invalid param or no sys memory for udf interface\n");
            }
        }
        else
        {
            printf("ZMQ RECV wrong data from interface response\n");
        }
    }
    zmq_close(zmqsock);
    zmq_ctx_destroy(zmqctx);
    return values;
}

// 准备下发格式，下发P4流表（ipv4）
// void send_p4_ipv4(uint8_t protocol, uint32_t source_ip, uint32_t destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B)
void send_p4_ipv4(string command, uint8_t protocol, uint32_t source_ip, uint32_t destination_ip, uint16_t destination_port, uint32_t payload4B)
{
    uint32_t ipmask = 0xffffffff;
    ipmask = htole32(ipmask);

    std::ostringstream s_ip;
    s_ip << std::hex << std::setw(8) << std::setfill('0') << source_ip;
    std::string S_ip = std::string("00000000" + s_ip.str() + "0000000000000000");

    std::ostringstream d_ip;
    d_ip << std::hex << std::setw(8) << std::setfill('0') << destination_ip;
    std::string D_ip = std::string("00000000" + d_ip.str() + "0000000000000000");

    std::ostringstream s_ipmask;
    s_ipmask << std::hex << std::setw(8) << std::setfill('0') << ipmask;
    std::string S_ipmask = std::string("00000000" + s_ipmask.str() + "0000000000000000");

    int p_num;
    string p = std::to_string(protocol);
    std::istringstream pp(p);
    pp >> p_num;
    std::ostringstream prot;
    prot << std::hex << p_num;
    std::string proto_value = prot.str();
    /**
        std::ostringstream soport;
        soport << std::hex << source_port;
        std::string sport_value = soport.str();
    */
    std::ostringstream deport;
    deport << std::hex << destination_port;
    std::string dport_value = deport.str();

    std::ostringstream payl4;
    payl4 << std::hex << payload4B;
    std::string pay_value = payl4.str();

    // std::string command = P4RT_USER_TABLE_ADD;
    std::string udf_table_name = APP_P4RT_UDF_PORTCLASSIFICATION_NAME;
    std::string proto = "local_md.lkp.ip_proto";
    std::string sip = "local_md.lkp.ip_src_addr";
    std::string dip = "local_md.lkp.ip_dst_addr";
    // std::string sport = "local_md.lkp.l4_src_port";
    std::string dport = "local_md.lkp.l4_dst_port";
    std::string pay4b = "local_md.payload32_0";
    sai_uint32_t priority = 100;
    // long unsigned int match_length = 6;
    long unsigned int match_length = 5;
    std::string ips_action = "deny";
    long unsigned int ips_action_length = 0;
    std::string p4_action = "port_collection";
    long unsigned int p4_action_length = 3;
    std::string mindex = "meter_index";
    uint8_t meter_index = 0;
    std::string sid = "session_id";
    uint16_t session_id = 10;
    std::string appid = "app_id";
    uint16_t app_id = 111;
    std::vector<FieldValueTuple> udf_entry_attrs;
    FieldValueTuple opcommand(udf_table_name, command);
    udf_entry_attrs.insert(udf_entry_attrs.begin(), opcommand);
    udf_entry_attrs.push_back(std::make_pair(MatchLengthField, std::to_string(match_length)));
    udf_entry_attrs.push_back(std::make_pair(sip, std::string("0x" + S_ip + "&" + "0x" + S_ipmask)));
    udf_entry_attrs.push_back(std::make_pair(dip, std::string("0x" + D_ip + "&" + "0x" + S_ipmask)));
    udf_entry_attrs.push_back(std::make_pair(proto, "0x" + proto_value + "&" + "0xff"));
    // udf_entry_attrs.push_back(std::make_pair(sport, "0x" + sport_value + "&" + "0xffff"));
    udf_entry_attrs.push_back(std::make_pair(dport, "0x" + dport_value + "&" + "0xffff"));
    udf_entry_attrs.push_back(std::make_pair(pay4b, "0x" + pay_value + "&" + "0xffffffff"));
    udf_entry_attrs.push_back(std::make_pair(UdfTablePriority, std::to_string(priority)));
    if (distribution_path == 1)
    {
        udf_entry_attrs.push_back(std::make_pair(ips_action, std::to_string(ips_action_length)));
    }
    else
    {
        udf_entry_attrs.push_back(std::make_pair(p4_action, std::to_string(p4_action_length)));
        udf_entry_attrs.push_back(std::make_pair(mindex, std::to_string(meter_index)));
        udf_entry_attrs.push_back(std::make_pair(sid, std::to_string(session_id)));
        udf_entry_attrs.push_back(std::make_pair(appid, std::to_string(app_id)));
    }
    std::string msg = buildJson(udf_entry_attrs);
    std::vector<FieldValueTuple> send_value = zmqSendRequest(msg, udf_table_name, command);
}

std::string NetworkOrderTransToLittleEndian(uint32_t *value, int size)
{
    std::string S_value;
    // to host byte order
    for (int i = 0; i < size; i++)
    {
        std::ostringstream s_value_u32;
        value[i] = ntohl(value[i]);
        value[i] = htole32(value[i]);
        s_value_u32 << std::hex << std::setw(8) << std::setfill('0') << value[i];
        S_value.append(s_value_u32.str());
    }
    return S_value;
}

// 准备下发格式，下发P4流表（ipv6）
// void send_p4_ipv6(uint8_t protocol, uint32_t *source_ip, uint32_t *destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B)
void send_p4_ipv6(string command, uint8_t protocol, uint32_t *source_ip, uint32_t *destination_ip, uint16_t destination_port, uint32_t payload4B)
{
    std::string S_ipV6;
    std::string D_ipV6;
    std::string S_ipV6Mask;
    uint32_t ipmask[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    S_ipV6 = NetworkOrderTransToLittleEndian(source_ip, 4);
    D_ipV6 = NetworkOrderTransToLittleEndian(destination_ip, 4);
    S_ipV6Mask = NetworkOrderTransToLittleEndian(ipmask, 4);

    int p_num;
    string p = std::to_string(protocol);
    std::istringstream pp(p);
    pp >> p_num;
    std::ostringstream prot;
    prot << std::hex << p_num;
    std::string proto_value = prot.str();
    /*
        std::ostringstream soport;
        soport << std::hex << source_port;
        std::string sport_value = soport.str();
    */
    std::ostringstream deport;
    deport << std::hex << destination_port;
    std::string dport_value = deport.str();

    std::ostringstream payl4;
    payl4 << std::hex << payload4B;
    std::string pay_value = payl4.str();

    // std::string command = P4RT_USER_TABLE_ADD;
    std::string udf_table_name = APP_P4RT_UDF_PORTCLASSIFICATION_NAME;
    std::string proto = "local_md.lkp.ip_proto";
    std::string sip = "local_md.lkp.ip_src_addr";
    std::string dip = "local_md.lkp.ip_dst_addr";
    // std::string sport = "local_md.lkp.l4_src_port";
    std::string dport = "local_md.lkp.l4_dst_port";
    std::string pay4b = "local_md.payload32_0";
    sai_uint32_t priority = 100;
    // long unsigned int match_length = 6;
    long unsigned int match_length = 5;
    std::string ips_action = "deny";
    long unsigned int ips_action_length = 0;
    std::string p4_action = "port_collection";
    long unsigned int p4_action_length = 3;
    std::string mindex = "meter_index";
    uint8_t meter_index = 0;
    std::string sid = "session_id";
    uint16_t session_id = 10;
    std::string appid = "app_id";
    uint16_t app_id = 111;
    std::vector<FieldValueTuple> udf_entry_attrs;
    FieldValueTuple opcommand(udf_table_name, command);
    udf_entry_attrs.insert(udf_entry_attrs.begin(), opcommand);
    udf_entry_attrs.push_back(std::make_pair(MatchLengthField, std::to_string(match_length)));
    udf_entry_attrs.push_back(std::make_pair(sip, std::string("0x" + S_ipV6 + "&" + "0x" + S_ipV6Mask)));
    udf_entry_attrs.push_back(std::make_pair(dip, std::string("0x" + D_ipV6 + "&" + "0x" + S_ipV6Mask)));
    udf_entry_attrs.push_back(std::make_pair(proto, "0x" + proto_value + "&" + "0xff"));
    // udf_entry_attrs.push_back(std::make_pair(sport, "0x" + sport_value + "&" + "0xffff"));
    udf_entry_attrs.push_back(std::make_pair(dport, "0x" + dport_value + "&" + "0xffff"));
    udf_entry_attrs.push_back(std::make_pair(pay4b, "0x" + pay_value + "&" + "0xffffffff"));
    udf_entry_attrs.push_back(std::make_pair(UdfTablePriority, std::to_string(priority)));
    if (distribution_path == 1)
    {
        udf_entry_attrs.push_back(std::make_pair(ips_action, std::to_string(ips_action_length)));
    }
    else
    {
        udf_entry_attrs.push_back(std::make_pair(p4_action, std::to_string(p4_action_length)));
        udf_entry_attrs.push_back(std::make_pair(mindex, std::to_string(meter_index)));
        udf_entry_attrs.push_back(std::make_pair(sid, std::to_string(session_id)));
        udf_entry_attrs.push_back(std::make_pair(appid, std::to_string(app_id)));
    }
    std::string msg = buildJson(udf_entry_attrs);
    std::vector<FieldValueTuple> send_value = zmqSendRequest(msg, udf_table_name, command);
}

// 生成p4 data 表 （ipv4 五元组 payload4b）
// void write_p4_data_ipv4(uint8_t protocol, uint32_t source_ip, uint32_t destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B)
void write_p4_data_ipv4(uint8_t protocol, uint32_t source_ip, uint32_t destination_ip, uint16_t destination_port, uint32_t payload4B)
{
    if ((p4_data_ipv4_count + p4_data_ipv6_count) >= P4_RULE_MAX) // 超过1000条不再下发，p4也只能容纳一千多条，用于测试 -- yifei.zhou
        return;
    bool flag = false;
    for (int i = 0; i < p4_data_ipv4_count; i++)
    {
        // if (p4_data_ipv4_array[i].protocol == protocol && p4_data_ipv4_array[i].source_ip == source_ip && p4_data_ipv4_array[i].destination_ip == destination_ip && p4_data_ipv4_array[i].source_port == source_port && p4_data_ipv4_array[i].destination_port == destination_port && p4_data_ipv4_array[i].payload4B == payload4B)
        if (p4_data_ipv4_array[i].protocol == protocol && p4_data_ipv4_array[i].source_ip == source_ip && p4_data_ipv4_array[i].destination_ip == destination_ip && p4_data_ipv4_array[i].destination_port == destination_port && p4_data_ipv4_array[i].payload4B == payload4B)
            flag = true;
    }
    if (flag == false)
    {
        p4_data_ipv4_array[p4_data_ipv4_count].protocol = protocol;
        p4_data_ipv4_array[p4_data_ipv4_count].source_ip = source_ip;
        p4_data_ipv4_array[p4_data_ipv4_count].destination_ip = destination_ip;
        // p4_data_ipv4_array[p4_data_ipv4_count].source_port = source_port;
        p4_data_ipv4_array[p4_data_ipv4_count].destination_port = destination_port;
        p4_data_ipv4_array[p4_data_ipv4_count].payload4B = payload4B;
        // send_p4_ipv4(protocol, source_ip, destination_ip, source_port, destination_port, payload4B);
        send_p4_ipv4(P4RT_USER_TABLE_ADD, protocol, source_ip, destination_ip, destination_port, payload4B);
        p4_data_ipv4_count++;
    }
}

/**
 * @brief 从p4中删除ipv4规则
 * @author yifei.zhou
 */
void del_p4_data_ipv4()
{
    for (int i = 0; i < p4_data_ipv4_count; i++)
    {
        send_p4_ipv4(P4RT_USER_TABLE_DEL,
                     p4_data_ipv4_array[i].protocol,
                     p4_data_ipv4_array[i].source_ip,
                     p4_data_ipv4_array[i].destination_ip,
                     p4_data_ipv4_array[i].destination_port,
                     p4_data_ipv4_array[i].payload4B);
    }
    // 清空数组
    memset(p4_data_ipv4_array, 0, sizeof(struct P4_array_ipv4) * p4_data_ipv4_count);
    p4_data_ipv4_count = 0;
}

// 生成p4 data 表 （ipv6 五元组 payload4b）
// void write_p4_data_ipv6(uint8_t protocol, uint32_t *source_ip, uint32_t *destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B)
void write_p4_data_ipv6(uint8_t protocol, uint32_t *source_ip, uint32_t *destination_ip, uint16_t destination_port, uint32_t payload4B)
{
    if ((p4_data_ipv4_count + p4_data_ipv6_count) >= P4_RULE_MAX) // 超过1000条不再下发，p4也只能容纳一千多条，用于测试 -- yifei.zhou
        return;
    bool flag = false;
    for (int i = 0; i < p4_data_ipv6_count; i++)
    {
        // if (p4_data_ipv6_array[i].protocol == protocol && p4_data_ipv6_array[i].source_ip[0] == source_ip[0] && p4_data_ipv6_array[i].source_ip[1] == source_ip[1] && p4_data_ipv6_array[i].source_ip[2] == source_ip[2] && p4_data_ipv6_array[i].source_ip[3] == source_ip[3] && p4_data_ipv6_array[i].destination_ip[0] == destination_ip[0] && p4_data_ipv6_array[i].destination_ip[1] == destination_ip[1] && p4_data_ipv6_array[i].destination_ip[2] == destination_ip[2] && p4_data_ipv6_array[i].destination_ip[3] == destination_ip[3] && p4_data_ipv6_array[i].source_port == source_port && p4_data_ipv6_array[i].destination_port == destination_port && p4_data_ipv6_array[i].payload4B == payload4B)
        if (p4_data_ipv6_array[i].protocol == protocol && p4_data_ipv6_array[i].source_ip[0] == source_ip[0] && p4_data_ipv6_array[i].source_ip[1] == source_ip[1] && p4_data_ipv6_array[i].source_ip[2] == source_ip[2] && p4_data_ipv6_array[i].source_ip[3] == source_ip[3] && p4_data_ipv6_array[i].destination_ip[0] == destination_ip[0] && p4_data_ipv6_array[i].destination_ip[1] == destination_ip[1] && p4_data_ipv6_array[i].destination_ip[2] == destination_ip[2] && p4_data_ipv6_array[i].destination_ip[3] == destination_ip[3] && p4_data_ipv6_array[i].destination_port == destination_port && p4_data_ipv6_array[i].payload4B == payload4B)
            flag = true;
    }
    if (flag == false)
    {
        p4_data_ipv6_array[p4_data_ipv6_count].protocol = protocol;
        p4_data_ipv6_array[p4_data_ipv6_count].source_ip[0] = source_ip[0];
        p4_data_ipv6_array[p4_data_ipv6_count].source_ip[1] = source_ip[1];
        p4_data_ipv6_array[p4_data_ipv6_count].source_ip[2] = source_ip[2];
        p4_data_ipv6_array[p4_data_ipv6_count].source_ip[3] = source_ip[3];
        p4_data_ipv6_array[p4_data_ipv6_count].destination_ip[0] = destination_ip[0];
        p4_data_ipv6_array[p4_data_ipv6_count].destination_ip[1] = destination_ip[1];
        p4_data_ipv6_array[p4_data_ipv6_count].destination_ip[2] = destination_ip[2];
        p4_data_ipv6_array[p4_data_ipv6_count].destination_ip[3] = destination_ip[3];
        // p4_data_ipv6_array[p4_data_ipv6_count].source_port = source_port;
        p4_data_ipv6_array[p4_data_ipv6_count].destination_port = destination_port;
        p4_data_ipv6_array[p4_data_ipv6_count].payload4B = payload4B;
        // send_p4_ipv6(protocol, source_ip, destination_ip, source_port, destination_port, payload4B);
        send_p4_ipv6(P4RT_USER_TABLE_ADD, protocol, source_ip, destination_ip, destination_port, payload4B);
        p4_data_ipv6_count++;
    }
}

/**
 * @brief 从p4中删除ipv6规则
 * @author yifei.zhou
 */
void del_p4_data_ipv6()
{
    for (int i = 0; i < p4_data_ipv6_count; i++)
    {
        send_p4_ipv6(P4RT_USER_TABLE_ADD,
                     p4_data_ipv6_array[i].protocol,
                     p4_data_ipv6_array[i].source_ip,
                     p4_data_ipv6_array[i].destination_ip,
                     p4_data_ipv6_array[i].destination_port,
                     p4_data_ipv6_array[i].payload4B);
    }
    // 清空数组
    memset(p4_data_ipv6_array, 0, sizeof(struct P4_array_ipv6) * p4_data_ipv6_count);
    p4_data_ipv6_count = 0;
}

// ipv4的alert数据包五元组+payload前四字节传输给p4 ipv4_acl表
void distribute_p4_ipv4(Packet *p, string pro)
{
    if (pro == "TCP")
    {
        SfIpString src_addr, dst_addr;
        uint16_t source_port = 0, destination_port = 0;
        uint8_t protocol = 6;
        source_port = p->ptrs.sp;
        destination_port = p->ptrs.dp;
        if (p->ptrs.tcph == nullptr || p->ptrs.ip_api.ip_data() == nullptr)
            return;
        const uint16_t tcph_len = p->ptrs.tcph->hlen();
        const uint8_t *tcp_data = p->ptrs.ip_api.ip_data() + tcph_len;
        const uint16_t pay_len = p->ptrs.ip_api.pay_len();
        if (pay_len < 4)
            return;
        uint32_t payload4B = (tcp_data[0] << 24) | (tcp_data[1] << 16) | (tcp_data[2] << 8) | tcp_data[3];
        string sip = p->ptrs.ip_api.get_src()->ntop(src_addr);
        string dip = p->ptrs.ip_api.get_dst()->ntop(dst_addr);
        if (sip.length() <= 16 && dip.length() <= 16)
        {
            struct in_addr sp, dp;
            u_int32_t source_ip, destination_ip;
            inet_pton(AF_INET, sip.c_str(), (void *)&sp);
            inet_pton(AF_INET, dip.c_str(), (void *)&dp);
            source_ip = sp.s_addr;
            destination_ip = dp.s_addr;
            source_ip = ntohl(source_ip);
            destination_ip = ntohl(destination_ip);
            // write_p4_data_ipv4(protocol, source_ip, destination_ip, source_port, destination_port, payload4B);
            write_p4_data_ipv4(protocol, source_ip, destination_ip, destination_port, payload4B);
        }
    }
    else
    {
        const ip::IP4Hdr *const ip4h = p->ptrs.ip_api.get_ip4h();
        IpProtocol proto = ip4h->proto();
        uint8_t protocol = (uint8_t)proto;
        uint32_t source_ip = ntohl(ip4h->get_src());
        uint32_t destination_ip = ntohl(ip4h->get_dst());
        uint16_t source_port = p->ptrs.sp;
        uint16_t destination_port = p->ptrs.dp;
        uint32_t payload4B = (p->data[0] << 24) | (p->data[1] << 16) | (p->data[2] << 8) | p->data[3];
        // write_p4_data_ipv4(protocol, source_ip, destination_ip, source_port, destination_port, payload4B);
        write_p4_data_ipv4(protocol, source_ip, destination_ip, destination_port, payload4B);
    }
}

// ipv6的alert数据包五元组+payload前四字节传输给p4 ipv6_acl表
void distribute_p4_ipv6(Packet *p)
{
    if (p->ptrs.ip_api.get_ip6h() == nullptr)
        return;
    const ip::IP6Hdr *const ip6h = p->ptrs.ip_api.get_ip6h();
    IpProtocol proto = ip6h->proto();
    uint8_t protocol = (uint8_t)proto;
    uint32_t source_ip[4] = {ip6h->get_src()->u6_addr32[0], ip6h->get_src()->u6_addr32[1], ip6h->get_src()->u6_addr32[2], ip6h->get_src()->u6_addr32[3]};
    uint32_t destination_ip[4] = {ip6h->get_dst()->u6_addr32[0], ip6h->get_dst()->u6_addr32[1], ip6h->get_dst()->u6_addr32[2], ip6h->get_dst()->u6_addr32[3]};
    uint16_t source_port = p->ptrs.sp;
    uint16_t destination_port = p->ptrs.dp;
    const uint16_t pay_len = p->ptrs.ip_api.pay_len();
    if (pay_len < 4)
        return;
    uint32_t payload4B = (p->data[0] << 24) | (p->data[1] << 16) | (p->data[2] << 8) | p->data[3];
    // write_p4_data_ipv6(protocol, source_ip, destination_ip, source_port, destination_port, payload4B);
    write_p4_data_ipv6(protocol, source_ip, destination_ip, destination_port, payload4B);
}

// 读取P4计数（ipv4）
// void read_p4_log_ipv4(uint8_t protocol, uint32_t source_ip, uint32_t destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B)
void read_p4_log_ipv4(uint8_t protocol, uint32_t source_ip, uint32_t destination_ip, uint16_t destination_port, uint32_t payload4B)
{
    uint32_t ipmask = 0xffffffff;
    ipmask = htole32(ipmask);

    std::ostringstream s_ip;
    s_ip << std::hex << std::setw(8) << std::setfill('0') << source_ip;
    std::string S_ip = std::string("00000000" + s_ip.str() + "0000000000000000");

    std::ostringstream d_ip;
    d_ip << std::hex << std::setw(8) << std::setfill('0') << destination_ip;
    std::string D_ip = std::string("00000000" + d_ip.str() + "0000000000000000");

    std::ostringstream s_ipmask;
    s_ipmask << std::hex << std::setw(8) << std::setfill('0') << ipmask;
    std::string S_ipmask = std::string("00000000" + s_ipmask.str() + "0000000000000000");

    int p_num;
    string p = std::to_string(protocol);
    std::istringstream pp(p);
    pp >> p_num;
    std::ostringstream prot;
    prot << std::hex << p_num;
    std::string proto_value = prot.str();
    /*
        std::ostringstream soport;
        soport << std::hex << source_port;
        std::string sport_value = soport.str();
    */
    std::ostringstream deport;
    deport << std::hex << destination_port;
    std::string dport_value = deport.str();

    std::ostringstream payl4;
    payl4 << std::hex << payload4B;
    std::string pay_value = payl4.str();

    std::string command = P4RT_USER_TABLE_GET;
    std::string udf_table_name = APP_P4RT_UDF_PORTCLASSIFICATION_NAME;
    std::string proto = "local_md.lkp.ip_proto";
    std::string sip = "local_md.lkp.ip_src_addr";
    std::string dip = "local_md.lkp.ip_dst_addr";
    // std::string sport = "local_md.lkp.l4_src_port";
    std::string dport = "local_md.lkp.l4_dst_port";
    std::string pay4b = "local_md.payload32_0";
    sai_uint32_t priority = 100;
    // long unsigned int match_length = 6;
    long unsigned int match_length = 5;
    std::vector<FieldValueTuple> udf_entry_attrs;
    FieldValueTuple opcommand(udf_table_name, command);
    udf_entry_attrs.insert(udf_entry_attrs.begin(), opcommand);
    udf_entry_attrs.push_back(std::make_pair(MatchLengthField, std::to_string(match_length)));
    udf_entry_attrs.push_back(std::make_pair(sip, std::string("0x" + S_ip + "&" + "0x" + S_ipmask)));
    udf_entry_attrs.push_back(std::make_pair(dip, std::string("0x" + D_ip + "&" + "0x" + S_ipmask)));
    udf_entry_attrs.push_back(std::make_pair(proto, "0x" + proto_value + "&" + "0xff"));
    // udf_entry_attrs.push_back(std::make_pair(sport, "0x" + sport_value + "&" + "0xffff"));
    udf_entry_attrs.push_back(std::make_pair(dport, "0x" + dport_value + "&" + "0xffff"));
    udf_entry_attrs.push_back(std::make_pair(pay4b, "0x" + pay_value + "&" + "0xffffffff"));
    udf_entry_attrs.push_back(std::make_pair(UdfTablePriority, std::to_string(priority)));
    std::string msg = buildJson(udf_entry_attrs);
    std::vector<FieldValueTuple> read_value = zmqSendRequest(msg, udf_table_name, command);
    if (read_value.size() == 0)
        return;
    FieldValueTuple count_packet = read_value.at(1);
    std::string &count_packet_value = fvValue(count_packet);
    FieldValueTuple count_bytes = read_value.at(2);
    std::string &count_bytes_value = fvValue(count_bytes);
    p4_read_mutex.lock();
    const char *dir1 = "/home/edmund/log/ips_log.txt";
    const char *dir2 = "/home/edmund/log/p4_log.txt";
    string time = get_time();
    struct in_addr addr1, addr2;
    char ipaddr_S[16];
    char ipaddr_D[16];
    addr1.s_addr = htonl(source_ip);
    addr2.s_addr = htonl(destination_ip);
    inet_ntop(AF_INET, (void *)&addr1, ipaddr_S, (socklen_t)sizeof(ipaddr_S));
    inet_ntop(AF_INET, (void *)&addr2, ipaddr_D, (socklen_t)sizeof(ipaddr_D));
    fstream file;
    if (distribution_path == 1)
    {
        file.open(dir1, ios::in);
        if (!file)
        {
            ofstream fout(dir1);
        }
        file.close();
        file.open(dir1, ios::out | ios::app);
    }
    else
    {
        file.open(dir2, ios::in);
        if (!file)
        {
            ofstream fout(dir2);
        }
        file.close();
        file.open(dir2, ios::out | ios::app);
    }
    if (p_num == 17)
    {
        // file << time << "  UDP  " << ipaddr_S << ":" << dec << source_port << "->" << hex << ipaddr_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
        file << time << "  UDP  " << ipaddr_S << "->" << hex << ipaddr_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
    }
    else if (p_num == 6)
    {
        // file << time << "  TCP  " << ipaddr_S << ":" << dec << source_port << "->" << ipaddr_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
        file << time << "  TCP  " << ipaddr_S << "->" << ipaddr_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
    }
    else
    {
        // file << time << "  " << p_num << "  " << ipaddr_S << ":" << dec << source_port << "->" << ipaddr_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
        file << time << "  " << p_num << "  " << ipaddr_S << "->" << ipaddr_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
    }
    file.close();
    p4_read_mutex.unlock();
}

// 读取P4计数（ipv6）
void read_p4_log_ipv6(uint8_t protocol, uint32_t *source_ip, uint32_t *destination_ip, uint16_t source_port, uint16_t destination_port, uint32_t payload4B)
{
    std::string S_ipV6;
    std::string D_ipV6;
    std::string S_ipV6Mask;
    uint32_t ipmask[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
    S_ipV6 = NetworkOrderTransToLittleEndian(source_ip, 4);
    D_ipV6 = NetworkOrderTransToLittleEndian(destination_ip, 4);
    S_ipV6Mask = NetworkOrderTransToLittleEndian(ipmask, 4);

    int p_num;
    string p = std::to_string(protocol);
    std::istringstream pp(p);
    pp >> p_num;
    std::ostringstream prot;
    prot << std::hex << p_num;
    std::string proto_value = prot.str();
    /*
        std::ostringstream soport;
        soport << std::hex << source_port;
        std::string sport_value = soport.str();
    */
    std::ostringstream deport;
    deport << std::hex << destination_port;
    std::string dport_value = deport.str();

    std::ostringstream payl4;
    payl4 << std::hex << payload4B;
    std::string pay_value = payl4.str();

    std::string command = P4RT_USER_TABLE_ADD;
    std::string udf_table_name = APP_P4RT_UDF_PORTCLASSIFICATION_NAME;
    std::string proto = "local_md.lkp.ip_proto";
    std::string sip = "local_md.lkp.ip_src_addr";
    std::string dip = "local_md.lkp.ip_dst_addr";
    // std::string sport = "local_md.lkp.l4_src_port";
    std::string dport = "local_md.lkp.l4_dst_port";
    std::string pay4b = "local_md.payload32_0";
    sai_uint32_t priority = 100;
    // long unsigned int match_length = 6;
    long unsigned int match_length = 5;
    std::vector<FieldValueTuple> udf_entry_attrs;
    FieldValueTuple opcommand(udf_table_name, command);
    udf_entry_attrs.insert(udf_entry_attrs.begin(), opcommand);
    udf_entry_attrs.push_back(std::make_pair(MatchLengthField, std::to_string(match_length)));
    udf_entry_attrs.push_back(std::make_pair(sip, std::string("0x" + S_ipV6 + "&" + "0x" + S_ipV6Mask)));
    udf_entry_attrs.push_back(std::make_pair(dip, std::string("0x" + D_ipV6 + "&" + "0x" + S_ipV6Mask)));
    udf_entry_attrs.push_back(std::make_pair(proto, "0x" + proto_value + "&" + "0xff"));
    // udf_entry_attrs.push_back(std::make_pair(sport, "0x" + sport_value + "&" + "0xffff"));
    udf_entry_attrs.push_back(std::make_pair(dport, "0x" + dport_value + "&" + "0xffff"));
    udf_entry_attrs.push_back(std::make_pair(pay4b, "0x" + pay_value + "&" + "0xffffffff"));
    udf_entry_attrs.push_back(std::make_pair(UdfTablePriority, std::to_string(priority)));
    std::string msg = buildJson(udf_entry_attrs);
    std::vector<FieldValueTuple> read_value = zmqSendRequest(msg, udf_table_name, command);
    FieldValueTuple count_packet = read_value.at(1);
    std::string &count_packet_value = fvValue(count_packet);
    FieldValueTuple count_bytes = read_value.at(2);
    std::string &count_bytes_value = fvValue(count_bytes);
    p4_read_mutex.lock();
    const char *dir1 = "/home/edmund/log/ips_log.txt";
    const char *dir2 = "/home/edmund/log/p4_log.txt";
    string time = get_time();
    struct in6_addr addr1, addr2;
    char ipaddr6_S[INET6_ADDRSTRLEN];
    char ipaddr6_D[INET6_ADDRSTRLEN];
    addr1.__in6_u.__u6_addr32[0] = source_ip[0];
    addr1.__in6_u.__u6_addr32[1] = source_ip[1];
    addr1.__in6_u.__u6_addr32[2] = source_ip[2];
    addr1.__in6_u.__u6_addr32[3] = source_ip[3];
    addr2.__in6_u.__u6_addr32[0] = destination_ip[0];
    addr2.__in6_u.__u6_addr32[1] = destination_ip[1];
    addr2.__in6_u.__u6_addr32[2] = destination_ip[2];
    addr2.__in6_u.__u6_addr32[3] = destination_ip[3];
    inet_ntop(AF_INET6, (void *)&addr1, ipaddr6_S, (socklen_t)sizeof(ipaddr6_S));
    inet_ntop(AF_INET6, (void *)&addr2, ipaddr6_D, (socklen_t)sizeof(ipaddr6_D));
    fstream file;
    if (distribution_path == 1)
    {
        file.open(dir1, ios::in);
        if (!file)
        {
            ofstream fout(dir1);
        }
        file.close();
        file.open(dir1, ios::out | ios::app);
    }
    else
    {
        file.open(dir2, ios::in);
        if (!file)
        {
            ofstream fout(dir2);
        }
        file.close();
        file.open(dir2, ios::out | ios::app);
    }
    if (p_num == 17)
    {
        // file << time << "  UDP  " << ipaddr6_S << ":" << dec << source_port << "->" << ipaddr6_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
        file << time << "  UDP  " << ipaddr6_S << "->" << ipaddr6_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
    }
    else if (p_num == 6)
    {
        // file << time << "  TCP  " << ipaddr6_S << ":" << dec << source_port << "->" << ipaddr6_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
        file << time << "  TCP  " << ipaddr6_S << "->" << ipaddr6_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
    }
    else
    {
        // file << time << "  " << p_num << "  " << ipaddr6_S << ":" << dec << source_port << "->" << ipaddr6_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
        file << time << "  " << p_num << "  " << ipaddr6_S << "->" << ipaddr6_D << ":" << dec << destination_port << " payload_4b:" << hex << payload4B << "  count_packet:" << count_packet_value << "  count_bytes:" << count_bytes_value << endl;
    }
    file.close();
    p4_read_mutex.unlock();
}

void read_p4_log()
{
    write_log_boundary();
    for (int i = 0; i < p4_data_ipv4_count; i++)
    {
        // read_p4_log_ipv4(p4_data_ipv4_array[i].protocol, p4_data_ipv4_array[i].source_ip, p4_data_ipv4_array[i].destination_ip, p4_data_ipv4_array[i].source_port, p4_data_ipv4_array[i].destination_port, p4_data_ipv4_array[i].payload4B);
        read_p4_log_ipv4(p4_data_ipv4_array[i].protocol, p4_data_ipv4_array[i].source_ip, p4_data_ipv4_array[i].destination_ip, p4_data_ipv4_array[i].destination_port, p4_data_ipv4_array[i].payload4B);
    }

    for (int j = 0; j < p4_data_ipv6_count; j++)
    {
        // read_p4_log_ipv6(p4_data_ipv6_array[j].protocol, p4_data_ipv6_array[j].source_ip, p4_data_ipv6_array[j].destination_ip, p4_data_ipv6_array[j].source_port, p4_data_ipv6_array[j].destination_port, p4_data_ipv6_array[j].payload4B);
        // read_p4_log_ipv6(p4_data_ipv6_array[j].protocol, p4_data_ipv6_array[j].source_ip, p4_data_ipv6_array[j].destination_ip, p4_data_ipv6_array[j].destination_port, p4_data_ipv6_array[j].payload4B);
    }
}

void AlertAction::exec(Packet *p, const OptTreeNode *otn)
{
    string pro = p->get_type();
    // 处理ipv4的alert数据包
    if (p->ptrs.ip_api.is_ip4() == 1 || pro == std::string("TCP"))
    {
        // p4模式
        if (distribution_path == 1 || distribution_path == 2)
        {
            distribute_p4_ipv4(p, pro);
        }
        // fpga模式
        if (distribution_path == 3)
        {
            packet_ipv4_hash_crc32(p, pro);
        }
    }
    // 处理ipv6的alert数据包，目前fpga不支持
    if (p->ptrs.ip_api.is_ip6())
    {
        // p4模式
        if (distribution_path == 1 || distribution_path == 2)
        {
            // distribute_p4_ipv6(p);
        }
        // fpga模式
        if (distribution_path == 3)
        {
            // packet_ipv6_hash_crc32(p);
        }
    }
    Actions::alert(p, otn);
}

//-------------------------------------------------------------------------

static IpsAction *alert_ctor(Module *)
{
    return new AlertAction;
}

static void alert_dtor(IpsAction *p)
{
    delete p;
}

static ActionApi alert_api{
    {
        PT_IPS_ACTION,
        sizeof(ActionApi),
        ACTAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        nullptr, // mod_ctor
        nullptr, // mod_dtor
    },
    IpsAction::IAP_ALERT,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    alert_ctor,
    alert_dtor};

const BaseApi *act_alert[] =
    {
        &alert_api.base,
        nullptr};
