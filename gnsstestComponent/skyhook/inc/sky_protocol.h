/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_PROTOCOL_H
#define SKY_PROTOCOL_H

#include <stdbool.h>
#include <assert.h>
#include <inttypes.h>
#include <endian.h>       // remove if not existing
#include <byteswap.h>     // remove if not existing

#define SKY_PROTOCOL_VERSION    1

#define URL_SIZE                512
#define AUTH_SIZE               512

#define MAC_SIZE                6
#define IPV4_SIZE               4
#define IPV6_SIZE               16

#define MAX_MACS                2   // max # of mac addresses
#define MAX_IPS                 2   // max # of ip addresses

#define MAX_APS                 100 // max # of access points
#define MAX_GPSS                2   // max # of gps
#define MAX_CELLS               7   // max # of cells
#define MAX_BLES                5   // max # of blue tooth

// max # of bytes for request buffer
#define SKY_PROT_RQ_BUFF_LEN                                                 \
    sizeof(sky_rq_header_t) + sizeof(sky_payload_t) + sizeof(sky_checksum_t) \
    + (sizeof(sky_entry_t) + MAX_MACS * MAC_SIZE)                            \
    + (sizeof(sky_entry_t) + MAX_IPS * IPV6_SIZE)                            \
    + (sizeof(sky_entry_t) + MAX_APS * sizeof(struct ap_t))                  \
    + (sizeof(sky_entry_t) + MAX_GPSS * sizeof(struct gps_t))                \
    + (sizeof(sky_entry_t) + MAX_CELLS * sizeof(union cell_t))               \
    + (sizeof(sky_entry_t) + MAX_BLES * sizeof(struct ble_t))

// max # of bytes for response buffer
#define SKY_PROT_RSP_BUFF_LEN                                                 \
    sizeof(sky_rsp_header_t) + sizeof(sky_payload_t) + sizeof(sky_checksum_t) \
    + sizeof(struct location_t) + sizeof(struct location_ext_t)               \
    + 1024 // the char array of full address

// max # of bytes for both request and response buffer
#define SKY_PROT_BUFF_LEN                                                     \
                            ((SKY_PROT_RQ_BUFF_LEN > SKY_PROT_RSP_BUFF_LEN) ? \
                            SKY_PROT_RQ_BUFF_LEN : SKY_PROT_RSP_BUFF_LEN)

#ifndef ENOBUFS
    #define ENOBUFS (ENOMEM)
#endif

// get a local (uint8_t *) buffer with size s and the starting memory address
// being aligned at uint32_t boundary.
#define SKY_LOCAL_BYTE_BUFF_32(b,s)                                           \
                            uint32_t sky____local_buffer____sky[(s)>>2];      \
                            assert(sizeof(*b) == sizeof(uint8_t));            \
                            (b) = (uint8_t *)sky____local_buffer____sky;

#ifndef _BYTESWAP_H // defined in <byteswap.h>
    #define __sky_bswap_16(x)                                                 \
         ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))
    #define __sky_bswap_32(x)                                                 \
         ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8)             \
        | (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
    #define __sky_bswap_64(x)                                                 \
         ((((x) & 0xff00000000000000ull) >> 56)                               \
        | (((x) & 0x00ff000000000000ull) >> 40)                               \
        | (((x) & 0x0000ff0000000000ull) >> 24)                               \
        | (((x) & 0x000000ff00000000ull) >> 8)                                \
        | (((x) & 0x00000000ff000000ull) << 8)                                \
        | (((x) & 0x0000000000ff0000ull) << 24)                               \
        | (((x) & 0x000000000000ff00ull) << 40)                               \
        | (((x) & 0x00000000000000ffull) << 56))
#else
    #define __sky_bswap_16(x)       __bswap_16(x)
    #define __sky_bswap_32(x)       __bswap_32(x)
    #define __sky_bswap_64(x)       __bswap_64(x)
#endif

#ifdef __BIG_ENDIAN__ // defined in <endian.h> by GNU C compilers
    #define SKY_ENDIAN_SWAP(x)                                                \
                           ({switch(sizeof(x)) {                              \
                             case (sizeof(uint8_t)):                          \
                                 break;                                       \
                             case (sizeof(uint16_t)):                         \
                                 (x) = __sky_bswap_16(x);                     \
                                 break;                                       \
                             case (sizeof(uint32_t)):                         \
                                 (x) = __sky_bswap_32(x);                     \
                                 break;                                       \
                             case (sizeof(uint64_t)):                         \
                                 (x) = __sky_bswap_64(x);                     \
                                 break;                                       \
                             default:                                         \
                                 perror("NOT C primitive types!");            \
                                 assert(false);                               \
                                 break;                                       \
                             }})
#else
    #define SKY_ENDIAN_SWAP(x) // do nothing
#endif


// stored in one byte
enum SKY_DATA_TYPE {
    DATA_TYPE_PAD = 0,      // padding byte
    DATA_TYPE_AP = 1,       // access point
    DATA_TYPE_GPS,          // gps
    DATA_TYPE_GSM,          // cell gsm
    DATA_TYPE_CDMA,         // cell cdma
    DATA_TYPE_UMTS,         // cell umts
    DATA_TYPE_LTE,          // cell lte
    DATA_TYPE_BLE,          // bluetooth

    DATA_TYPE_LAT_LON,      // lat and lon
    DATA_TYPE_STREET_NUM,
    DATA_TYPE_ADDRESS,
    DATA_TYPE_CITY,
    DATA_TYPE_STATE,
    DATA_TYPE_STATE_CODE,
    DATA_TYPE_METRO1,
    DATA_TYPE_METRO2,
    DATA_TYPE_POSTAL_CODE,
    DATA_TYPE_COUNTY,
    DATA_TYPE_COUNTRY,
    DATA_TYPE_COUNTRY_CODE,

    DATA_TYPE_IPV4,         // ipv4 address
    DATA_TYPE_IPV6,         // ipv6 address
    DATA_TYPE_MAC,          // device MAC address
};

// request payload types
enum SKY_RQ_PAYLOAD_TYPE {
    REQ_PAYLOAD_TYPE_NONE = 0,  // initialization value

    LOCATION_RQ,                // location request
    LOCATION_RQ_ADDR,           // location request full
    PROBE_REQUEST,              // probe test
};

// response payload types
enum SKY_RSP_PAYLOAD_TYPE {
    RSP_PAYLOAD_TYPE_NONE = 0,  // initialization value

    // success codes
    LOCATION_RQ_SUCCESS,        // lat+lon success
    LOCATION_RQ_ADDR_SUCCESS,   // full address success
    PROBE_REQUEST_SUCCESS,      // probe success

    // error codes
    LOCATION_RQ_ERROR = 10,      // client domain errors
    LOCATION_GATEWAY_ERROR,      // elg server domain errors
    LOCATION_API_ERROR,          // api server domain errors
    LOCATION_UNKNOWN,            // do not know which domain errors

    // detailed client domain error codes
    LOCATION_UNABLE_TO_DETERMINE = 20,// api-server is unable to determine the client
                                      // location by the given client data.
};

// internal error codes
enum SKY_STATUS {
    SKY_OK = 0,
    ZLOG_INIT_PERM,
    ZLOG_INIT_ERR,
    LOAD_CONFIG_FAILED,
    API_URL_UNKNOWN,
    RELAY_URL_UNKNOWN,
    LOAD_KEYS_FAILED,
    BAD_KEY,
    CREATE_THREAD_FAILED,
    SETSOCKOPT_FAILED,
    SOCKET_OPEN_FAILED,
    SOCKET_CONN_FAILED,
    SOCKET_BIND_FAILED,
    SOCKET_LISTEN_FAILED,
    SOCKET_ACCEPT_FAILED,
    SOCKET_RECV_FAILED,
    SOCKET_WRITE_FAILED,
    SOCKET_TIMEOUT_FAILED,
    MSG_TOO_SHORT,
    SEND_PROBE_FAILED,
    SEND_UDF_PROT_FAILED,
    SENDTO_FAILED,
    DECRYPT_BIN_FAILED,
    ENCODE_XML_FAILED,
    DECODE_BIN_FAILED,
    ENCODE_BIN_FAILED,
    ENCRYPT_BIN_FAILED,
    DECODE_XML_FAILED,
    CREATE_META_FAILED,
    ARRAY_SIZE_TOO_SMALL,
    ERROR_XML_MSG,

    /* HTTP response codes >= 100 */
    /* http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html */
};

//
// protocol header, payload and checksum data types
//

// Note: For multi-byte integers, the server code runs on little-endian machines.
//       As the protocol requires little-endianness, server code does not need to
//       concern about byte ordering.
typedef struct {
    uint8_t version;           // protocol version
    uint8_t unused;            // padding byte
    uint16_t payload_length;   // payload length
    uint32_t user_id;          // user id
    uint8_t iv[16];            // initialization vector
} sky_rq_header_t;

typedef struct {
    uint8_t version;           // protocol version
    uint8_t unused;            // padding byte
    uint16_t payload_length;   // payload length
    uint8_t iv[16];            // initialization vector
} sky_rsp_header_t;

typedef struct {
    uint8_t data_type;         // data type enum (i.e. SkyDataType)
    uint8_t data_type_count;   // data type count
} sky_entry_t;

// read and write in place in buffer
typedef struct {
    sky_entry_t * entry;       // entry without data
    uint8_t * data;            // array size = sizeof(data type) * count
} sky_entry_ext_t;

typedef struct {
    uint8_t sw_version;        // client sw version for request and server sw version for response
    uint8_t timestamp[6];      // timestamp in milliseconds
    uint8_t type;              // payload type
} sky_payload_t;

typedef struct {
    sky_payload_t payload;     // payload without data entries
    sky_entry_ext_t data_entry;// data_entry is updated to iterate over an unbounded array of data entries in buffer
} sky_payload_ext_t;

typedef uint16_t sky_checksum_t;

// enum values to set struct ap_t::flag.
enum SKY_BAND {
    BAND_UNKNOWN = 0,
    BAND_2_4G,
    BAND_5G,
};

//
// protocol payload data entry data types
// location request
// Note: all data types are explicitly padded for 32-bit alignment.
//

/* WARNING:
 * it is important to keep the order
 * the larger size vars first in the structs
 * because the compiler pads the struct to align
 * to the largest size
 */

// access point
// Note: Padding bytes will be appended at the end of the very last "struct ap_t",
//       if the memory boundary of the end is not aligned at 32-bits.
struct ap_t {
    uint8_t MAC[6];
    int8_t rssi;
    uint8_t flag; // bit fields:
                  // bit 0: 1 if the device is currently connected to this AP. 0 otherwise.
                  // bits 1-3: Band indicator. Allowable values:
                  //                                             0: unknown
                  //                                             1: 2.4 GHz
                  //                                             2: 5 GHz
                  //                                             3-7: Reserved
                  // bits 4-7: Reserved
};

// http://wiki.opencellid.org/wiki/API
struct gsm_t {
    uint32_t ci;
    uint32_t age;
    uint16_t mcc; // country
    uint16_t mnc;
    uint16_t lac;
    int8_t rssi; // -255 unkonwn - map it to - 128
    uint8_t unused; // padding byte
};

// 64-bit aligned due to double
struct cdma_t {
    double lat;
    double lon;
    uint32_t age;
    uint16_t sid;
    uint16_t nid;
    uint16_t bsid;
    int8_t rssi;
    uint8_t unused[5]; // padding bytes
};

struct umts_t {
    uint32_t ci;
    uint32_t age;
    uint16_t mcc; // country
    uint16_t mnc;
    uint16_t lac;
    int8_t rssi;
    uint8_t unused; // padding byte
};

struct lte_t {
    uint32_t age;
    uint32_t eucid;
    uint16_t mcc;
    uint16_t mnc;
    int8_t rssi;
    uint8_t unused[3]; // padding bytes
};

union cell_t {
    struct gsm_t gsm;
    struct cdma_t cdma;
    struct umts_t umts;
    struct lte_t lte;
};

// 64-bit aligned due to double
struct gps_t {
    double lat;
    double lon;
    float hdop;
    float alt; // altitude
    float hpe;
    float speed;
    uint32_t age; // last seen in ms
    uint8_t nsat;
    uint8_t fix;
    uint8_t unused[2]; // padding bytes
};

// blue tooth
struct ble_t {
    uint16_t major;
    uint16_t minor;
    uint8_t MAC[6];
    uint8_t uuid[16];
    int8_t rssi;
    uint8_t unused; // padding byte
};

//
// protocol payload data entry data types
// location response
// Note:
// * location_t is the only type 64-bit aligned. All the other types
//   are 32-bit aligned.
// * location_ext_t needs to be reinterpreted in place in buffer,
//   and it is the last data type structure in the response buffer,
//   so it is unnecessary to be padded at the end for 32-bit alignment.
//

// location result
struct location_t {
    double lat; // 64 bit IEEE-754
    double lon; // 64 bit IEEE-754
    float hpe;  // 32 bit IEEE-754
    float distance_to_point; // 32 bit IEEE-754
};

// extended location result
struct location_ext_t {

    uint8_t mac_len;
    uint8_t *mac;

    uint8_t ip_len;
    uint8_t ip_type;  // DATA_TYPE_IPV4 or DATA_TYPE_IPV6
    uint8_t *ip_addr; // ipv4 (4 bytes) or ipv6 (16 bytes)

    uint8_t street_num_len;
    char *street_num;

    uint8_t address_len;
    char *address;

    uint8_t city_len;
    char *city;

    uint8_t state_len;
    char *state;

    uint8_t state_code_len;
    char *state_code;

    uint8_t metro1_len;
    char *metro1;

    uint8_t metro2_len;
    char *metro2;

    uint8_t postal_code_len;
    char *postal_code;

    uint8_t county_len;
    char *county;

    uint8_t country_len;
    char *country;

    uint8_t country_code_len;
    char *country_code;
};

//
// client application data types
//

struct sky_srv_t {
    char url[URL_SIZE];
    char cred[AUTH_SIZE];
};

// relay setting for echoing the location results
struct sky_relay_t {
    struct sky_srv_t srv;
    uint8_t valid;
};

// stores keys in a binary tree
struct sky_key_t {
    uint32_t partner_id;
    uint8_t aes_key[16];  // 128 bit aes key
    char keyid[128];      // api key
    struct sky_relay_t relay; // relay responses
};

struct location_rq_t {

    //
    // protocol attributes
    //

    sky_rq_header_t header;
    sky_payload_ext_t payload_ext;

    uint8_t mac_count; // count of MAC address
    uint8_t *mac;      // client device MAC identifier

    uint8_t ip_count; // count of IP address
    uint8_t ip_type;
    uint8_t *ip_addr; // ipv4 or ipv6

    // wifi access points
    uint8_t ap_count;
    struct ap_t *aps;

    // blue tooth
    uint8_t ble_count;
    struct ble_t *bles;

    // cell
    // note: *DEPRECATED*, please use gsm, cdma, lte, and umts which are defined below.
    uint8_t cell_count; // deprecated, use gsm, cdma, lte and umts instead
    uint8_t cell_type;  // deprecated, use gsm, cdma, lte and umts instead
    union cell_t *cell; // deprecated, use gsm, cdma, lte and umts instead

    // gsm
    uint8_t gsm_count;
    struct gsm_t *gsms;

    // cdma
    uint8_t cdma_count;
    struct cdma_t *cdmas;

    // lte
    uint8_t lte_count;
    struct lte_t *ltes;

    // umts
    uint8_t umts_count;
    struct umts_t *umtss;

    // gps
    uint8_t gps_count;
    struct gps_t *gps;

    //
    // additional attributes
    //

    struct sky_key_t key; // user key
    char *api_version; // api server version number (string 2.34)

    // http server settings
    char *http_url;
    char *http_uri;
};

struct location_rsp_t {

    //
    // protocol_version attributes
    //

    sky_rsp_header_t header;
    sky_payload_ext_t payload_ext;

    //
    // additional attributes
    //

    struct sky_key_t key; // user key

    struct location_t location; // location result: lat and lon

    struct location_ext_t location_ext; // ext location result: full address, etc.
};

/***********************************************
 BINARY REQUEST PROTOCOL FORMAT
 ************************************************
 0  - protocol version 0
 1  - client id 0
 2  - client id 1
 3  - client id 2
 4  - client id 3
 5  - entire payload length 0 - LSB count includes byte 0
 6  - entire payload length 1 - MSB
 7  - iv 0
 8  - iv 1
 9  - iv 2
 10 - iv 3
 11 - iv 4
 12 - iv 5
 13 - iv 6
 14 - iv 7
 15 - iv 8
 16 - iv 9
 17 - iv 10
 18 - iv 11
 19 - iv 12
 20 - iv 13
 21 - iv 14
 22 - iv 15
 --- encrypted after this ---
 23 - client software version
 24 - client MAC 0
 25 - client MAC 1
 26 - client MAC 2
 27 - client MAC 3
 28 - clinet MAC 4
 29 - clinet MAC 5
 30 - payload type -- e.g. location request
 -------------------
 payload data can be out of order (type,count/size,data)
 31 - data type -- refers to DATA_TYPE enum and struct
 32 - data type count -- this a the number of structs (0 - 255)
 33 - data... memcopied data struct (ap, cell, ble, gps)
 ...
 n - 2 verify 0 fletcher 16
 n - 1 verify 1 fletcher 16
 *************************************************/

/***********************************************
 BINARY RESPONSE PROTOCOL FORMAT
 ************************************************
 0  - protocol version
 1  - entire payload length 0 - LSB count includes byte 0
 2  - entire payload length 1 - MSB
 3  - iv 0
 4  - iv 1
 5  - iv 2
 6  - iv 3
 7  - iv 4
 8  - iv 5
 9  - iv 6
 10 - iv 7
 11 - iv 8
 12 - iv 9
 13 - iv 10
 14 - iv 11
 15 - iv 12
 16 - iv 13
 17 - iv 14
 18 - iv 15
 --- encrypted after this ---
 19 - server software version
 20 - timestamp 0
 21 - timestamp 1
 22 - timestamp 2
 23 - timestamp 3
 24 - timestamp 4
 25 - timestamp 5
 26 - payload type -- e.g. location request
 27 - lat 8 bytes
 35 - lon 8 bytes
 43 - hpe 4 bytes
 (47) optional 6 - byte device MAC
 -------------------
 payload data can be out of order (type,count/size,data)
 47 - data type -- refers to DATA_TYPE enum and struct
 48 - data type count -- this a the number of structs (0 - 255)
 49 - data... memcopied data struct (ap, cell, ble, gps)
 ...
 n - 2 verify 0 fletcher 16
 n - 1 verify 1 fletcher 16
 *************************************************/

// set the flag of an access point to claim the device is currently connected
void sky_set_ap_connected(struct ap_t* ap, bool is_connected);

// set the flag of an access point for the bandwidth
void sky_set_ap_band(struct ap_t* ap, enum SKY_BAND band);

// initialize the attributes of GPS to default or invalid values
void sky_init_gps_attrib(struct gps_t * gps);

// find aes key  based on partner_id in key root and set it
//int sky_set_key(void *key_root, struct location_head_t *head);
uint32_t sky_get_partner_id_from_rq_header(uint8_t *buff, uint32_t buff_len);

// received by the server from the client
// decode binary data from client, result is in the location_req_t struct
int32_t sky_decode_req_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_rq_t *creq);

// sent by the server to the client
// encodes the loc struct into binary formatted packet sent to client
// returns the packet len or -1 when fails
int32_t sky_encode_resp_bin(uint8_t *buff, uint32_t buff_len,
        struct location_rsp_t *cresp);

// sent by the client to the server
/* encodes the request struct into binary formatted packet */
// returns the packet len or -1 when fails
int32_t sky_encode_req_bin(uint8_t *buff, uint32_t buff_len,
        struct location_rq_t *creq);

// received by the client from the server
/* decodes the binary data and the result is in the location_resp_t struct */
int32_t sky_decode_resp_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_rsp_t *cresp);

#endif

#ifdef __cplusplus
}
#endif
