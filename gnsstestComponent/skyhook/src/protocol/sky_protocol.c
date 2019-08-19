/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <float.h>
#include "sky_crypt.h"
#include "sky_protocol.h"

#define inline

// set the flag of an access point to claim the device is currently connected
inline
void sky_set_ap_connected(struct ap_t* ap, bool is_connected) {
    ap->flag |= 1; // set bit 0
}

// set the flag of an access point for the bandwidth
inline
void sky_set_ap_band(struct ap_t* ap, enum SKY_BAND band) {
    switch (band) {
    case BAND_UNKNOWN:
        break;
    case BAND_2_4G:
        ap->flag |= 1 << 1; // set bit 1
        break;
    case BAND_5G:
        ap->flag |= 1 << 2; // set bit 2
        break;
    default:
        perror("undefined SKY_BAND");
        break;
    }
}

// initialize the attributes of GPS to default or invalid values
inline
void sky_init_gps_attrib(struct gps_t * gps) {
    gps->nsat = 0; // default
    gps->fix = 1;  // default
    gps->age = UINT_MAX; // invalid
    gps->alt = FLT_MAX;  // invalid
    gps->hdop = -1;      // invalid
    gps->hpe = -1;       // invalid
    gps->lat = DBL_MAX;  // invalid
    gps->lon = DBL_MAX;  // invalid
    gps->speed = -1;     // invalid
}

// Return the number to add to become a multiple of 16.
inline
uint8_t pad_16(uint32_t num) {
    uint8_t residual_16 = num & 0X0F;
    return (residual_16 == 0) ? 0 : (~residual_16 & 0X0F) + 1;
}

// Return data entry by parameter "sky_entry & entry".
inline
bool adjust_data_entry(const uint8_t * buff, uint32_t buff_len, uint32_t offset, sky_entry_ext_t * p_entry) {
    if (offset >= buff_len) {
        return false;
    }
    // The "entry" attributes point to buffer address;
    // so read and write "entry" means read and write in buffer in place.
    p_entry->entry = (sky_entry_t *)(buff + offset);
    p_entry->data = (uint8_t *)buff + offset + sizeof(sky_entry_t);
    return true;
}

inline
void sky_header_endian_swap(uint8_t * p_header, uint32_t header_len) {
    assert(p_header != NULL);
    switch (header_len) {
    case (sizeof(sky_rq_header_t)): {
        sky_rq_header_t * p = (sky_rq_header_t *)p_header;
        SKY_ENDIAN_SWAP(p->payload_length);
        SKY_ENDIAN_SWAP(p->user_id);
        (void)p; // suppress warning [-Werror=unused-variable]
        break;
    }
    case (sizeof(sky_rsp_header_t)): {
        sky_rsp_header_t * p = (sky_rsp_header_t *)p_header;
        SKY_ENDIAN_SWAP(p->payload_length);
        (void)p; // suppress warning [-Werror=unused-variable]
        break;
    }
    default:
        break;
    }
}

inline
void sky_gsm_endian_swap(struct gsm_t * p) {
    assert(p != NULL);
    SKY_ENDIAN_SWAP(p->ci);
    SKY_ENDIAN_SWAP(p->age);
    SKY_ENDIAN_SWAP(p->mcc);
    SKY_ENDIAN_SWAP(p->mnc);
    SKY_ENDIAN_SWAP(p->lac);
}

inline
void sky_cdma_endian_swap(struct cdma_t * p) {
    assert(p != NULL);
    SKY_ENDIAN_SWAP(p->lat);
    SKY_ENDIAN_SWAP(p->lon);
    SKY_ENDIAN_SWAP(p->age);
    SKY_ENDIAN_SWAP(p->sid);
    SKY_ENDIAN_SWAP(p->nid);
    SKY_ENDIAN_SWAP(p->bsid);
}

inline
void sky_umts_endian_swap(struct umts_t * p) {
    assert(p != NULL);
    SKY_ENDIAN_SWAP(p->ci);
    SKY_ENDIAN_SWAP(p->age);
    SKY_ENDIAN_SWAP(p->mcc);
    SKY_ENDIAN_SWAP(p->mnc);
    SKY_ENDIAN_SWAP(p->lac);
}

inline
void sky_lte_endian_swap(struct lte_t * p) {
    assert(p != NULL);
    SKY_ENDIAN_SWAP(p->age);
    SKY_ENDIAN_SWAP(p->eucid);
    SKY_ENDIAN_SWAP(p->mcc);
    SKY_ENDIAN_SWAP(p->mnc);
}

inline
void sky_gps_endian_swap(struct gps_t * p) {
    assert(p != NULL);
    SKY_ENDIAN_SWAP(p->lat);
    SKY_ENDIAN_SWAP(p->lon);
    SKY_ENDIAN_SWAP(p->alt);
    SKY_ENDIAN_SWAP(p->hpe);
    SKY_ENDIAN_SWAP(p->speed);
    SKY_ENDIAN_SWAP(p->age);
}

inline
void sky_ble_endian_swap(struct ble_t * p) {
    assert(p != NULL);
    SKY_ENDIAN_SWAP(p->major);
    SKY_ENDIAN_SWAP(p->minor);
}

inline
void sky_location_endian_swap(struct location_t * p) {
    assert(p != NULL);
    SKY_ENDIAN_SWAP(p->lat);
    SKY_ENDIAN_SWAP(p->lon);
    SKY_ENDIAN_SWAP(p->hpe);
    SKY_ENDIAN_SWAP(p->distance_to_point);
}

inline
bool check_rq_max_counts(const struct location_rq_t * p_rq) {
    if (p_rq->mac_count > MAX_MACS) {
        perror("Too big: mac_count > MAX_MACS");
        return false;
    }
    if (p_rq->ip_count > MAX_IPS) {
        perror("Too big: ip_count > MAX_IPS");
        return false;
    }
    if (p_rq->ap_count > MAX_APS) {
        perror("Too big: ap_count > MAX_APS");
        return false;
    }
    if (p_rq->cell_count > MAX_CELLS) {
        perror("Too big: cell_count > MAX_CELLS");
        return false;
    }
    if (p_rq->gps_count > MAX_GPSS) {
        perror("Too big: gps_count > MAX_GPSS");
        return false;
    }
    if (p_rq->ble_count > MAX_BLES) {
        perror("Too big: ble_count > MAX_BLES");
        return false;;
    }
    return true;
}

// Return header by parameter "header & h".
inline
bool sky_get_header(const uint8_t * buff, uint32_t buff_len, uint8_t * p_header, uint32_t header_len) {
    if (buff_len < header_len) {
        perror("buffer too small");
        return false;
    }
    memcpy(p_header, buff, header_len);
#ifdef __BIG_ENDIAN__
    sky_header_endian_swap(p_header, header_len);
#endif
    return true;
}

// Return payload content by parameter "sky_payload_ex & payload".
// Note: payload_ex.data_entry is a pointer referring to an address in buffer.
inline
bool sky_get_payload(const uint8_t * buff, uint32_t buff_len, uint8_t header_len,
        sky_payload_ext_t * p_payload_ex, uint16_t payload_len) {
    if (buff_len < header_len + payload_len) {
        perror("buffer too small");
        return false;
    }
    memcpy(&p_payload_ex->payload, buff + header_len, sizeof(sky_payload_t));
    // initialize payload_ex.data_entry
    adjust_data_entry(buff, buff_len, header_len + sizeof(sky_payload_t), &p_payload_ex->data_entry);
    return true;
}

// Verify checksum.
inline
bool sky_verify_checksum(const uint8_t * buff, uint32_t buff_len, uint8_t header_len, uint16_t payload_len) {
    if (buff_len < header_len + payload_len + sizeof(sky_checksum_t)) {
        perror("buffer too small");
        return false;
    }
    sky_checksum_t cs = *(sky_checksum_t *)(buff + header_len + payload_len); // little endianness
    SKY_ENDIAN_SWAP(cs);
    if (cs == fletcher16(buff, header_len + payload_len))
        return 1;
    else {
        perror("invalid checksum");
        return true;
    }
}

// Set header in parameter "uint8_t * buff".
inline
bool sky_set_header(uint8_t * buff, uint32_t buff_len, uint8_t * p_header, uint32_t header_len) {
    if (buff_len < header_len) {
        perror("buffer too small");
        return false;
    }
#ifdef __BIG_ENDIAN__
    sky_header_endian_swap(p_header, header_len);
#endif
    memcpy(buff, p_header, header_len);
    return true;
}

// Set payload in parameter "uint8_t * buff".
// Only set the payload without data entries; the data entries needs to be filled in place in buffer
// by using "payload_ex.data_entry".
inline
bool sky_set_payload(uint8_t * buff, uint32_t buff_len, uint8_t header_len,
        sky_payload_ext_t * p_payload_ex, uint16_t payload_len) {
    if (buff_len < header_len + payload_len) {
        perror("buffer too small");
        return false;
    }
    memcpy(buff + header_len, &p_payload_ex->payload, sizeof(sky_payload_t));
    // initialize payload_ex.data_entry
    adjust_data_entry(buff, buff_len, header_len + sizeof(sky_payload_t), &p_payload_ex->data_entry);
    return true;
}

// Set checksum in parameter "uint8_t * buff".
inline
bool sky_set_checksum(uint8_t * buff, uint32_t buff_len, uint8_t header_len, uint16_t payload_len) {
    if (buff_len < header_len + payload_len + sizeof(sky_checksum_t)) {
        perror("buffer too small");
        return false;
    }
    sky_checksum_t cs = fletcher16(buff, header_len + payload_len);
    SKY_ENDIAN_SWAP(cs);
    *(sky_checksum_t *)(buff + header_len + payload_len) = cs; // little endianness
    return true;
}

inline
uint8_t sky_get_ip_type(const struct location_rq_t * p_loc_rq) {
    uint8_t zero_12[12];
    memset(zero_12, 0, sizeof(zero_12));
    if (memcmp(p_loc_rq->ip_addr + 4, zero_12, sizeof(zero_12)) == 0)
        return DATA_TYPE_IPV4;
    else
        return DATA_TYPE_IPV6;
}

inline
uint8_t sky_get_ipaddr_len(const struct location_rq_t * p_loc_rq) {
    return (sky_get_ip_type(p_loc_rq) == DATA_TYPE_IPV4) ? 4 : 16;
}

// find aes key  based on partner_id in key root and set it
//int sky_set_key(void *key_root, struct location_head_t *head);
uint32_t sky_get_partner_id_from_rq_header(uint8_t *buff, uint32_t buff_len) {
    sky_rq_header_t header;
    memset(&header, 0, sizeof(header));
    if (sky_get_header(buff, buff_len, (uint8_t *)&header, sizeof(header))) {
        return header.user_id;
    }
    return 0;
}

// received by the server from the client
/* decode binary data from client, result is in the location_req_t struct */
/* binary encoded data in buff from client with data */
int32_t sky_decode_req_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_rq_t *creq) {

    memset(&creq->header, 0, sizeof(creq->header));
    if (!sky_get_header(buff, buff_len, (uint8_t *)&creq->header, sizeof(creq->header)))
        return -1;
    if (!sky_verify_checksum(buff, buff_len, (uint8_t)sizeof(creq->header), creq->header.payload_length))
        return -1;
    memset(&creq->payload_ext, 0, sizeof(creq->payload_ext));
    if (!sky_get_payload(buff, buff_len, sizeof(sky_rq_header_t), &creq->payload_ext, creq->header.payload_length))
        return -1;

    /* binary protocol description in sky_protocol.h */
    creq->key.partner_id = creq->header.user_id;

    if (creq->payload_ext.payload.type != LOCATION_RQ
            && creq->payload_ext.payload.type != LOCATION_RQ_ADDR) {
        fprintf(stderr, "Unknown payload type %d\n", creq->payload_ext.payload.type);
        return -1;
    }

    // read data entries from buffer
    sky_entry_ext_t * p_entry_ex = &creq->payload_ext.data_entry;
    uint32_t payload_offset = sizeof(sky_payload_t);
    while (payload_offset < creq->header.payload_length) {
        uint32_t sz = 0;
        switch (p_entry_ex->entry->data_type) {
        case DATA_TYPE_MAC:
            creq->mac_count = p_entry_ex->entry->data_type_count;
            sz = MAC_SIZE * p_entry_ex->entry->data_type_count;
            creq->mac = p_entry_ex->data;
            break;
        case DATA_TYPE_IPV4:
            creq->ip_count = p_entry_ex->entry->data_type_count;
            creq->ip_type = DATA_TYPE_IPV4;
            sz = IPV4_SIZE * p_entry_ex->entry->data_type_count;
            creq->ip_addr = p_entry_ex->data;
            break;
        case DATA_TYPE_IPV6:
            creq->ip_count = p_entry_ex->entry->data_type_count;
            creq->ip_type = DATA_TYPE_IPV6;
            sz = IPV6_SIZE * p_entry_ex->entry->data_type_count;
            creq->ip_addr = p_entry_ex->data;
            break;
        case DATA_TYPE_AP:
            creq->ap_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct ap_t) * p_entry_ex->entry->data_type_count;
            creq->aps = (struct ap_t *)p_entry_ex->data;
            break;
        case DATA_TYPE_BLE:
            creq->ble_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct ble_t) * p_entry_ex->entry->data_type_count;
            creq->bles = (struct ble_t *)p_entry_ex->data;
#ifdef __BIG_ENDIAN__
            sky_ble_endian_swap(creq->bles);
#endif
            break;
        case DATA_TYPE_GSM:
            creq->gsm_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct gsm_t) * p_entry_ex->entry->data_type_count;
            creq->gsms = (struct gsm_t *)p_entry_ex->data;
#ifdef __BIG_ENDIAN__
            sky_gsm_endian_swap(&creq->cell->gsm);
#endif
            break;
        case DATA_TYPE_CDMA:
            creq->cdma_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct cdma_t) * p_entry_ex->entry->data_type_count;
            creq->cdmas = (struct cdma_t *)p_entry_ex->data;
#ifdef __BIG_ENDIAN__
            sky_cdma_endian_swap(&creq->cell->cdma);
#endif
            break;
        case DATA_TYPE_UMTS:
            creq->umts_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct umts_t) * p_entry_ex->entry->data_type_count;
            creq->umtss = (struct umts_t *)p_entry_ex->data;
#ifdef __BIG_ENDIAN__
            sky_umts_endian_swap(&creq->cell->umtss);
#endif
            break;
        case DATA_TYPE_LTE:
            creq->lte_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct lte_t) * p_entry_ex->entry->data_type_count;
            creq->ltes = (struct lte_t *)p_entry_ex->data;
#ifdef __BIG_ENDIAN__
            sky_lte_endian_swap(&creq->cell->lte);
#endif
            break;
        case DATA_TYPE_GPS:
            creq->gps_count = p_entry_ex->entry->data_type_count;
            sz = sizeof(struct gps_t) * p_entry_ex->entry->data_type_count;
            creq->gps = (struct gps_t *)p_entry_ex->data;
#ifdef __BIG_ENDIAN__
            sky_gps_endian_swap(creq->gps);
#endif
            break;
        case DATA_TYPE_PAD:
            return 0; // success
        default:
            perror("unknown data type");
            return -1;
        }
        payload_offset += sizeof(sky_entry_t) + sz;
        adjust_data_entry(buff, buff_len, sizeof(sky_rq_header_t) + payload_offset, p_entry_ex);
    }
    return 0;
}

// sent by the server to the client
/* encodes the loc struct into binary formatted packet sent to client */
// returns the packet len or -1 when fails
int32_t sky_encode_resp_bin(uint8_t *buff, uint32_t buff_len, struct location_rsp_t *cresp) {

    uint32_t payload_length = sizeof(sky_payload_t);

    // count bytes of data entries
    switch (cresp->payload_ext.payload.type) {
    case LOCATION_RQ_SUCCESS:
        payload_length += sizeof(sky_entry_t) + sizeof(struct location_t); // latitude and longitude
        break;
    case LOCATION_RQ_ADDR_SUCCESS:
        payload_length += sizeof(sky_entry_t) + sizeof(struct location_t); // latitude and longitude
        if (cresp->location_ext.mac_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.mac_len;
        if (cresp->location_ext.ip_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.ip_len;
        if (cresp->location_ext.street_num_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.street_num_len;
        if (cresp->location_ext.address_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.address_len;
        if (cresp->location_ext.city_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.city_len;
        if (cresp->location_ext.state_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.state_len;
        if (cresp->location_ext.state_code_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.state_code_len;
        if (cresp->location_ext.metro1_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.metro1_len;
        if (cresp->location_ext.metro2_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.metro2_len;
        if (cresp->location_ext.postal_code_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.postal_code_len;
        if (cresp->location_ext.county_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.county_len;
        if (cresp->location_ext.country_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.country_len;
        if (cresp->location_ext.country_code_len > 0)
            payload_length += sizeof(sky_entry_t) + cresp->location_ext.country_code_len;
        break;
    default: // i.e. PROBE_REQUEST_SUCCESS, LOCATION_RQ_ERROR, LOCATION_GATEWAY_ERROR, LOCATION_API_ERROR, etc.
        // no data entry in payload so far
        break;
    }

    // payload length must be a multiple of 16 bytes
    uint8_t pad_len = pad_16(payload_length);
    payload_length += pad_len;

    // Note that buffer contains the legacy date for location request,
    // so some fields (e.g. user id) are correct already.
    // update fields in buffer
    cresp->header.payload_length = payload_length;
    sky_gen_iv(cresp->header.iv); // 16 byte initialization vector
    if (!sky_set_header(buff, buff_len, (uint8_t *)&cresp->header, sizeof(cresp->header)))
        return -1;

    if (!sky_set_payload(buff, buff_len, sizeof(sky_rsp_header_t), &cresp->payload_ext, cresp->header.payload_length))
        return -1;

    // fill in data entries in place in buffer

#ifdef __BIG_ENDIAN__
    sky_location_endian_swap(&cresp->location);
#endif

    // latitude and longitude
    if (cresp->payload_ext.payload.type == LOCATION_RQ_SUCCESS) {
        sky_entry_ext_t * p_entry_ex = &cresp->payload_ext.data_entry;
        p_entry_ex->entry->data_type = DATA_TYPE_LAT_LON;
        p_entry_ex->entry->data_type_count = sizeof(cresp->location);
        memcpy(p_entry_ex->data, &cresp->location, sizeof(cresp->location));
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
    }
    // latitude, longitude, and full address, etc.
    if (cresp->payload_ext.payload.type == LOCATION_RQ_ADDR_SUCCESS) {
        sky_entry_ext_t * p_entry_ex = &cresp->payload_ext.data_entry;
        p_entry_ex->entry->data_type = DATA_TYPE_LAT_LON;
        p_entry_ex->entry->data_type_count = sizeof(cresp->location);
        memcpy(p_entry_ex->data, &cresp->location, sizeof(cresp->location));
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);

        if (cresp->location_ext.mac_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_MAC;
            p_entry_ex->entry->data_type_count = cresp->location_ext.mac_len;
            memcpy(p_entry_ex->data, cresp->location_ext.mac, p_entry_ex->entry->data_type_count);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.ip_len > 0) {
            p_entry_ex->entry->data_type = cresp->location_ext.ip_type;
            p_entry_ex->entry->data_type_count = cresp->location_ext.ip_len;
            memcpy(p_entry_ex->data, cresp->location_ext.ip_addr, p_entry_ex->entry->data_type_count);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.street_num_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_STREET_NUM;
            p_entry_ex->entry->data_type_count = cresp->location_ext.street_num_len;
            memcpy(p_entry_ex->data, cresp->location_ext.street_num, cresp->location_ext.street_num_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.address_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_ADDRESS;
            p_entry_ex->entry->data_type_count = cresp->location_ext.address_len;
            memcpy(p_entry_ex->data, cresp->location_ext.address, cresp->location_ext.address_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.city_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_CITY;
            p_entry_ex->entry->data_type_count = cresp->location_ext.city_len;
            memcpy(p_entry_ex->data, cresp->location_ext.city, cresp->location_ext.city_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.state_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_STATE;
            p_entry_ex->entry->data_type_count = cresp->location_ext.state_len;
            memcpy(p_entry_ex->data, cresp->location_ext.state, cresp->location_ext.state_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.state_code_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_STATE_CODE;
            p_entry_ex->entry->data_type_count = cresp->location_ext.state_code_len;
            memcpy(p_entry_ex->data, cresp->location_ext.state_code, cresp->location_ext.state_code_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.metro1_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_METRO1;
            p_entry_ex->entry->data_type_count = cresp->location_ext.metro1_len;
            memcpy(p_entry_ex->data, cresp->location_ext.metro1, cresp->location_ext.metro1_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.metro2_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_METRO2;
            p_entry_ex->entry->data_type_count = cresp->location_ext.metro2_len;
            memcpy(p_entry_ex->data, cresp->location_ext.metro2, cresp->location_ext.metro2_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.postal_code_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_POSTAL_CODE;
            p_entry_ex->entry->data_type_count = cresp->location_ext.postal_code_len;
            memcpy(p_entry_ex->data, cresp->location_ext.postal_code, cresp->location_ext.postal_code_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);;
        }

        if (cresp->location_ext.county_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_COUNTY;
            p_entry_ex->entry->data_type_count = cresp->location_ext.county_len;
            memcpy(p_entry_ex->data, cresp->location_ext.county, cresp->location_ext.county_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.country_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_COUNTRY;
            p_entry_ex->entry->data_type_count = cresp->location_ext.country_len;
            memcpy(p_entry_ex->data, cresp->location_ext.country, cresp->location_ext.country_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }

        if (cresp->location_ext.country_code_len > 0) {
            p_entry_ex->entry->data_type = DATA_TYPE_COUNTRY_CODE;
            p_entry_ex->entry->data_type_count = cresp->location_ext.country_code_len;
            memcpy(p_entry_ex->data, cresp->location_ext.country_code, cresp->location_ext.country_code_len);
            adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + p_entry_ex->entry->data_type_count, p_entry_ex);
        }
    }

    // fill in padding bytes
    if (pad_len > 0) {
        uint8_t * pad_bytes = buff + sizeof(sky_rsp_header_t) + cresp->header.payload_length - pad_len;
        memset(pad_bytes, DATA_TYPE_PAD, pad_len);
    }

    sky_set_checksum(buff, buff_len, (uint8_t)sizeof(cresp->header), cresp->header.payload_length);

    return sizeof(sky_rsp_header_t) + cresp->header.payload_length + sizeof(sky_checksum_t);
}

// sent by the client to the server
/* encodes the request struct into binary formatted packet sent to server */
// returns the packet len or -1 when fails
int32_t sky_encode_req_bin(uint8_t *buff, uint32_t buff_len, struct location_rq_t *creq) {

    if (creq->cell_count &&
            (creq->gsm_count || creq->cdma_count || creq->umts_count || creq->lte_count)) {
        perror("struct location_rq_t: use cell_t or gsm_t|cdma_t|umts_t|lte_t, but not both");
        return -1;
    }
    if (!check_rq_max_counts(creq))
        return -1;

    if (creq->payload_ext.payload.type != LOCATION_RQ
            && creq->payload_ext.payload.type != LOCATION_RQ_ADDR) {
        fprintf(stderr, "sky_encode_req_bin: unknown payload type %d\n", creq->payload_ext.payload.type);
        return -1;
    }

    uint32_t payload_length = sizeof(sky_payload_t);
    if (creq->mac_count > 0)
        payload_length += sizeof(sky_entry_t) + creq->mac_count * MAC_SIZE;
    if (creq->ip_count > 0)
        payload_length += sizeof(sky_entry_t) +
            creq->ip_count * (creq->ip_type == DATA_TYPE_IPV4 ? IPV4_SIZE : IPV6_SIZE);
    if (creq->ap_count > 0)
        payload_length += sizeof(sky_entry_t) + creq->ap_count * sizeof(struct ap_t);
    if (creq->ble_count > 0)
        payload_length += sizeof(sky_entry_t) + creq->ble_count * sizeof(struct ble_t);
    if (creq->gps_count > 0)
        payload_length += sizeof(sky_entry_t) + creq->gps_count * sizeof(struct gps_t);
    if (creq->cell_count > 0) {
        uint32_t sz;
        switch (creq->cell_type) {
        case DATA_TYPE_GSM:
            sz = sizeof(struct gsm_t);
            break;
        case DATA_TYPE_CDMA:
            sz = sizeof(struct cdma_t);
            break;
        case DATA_TYPE_UMTS:
            sz = sizeof(struct umts_t);
            break;
        case DATA_TYPE_LTE:
            sz = sizeof(struct lte_t);
            break;
        default:
            perror("unknown data type");
            return -1;
        }
        payload_length += creq->cell_count * sz + sizeof(sky_entry_t);
    }
    if (creq->gsm_count > 0) {
        payload_length += sizeof(sky_entry_t) + creq->gsm_count * sizeof(struct gsm_t);
    }
    if (creq->cdma_count > 0) {
        payload_length += sizeof(sky_entry_t) + creq->cdma_count * sizeof(struct cdma_t);
    }
    if (creq->umts_count > 0) {
        payload_length += sizeof(sky_entry_t) + creq->umts_count * sizeof(struct umts_t);
    }
    if (creq->lte_count > 0) {
        payload_length += sizeof(sky_entry_t) + creq->lte_count * sizeof(struct lte_t);
    }

    // payload length must be a multiple of 16 bytes
    uint8_t pad_len = pad_16(payload_length);
    payload_length += pad_len;

    creq->header.payload_length = payload_length;
    creq->header.user_id = creq->key.partner_id;
    // 16 byte initialization vector
    sky_gen_iv(creq->header.iv);
    if (!sky_set_header(buff, buff_len, (uint8_t *)&creq->header, sizeof(creq->header)))
        return -1;

    if (!sky_set_payload(buff, buff_len, sizeof(sky_rq_header_t), &creq->payload_ext, creq->header.payload_length))
        return -1;

    // fill in data entries in buffer
    sky_entry_ext_t * p_entry_ex = &creq->payload_ext.data_entry;
    uint32_t sz = 0;
    // MAC
    {
        p_entry_ex->entry->data_type = DATA_TYPE_MAC;
        p_entry_ex->entry->data_type_count = creq->mac_count;
        sz = MAC_SIZE * p_entry_ex->entry->data_type_count;
        memcpy(p_entry_ex->data, creq->mac, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // IP
    if (creq->ip_type == DATA_TYPE_IPV4) {
        // IPv4
        p_entry_ex->entry->data_type = DATA_TYPE_IPV4;
        p_entry_ex->entry->data_type_count = creq->ip_count;
        sz = IPV4_SIZE * p_entry_ex->entry->data_type_count;
        memcpy(p_entry_ex->data, creq->ip_addr, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    } else {
        // IPv6
        p_entry_ex->entry->data_type = DATA_TYPE_IPV6;
        p_entry_ex->entry->data_type_count = creq->ip_count;
        sz = IPV6_SIZE * p_entry_ex->entry->data_type_count;
        memcpy(p_entry_ex->data, creq->ip_addr, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // Access Point
    if (creq->ap_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_AP;
        p_entry_ex->entry->data_type_count = creq->ap_count;
        sz = sizeof(struct ap_t) * creq->ap_count;
        memcpy(p_entry_ex->data, creq->aps, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // Blue Tooth
    if (creq->ble_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_BLE;
        p_entry_ex->entry->data_type_count = creq->ble_count;
        sz = sizeof(struct ble_t) * creq->ble_count;
#ifdef __BIG_ENDIAN__
        sky_ble_endian_swap(creq->bles);
#endif
        memcpy(p_entry_ex->data, creq->bles, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // Cell
    if (creq->cell_count > 0) {
        p_entry_ex->entry->data_type = creq->cell_type;
        p_entry_ex->entry->data_type_count = creq->cell_count;
        switch (creq->cell_type) {
        case DATA_TYPE_GSM:
            sz = sizeof(struct gsm_t) * creq->cell_count;
#ifdef __BIG_ENDIAN__
            sky_gsm_endian_swap(&creq->cell->gsm);
#endif
            memcpy(p_entry_ex->data, &creq->cell->gsm, sz);
            break;
        case DATA_TYPE_LTE:
            sz = sizeof(struct lte_t) * creq->cell_count;
#ifdef __BIG_ENDIAN__
            sky_lte_endian_swap(&creq->cell->lte);
#endif
            memcpy(p_entry_ex->data, &creq->cell->lte, sz);
            break;
        case DATA_TYPE_CDMA:
            sz = sizeof(struct cdma_t) * creq->cell_count;
#ifdef __BIG_ENDIAN__
            sky_cdma_endian_swap(&creq->cell->cdma);
#endif
            memcpy(p_entry_ex->data, &creq->cell->cdma, sz);
            break;
        case DATA_TYPE_UMTS:
            sz = sizeof(struct umts_t) * creq->cell_count;
#ifdef __BIG_ENDIAN__
            sky_umts_endian_swap(&creq->cell->umts);
#endif
            memcpy(p_entry_ex->data, &creq->cell->umts, sz);
            break;
        default:
            perror("unknown data type");
            return -1;
        }
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // GSM
    if (creq->gsm_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_GSM;
        p_entry_ex->entry->data_type_count = creq->gsm_count;
        sz = sizeof(struct gsm_t) * creq->gsm_count;
#ifdef __BIG_ENDIAN__
        sky_gsm_endian_swap(creq->gsms);
#endif
        memcpy(p_entry_ex->data, creq->gsms, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // CDMA
    if (creq->cdma_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_CDMA;
        p_entry_ex->entry->data_type_count = creq->cdma_count;
        sz = sizeof(struct cdma_t) * creq->cdma_count;
#ifdef __BIG_ENDIAN__
        sky_cdma_endian_swap(creq->cdmas);
#endif
        memcpy(p_entry_ex->data, creq->cdmas, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // UMTS
    if (creq->umts_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_UMTS;
        p_entry_ex->entry->data_type_count = creq->umts_count;
        sz = sizeof(struct umts_t) * creq->umts_count;
#ifdef __BIG_ENDIAN__
        sky_umts_endian_swap(creq->umtss);
#endif
        memcpy(p_entry_ex->data, creq->umtss, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // LTE
    if (creq->lte_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_LTE;
        p_entry_ex->entry->data_type_count = creq->lte_count;
        sz = sizeof(struct lte_t) * creq->lte_count;
#ifdef __BIG_ENDIAN__
        sky_lte_endian_swap(creq->ltes);
#endif
        memcpy(p_entry_ex->data, creq->ltes, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }
    // GPS
    if (creq->gps_count > 0) {
        p_entry_ex->entry->data_type = DATA_TYPE_GPS;
        p_entry_ex->entry->data_type_count = creq->gps_count;
        sz = sizeof(struct gps_t) * creq->gps_count;
#ifdef __BIG_ENDIAN__
        sky_gps_endian_swap(creq->gps);
#endif
        memcpy(p_entry_ex->data, creq->gps, sz);
        adjust_data_entry(buff, buff_len, (p_entry_ex->data - buff) + sz, p_entry_ex);
    }

    // fill in padding bytes
    if (pad_len > 0) {
        uint8_t * pad_bytes = p_entry_ex->data - sizeof(sky_entry_t);
        memset(pad_bytes, DATA_TYPE_PAD, pad_len);
    }

    if (!sky_set_checksum(buff, buff_len, (uint8_t)sizeof(creq->header), creq->header.payload_length))
        return -1;

    return sizeof(sky_rq_header_t) + creq->header.payload_length + sizeof(sky_checksum_t);
}

// received by the client from the server
/* decodes the binary data and the result is in the location_resp_t struct */
int32_t sky_decode_resp_bin(uint8_t *buff, uint32_t buff_len, uint32_t data_len,
        struct location_rsp_t *cresp) {

    memset(&cresp->header, 0, sizeof(cresp->header));
    if (!sky_get_header(buff, buff_len, (uint8_t *)&cresp->header, sizeof(cresp->header)))
        return -1;
    if (!sky_verify_checksum(buff, buff_len, (uint8_t)sizeof(cresp->header), cresp->header.payload_length))
        return -1;
    if (!sky_get_payload(buff, buff_len, sizeof(sky_rsp_header_t), &cresp->payload_ext, cresp->header.payload_length))
        return -1;

    if (cresp->payload_ext.payload.type != LOCATION_RQ_SUCCESS
            && cresp->payload_ext.payload.type != LOCATION_RQ_ADDR_SUCCESS) {

        switch (cresp->payload_ext.payload.type) {
        case PROBE_REQUEST_SUCCESS:
        case LOCATION_RQ_ERROR:
        case LOCATION_GATEWAY_ERROR:
        case LOCATION_API_ERROR:
        case LOCATION_UNKNOWN:
        case LOCATION_UNABLE_TO_DETERMINE:
            return 0; // success
        default:
            fprintf(stderr, "Unknown payload type %d\n", cresp->payload_ext.payload.type);
            return -1;
        }
    }

    // read data entries from buffer
    // latitude, longitude and full address, etc.
    sky_entry_ext_t * p_entry_ex = &cresp->payload_ext.data_entry;
    uint32_t payload_offset = sizeof(sky_payload_t);
    while (payload_offset < cresp->header.payload_length) {
        switch (p_entry_ex->entry->data_type) {
        case DATA_TYPE_MAC:
            cresp->location_ext.mac_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.mac = p_entry_ex->data;
            break;
        case DATA_TYPE_IPV4:
            cresp->location_ext.ip_type = DATA_TYPE_IPV4;
            cresp->location_ext.ip_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.ip_addr = p_entry_ex->data;
            break;
        case DATA_TYPE_IPV6:
            cresp->location_ext.ip_type = DATA_TYPE_IPV6;
            cresp->location_ext.ip_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.ip_addr = p_entry_ex->data;
            break;
        case DATA_TYPE_LAT_LON:
#ifdef __BIG_ENDIAN__
            sky_location_endian_swap(&cresp->location);
#endif
            memcpy(&cresp->location, p_entry_ex->data, p_entry_ex->entry->data_type_count);
            break;
        case DATA_TYPE_STREET_NUM:
            cresp->location_ext.street_num_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.street_num = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_ADDRESS:
            cresp->location_ext.address_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.address = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_CITY:
            cresp->location_ext.city_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.city = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_STATE:
            cresp->location_ext.state_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.state = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_STATE_CODE:
            cresp->location_ext.state_code_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.state_code = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_METRO1:
            cresp->location_ext.metro1_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.metro1 = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_METRO2:
            cresp->location_ext.metro2_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.metro2 = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_POSTAL_CODE:
            cresp->location_ext.postal_code_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.postal_code = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_COUNTY:
            cresp->location_ext.county_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.county = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_COUNTRY:
            cresp->location_ext.country_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.country = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_COUNTRY_CODE:
            cresp->location_ext.country_code_len = p_entry_ex->entry->data_type_count;
            cresp->location_ext.country_code = (char *)p_entry_ex->data;
            break;
        case DATA_TYPE_PAD:
            return 0; // success
        default:
            perror("unknown data type");
            return -1;
        }
        payload_offset += sizeof(sky_entry_t) + p_entry_ex->entry->data_type_count;
        adjust_data_entry(buff, buff_len, sizeof(sky_rsp_header_t) + payload_offset, p_entry_ex);
    }
    return 0; // success
}
