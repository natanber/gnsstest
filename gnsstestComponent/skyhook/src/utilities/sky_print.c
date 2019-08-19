/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "sky_protocol.h"
#include "sky_util.h"
#include "sky_print.h"

void print_location_rq(struct location_rsp_t* cr) {
    puts("LOCATION_RQ");
    printf("latitude: %f\n", cr->location.lat);
    printf("longitude: %f\n", cr->location.lon);
    printf("hpe: %f\n", cr->location.hpe);
    printf("distance_to_point: %f\n", cr->location.distance_to_point);
}

void print_location_rq_addr(struct location_rsp_t* cr) {
    printf("Device MAC: ");
    if (cr->location_ext.mac_len > 0) {
        uint8_t i;
        for (i = 0; i < 6; i++)
            printf("%02X", cr->location_ext.mac[i]);
        printf("\n");
    } else {
        printf("n/a\n");
    }
    puts("LOCATION_RQ_ADDR");
    printf("street num: ");
    print_s(cr->location_ext.street_num, cr->location_ext.street_num_len);
    printf("address: ");
    print_s(cr->location_ext.address, cr->location_ext.address_len);
    printf("city: ");
    print_s(cr->location_ext.city, cr->location_ext.city_len);
    printf("state: ");
    print_s(cr->location_ext.state, cr->location_ext.state_len);
    printf("state code: ");
    print_s(cr->location_ext.state_code, cr->location_ext.state_code_len);
    printf("postal code: ");
    print_s(cr->location_ext.postal_code, cr->location_ext.postal_code_len);
    printf("county: ");
    print_s(cr->location_ext.county, cr->location_ext.county_len);
    printf("country: ");
    print_s(cr->location_ext.country, cr->location_ext.country_len);
    printf("country code: ");
    print_s(cr->location_ext.country_code, cr->location_ext.country_code_len);
    printf("metro1: ");
    print_s(cr->location_ext.metro1, cr->location_ext.metro1_len);
    printf("metro2: ");
    print_s(cr->location_ext.metro2, cr->location_ext.metro2_len);
    printf("ip: ");
    if (cr->location_ext.ip_len > 0) {
        print_ip(cr->location_ext.ip_addr, cr->location_ext.ip_type);
    } else {
        printf("n/a\n");
    }
}

void print_location_resp(struct location_rsp_t *cr) {
    uint64_t timestamp = 0;
    memcpy((uint8_t *)&timestamp, cr->payload_ext.payload.timestamp, sizeof(cr->payload_ext.payload.timestamp));
    printf("\n");
    printf("timestamp: %llu\n", timestamp);
    printf("protocol: %d\n", cr->header.version);
    printf("server version: %d\n", cr->payload_ext.payload.sw_version);
    printf("payload type no: %d\n", cr->payload_ext.payload.type);

    switch (cr->payload_ext.payload.type) {
    case LOCATION_RQ_SUCCESS:
        puts("LOCATION_RQ_SUCCESS");
        print_location_rq(cr);
        break;
    case LOCATION_RQ_ADDR_SUCCESS:
        puts("LOCATION_RQ_ADDR_SUCCESS");
        print_location_rq(cr);
        print_location_rq_addr(cr);
        break;
    case PROBE_REQUEST_SUCCESS:
        puts("PROBE_REQUEST_SUCCESS");
        break;
    case LOCATION_API_ERROR:
        puts("LOCATION_API_ERROR");
        break;
    case LOCATION_GATEWAY_ERROR:
        puts("LOCATION_GATEWAY_ERROR");
        break;
    case LOCATION_RQ_ERROR:
        puts("LOCATION_RQ_ERROR");
        break;
    case LOCATION_UNABLE_TO_DETERMINE:
        puts("LOCATION_UNABLE_TO_DETERMINE");
        break;
    case LOCATION_UNKNOWN:
        puts("LOCATION_UNKNOWN");
        break;
    }
}

void print_location_req(struct location_rq_t *cr) {
    int32_t i, j;

    printf("protocol: %d\n", cr->header.version);
    printf("payload type: %d\n", cr->payload_ext.payload.type);
    printf("firmware version: %d\n", cr->payload_ext.payload.sw_version);

    printf("partner_id: %d\n", cr->key.partner_id);

    printf("Device MAC: ");
    if (cr->mac_count > 0) {
        for (i = 0; i < 6; i++)
            printf("%02X", cr->mac[i]);
    } else {
        printf("n/a");
    }
    printf("\n");

    printf("Access points %d\n", cr->ap_count);
    for (i = 0; i < cr->ap_count; i++) {
        printf("MAC: ");
        for (j = 0; j < 6; j++)
            printf("%02X", cr->aps[i].MAC[j]);
        printf("\n");
        printf("rssi: %d\n", cr->aps[i].rssi);
    }

    printf("BLE %d\n", cr->ble_count);

    for (i = 0; i < cr->ble_count; i++) {
        printf("MAC: ");
        for (j = 0; j < 6; j++)
            printf("%02X", cr->bles[i].MAC[j]);
        printf("\n");
        printf("major: %d\n", cr->bles[i].major);
        printf("minor: %d\n", cr->bles[i].minor);

        printf("uuid: ");
        for (j = 0; j < 16; j++)
            printf("%02X", cr->bles[i].uuid[j]);
        printf("\n");
    }

    printf("CELL %d\n", cr->cell_count);

    switch (cr->cell_type) {
    case DATA_TYPE_GSM:
        puts("CELL TYPE: GSM");
        break;
    case DATA_TYPE_CDMA:
        puts("CELL TYPE: CDMA");
        break;
    case DATA_TYPE_UMTS:
        puts("CELL TYPE: UMTS");
        break;
    case DATA_TYPE_LTE:
        puts("CELL TYPE: LTE");
        break;
    default:
        puts("CELL TYPE: NONE");
    }

    for (i = 0; i < cr->cell_count; i++) {
        switch (cr->cell_type) {
        case DATA_TYPE_GSM:
            printf("age: %d\n", cr->cell[i].gsm.age);
            printf("ci: %d\n", cr->cell[i].gsm.ci);
            printf("mcc: %d\n", cr->cell[i].gsm.mcc);
            printf("mnc: %d\n", cr->cell[i].gsm.mnc);
            printf("lac: %d\n", cr->cell[i].gsm.lac);
            printf("rssi: %d\n", cr->cell[i].gsm.rssi);
            break;

        case DATA_TYPE_UMTS:
            printf("age: %d\n", cr->cell[i].umts.age);
            printf("ci: %d\n", cr->cell[i].umts.ci);
            printf("mcc: %d\n", cr->cell[i].umts.mcc);
            printf("mnc: %d\n", cr->cell[i].umts.mnc);
            printf("lac: %d\n", cr->cell[i].umts.lac);
            printf("rssi: %d\n", cr->cell[i].umts.rssi);
            break;

        case DATA_TYPE_CDMA:
            printf("age: %d\n", cr->cell[i].cdma.age);
            printf("lat: %f\n", cr->cell[i].cdma.lat);
            printf("lon: %f\n", cr->cell[i].cdma.lon);
            printf("sid: %d\n", cr->cell[i].cdma.sid);
            printf("nid: %d\n", cr->cell[i].cdma.nid);
            printf("bsid: %d\n", cr->cell[i].cdma.bsid);
            printf("rssi: %d\n", cr->cell[i].cdma.rssi);
            break;

        case DATA_TYPE_LTE:
            printf("age: %d\n", cr->cell[i].lte.age);
            printf("eucid: %d\n", cr->cell[i].lte.eucid);
            printf("mcc: %d\n", cr->cell[i].lte.mcc);
            printf("mnc: %d\n", cr->cell[i].lte.mnc);
            printf("rssi: %d\n", cr->cell[i].lte.rssi);
            break;

        default:
            printf("unknown cell type %d\n", cr->cell_type);
        }
    }

    printf("GSM %d\n", cr->gsm_count);

    for (i = 0; i < cr->gsm_count; i++) {
        printf("age: %d\n", cr->gsms[i].age);
        printf("ci: %d\n", cr->gsms[i].ci);
        printf("mcc: %d\n", cr->gsms[i].mcc);
        printf("mnc: %d\n", cr->gsms[i].mnc);
        printf("lac: %d\n", cr->gsms[i].lac);
        printf("rssi: %d\n", cr->gsms[i].rssi);
    }

    printf("CDMA %d\n", cr->cdma_count);

    for (i = 0; i < cr->cdma_count; i++) {
        printf("age: %d\n", cr->cdmas[i].age);
        printf("lat: %f\n", cr->cdmas[i].lat);
        printf("lon: %f\n", cr->cdmas[i].lon);
        printf("sid: %d\n", cr->cdmas[i].sid);
        printf("nid: %d\n", cr->cdmas[i].nid);
        printf("bsid: %d\n", cr->cdmas[i].bsid);
        printf("rssi: %d\n", cr->cdmas[i].rssi);
    }

    printf("UMTS %d\n", cr->umts_count);

    for (i = 0; i < cr->umts_count; i++) {
        printf("age: %d\n", cr->umtss[i].age);
        printf("ci: %d\n", cr->umtss[i].ci);
        printf("mcc: %d\n", cr->umtss[i].mcc);
        printf("mnc: %d\n", cr->umtss[i].mnc);
        printf("lac: %d\n", cr->umtss[i].lac);
        printf("rssi: %d\n", cr->umtss[i].rssi);
    }

    printf("LTE %d\n", cr->lte_count);

    for (i = 0; i < cr->lte_count; i++) {
        printf("age: %d\n", cr->ltes[i].age);
        printf("eucid: %d\n", cr->ltes[i].eucid);
        printf("mcc: %d\n", cr->ltes[i].mcc);
        printf("mnc: %d\n", cr->ltes[i].mnc);
        printf("rssi: %d\n", cr->ltes[i].rssi);
    }

    printf("GPS %d\n", cr->gps_count);

    for (i = 0; i < cr->gps_count; i++) {
        printf("lat: %f\n", cr->gps[i].lat);
        printf("lon: %f\n", cr->gps[i].lon);
        printf("hdop: %f\n", cr->gps[i].hdop);
        printf("alt: %f\n", cr->gps[i].alt);
        printf("hpe: %f\n", cr->gps[i].hpe);
        printf("speed: %f\n", cr->gps[i].speed);
        printf("nsat: %d\n", cr->gps[i].nsat);
        printf("fix: %d\n", cr->gps[i].fix);
        printf("age: %d\n", cr->gps[i].age);
    }

}
