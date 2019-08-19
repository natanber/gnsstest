/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <float.h>
#include "sky_xml.h"
#include "sky_util.h"

// TODO replace this with a proper xml parser

// returns count of non-overlapping occurrences of 'tag' in 'buff'
uint32_t countTag(const char * buff, const char * tag) {
    uint32_t tag_len = strlen(tag);
    if (tag_len == 0)
        return 0;

    uint32_t count = 0;
    const char * p = buff;
    while ((p = strstr(p, tag))) {
        ++count;
        p += tag_len;
    }
    return count;
}

// encodes location_req_t into xml result is in buff
// returns str len or -1 if it fails
int32_t sky_encode_req_xml(char *buff, int32_t bufflen, const struct location_rq_t *creq) {
    const char xml[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    const char locrq[] =
            "<LocationRQ xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                    "xsi:schemaLocation=\"http://skyhookwireless.com/wps/2005 ../../src/xsd/location.xsd\"\n"
                    "xmlns=\"http://skyhookwireless.com/wps/2005\"\n"
                    "version=\"%s\"\n"
                    "street-address-lookup=\"%s\">\n";

    const char locrq_eof[] = "</LocationRQ>\n";

    const char auth[] = "<authentication version=\"2.2\">\n"
            "<key key=\"%s\" "
            "username=\"%s\"/>\n"
            "</authentication>\n";

    const char ap[] = "<access-point>\n";
    const char ap_eof[] = "</access-point>\n";
    const char mac[] = "<mac>%s</mac>\n";
    const char sigs[] = "<signal-strength>%d</signal-strength>\n";

    const char ble[] = "<ble>\n";
    const char ble_eof[] = "</ble>\n";
    const char major[] = "<major>%d</major>";
    const char minor[] = "<minor>%d</minor>";
    const char uuid[] = "<uuid>%s</uuid>";

    const char gsm[] = "<gsm-tower>\n";
    const char gsm_eof[] = "</gsm-tower>\n";
    const char umts[] = "<umts-tower>\n";
    const char umts_eof[] = "</umts-tower>\n";
    const char lte[] = "<lte-tower>\n";
    const char lte_eof[] = "</lte-tower>\n";
    const char cdma[] = "<cdma-tower>\n";
    const char cdma_eof[] = "</cdma-tower>\n";

    const char mcc[] = "<mcc>%d</mcc>\n";
    const char mnc[] = "<mnc>%d</mnc>\n";
    const char lac[] = "<lac>%d</lac>\n";
    const char ci[] = "<ci>%d</ci>\n";
    const char rssi[] = "<rssi>%d</rssi>\n";
    const char sid[] = "<sid>%d</sid>\n";
    const char nid[] = "<nid>%d</nid>\n";
    const char bsid[] = "<bsid>%d</bsid>\n";
    const char eucid[] = "<eucid>%d</eucid>\n";
    const char cdma_lat[] = "<cdma-lat>%f</cdma-lat>\n";
    const char cdma_lon[] = "<cdma-lon>%f</cdma-lon>\n";

    //const char gps[] = "<gps-location fix=\"%d\" nsat=\"%d\" hdop=\"%f\">\n";
    const char gps_[] = "<gps-location ";
    const char gps_eof[] = "</gps-location>\n";
    const char lat[] = "<latitude>%f</latitude>\n";
    const char lon[] = "<longitude>%f</longitude>\n";
    const char hpe[] = "<hpe>%.0f</hpe>\n";
    const char alt[] = "<altitude>%f</altitude>\n";
    //const char height[]     = "<height>%f</height>\n";
    //const char vpe[]        = "<vpe>%.0f</vpe>\n";
    const char speed[] = "<speed>%f</speed>\n";
    const char age[] = "<age>%d</age>\n";

    // calculate whether xml will fit into buff
    int32_t sizes = 310 + 39 + 236 + 14 + 96
            +\
 (17 + 18 + 18 + 42 + 12 + 4) * creq->ap_count
            +\
 (8 + 9 + 18 + 21 + 21 + 19 + 12 + 5 + 5 + 32) * creq->ble_count
            +\
 (15 + 16 + 18 + 18 + 18 + 16 + 20 + 5 + 5 + 5 + 7 + 5 + 3)
                    * (creq->gsm_count + creq->cdma_count + creq->umts_count + creq->lte_count)
            +\
 (36 + 18 + 28 + 30 + 18 + 28 + 24 + 18 + 18 + 12 + 12 + 8 + 8
                    + 8 + 8 + 8 + 8) * creq->gps_count;

    if (bufflen < sizes + 200) //add 200 for safety margin
            {
        perror("xml buffer too small");
        return -1;
    }

    int32_t i;
    size_t sz;

    char *p = buff;
    sz = strlen(xml);
    strncpy(p, xml, sz);
    p += sz;

    if (creq->payload_ext.payload.type == LOCATION_RQ_ADDR)
        p += sprintf(p, locrq, creq->api_version, "full");
    else
        p += sprintf(p, locrq, creq->api_version, "none");

    char hexstr[33]; // max is ble uuid + 1

    if (bin2hex(hexstr, 32, creq->mac, 6) == -1) {
        perror("target buffer too small");
        return -1;
    }

    hexstr[12] = '\0'; // end the string
    p += sprintf(p, auth, creq->key.keyid, hexstr); // using software version as username

    // set ap attributes
    for (i = 0; i < creq->ap_count; i++) {
        sz = strlen(ap);
        strncpy(p, ap, sz);
        p += sz;

        if (bin2hex(hexstr, 32, creq->aps[i].MAC, 6) == -1) {
            perror("target buffer too small");
            return -1;
        }
        hexstr[12] = '\0';

        p += sprintf(p, mac, hexstr);
        p += sprintf(p, sigs, creq->aps[i].rssi);

        sz = strlen(ap_eof);
        strncpy(p, ap_eof, sz);
        p += sz;
    }

    // set ble attributes
    for (i = 0; i < creq->ble_count; i++) {
        sz = strlen(ble);
        strncpy(p, ble, sz);
        p += sz;

        if (bin2hex(hexstr, 32, creq->bles[i].MAC, 6) == -1) {
            perror("target buffer too small");
            return -1;
        }
        hexstr[12] = '\0';
        p += sprintf(p, mac, hexstr);
        p += sprintf(p, major, creq->bles[i].major);
        p += sprintf(p, minor, creq->bles[i].minor);

        if (bin2hex(hexstr, 32, creq->bles[i].uuid, 16) == -1) {
            perror("target buffer too small");
            return -1;
        }
        hexstr[32] = '\0';
        p += sprintf(p, uuid, hexstr);
        p += sprintf(p, rssi, creq->bles[i].rssi);
        sz = strlen(ble_eof);
        strncpy(p, ble_eof, sz);
        p += sz;
    }

    // set gsm attributes
    for (i = 0; i < creq->gsm_count; i++) {
        sz = strlen(gsm);
        strncpy(p, gsm, sz);
        p += sz;
        p += sprintf(p, mcc, creq->gsms[i].mcc);
        p += sprintf(p, mnc, creq->gsms[i].mnc);
        p += sprintf(p, lac, creq->gsms[i].lac);
        p += sprintf(p, ci, creq->gsms[i].ci);
        p += sprintf(p, rssi, creq->gsms[i].rssi);
        p += sprintf(p, age, creq->gsms[i].age);
        sz = strlen(gsm_eof);
        strncpy(p, gsm_eof, sz);
        p += sz;
    }
    // set cdma attributes
    for (i = 0; i < creq->cdma_count; i++) {
        sz = strlen(cdma);
        strncpy(p, cdma, sz);
        p += sz;
        p += sprintf(p, sid, creq->cdmas[i].sid);
        p += sprintf(p, nid, creq->cdmas[i].nid);
        p += sprintf(p, bsid, creq->cdmas[i].bsid);
        p += sprintf(p, cdma_lat, creq->cdmas[i].lat);
        p += sprintf(p, cdma_lon, creq->cdmas[i].lon);
        p += sprintf(p, rssi, creq->cdmas[i].rssi);
        p += sprintf(p, age, creq->cdmas[i].age);
        sz = strlen(cdma_eof);
        strncpy(p, cdma_eof, sz);
        p += sz;
    }
    // set umts attributes
    for (i = 0; i < creq->umts_count; i++) {
        sz = strlen(umts);
        strncpy(p, umts, sz);
        p += sz;
        p += sprintf(p, mcc, creq->umtss[i].mcc);
        p += sprintf(p, mnc, creq->umtss[i].mnc);
        p += sprintf(p, lac, creq->umtss[i].lac);
        p += sprintf(p, ci, creq->umtss[i].ci);
        p += sprintf(p, rssi, creq->umtss[i].rssi);
        p += sprintf(p, age, creq->umtss[i].age);
        sz = strlen(umts_eof);
        strncpy(p, umts_eof, sz);
        p += sz;
    }
    // set lte attributes
    for (i = 0; i < creq->lte_count; i++) {
        sz = strlen(lte);
        strncpy(p, lte, sz);
        p += sz;
        p += sprintf(p, mcc, creq->ltes[i].mcc);
        p += sprintf(p, mnc, creq->ltes[i].mnc);
        p += sprintf(p, eucid, creq->ltes[i].eucid);
        p += sprintf(p, rssi, creq->ltes[i].rssi);
        p += sprintf(p, age, creq->ltes[i].age);
        sz = strlen(lte_eof);
        strncpy(p, lte_eof, sz);
        p += sz;
    }

    // set gps attributes
    // if the value of an attribute is invalid, it will be silently ignored.
    for (i = 0; i < creq->gps_count; i++) {
        //p += sprintf(p, gps, creq->gps[i].fix, creq->gps[i].nsat, creq->gps[i].hdop);
        p += sprintf(p, gps_);
        p += sprintf(p, " fix=\"%d\" ", creq->gps[i].fix);
        p += sprintf(p, " nsat=\"%d\" ", creq->gps[i].nsat);
        if (creq->gps[i].hdop != -1) // invalid
            p += sprintf(p, " hdop=\"%f\" ", creq->gps[i].hdop);
        p += sprintf(p, ">\n");
        if (creq->gps[i].lat != DBL_MAX) // invalid
            p += sprintf(p, lat, creq->gps[i].lat);
        if (creq->gps[i].lon != DBL_MAX) // invalid
            p += sprintf(p, lon, creq->gps[i].lon);
        if (creq->gps[i].hpe != -1) // invalid
            p += sprintf(p, hpe, creq->gps[i].hpe);
        if (creq->gps[i].alt != FLT_MAX) // invalid
            p += sprintf(p, alt, creq->gps[i].alt);
        if (creq->gps[i].speed != -1) // invalid
            p += sprintf(p, speed, creq->gps[i].speed);
        if (creq->gps[i].age != UINT_MAX) // invalid
            p += sprintf(p, age, creq->gps[i].age);
        sz = strlen(gps_eof);
        strncpy(p, gps_eof, sz);
        p += sz;
    }

    sz = strlen(locrq_eof);
    strncpy(p, locrq_eof, sz);
    p += sz;
    *p = '\0';

    return (int32_t) (p - buff);
}

// decodes xml into location_resp_t
// Return code:
// < 0 : non-meaningful error code
// = 0 : success
// > 0 : meaningful error code (i.e. API returns meaningful error response)
int32_t sky_decode_resp_xml(char *buff, int32_t buff_len, int32_t data_len,
        const struct location_rq_t * creq, struct location_rsp_t *cresp) {

    buff[buff_len - 1] = 0; // make sure it ends with \0

    memset(&cresp->payload_ext.payload.timestamp, 0, sizeof(cresp->payload_ext.payload.timestamp));
    cresp->header.version = 0;
    cresp->payload_ext.payload.type = 0;

    memset(&cresp->location_ext, 0, sizeof(cresp->location_ext)); // zero out the counts

    double dval;
    float fval;
    int32_t slen;
    char *p = NULL;

    const char distpoint[] = "<street-address distanceToPoint=\"";
    const char distpoints[] = "<street-address distanceToPoint=\"%f\">";
    const char lat[] = "<latitude>";
    const char lats[] = "<latitude>%lf</latitude>";
    const char lon[] = "<longitude>";
    const char lons[] = "<longitude>%lf</longitude>";
    const char hpe[] = "<hpe>";
    const char hpes[] = "<hpe>%f</hpe>";
    const char street[] = "<street-number>";
    const char streetf[] = "</street-number>";
    const char addr[] = "<address-line>";
    const char addrf[] = "</address-line>";
    const char city[] = "<city>";
    const char cityf[] = "</city>";
    const char metro1[] = "<metro1>";
    const char metro1f[] = "</metro1>";
    const char metro2[] = "<metro2>";
    const char metro2f[] = "</metro2>";
    const char postcode[] = "<postal-code>";
    const char postcodef[] = "</postal-code>";
    const char statec[] = "<state code=\"";
    const char statef[] = "</state>";
    const char county[] = "<county>";
    const char countyf[] = "</county>";
    const char countryc[] = "<country code=\"";
    const char countryf[] = "</country>";
    const char closebr[] = "\">";
    const char error[] = "<error>";
    const char errorf[] = "</error>";
    const char nondeterministic[] = "<error>Unable to determine location</error>";
    const char location_rs_end[] = "</LocationRS>";

    // TODO check http response header validity

    if (strstr(buff, location_rs_end) == NULL) {
        cresp->payload_ext.payload.type = LOCATION_UNKNOWN;
        return -1; // non-meaningful error
    }

    if (strstr(buff, error) != NULL && strstr(buff, errorf) != NULL) {
        if (strstr(buff, nondeterministic) != NULL)
            // unable to determine client location
            cresp->payload_ext.payload.type = LOCATION_UNABLE_TO_DETERMINE;
        else
            cresp->payload_ext.payload.type = LOCATION_API_ERROR;
        return 1; // meaningful error
    }

    switch (creq->payload_ext.payload.type) {
    case LOCATION_RQ:
        cresp->payload_ext.payload.type = LOCATION_RQ_SUCCESS;
        break;
    case LOCATION_RQ_ADDR:
        cresp->payload_ext.payload.type = LOCATION_RQ_ADDR_SUCCESS;
        break;
    default:
        cresp->payload_ext.payload.type = LOCATION_RQ_ERROR;
    }

    p = strstr(buff, lat);

    if (p != NULL && sscanf(p, lats, &dval) == 1)
        cresp->location.lat = dval;

    p = strstr(buff, lon);

    if (p != NULL && sscanf(p, lons, &dval) == 1)
        cresp->location.lon = dval;

    p = strstr(buff, hpe);

    if (p != NULL && sscanf(p, hpes, &fval) == 1)
        cresp->location.hpe = fval;

    p = strstr(buff, distpoint);

    if (p != NULL && sscanf(p, distpoints, &fval) == 1)
        cresp->location.distance_to_point = fval;

    if ((slen = get_xval(buff, street, streetf, &p)) > 0) {
        cresp->location_ext.street_num_len = slen;
        cresp->location_ext.street_num = p;
    }

    if ((slen = get_xval(buff, addr, addrf, &p)) > 0) {
        cresp->location_ext.address_len = slen;
        cresp->location_ext.address = p;
    }

    if ((slen = get_xval(buff, city, cityf, &p)) > 0) {
        cresp->location_ext.city_len = slen;
        cresp->location_ext.city = p;
    }

    if ((slen = get_xval(buff, metro1, metro1f, &p)) > 0) {
        cresp->location_ext.metro1_len = slen;
        cresp->location_ext.metro1 = p;
    }

    if ((slen = get_xval(buff, metro2, metro2f, &p)) > 0) {
        cresp->location_ext.metro2_len = slen;
        cresp->location_ext.metro2 = p;
    }

    if ((slen = get_xval(buff, postcode, postcodef, &p)) > 0) {
        cresp->location_ext.postal_code_len = slen;
        cresp->location_ext.postal_code = p;
    }

    if ((slen = get_xval(buff, county, countyf, &p)) > 0) {
        cresp->location_ext.county_len = slen;
        cresp->location_ext.county = p;
    }

    if ((slen = get_xval(buff, statec, closebr, &p)) > 0) {
        cresp->location_ext.state_code_len = slen;
        cresp->location_ext.state_code = p;
    }

    // has to be right after the statec, reusing the pointer
    if ((slen = get_xval(p, closebr, statef, &p)) > 0) {
        cresp->location_ext.state_len = slen;
        cresp->location_ext.state = p;
    }

    if ((slen = get_xval(buff, countryc, closebr, &p)) > 0) {
        cresp->location_ext.country_code_len = slen;
        cresp->location_ext.country_code = p;
    }

    // has to be right after the countryf, reusing the pointer
    if ((slen = get_xval(p, closebr, countryf, &p)) > 0) {
        cresp->location_ext.country_len = slen;
        cresp->location_ext.country = p;
    }

    return 0; // success
}

char api_req_decode_ap(int32_t count, int32_t slen,
        struct location_rq_t* req, char* buff) {
    req->aps = (struct ap_t*) (calloc(count, sizeof(struct ap_t)));
    char* p = buff;
    char num_errors = 0;
    char * ps, * pe;
    while ((p = strstr(p, XML_TAG_AP)) != NULL) {
        pe = strstr(p, XML_TAG_APF);
        ps = p;
        slen = get_xval(ps, XML_TAG_MAC, XML_TAG_MACF, &p);
        if (p < pe && slen > 0) // next ap or could not be parsed
                {
            uint32_t res = hex2bin(p, slen, req->aps[req->ap_count].MAC,
                    sizeof(req->aps[req->ap_count].MAC));
            if (res < sizeof(req->aps[req->ap_count].MAC)) {
                printf("mac %d is too short\n", req->ap_count);
                num_errors++;
            }
        } else
            num_errors++;

        p = strstr(ps, XML_TAG_SIG);
        int32_t dval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_SIGS, &dval) == 1) {
            if (dval < -128)
                dval = -128;

            req->aps[req->ap_count].rssi = (int8_t) (dval);
        } else
            num_errors++;

        p = pe;
        req->ap_count++;
    }
    if (num_errors > 0)
        printf("ACCESS POINTS %d ERRORS\n", num_errors);
    return num_errors;
}

char api_req_decode_gps(int32_t count,
        struct location_rq_t * req, char * buff) {
    req->gps = (struct gps_t*) (calloc(count, sizeof(struct gps_t)));
    char* p = buff;
    char num_errors = 0;
    char * ps, * pe;
    while ((p = strstr(p, XML_TAG_GPS)) != NULL) {
        ps = p;
        pe = strstr(ps, XML_TAG_GPSF);
        if (pe == NULL) {
            ++num_errors;
            break;
        }
        p = strstr(ps, XML_TAG_FIX);
        int32_t dval;
        float fval;
        double dfval;

        if (p != NULL && p < pe && sscanf(p, XML_TAG_FIXS, &dval) == 1)
            req->gps[req->gps_count].fix = (uint8_t) (dval);
        else
            req->gps[req->gps_count].fix = 1; // default

        p = strstr(ps, XML_TAG_NSAT);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_NSATS, &dval) == 1)
            req->gps[req->gps_count].nsat = (uint8_t) (dval);
        else
            req->gps[req->gps_count].nsat = 0; // default

        p = strstr(ps, XML_TAG_HDOP);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_HDOPS, &fval) == 1)
            req->gps[req->gps_count].hdop = fval;
        else
            req->gps[req->gps_count].hdop = -1; // invalid

        p = strstr(ps, XML_TAG_LAT);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_LATS, &dfval) == 1)
            req->gps[req->gps_count].lat = dfval;
        else
            req->gps[req->gps_count].lat = DBL_MAX; // invalid

        p = strstr(ps, XML_TAG_LON);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_LONS, &dfval) == 1)
            req->gps[req->gps_count].lon = dfval;
        else
            req->gps[req->gps_count].lon = DBL_MAX; // invalid

        p = strstr(ps, XML_TAG_HPE);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_HPES, &fval) == 1)
            req->gps[req->gps_count].hpe = fval;
        else
            req->gps[req->gps_count].hpe = -1; // invalid

        p = strstr(ps, XML_TAG_ALTITUDE);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_ALTITUDES, &fval) == 1)
            req->gps[req->gps_count].alt = fval;
        else
            req->gps[req->gps_count].alt = FLT_MAX; // invalid

        p = strstr(ps, XML_TAG_SPEED);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_SPEEDS, &fval) == 1)
            req->gps[req->gps_count].speed = fval;
        else
            req->gps[req->gps_count].speed = -1; // invalid

        p = strstr(ps, XML_TAG_AGE);
        uint32_t uval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_AGES, &uval) == 1)
            req->gps[req->gps_count].age = uval;
        else
            req->gps[req->gps_count].age = UINT_MAX; // invalid

        p = pe;
        req->gps_count++;
    }
    if (num_errors > 0)
        printf("GPS %d ERRORS\n", num_errors);
    return num_errors;
}

char api_req_decode_ble(int32_t count, int32_t slen,
        struct location_rq_t* req, char* buff) {
    req->bles = (struct ble_t*) (calloc(count, sizeof(struct ble_t)));
    char* p = buff;
    char num_errors = 0;
    char * ps, * pe;
    while ((p = strstr(p, XML_TAG_BLE)) != NULL) {
        uint32_t res = 0;
        pe = strstr(p, XML_TAG_BLEF);
        ps = p;
        slen = get_xval(p, XML_TAG_MAC, XML_TAG_MACF, &p);
        if (p < pe && slen > 0) {
            res = hex2bin(p, slen, req->bles[req->ble_count].MAC,
                    sizeof(req->bles[req->ble_count].MAC));
            if (res < sizeof(req->bles[req->ble_count].MAC)) {
                printf("ble mac %d is too short\n", req->ble_count);
                num_errors++;
            }
        } else
            num_errors++;

        p = strstr(ps, XML_TAG_UUID);
        slen = get_xval(p, XML_TAG_UUID, XML_TAG_UUIDF, &p);
        if (p < pe && slen > 0) {
            res = hex2bin(p, slen, req->bles[req->ble_count].uuid,
                    sizeof(req->bles[req->ble_count].uuid));
            if (res < sizeof(req->bles[req->ble_count].uuid)) {
                printf("ble uuid %d is too short\n", req->ble_count);
                num_errors++;
            }
        } else
            num_errors++;

        p = strstr(ps, XML_TAG_MAJOR);
        int32_t dval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_MAJORS, &dval) == 1)
            req->bles[req->ble_count].major = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_MINOR);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_MINORS, &dval) == 1)
            req->bles[req->ble_count].minor = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_RSSI);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_RSSIS, &dval) == 1) {
            if (dval < -128)
                dval = -128;

            req->bles[req->ble_count].rssi = (int8_t) (dval);
        } else
            num_errors++;

        p = pe;
        req->ble_count++;
    }
    if (num_errors > 0)
        printf("BLE %d ERRORS\n", num_errors);
    return num_errors;
}

char api_req_decode_cdma(int32_t count, struct location_rq_t* req, char* buff) {
    req->cdmas = (struct cdma_t*) (calloc(count, sizeof(struct cdma_t)));
    char* p = buff;
    char * ps, * pe;
    char num_errors = 0;
    while ((p = strstr(p, XML_TAG_CDMA)) != NULL) {
        ps = p;
        pe = strstr(ps, XML_TAG_CDMAF);
        p = strstr(ps, XML_TAG_SID);
        int32_t dval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_SIDS, &dval) == 1)
            req->cdmas[req->cdma_count].sid = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_NID);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_NIDS, &dval) == 1)
            req->cdmas[req->cdma_count].nid = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_BSID);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_BSIDS, &dval) == 1)
            req->cdmas[req->cdma_count].bsid = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_CDMA_LAT);
        double dfval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_CDMA_LATS, &dfval) == 1)
            req->cdmas[req->cdma_count].lat = dfval;
        else
            num_errors++;

        p = strstr(ps, XML_TAG_CDMA_LON);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_CDMA_LONS, &dfval) == 1)
            req->cdmas[req->cdma_count].lon = dfval;
        else
            num_errors++;

        p = strstr(ps, XML_TAG_RSSI);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_RSSIS, &dval) == 1) {
            if (dval < -128)
                dval = -128; // the min we can fit into int8_t
            req->cdmas[req->cdma_count].rssi = (int8_t) (dval);
        } else
            num_errors++;

        p = strstr(ps, XML_TAG_AGE);
        uint32_t uval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_AGES, &uval) == 1)
            req->cdmas[req->cdma_count].age = uval;

        p = pe;
        req->cdma_count++;
    }
    if (num_errors > 0)
        printf("CDMA %d ERRORS\n", num_errors);
    return num_errors;
}

char api_req_decode_gsm(int32_t count, struct location_rq_t* req, char* buff) {
    req->gsms = (struct gsm_t *) (calloc(count, sizeof(struct gsm_t)));
    char* p = buff;
    char * ps, * pe;
    char num_errors = 0;
    while ((p = strstr(p, XML_TAG_GSM)) != NULL) {
        ps = p;
        pe = strstr(ps, XML_TAG_GSMF);
        p = strstr(ps, XML_TAG_MCC);
        int32_t dval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_MCCS, &dval) == 1)
            req->gsms[req->gsm_count].mcc = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_MNC);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_MNCS, &dval) == 1)
            req->gsms[req->gsm_count].mnc = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_LAC);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_LACS, &dval) == 1)
            req->gsms[req->gsm_count].lac = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_CI);
        uint32_t uval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_CIS, &uval) == 1)
            req->gsms[req->gsm_count].ci = uval;
        else
            num_errors++;

        p = strstr(ps, XML_TAG_RSSI);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_RSSIS, &dval) == 1) {
            if (dval < -128)
                dval = -128; // the min we can fit into int8_t
            req->gsms[req->gsm_count].rssi = (int8_t) (dval);
        } else
            num_errors++;

        p = strstr(ps, XML_TAG_AGE);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_AGES, &uval) == 1)
            req->gsms[req->gsm_count].age = uval;

        p = pe;
        req->gsm_count++;
    }
    if (num_errors > 0)
        printf("GSM %d ERRORS\n", num_errors);
    return num_errors;
}

char api_req_decode_lte(int32_t count, struct location_rq_t* req, char* buff) {
    req->ltes = (struct lte_t *) (calloc(count, sizeof(struct lte_t)));
    char* p = buff;
    char * ps, * pe;
    char num_errors = 0;
    while ((p = strstr(p, XML_TAG_LTE)) != NULL) {
        ps = p;
        pe = strstr(ps, XML_TAG_LTEF);
        p = strstr(ps, XML_TAG_MCC);
        int32_t dval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_MCCS, &dval) == 1)
            req->ltes[req->lte_count].mcc = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_MNC);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_MNCS, &dval) == 1)
            req->ltes[req->lte_count].mnc = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_EUCID);
        uint32_t uval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_EUCIDS, &uval) == 1)
            req->ltes[req->lte_count].eucid = uval;
        else
            num_errors++;

        p = strstr(ps, XML_TAG_AGE);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_AGES, &uval) == 1)
            req->ltes[req->lte_count].age = uval;

        p = strstr(ps, XML_TAG_RSSI);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_RSSIS, &dval) == 1) {
            if (dval < -128)
                dval = -128; // the min we can fit into int8_t
            req->ltes[req->lte_count].rssi = (int8_t) (dval);
        } else
            num_errors++;

        p = pe;
        req->lte_count++;
    }
    if (num_errors > 0)
        printf("LTE %d ERRORS\n", num_errors);
    return num_errors;
}

char api_req_decode_umts(int32_t count, struct location_rq_t* req, char* buff) {
    req->umtss = (struct umts_t *) (calloc(count, sizeof(struct umts_t)));
    char* p = buff;
    char * ps, * pe;
    char num_errors = 0;
    while ((p = strstr(p, XML_TAG_UMTS)) != NULL) {
        ps = p;
        pe = strstr(ps, XML_TAG_UMTSF);
        p = strstr(ps, XML_TAG_MCC);
        int32_t dval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_MCCS, &dval) == 1)
            req->umtss[req->umts_count].mcc = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_MNC);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_MNCS, &dval) == 1)
            req->umtss[req->umts_count].mnc = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_LAC);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_LACS, &dval) == 1)
            req->umtss[req->umts_count].lac = (uint16_t) (dval);
        else
            num_errors++;

        p = strstr(ps, XML_TAG_CI);
        uint32_t uval;
        if (p != NULL && p < pe && sscanf(p, XML_TAG_CIS, &uval) == 1)
            req->umtss[req->umts_count].ci = uval;
        else
            num_errors++;

        p = strstr(ps, XML_TAG_RSSI);
        if (p != NULL && p < pe && sscanf(p, XML_TAG_RSSIS, &dval) == 1) {
            if (dval < -128)
                dval = -128; // the min we can fit into int8_t
            req->umtss[req->umts_count].rssi = (int8_t) (dval);
        } else
            num_errors++;

        p = pe;
        req->umts_count++;
    }
    if (num_errors > 0)
        printf("UMTS %d ERRORS\n", num_errors);
    return num_errors;
}

/* make sure after use free resources:

 free(creq.aps);
 free(creq.bles);
 free(creq.gsm);
 free(creq.cdma);
 free(creq.umts);
 free(creq.lte);
 free(creq.gps);

 sets payload_type, aps, ap_count, bles, ble_count, cells, cell_count, gps, gps_count
 */
int32_t sky_decode_req_xml(char *buff, int32_t buff_len, int32_t data_len,
        struct location_rq_t *req) {
    buff[buff_len - 1] = 0; // make sure it ends with 0

    memset(req, 0, sizeof(*req)); // zero out the counts

    int32_t slen;
    char * p;

    if ((slen = get_xval(buff, XML_TAG_ADDR_LOOKUP, "\"", &p)) > 0) {
        req->payload_ext.payload.type =
                strncmp(p, "full", 4) == 0 ? LOCATION_RQ_ADDR : LOCATION_RQ;
    }

    int32_t count = 0;
    char num_ap_errors = 0;
    char num_gsm_errors = 0;
    char num_umts_errors = 0;
    char num_cdma_errors = 0;
    char num_lte_errors = 0;
    char num_ble_errors = 0;
    char num_gps_errors = 0;

    /* AP */
    if ((count = countTag(buff, XML_TAG_AP)) > 0) {
        num_ap_errors = api_req_decode_ap(count, slen, req, buff);
    }

    /* GSM */
    if ((count = countTag(buff, XML_TAG_GSM)) > 0) {
        num_gsm_errors = api_req_decode_gsm(count, req, buff);

    }

    /* CDMA */
    if ((count = countTag(buff, XML_TAG_CDMA)) > 0) {
        num_cdma_errors = api_req_decode_cdma(count, req, buff);
    }

    /* UMTS */
    if ((count = countTag(buff, XML_TAG_UMTS)) > 0) {
        num_umts_errors = api_req_decode_umts(count, req, buff);
    }

    /* LTE */
    if ((count = countTag(buff, XML_TAG_LTE)) > 0) {
        num_lte_errors = api_req_decode_lte(count, req, buff);
    }

    /* GPS */
    if ((count = countTag(buff, XML_TAG_GPS)) > 0) {
        num_gps_errors = api_req_decode_gps(count, req, buff);
    }

    /* BLE */
    if ((count = countTag(buff, XML_TAG_BLE)) > 0) {
        num_ble_errors = api_req_decode_ble(count, slen, req, buff);
    }

    return 0 - num_ap_errors - num_ble_errors - num_gps_errors - num_lte_errors - num_umts_errors - num_cdma_errors - num_gsm_errors;
}
