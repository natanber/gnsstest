/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_XML_H
#define SKY__XML_H

#include "sky_protocol.h"

#define XML_TAG_ADDR_LOOKUP "street-address-lookup=\""
#define XML_TAG_AP "<access-point>"
#define XML_TAG_APF "</access-point>"
#define XML_TAG_MAC "<mac>"
#define XML_TAG_MACF "</mac>"
#define XML_TAG_SIG "<signal-strength>"
#define XML_TAG_SIGS "<signal-strength>%d</signal-strength>"
#define XML_TAG_GSM "<gsm-tower>"
#define XML_TAG_GSMF "</gsm-tower>"
#define XML_TAG_CDMA "<cdma-tower>"
#define XML_TAG_CDMAF "</cdma-tower>"
#define XML_TAG_UMTS "<umts-tower>"
#define XML_TAG_UMTSF "</umts-tower>"
#define XML_TAG_LTE "<lte-tower>"
#define XML_TAG_LTEF "</lte-tower>"
#define XML_TAG_MCC "<mcc>"
#define XML_TAG_MCCS "<mcc>%d</mcc>"
#define XML_TAG_MNC "<mnc>"
#define XML_TAG_MNCS "<mnc>%d</mnc>"
#define XML_TAG_LAC "<lac>"
#define XML_TAG_LACS "<lac>%d</lac>"
#define XML_TAG_CI "<ci>"
#define XML_TAG_CIS "<ci>%u</ci>"
#define XML_TAG_RSSI "<rssi>"
#define XML_TAG_RSSIS "<rssi>%u</rssis>"
#define XML_TAG_SID "<sid>"
#define XML_TAG_SIDS "<sid>%u</sid>"
#define XML_TAG_NID "<nid>"
#define XML_TAG_NIDS "<nid>%u</nid>"
#define XML_TAG_BSID "<bsid>"
#define XML_TAG_BSIDS "<bsid>%u</bsid>"
#define XML_TAG_EUCID "<eucid>"
#define XML_TAG_EUCIDS "<eucid>%u</eucid>"
#define XML_TAG_CDMA_LAT "<cdma-lat>"
#define XML_TAG_CDMA_LATS "<cdma-lat>%lf</cdma-lat>"
#define XML_TAG_CDMA_LON "<cdma-lon>"
#define XML_TAG_CDMA_LONS "<cdma-lon>%lf</cdma-lon>"
// note: gps-location tag contains attributes in the scope of this tag.
#define XML_TAG_GPS "<gps-location "
#define XML_TAG_GPSF "</gps-location>"
#define XML_TAG_LAT "<latitude>"
#define XML_TAG_LATS "<latitude>%lf</latitude>"
#define XML_TAG_LON "<longitude>"
#define XML_TAG_LONS "<longitude>%lf</longitude>"
#define XML_TAG_HPE "<hpe>"
#define XML_TAG_HPES "<hpe>%f</hpe>"
#define XML_TAG_ALTITUDE "<altitude>"
#define XML_TAG_ALTITUDES "<altitude>%f</altitude>"
#define XML_TAG_HEIGHT "<height>"
#define XML_TAG_HEIGHTS "<height>%f</height>"
#define XML_TAG_VPE "<vpe>"
#define XML_TAG_VPES "<vpe>%f</vpe>"
#define XML_TAG_SPEED "<speed>"
#define XML_TAG_SPEEDS "<speed>%f</speed>"
#define XML_TAG_AGE "<age>"
#define XML_TAG_AGES "<age>%u</age>"
#define XML_TAG_FIX "fix=\""
#define XML_TAG_FIXS "fix=\"%d\""
#define XML_TAG_NSAT "nsat=\""
#define XML_TAG_NSATS "nsat=\"%d\""
#define XML_TAG_HDOP "hdop=\""
#define XML_TAG_HDOPS "hdop=\"%f\""
#define XML_TAG_BLE "<ble>"
#define XML_TAG_BLEF "</ble>"
#define XML_TAG_UUID "<uuid>"
#define XML_TAG_UUIDF "</uuid>"
#define XML_TAG_MAJOR "<major>"
#define XML_TAG_MAJORS "<major>%d</major>"
#define XML_TAG_MINOR "<minor>"
#define XML_TAG_MINORS "<minor>%d</minor>"

// encodes location_req_t into xml result is in buff
int32_t sky_encode_req_xml(char *buff, int32_t bufflen, const struct location_rq_t *creq);

// decodes xml into location_resp_t
int32_t sky_decode_resp_xml(char *buff, int32_t buff_len, int32_t data_len,
        const struct location_rq_t * creq, struct location_rsp_t *cresp);

int32_t sky_decode_req_xml(char *buff, int32_t buff_len, int32_t data_len,
        struct location_rq_t *req);

#endif

#ifdef __cplusplus
}
#endif
