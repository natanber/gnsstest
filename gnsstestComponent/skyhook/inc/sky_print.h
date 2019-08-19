/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_PRINT_H
#define SKY_PRINT_H

void print_location_resp(struct location_rsp_t *cr);

void print_location_req(struct location_rq_t *cr);

#endif

#ifdef __cplusplus
}
#endif
