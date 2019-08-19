
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include "legato.h"
#include "interfaces.h"
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include "errno.h"

#include "sky_crypt.h"
#include "sky_print.h"
#include "sky_protocol.h"
#include "sky_util.h"

static int time_to_sleep_sec = 10;
static int time_optiont = 200;
static int time_optiont_1 = 1010;
static int accuracy_diff = 20;
static le_pm_WakeupSourceRef_t wakeUpSource;
static int options = 2;
uint32_t ttff = 0;
le_result_t res;
int use_start = 0;
FILE* fd;
int count_get_points = 0;
uint32_t rate_gnss = 0;
le_sem_Ref_t sema_ref_make_query;
le_sem_Ref_t sema_ref_wait_gnss_enable;
le_thread_Ref_t delay_gnss_poll;
int delay_task_tyme = 1010;
int scan_cell = 0;
int scan_wifi_on = 0;
bool scan_cell_once = true;
bool scan_wifi_once = true;
char *st0 = 0;
int get_points_num = 0;
int file_num = 0;
static le_wifiClient_NewEventHandlerRef_t scan_hdlr_ref = NULL;
static le_data_RequestObjRef_t connection_ref;
static bool connect_data;

#define TOWERS_MAX 10

struct cell_data {
    uint32_t eucid;
    uint16_t mcc;
    uint16_t mnc;
    uint16_t lac;
    int8_t rssi;
    uint8_t unused[3]; // padding bytes
};


struct towers_t {
	uint16_t mcc;
	uint16_t mnc;
	uint32_t cid;
	int lac;
	struct cell_data cell_towers[TOWERS_MAX];
	int num_cells;
	le_mrc_Rat_t rat;
};

struct towers_t towers;

uint64_t now_tp_abs() {
	struct timespec cur_time;

    //clock_gettime(CLOCK_BOOTTIME, &cur_time);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cur_time);
    uint64_t res = cur_time.tv_sec * 1000000000 + cur_time.tv_nsec;
    return res;    
}

uint64_t now_tp_abs_bt() {
	struct timespec cur_time;

    clock_gettime(CLOCK_BOOTTIME, &cur_time);
    uint64_t res = cur_time.tv_sec * 1000000000 + cur_time.tv_nsec;
    return res;    
}



uint64_t GetTimeStampLegato() 
{
    le_clk_Time_t 	time_get = le_clk_GetRelativeTime();
    uint64_t res = time_get.sec*(uint64_t)1000000 + time_get.usec;
   
    return res;
}

uint64_t GetTimeStamp() 
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec*(uint64_t)1000000+tv.tv_usec;
}

char *str_time(time_t t)
{
	struct tm tm;
	localtime_r(&t, &tm);

	char *s = (char *)malloc(20);

	if (!s)
		return NULL;
	strftime(s, 20, "%02y-%02m-%02d %02H:%02M:%02S", &tm);
	return s;
}

const char *get_state_name(int state_num)
{
    switch (state_num)
    {
        case 0 : return "ForceHotRestart";
        case 1 : return "ForceColdRestart";
        case 2 : return "ForceWarmRestart";
        case 3 : return "ForceHotRestart";
        default : return "ERROR_STATE";
    }
}
const char *print_network_name(le_mrc_Rat_t technology)
{
	switch (technology) {
	case LE_MRC_RAT_UNKNOWN:
		return "Undefined";
	case LE_MRC_RAT_GSM:
		return "GSM";
	case LE_MRC_RAT_UMTS:
		return "UMTS";
	case LE_MRC_RAT_TDSCDMA:
		return "TD-SCDMA";
	case LE_MRC_RAT_LTE:
		return "LTE";
	case LE_MRC_RAT_CDMA:
		return "CDMA";
	}
	return "Undefined";
}

int get_ip_addr(struct location_rq_t *p_creq)
{
    struct ifaddrs *ifaddr;

    if (getifaddrs(&ifaddr) < 0) {
        perror("getifaddrs");
        return -1;
    }
    struct ifaddrs *ifa = ifaddr;

    while (ifa) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, "eth0") == 0) {
            struct sockaddr_in *p_addr = (struct sockaddr_in *)ifa->ifa_addr;
            uint32_t ip_addr = p_addr->sin_addr.s_addr;
            // ip_addr = __bswap_32(ip_addr); // swap to little endian if on
            // big-endian platform
            memcpy(p_creq->ip_addr, &ip_addr, sizeof(ip_addr));
            //printf("%s: %s\n", ifa->ifa_name, inet_ntoa(p_addr->sin_addr));
        }
        ifa = ifa->ifa_next;
    }

    freeifaddrs(ifaddr);
    return 0;
}
const uint8_t ap_count = 20;
struct ap_t aps[20];
int num_wifi = 0;

static int send_querry_to_skyhook(void)
{
    char server[] = "elg.skyhook.com"; // 52.52.203.139, 54.183.50.25
	int port = 9755;

	struct sky_key_t key_sk = { .partner_id = 26637,
			     .aes_key =  { 0xAB, 0xA0, 0x8B, 0x78, 0x6B, 0x8B, 0xF1, 0x5A, 0xFA, 0xDA, 0xE3, 0xD2, 0x0E, 0x0B, 0x6E, 0x58}
			   };
      
    struct location_rq_t rq;
    unsigned char buff[1024] = {0}; 
    uint8_t device_mac[] = { 0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE };
    struct sky_key_t key;
    memset(&key, 0, sizeof(key));
    memset(&rq,0,sizeof(rq));
    key = key_sk;

    rq.key = key_sk;

    //printf("rq.gsm_count = %d rq.umts_count= %d rq.lte_coun= %d\n",
    //       rq.gsm_count, rq.umts_count, rq.lte_count);

    /* set protocol version */
    rq.header.version = SKY_PROTOCOL_VERSION;

    rq.mac_count = 1;
    rq.mac = device_mac;

    rq.ip_count = 1;
    rq.ip_type = DATA_TYPE_IPV4;
    uint8_t ip_addr[4];

    rq.ip_addr = ip_addr;
    get_ip_addr(&rq);

    rq.payload_ext.payload.sw_version = 1;

    /* LOCATION_RQ will return latitude, longitude and hpe */
    /* LOCATION_RQ_ADDR will also include street address lookup */

    rq.payload_ext.payload.type = LOCATION_RQ_ADDR;	// full address lookup
    /* set access points */
    rq.ap_count = num_wifi;
    rq.aps = &aps[0];

    int32_t cnt = sky_encode_req_bin(buff, sizeof(buff), &rq);

    if (cnt < 0) 
    {
        perror("encode binary protocol failed");
       
    }

    if (sky_aes_encrypt(buff + sizeof(sky_rq_header_t),
                cnt - sizeof(sky_rq_header_t) - sizeof(sky_checksum_t), key_sk.aes_key,
                buff + sizeof(sky_rq_header_t) - sizeof(rq.header.iv)) == -1)
    {
        perror("failed to encrypt request");
        return -1;
      
    }

    int sockfd;

    char ipaddr[16];	// the char representation of an ipv4 address

    if (hostname_to_ip((char*)server, ipaddr, sizeof(ipaddr)) != 0)
    {
        puts("Could not resolve host");
        if (connect_data == false)
        {
            system("/legato/systems/current/bin/cm data connect");
        }
        return -1;
    }

    struct sockaddr_in serv_addr = 
    {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {.s_addr = inet_addr(ipaddr)},
    };

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("cannot open socket");
        return -1;
    }
    /* setup connection timeout */
    struct timeval tv;
    tv.tv_sec = 10; // in seconds
    tv.tv_usec = 0; // Not zeroing this may cause errors
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
                 sizeof(struct timeval))) 
    {
        perror("setsockopt failed");
        return -1;
    }
    /* start connection */
    int32_t rc = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (rc < 0) 
    {
        close(sockfd);
        perror("connect to server failed");
        return -1;
    }

    /* send data to the server */
    rc = send(sockfd, buff, (size_t)cnt, 0);
    if (rc != cnt) 
    {
        close(sockfd);
        perror("send() sent a different number of bytes than expected");
        return -1;
    }
    LE_INFO("total bytes sent to server %d\n", rc);

    /* clear the buffer */
    memset(buff, 0, sizeof(buff));

    /* wait for tcp response */
    cnt = recv(sockfd, buff, sizeof(buff), 0);

    if (cnt == 0) 
    {
        // connection closed or timeout
        errno = ETIMEDOUT;
        close(sockfd);
        perror("connection closed (timeout?)");
        return -1;
    } 
    else if (cnt < 0) 
    {
        // error in receiving
        close(sockfd);
        perror("recv failed");
        return -1;
    }

    // print encrypted received buffer
    LE_INFO("total received bytes: %d\n", cnt);
    LE_INFO("\n------ recv packet -------");
    print_buff(buff, cnt);
    LE_INFO("---------------------\n");

    close(sockfd);

    key = key_sk;

     /* decrypt the received packet
      * this can be replaced with hardware decryption when available */
    if (sky_aes_decrypt(buff + sizeof(sky_rsp_header_t),
                          cnt - sizeof(sky_rsp_header_t) - sizeof(sky_checksum_t),
                          key.aes_key,
                          buff + sizeof(sky_rsp_header_t) -
                              sizeof(rq.header.iv)) != 0) 
    {
        perror("failed to decrypt response");
    }

    // print decrypted packet
    LE_INFO("\n------ decrypted recv packet -------");
    print_buff(buff, cnt);
    LE_INFO("---------------------\n");

    /* decode packet
    * location response will be decoded to p_lct_rsp */
    struct location_rsp_t loc_rsp = { 0 };
    if (sky_decode_resp_bin(buff, sizeof(buff), cnt, &loc_rsp) == -1)
    {
        perror("failed to decode response");
    }

     //print location response
     puts("--------------");
     puts("PARSED RESPONSE");
     puts("--------------");
     print_location_resp(&loc_rsp);
     LE_INFO("loc_rsp.location.lat = %f loc_rsp.location.lon = %f loc_rsp.location.hpe = %f", 
        (float)loc_rsp.location.lat,(float)loc_rsp.location.lon,(float)loc_rsp.location.hpe);

	st0 = str_time(time(0));
    fprintf(fd, "%s,wifi,%f ,%f ,hpe =, %f\n",
    st0, (float)loc_rsp.location.lat, (float)loc_rsp.location.lon, (float)loc_rsp.location.hpe);
    fflush(fd);
    free(st0);

    return 0;
}

static le_result_t scan_wifi(void)
{
    memset(&aps, 0, sizeof(aps));
    le_result_t   result = LE_OK;
    le_result_t   scanResultPtr = LE_OK;
    le_wifiClient_AccessPointRef_t apRef = 0;
    num_wifi = 0;

    
    if (NULL != (apRef = le_wifiClient_GetFirstAccessPoint()))
    {
        do
        {
            char bssid[LE_WIFIDEFS_MAX_BSSID_BYTES];
            uint8_t ssidBytes[LE_WIFIDEFS_MAX_SSID_BYTES];
            // Contains ssidNumElements number of bytes
            size_t ssidNumElements = LE_WIFIDEFS_MAX_SSID_LENGTH;

            result = le_wifiClient_GetSsid(apRef, ssidBytes, &ssidNumElements);
            if (result != LE_OK)
            {
                LE_INFO("ERROR::le_wifiClient_GetSsid failed: %d", result);
                //exit(EXIT_FAILURE);
                break;
            }

            result = le_wifiClient_GetBssid(apRef, bssid, sizeof(bssid) - 1);
            if (result != LE_OK)
            {
                LE_INFO("ERROR::le_wifiClient_GetBssid failed: %d", result);
                //exit(EXIT_FAILURE);
                break;
            }

            LE_INFO("scan_wifi Found:\tSSID:\t\"%.*s\"\tBSSID:\t\"%s\"\tStrength:%d\tRef:%p\n",
                   (int)ssidNumElements,
                   (char* )&ssidBytes[0],
                   (char* )&bssid[0],
                   le_wifiClient_GetSignalStrength(apRef),
                   apRef);
            aps[num_wifi].rssi = le_wifiClient_GetSignalStrength(apRef);            
            
            sscanf(bssid,"%x:%x:%x:%x:%x:%x",(int *)&aps[num_wifi].MAC[0],(int *)&aps[num_wifi].MAC[1],(int *)&aps[num_wifi].MAC[2],
            (int *)&aps[num_wifi].MAC[3],(int *)&aps[num_wifi].MAC[4],(int *)&aps[num_wifi].MAC[5]);

            LE_INFO("MAC = %x%x%x%x%x%x",aps[num_wifi].MAC[0],aps[num_wifi].MAC[1],aps[num_wifi].MAC[2],aps[num_wifi].MAC[3],
                aps[num_wifi].MAC[4],aps[num_wifi].MAC[5]);

            LE_INFO("bssid = %s",bssid);
            aps[num_wifi++].flag = 0;

        } while (NULL != (apRef = le_wifiClient_GetNextAccessPoint()));
    }
    else
    {
        LE_ERROR("le_wifiClient_GetFirstAccessPoint ERROR");
        LE_INFO("DEBUG: le_wifiClient_GetFirstAccessPoint ERROR");
    }
    scan_wifi_once = true;
    send_querry_to_skyhook();
    return scanResultPtr;
}

static void scan_wifi_cmd(void)
{
    //Found:	SSID:	"LO_Guest"	    BSSID:	"b6:4e:26:66:4d:0a"	Strength:-78	Ref:0x10000027
    //Found:	SSID:	"Attenti-TLV"	BSSID:	"06:8d:db:b2:97:fa"	Strength:-52	Ref:0x10000003

    FILE *wifi_data = fopen("/home/root/data_wifi.txt","r");
    if (wifi_data == NULL)
    {
        LE_INFO("no file /home/root/data_wifi.txt");
        return;
    }
    char mac_address[256];
    char data_mac[256] = {0};
    char data_strength[256] = {0};
    char data_name[256] = {0};
    int num = 0;
    memset(mac_address, 0, sizeof(mac_address));
    memset(data_mac, 0, sizeof(data_mac));
    memset(data_name, 0, sizeof(data_name));
    memset(data_strength, 0, sizeof(data_strength));
    memset(&aps,0,sizeof(aps));
    num_wifi = 0;
    while ((num = fscanf(wifi_data, "%s", (char *)&mac_address)) != EOF) 
    {
        //LE_INFO("%s\n", mac_address);
        if (strcmp(mac_address,"BSSID:") == 0)
        {
            int8_t rssi = 0;
            int res = 0;
            num = fscanf(wifi_data, "%s", (char *)&data_mac);
            num = fscanf(wifi_data, "%s", (char *)&data_strength);
            LE_INFO("data_mac = %s signal_strength = %s",data_mac,data_strength);
            res = sscanf(data_strength,"Strength:%d",(int *)&rssi);
            LE_INFO("data_mac = %s rssi = %d res = %d",data_mac,rssi,res);
            aps[num_wifi].rssi = rssi;            
            res =  sscanf(data_mac,"\"%x:%x:%x:%x:%x:%x",(int *)&aps[num_wifi].MAC[0],(int *)&aps[num_wifi].MAC[1],(int *)&aps[num_wifi].MAC[2],
            (int *)&aps[num_wifi].MAC[3],(int *)&aps[num_wifi].MAC[4],(int *)&aps[num_wifi].MAC[5]);

            LE_INFO("MAC = %x%x%x%x%x%x res = %d",aps[num_wifi].MAC[0],aps[num_wifi].MAC[1],aps[num_wifi].MAC[2],aps[num_wifi].MAC[3],
                aps[num_wifi].MAC[4],aps[num_wifi].MAC[5],res);
            aps[num_wifi++].flag = 0;            
        }
        memset(mac_address, 0, sizeof(mac_address));
        memset(data_strength, 0, sizeof(data_strength));
        if (num == EOF) 
        {
            break;
        }
  }
  if (num_wifi != 0)
  {
      send_querry_to_skyhook();
  }
}


void get_signal_metrics(int32_t *rx_level_get)
{
	le_result_t   res;
	le_mrc_Rat_t  rat;
	int32_t rssi = 0;
	uint32_t er = 0;
	int32_t ecio = 0;
	int32_t rscp = 0;
	int32_t sinr = 0;
	int32_t rsrq = 0;
	int32_t rsrp = 0;
	int32_t snr = 0;
	int32_t io = 0;

	le_mrc_MetricsRef_t m = le_mrc_MeasureSignalMetrics();
	LE_ASSERT(m != NULL);

	rat = le_mrc_GetRatOfSignalMetrics(m);
	LE_INFO("%s RAT of signal metrics is %d", __func__, rat);
	switch (rat) {
	case LE_MRC_RAT_GSM:
		res = le_mrc_GetGsmSignalMetrics(m, &rssi, &er);
		LE_ASSERT(res == LE_OK);
		LE_INFO("%s GSM metrics rssi.%ddBm, er.%d", __func__, rssi, er);
		break;

	case LE_MRC_RAT_UMTS:
	case LE_MRC_RAT_TDSCDMA:
		res = le_mrc_GetUmtsSignalMetrics(m, &rssi, &er, &ecio, &rscp, &sinr);
		LE_ASSERT(res == LE_OK);
		LE_INFO("%s UMTS/TD-SCDMA metrics rssi.%ddBm, er.%d, ecio.%010.1fdB,"
			"rscp.%ddBm, sinr.%ddB", __func__, rssi, er, ((double)ecio / 10), rscp, sinr);
		break;

	case LE_MRC_RAT_LTE:
		res = le_mrc_GetLteSignalMetrics(m, &rssi, &er, &rsrq, &rsrp, &snr);
		LE_ASSERT(res == LE_OK);
		LE_INFO("%s LTE metrics rssi.%ddBm, er.%d, rsrq.%010.1fdB, "
			"rsrp.%010.1fdBm, snr.%010.1fdB",
			__func__, rssi, er, ((double)rsrq / 10), ((double)rsrp / 10), ((double)snr / 10));
		break;

	case LE_MRC_RAT_CDMA:
		res = le_mrc_GetCdmaSignalMetrics(m,  &rssi, &er, &ecio, &sinr, &io);
		LE_ASSERT(res == LE_OK);
		LE_INFO("%s CDMA metrics rssi.%ddBm, er.%d, ecio.%010.1fdB, "
			"sinr.%ddB, io.%ddBm",
			__func__, rssi, er, ((double)ecio / 10), sinr, io);
		break;

	default:
		LE_FATAL("Unknown RAT!");
		break;
	}

	le_mrc_DeleteSignalMetrics(m);
	*rx_level_get = rssi;
}

void get_loc_info(void)
{
	uint32_t cid;
	le_result_t res;
	char mcc[LE_MRC_MCC_BYTES] = { 0 };
	char mnc[LE_MRC_MNC_BYTES] = { 0 };
	le_mrc_Rat_t rat = LE_MRC_RAT_UNKNOWN;

	memset(&towers, 0, sizeof(towers));
	cid = le_mrc_GetServingCellId();
	if (cid == UINT32_MAX)
		return;

	towers.lac = le_mrc_GetServingCellLocAreaCode();
	if (towers.lac == UINT32_MAX)
		towers.lac = le_mrc_GetServingCellLteTracAreaCode();
	towers.cid = cid;
	res = le_mrc_GetCurrentNetworkMccMnc(mcc, LE_MRC_MCC_BYTES, mnc, LE_MRC_MNC_BYTES);
	if (res == LE_OK) 
    {
		towers.mcc = atoi(mcc);
		towers.mnc = atoi(mnc);
	} else
		LE_INFO("le_mrc_GetCurrentNetworkMccMnc res = %x", res);
	int32_t rssi = 0;
	get_signal_metrics(&rssi);
	LE_INFO("%s rssi = %d", __func__, rssi);
	res = le_mrc_GetRadioAccessTechInUse(&rat);
	if (res != LE_OK) 
    {
		LE_INFO("le_mrc_GetRadioAccessTechInUse res = %x", res);
		return;
	}
	LE_INFO("le_mrc_GetRadioAccessTechInUse rat = %d %s", rat, print_network_name(rat));

	towers.rat = rat;

	towers.cell_towers[towers.num_cells++] = (struct cell_data) {
			.eucid = cid, .mcc = towers.mcc, .mnc = towers.mnc, .rssi = (int8_t)rssi
    };
}
void update_cell_data_lg(le_mrc_Rat_t rat, uint32_t cid, uint32_t lac, int32_t rssi)
{
	if (cid == towers.cid) 
    {
		LE_INFO("%s cid main found cid = %d", __func__, cid);
		towers.cell_towers[towers.num_cells].rssi = rssi;
        return;
	}

    towers.cell_towers[towers.num_cells].rssi = rssi;
    towers.cell_towers[towers.num_cells].eucid = cid;
	towers.cell_towers[towers.num_cells].lac = lac;
	towers.cell_towers[towers.num_cells].mcc = towers.mcc;
	towers.cell_towers[towers.num_cells].mnc = towers.mnc;
    towers.num_cells++;
}

void get_neighboring_cells_info_lg(void)
{
	le_mrc_NeighborCellsRef_t ngbr;
	le_mrc_CellInfoRef_t cell;
	uint32_t i = 0;

	LE_INFO("Start %s", __func__);

	ngbr = le_mrc_GetNeighborCellsInfo();
	if (!ngbr)
		return;

	cell = le_mrc_GetFirstNeighborCellInfo(ngbr);
	LE_ASSERT(cell);
	do {
		uint32_t cid = le_mrc_GetNeighborCellId(cell);
		uint32_t lac = le_mrc_GetNeighborCellLocAreaCode(cell);
		if (lac == UINT16_MAX)
			lac = towers.lac;
		int32_t rssi = le_mrc_GetNeighborCellRxLevel(cell);
		le_mrc_Rat_t rat = le_mrc_GetNeighborCellRat(cell);
		update_cell_data_lg(rat, cid, lac, rssi);
		i++;
	} while ((cell = le_mrc_GetNextNeighborCellInfo(ngbr)));
	le_mrc_DeleteNeighborCellsInfo(ngbr);
}

void get_ttft(void)
{
    int cnt = 0;
    res = le_gnss_GetTtff(&ttff);
    while ((res != LE_OK) && (cnt++ < 20))
    {
        sleep(1);
        res = le_gnss_GetTtff(&ttff);
    }
    LE_INFO("res = %d cnt = %d in msec ttff = %d use_start = %d %s", res,cnt, ttff,use_start,get_state_name(use_start));
}

void scan_cells(void)
{
    le_mrc_ConnectService();
	get_loc_info();
	get_neighboring_cells_info_lg();
    le_mrc_DisconnectService();
}

uint16_t pdop;
int res_pdop;
uint64_t t_start;
uint64_t t_start_bt;
uint64_t t_gotpoint = 0;
uint64_t t_gotpoint_bt = 0;
int32_t latitude, longitude;
le_gnss_FixState_t state;
int32_t hAccuracy;
le_gnss_SampleRef_t samp;
uint64_t epochTimeStart = 0;

int nsleep(long miliseconds)
{
   struct timespec req, rem;

   if(miliseconds > 999)
   {   
        req.tv_sec = (int)(miliseconds / 1000);                            /* Must be Non-Negative */
        req.tv_nsec = (miliseconds - ((long)req.tv_sec * 1000)) * 1000000; /* Must be in range of 0 to 999999999 */
   }   
   else
   {   
        req.tv_sec = 0;                         /* Must be Non-Negative */
        req.tv_nsec = miliseconds * 1000000;    /* Must be in range of 0 to 999999999 */
   }   

   return nanosleep(&req , &rem);
}
//--------------------------------------------------------------------------------------------------
/**
 * Handler for WiFi client Scan event
 *
 */
//--------------------------------------------------------------------------------------------------
static void wifi_client_scan_event_handler
(
    le_wifiClient_Event_t event,
        ///< [IN]
        ///< WiFi event to process
    void* contextPtr
        ///< [IN]
        ///< Associated event context
)
{
    LE_INFO("WiFi Client event received event = %d",event);
    switch(event)
    {
        case LE_WIFICLIENT_EVENT_CONNECTED:
        {
            LE_INFO("FYI: Got EVENT CONNECTED, was while waiting for SCAN.");
        }
        break;

        case LE_WIFICLIENT_EVENT_DISCONNECTED:
        {
            LE_INFO("FYI: Got EVENT DISCONNECTED, was while waiting for SCAN.");
        }
        break;

        case LE_WIFICLIENT_EVENT_SCAN_DONE:
        {
            LE_INFO("LE_WIFICLIENT_EVENT_SCAN_DONE: Now read the results ");
            scan_wifi();
            le_wifiClient_RemoveNewEventHandler(scan_hdlr_ref);
            scan_hdlr_ref = NULL;
            //exit(EXIT_SUCCESS);
        }
        break;

        case LE_WIFICLIENT_EVENT_SCAN_FAILED:
        {
            LE_ERROR("ERROR: Scan failed.\n");
            le_wifiClient_RemoveNewEventHandler(scan_hdlr_ref);
            scan_hdlr_ref = NULL;
            //exit(EXIT_FAILURE);
        }
        break;

        default:
            LE_ERROR("ERROR Unknown event %d", event);
        break;
    }
}
static void *delay_gnns_queery(void *context)
{
    delay_task_tyme = time_optiont_1;
    
    while (true)
    {
        LE_INFO("delay_gnns_queery enter");
        le_sem_Wait(sema_ref_wait_gnss_enable);
        le_wdog_ConnectService() ;
        le_wdog_Kick();
        le_wdog_DisconnectService();        
        LE_INFO("delay_gnns_queery start delay_task_tyme = %d",delay_task_tyme);
        if ((scan_cell != 0) && (scan_cell_once == true))
        {
            scan_cells();
        }
        nsleep(delay_task_tyme);
        LE_INFO("delay_gnns_queery take gnss");
        le_sem_Post(sema_ref_make_query);
    }
    le_event_RunLoop();
    LE_INFO("delay_gnns_queery done");
    return NULL;
}
int get_point(void)
{
    res_pdop = -1;
    epochTimeStart = 0;
    int cnt = 50;
    while ((res_pdop != LE_OK)  && (cnt-- > 0))
    {               
        samp = le_gnss_GetLastSampleRef();
        //res = le_gnss_GetPositionState(samp, &state);
        LE_INFO("res = %d state = %d epochTimeStart = %llu time = %llu", res,state,(unsigned long long int)epochTimeStart,(unsigned long long int)time(NULL));
        res = le_gnss_GetLocation(samp, &latitude, &longitude, &hAccuracy);
        res_pdop = le_gnss_GetDilutionOfPrecision(samp, LE_GNSS_PDOP, &pdop);           
        if (res_pdop != LE_OK)
        {
             count_get_points++;
             nsleep(200);
        }
        LE_INFO("latitude = %f longitude = %f hAccuracy = %f",(float)latitude/1000000.0, (float)longitude/1000000.0, (float)hAccuracy/100);
        LE_INFO("res = %d state = %d epochTimeStart = %llu res_pdop = %d cnt = %d", res,state,(unsigned long long int)epochTimeStart,res_pdop,cnt);
    }
    return res_pdop;
}
void stop_start(int start)
{
    le_gnss_ConnectService();
    res = le_gnss_Enable();
    res = le_gnss_Start();
    int gnns_state = le_gnss_GetState();
    LE_INFO("%s gnns_state = %d start = %d", __func__,gnns_state,start);
    if (start == 0)
    {
        res = le_gnss_ForceHotRestart();
        LE_INFO("le_gnss_ForceHotRestart() res = %d", res);
    }
    if (start == 1)
    {
        res = le_gnss_ForceColdRestart();
        LE_INFO("le_gnss_ForceColdRestart() res = %d", res);
    }
    if (start == 2)
    {
        res = le_gnss_ForceWarmRestart();
        LE_INFO("le_gnss_ForceWarmRestart() res = %d", res);
    }
    if (start == 3)
    {
        res = le_gnss_ForceHotRestart();
        LE_INFO("le_gnss_ForceHotRestart() res = %d", res);
    }    
    get_ttft();
    le_gnss_Stop();
    le_gnss_Disable();
    le_gnss_DisconnectService();
}

static void get_point_time(void)
{
    res_pdop = 0;
    if (options == 1)
    {
        le_sem_Post(sema_ref_wait_gnss_enable);
        le_sem_Wait(sema_ref_make_query);
    }
    hAccuracy = 100000000;
    int cnt = 0;
    count_get_points = 0;
    t_start  = GetTimeStampLegato();
    t_start_bt = 0;
    t_start_bt  = now_tp_abs_bt();
    LE_INFO("get_point_time !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!   t_start = %llu",(unsigned long long int)t_start);
    get_point();
    while ((cnt < 100) && (hAccuracy >= accuracy_diff*100))
    {
        get_point();
        cnt++;
        count_get_points++;
        nsleep(time_optiont);            
        LE_INFO("latitude = %f longitude = %f hAccuracy = %f", (float)latitude/1000000.0, (float)longitude/1000000.0,(float)hAccuracy/100);
        LE_INFO("cnt = %d count_get_points = %d time_optiont = %d ",cnt,count_get_points,time_optiont);            
    }
    t_gotpoint = GetTimeStampLegato();
    t_gotpoint_bt = 0;
    t_gotpoint_bt =  now_tp_abs_bt();
    LE_INFO("get_point_time ********************************************************************* t_gotpoint = %llu",(unsigned long long int)t_gotpoint);
    LE_INFO("get_point_time diff bt = %llu",(unsigned long long int) ((t_gotpoint - t_start)/1000));

	st0 = str_time(time(0));
    fprintf(fd, "%s latitude = %f longitude = %f hAccuracy = %f time in nano sec = %llu \n",
    st0, (float)latitude/1000000.0, (float)longitude/1000000.0, (float)hAccuracy/100,(unsigned long long int)(t_gotpoint - t_start)/1000);
    
    LE_INFO("res_pdop = %d pdop = %f time in micro sec = %llu", res_pdop,(float)pdop,(unsigned long long int)(t_gotpoint - t_start)/1000);
    if (t_gotpoint_bt < t_start_bt)
    {
        uint64_t t_timer_tmp = t_start_bt;
        LE_WARN("t_gotpoint_bt = %llu  t_start_bt = %llu",(unsigned long long int)(t_gotpoint )/1000,(unsigned long long int)(t_start_bt )/1000);
        t_start_bt = t_gotpoint_bt;
        t_gotpoint_bt = t_timer_tmp;
    }
    LE_INFO("res_pdop = %d pdop = %f time in micro sec = %llu  msec = %llu bt",   
    res_pdop,(float)pdop,(unsigned long long int)(t_gotpoint_bt - t_start_bt)/1000,(unsigned long long int)((t_gotpoint_bt - t_start_bt)/1000000));

    LE_INFO("latitude = %f longitude = %f hAccuracy = %f",(float)latitude/1000000.0, (float)longitude/1000000.0, (float)hAccuracy/100);
    LE_INFO("count_get_points = %d time_optiont_1 = %d",count_get_points,time_optiont_1);
    free(st0);
}

static void get_point_time_option0(void)
{
    res_pdop = 0;
    hAccuracy = 100000000;
    int cnt = 0;
    count_get_points = 0;
    t_start  = GetTimeStampLegato();
    LE_INFO("get_point_time !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!   t_start = %llu",(unsigned long long int)t_start);
    get_point();
    while ((cnt < 100) && (hAccuracy >= accuracy_diff*100))
    {
        get_point();
        cnt++;
        count_get_points++;
        nsleep(time_optiont);                    
        LE_INFO("latitude = %f longitude = %f hAccuracy = %f", 
            (float)latitude/1000000.0, (float)longitude/1000000.0, (float)hAccuracy/100);
        LE_INFO("cnt = %d count_get_points = %d time_optiont = %d ",cnt,count_get_points,time_optiont);            
    }
    t_gotpoint = GetTimeStampLegato();
    LE_INFO("get_point_time ********************************************************************* t_gotpoint = %llu",(unsigned long long int)t_gotpoint);
    LE_INFO("get_point_time diff bt = %llu",(unsigned long long int) ((t_gotpoint - t_start)/1000));

    LE_INFO("res_pdop = %d pdop = %f time in micro sec = %llu  msec = %llu bt",   
    res_pdop,(float)pdop,(unsigned long long int)(t_gotpoint_bt - t_start_bt)/1000,(unsigned long long int)((t_gotpoint_bt - t_start_bt)/1000000));

    LE_INFO("latitude = %f longitude = %f hAccuracy = %f",(float)latitude/1000000.0, (float)longitude/1000000.0, (float)hAccuracy/100);
    LE_INFO("count_get_points = %d time_optiont_1 = %d",count_get_points,time_optiont_1);
    LE_INFO("options = %d accuracy_diff = %d cnt = %d",options,accuracy_diff,cnt);
}

static void get_point_time_option2(void)
{
    int res_pdop = 0;
    hAccuracy = 100000000;
    int cnt = 0;
    count_get_points = 0;
    uint8_t sats_in_view = 0;
    uint8_t sats_tracking = 0;
    uint8_t sats_used = 0;
    uint16_t pdop = 0;
    uint16_t hdop = 0;
    t_start  = GetTimeStampLegato();
    delay_task_tyme = time_optiont_1;
    le_sem_Post(sema_ref_wait_gnss_enable);
    le_sem_Wait(sema_ref_make_query);        
    LE_INFO("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!   t_start = %llu",(unsigned long long int)t_start);
    res_pdop = get_point();
    if (res_pdop != LE_OK)
    {
	    st0 = str_time(time(0));
        fprintf(fd, "%s No point res_pdop = %d \n",st0, res_pdop);
        fflush(fd);
        LE_INFO("No point res_pdop = %d",res_pdop);
        free(st0);      
        return;
    }

    while ((cnt < 50) && (hAccuracy >= accuracy_diff*100))
    {
        delay_task_tyme = time_optiont_1/4;
        le_sem_Post(sema_ref_wait_gnss_enable);
        le_sem_Wait(sema_ref_make_query);        
        get_point();
        cnt++;
        count_get_points++;
        LE_INFO("latitude = %f longitude = %f hAccuracy = %f", 
            (float)latitude/1000000.0, (float)longitude/1000000.0,(float)hAccuracy/100);
        LE_INFO("cnt = %d count_get_points = %d delay_task_tyme = %d ",cnt,count_get_points,delay_task_tyme);
        res = le_gnss_GetSatellitesStatus(samp, &sats_in_view, &sats_tracking, &sats_used);
        LE_INFO("options = %d accuracy_diff = %d sats_in_view = %d sats_tracking = %d sats_used = %d res = %d",
            options,accuracy_diff,sats_in_view,sats_tracking,sats_used,res);
	    st0 = str_time(time(0));
        fprintf(fd, "%s,%f ,%f ,hAccuracy =, %f ,sats_in_view = %d, sats_tracking = %d, sats_used = %d, cnt = %d\n",
        st0, (float)latitude/1000000.0, (float)longitude/1000000.0, (float)hAccuracy/100,sats_in_view,sats_tracking,sats_used,cnt);
        fflush(fd);
        free(st0);            
    }
    t_gotpoint = GetTimeStampLegato();
    LE_INFO("===================================================================== t_gotpoint = %llu",(unsigned long long int)t_gotpoint);
    LE_INFO("diff bt = %llu",(unsigned long long int) ((t_gotpoint - t_start)/1000));

    LE_INFO("latitude = %f longitude = %f hAccuracy = %f pdop = %f",
    (float)latitude/1000000.0, (float)longitude/1000000.0, (float)hAccuracy/100,(float)pdop);
    res = le_gnss_GetSatellitesStatus(samp, &sats_in_view, &sats_tracking, &sats_used);    
    LE_INFO("count_get_points = %d time_optiont_1 = %d",count_get_points,time_optiont_1);
    LE_INFO("options = %d accuracy_diff = %d sats_in_view = %d sats_tracking = %d sats_used = %d res = %d",
        options,accuracy_diff,sats_in_view,sats_tracking,sats_used,res);
    res = le_gnss_GetDilutionOfPrecision(samp, LE_GNSS_PDOP, &pdop);
    res = le_gnss_GetDilutionOfPrecision(samp, LE_GNSS_VDOP, &hdop);
	st0 = str_time(time(0));
    fprintf(fd, "%s,%f ,%f ,hAccuracy =, %f time in mili sec =, %llu ,sats_in_view = %d, sats_tracking = %d, sats_used = %d,  pdop = %d, hdop = %d\n",
    st0, (float)latitude/1000000.0, (float)longitude/1000000.0, (float)hAccuracy/100,(unsigned long long int)(t_gotpoint - t_start)/1000, \
    sats_in_view,sats_tracking,sats_used,pdop,hdop);
    fflush(fd);
    free(st0);
}
static int timer_counter = 0;

static void ShortTimerExpiryHandler(le_timer_Ref_t timerRef)
{	
    le_pm_StayAwake(wakeUpSource);
    le_wdog_Kick();
    if (++get_points_num % 100)
    {
        fseek(fd, 0, SEEK_END);
        int size = ftell(fd);
        fseek(fd, 0L, SEEK_SET);
        if (size > 250000)
        {
            fflush(fd);
            fclose(fd);
            char newfile[256]={0};
            sprintf(newfile,"/home/root/data%d.txt",file_num++);
            rename( "/home/root/data.txt" ,newfile );
            fd = fopen("/home/root/data.txt","w");
            LE_INFO("size = %d fd = %p newfile = %s",size,fd,newfile);
        }
    }
    if (options == 0)
    {
        get_point_time_option0();
    }


    if (options == 1)
    {
        res = le_gnss_Enable();
        res = le_gnss_Start();
        get_point_time();
        le_gnss_Stop();
        le_gnss_Disable();    

    }    

    if (options == 2)
    {
        res = le_gnss_Start();
        if (res != LE_OK)
        {
             LE_ERROR("le_gnss_Start() options = %d",options);
        }
        get_point_time_option2();
        res = le_gnss_Stop();
        if (res != LE_OK)
        {
             LE_ERROR("le_gnss_Start() options = %d",options);
        }
    }

    LE_INFO("timer_counter = %d",timer_counter);
    if (timer_counter++ > 1)
    {
        timer_counter = 0;
        if ((scan_wifi_on == 1))
        {
            if (scan_wifi_once == true)
            {
                if (scan_hdlr_ref)
                    le_wifiClient_RemoveNewEventHandler(scan_hdlr_ref);
                scan_hdlr_ref = NULL;            
                res = le_wifiClient_Scan();
                if (res == LE_OK)
                {
                    LE_INFO("ShortTimerExpiryHandler enter start wifi scan scan_hdlr_ref = %p",scan_hdlr_ref);
                    scan_wifi_once = false;
                    scan_hdlr_ref = le_wifiClient_AddNewEventHandler(wifi_client_scan_event_handler, NULL);
                }
                else
                {
                    LE_INFO("ShortTimerExpiryHandler le_wifiClient_Scan() res = %d",res);
                    res = le_wifiClient_Stop();
                    //le_appCtrl_Stop("wifi");
                    //le_appCtrl_Start("wifi");
                    system("/mnt/flash/legato/systems/current/bin/wifi client stop");
                    system("/mnt/flash/legato/systems/current/bin/wifi client start");
                    res = le_wifiClient_Start();
                    LE_INFO("ShortTimerExpiryHandler once more le_wifiClient_Scan() res = %d",res);
                    timer_counter = 2;
                }
            }
            else
            {
                    LE_INFO("ShortTimerExpiryHandler le_wifiClient_Scan() res = %d",res);
                    res = le_wifiClient_Stop();
                    //le_appCtrl_Stop("wifi");
                    //le_appCtrl_Start("wifi");
                    system("/mnt/flash/legato/systems/current/bin/wifi client stop");
                    system("/mnt/flash/legato/systems/current/bin/wifi client start");
                    res = le_wifiClient_Start();
                    LE_INFO("ShortTimerExpiryHandler once more le_wifiClient_Scan() res = %d",res);
                    timer_counter = 2;
            }
        }
        if (scan_wifi_on == 2)       
        {
            uint64_t t_start_wifi  = GetTimeStampLegato();
            system("/mnt/flash/legato/systems/current/bin/wifi client scan > /home/root/data_wifi.txt");
            uint64_t t_scan_done_wifi  = GetTimeStampLegato();
            scan_wifi_cmd();
            uint64_t t_done_wifi  = GetTimeStampLegato();
            LE_INFO("scan wifi %llu = wifi_skyhook = %llu",
            (unsigned long long int)(t_scan_done_wifi - t_start_wifi )/1000,(unsigned long long int)(t_done_wifi - t_start_wifi)/1000);
        }
    }

    LE_INFO("le_pm_Relax options = %d",options);
    le_pm_Relax(wakeUpSource);
}
static void connection_state_handler
(
	const char *intfName,
	bool isConnected,
	void *contextPtr
)
{
	connect_data = isConnected;
    LE_INFO("intfName = %s isConnected = %d contextPtr = %p", intfName, isConnected, contextPtr);
}


static void gnss_atexit(void)
{
	LE_INFO("%s", __func__);
    st0 = str_time(time(0));
    fprintf(fd, "%s *********** STOP gnsstest ******** \n",st0);
    fflush(fd);
    free(st0);    
    fclose(fd);
    le_pm_Relax(wakeUpSource);
}
static void PrintHelp(void){
    puts(   "NAME\n"
            "        gnsstest -gnsstest functionality .\n"
            "\n"
            "SYNOPSIS\n"
            "        gnsstest -h\n"
            "        gnsstest --help\n"
            "\n"
            "OPTIONS\n"
            "       -p--time_option     \n"
    		"       -t--time    - time to sleep between sending packets\n"
            "       -n--time_optiont_1 \n"
            "       -o--options    - 0 \n"
            "       -m--mode_testmode_test    - 0 \n"

            "EXAMPLE\n"
            "app runProc gnsstest --exe=gnsstest -- -t 10 -p 8 -n 2 -o 0 -m 3\n"
            "app runProc gnsstest --exe=gnsstest -- -t 10 -p 8 -n 2 -o 1 -m 3 & \n"
        );

 exit(EXIT_SUCCESS);
}
//cat /sys/power/wake_lock
//app runProc gnsstest --exe=gnsstest -- --help
 //Execute app :  app runProc  gnsstest --exe=gnsstest --  -h
//clear log: syslogd

//app runProc gnsstest --exe=gnsstest1 -- -t 14 -p 1400 -n 100 -o 1 -m 3 &
//app runProc gnsstest --exe=gnsstest1 -- -t 14 -p 1200 -n 1010 -o 1 -m 3 &
//app runProc gnsstest --exe=gnsstest1 -- -t 60 -p 1200 -n 2010 -o 1 -m 2 &
//app runProc gnsstest --exe=gnsstest1 -- -t 60 -p 1200 -n 2010 -o 1 -m 2 &
COMPONENT_INIT
{
	le_timer_Ref_t shortTimer;
	le_clk_Time_t oneSecInterval = { 1, 0 };
    LE_INFO("Start test");
   
    options = 2;
    le_arg_SetFlagCallback(PrintHelp, "h", "help");
    le_arg_SetIntVar(&time_to_sleep_sec, "t", "time");
    le_arg_SetIntVar(&time_optiont, "p", "time_optiont");
    le_arg_SetIntVar(&time_optiont_1, "n", "time_optiont_1");
    le_arg_SetIntVar(&options, "o", "options");
    le_arg_SetIntVar(&accuracy_diff, "m", "accuracy_diff");
    le_arg_Scan();

    atexit(gnss_atexit);
    //res = le_appCtrl_Stop("devMode");
    system("/mnt/legato/system/bin/app stop devMode");
    accuracy_diff = 20;
    delay_task_tyme = 0;   
    scan_cell = 0;
    scan_wifi_on = 0;
    scan_cell_once = false;
    scan_wifi_once = true;
    fd = fopen("/home/root/data.txt","a");
    FILE  *fd_data = fopen("/home/root/data_params.txt","r");
    fscanf(fd_data,"%d%d%d%d%d%d",&options,&time_to_sleep_sec,&time_optiont_1,&accuracy_diff,&scan_cell,&scan_wifi_on);
    fclose(fd_data);
    st0 = str_time(time(0));
    fprintf(fd, "%s =========== STARTING gnsstest ======== \n",st0);
    fflush(fd);
    free(st0);
    LE_INFO("time_to_sleep_sec = %d time_optiont_1 = %d",time_to_sleep_sec,time_optiont_1);
    LE_INFO("options = %d accuracy_diff = %d, scan_cell = %d scan_wifi_on = %d", options,accuracy_diff,scan_cell,scan_wifi_on); 
    use_start = 3;
    
    //le_gnss_ForceHotRestart()
    shortTimer = le_timer_Create("short timer from default");
    sema_ref_make_query = le_sem_Create("gnss_wait_for_point", 0);
    sema_ref_wait_gnss_enable = le_sem_Create("gnss_wait_enable", 0);
    delay_gnss_poll = le_thread_Create("gnss_delay_get_point", delay_gnns_queery, NULL);
    le_thread_Start(delay_gnss_poll);
    le_clk_Time_t shortTimerInterval = le_clk_Multiply(oneSecInterval, time_to_sleep_sec);
    le_timer_SetInterval( shortTimer, shortTimerInterval );
    le_timer_SetRepeat(shortTimer, 0);
    le_timer_SetHandler(shortTimer, ShortTimerExpiryHandler);
    le_gnss_ConnectService();
    le_gnss_Enable();
    le_gnss_Start();
    int gnns_state = le_gnss_GetState();
    LE_INFO("%s gnns_state = %d", __func__,gnns_state);
    //res = le_gnss_ForceFactoryRestart();
    //LE_INFO("le_gnss_ForceFactoryRestart() res = %d", res);
    //get_ttft();
    //res = le_gnss_ForceHotRestart();
    //LE_INFO("le_gnss_ForceHotRestart() res = %d", res);
    get_ttft();    
    
    le_gnss_GetAcquisitionRate(&rate_gnss);
    LE_INFO("%s time_to_sleep_sec = %d time_optiont = %d time_optiont_1 = %d", __func__,time_to_sleep_sec,time_optiont,time_optiont_1);
    LE_INFO("%s options = %d accuracy_diff = %d, rate_gnss = %d", __func__,options,accuracy_diff,rate_gnss);
    system("/mnt/flash/legato/systems/current/bin/wifi client stop");
    //res = le_wifiClient_Stop();
    if (scan_wifi_on != 0)
    {
        res = le_wifiClient_Start();
    }
    LE_INFO("scan_wifi_on = %d res = %d",scan_wifi_on,res);
    //scan_hdlr_ref = le_wifiClient_AddNewEventHandler(wifi_client_scan_event_handler, NULL);
    scan_hdlr_ref = NULL;
    //le_gnss_GetAcquisitionRate(&time_optiont);
#if 0    
    int  cnt = 20;
    get_point();
    best_hAccuracy = hAccuracy;
    while (cnt > 0)
    {
        get_point();
        cnt--;
        LE_INFO("cnt = %d latitude = %f longitude = %f hAccuracy = %f", 
            cnt,(float)latitude/1000000.0, (float)longitude/1000000.0, (float)hAccuracy/100);
        if (best_hAccuracy > hAccuracy)
        {
            best_hAccuracy = hAccuracy;
        }
        nsleep(200);
    }
    get_ttft();
    le_gnss_DisconnectService();
    LE_INFO("%s best_hAccuracy = %f", __func__,(float)best_hAccuracy/100); 
#endif
    connect_data = false;
    if (scan_wifi_on)
    {
	    le_data_AddConnectionStateHandler(&connection_state_handler, NULL);
	    connection_ref = le_data_Request();
    }
    nsleep(1000);
    get_points_num = 0;
    file_num = 0;
    timer_counter = 0;
    le_timer_Start(shortTimer);   
    wakeUpSource = le_pm_NewWakeupSource(0, "Attenti_gnss");
    //le_gnss_Stop();
}
