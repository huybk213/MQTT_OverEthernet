#include "app_mqtt.h"

#include "lwip/opt.h"
#include "lwip/arch.h"
#include "lwip/api.h"
#include "lwip/apps/fs.h"
#include "string.h"
#include <stdio.h>
#include "cmsis_os.h"
#include "app_debug.h"
#include <stdio.h>
#include <string.h>
#include "lwip/pbuf.h"
#include "lwip/apps/mqtt.h"
#include "lwip/apps/mqtt_priv.h"
#include "lwip/netif.h"
#include "lwip/dns.h"
#include "app_ethernet.h"
#include "main.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "lwip/altcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/priv/altcp_priv.h"

#define MQTT_CLIENT_THREAD_PRIO    osPriorityAboveNormal
#define MQTT_CLIENT_SUB_QOS        0
#define MQTT_CLIENT_PUB_QOS        0
#define MQTT_CLIENT_RETAIN         0
static void mqtt_client_thread(void *arg);
static app_mqtt_state_t m_mqtt_state = APP_MQTT_DISCONNECTED;



#define MQTT_KEEP_ALIVE_INTERVAL 600
#define MQTT_TOPIC_BUFF_LEN 36
#define MQTT_RX_BUFFER_SIZE   (512)
#define MQTT_TX_BUFFER_SIZE   (512)
#define MQTT_AES_BUFFER_SIZE  (512)

#define	TOPIC_PUB_HEADER	"fire/pub/"
#define	TOPIC_SUB_HEADER	"fire/sub/"

static char m_mqtt_pub_topic[MQTT_TOPIC_BUFF_LEN];
static char m_mqtt_sub_topic[MQTT_TOPIC_BUFF_LEN];
static ip_addr_t m_mqtt_server_address;
static mqtt_client_t m_mqtt_client;
static uint8_t m_is_valid_sub_topic;

//static uint8_t MQTTState = APP_MQTT_DISCONNECTED;
static uint8_t m_DNS_resolved = 0;

char mqttTempBuffer[MQTT_RX_BUFFER_SIZE];
char m_mqtt_tx_buffer[MQTT_TX_BUFFER_SIZE];
static uint16_t m_msg_seq = 0;
static bool m_config_sended = false;

/* Ma hoa */
static uint8_t AESBuffer[MQTT_AES_BUFFER_SIZE];
static uint8_t Base64Buffer[MQTT_AES_BUFFER_SIZE];
static bool RenewServer = false;
static uint32_t m_sub_req_err_count;
static uint32_t m_mqtt_ping_s = 60;   
const char * m_mqtt_client_id = "huytv_test";
//const char * m_mqtt_username = "bytech.sful";
//const char * m_mqtt_password = "bytech.sful@2020";
const char * m_mqtt_broker = "a2fpu8zc49udz1-ats.iot.ap-southeast-1.amazonaws.com";
const uint16_t m_mqtt_port = 8883;

static const char * root_ca = "-----BEGIN CERTIFICATE-----\n\
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n\
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n\
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n\
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n\
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n\
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n\
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n\
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n\
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n\
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n\
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n\
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n\
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n\
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n\
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n\
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n\
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n\
rqXRfboQnoZsG4q5WTP468SQvvG5\n\
-----END CERTIFICATE-----";

static const char * client_key = "-----BEGIN CERTIFICATE-----\n\
MIIDWjCCAkKgAwIBAgIVAIbb/R9GqyZ2cDjeZaqifS9zRGXjMA0GCSqGSIb3DQEB\n\
CwUAME0xSzBJBgNVBAsMQkFtYXpvbiBXZWIgU2VydmljZXMgTz1BbWF6b24uY29t\n\
IEluYy4gTD1TZWF0dGxlIFNUPVdhc2hpbmd0b24gQz1VUzAeFw0yMDA3MDcwNDU2\n\
MjlaFw00OTEyMzEyMzU5NTlaMB4xHDAaBgNVBAMME0FXUyBJb1QgQ2VydGlmaWNh\n\
dGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9HZKJTXMYH66JFwer\n\
b1LeoyJK7D0hQUG6ioDqHaCpwuAXPB+styW3kUzxp5TfE7ut1MqwRoylXGo0/qzf\n\
mL08AMGACmXa/WsbU2nhNKH/q9MbluNLT/k8TbvkhBJ4JslXXgtIyP/QOaUHh8aj\n\
EH8P8JJwcFg9dSxVzxb+OgzyRciqexQ/Dga/yq2u91Ie/QUdknynk1PdStewPnMM\n\
HHPZO+JFJxA4wAZ7G7ZY0NZY3i/aiJF0TgSbyIML2118mjVh0GGnEeFxQuN5vP2E\n\
mqelgZ2dj1CMxjIb0SuLR1zVkCxt4EGjWdJQXbkoRtTO582dX+sFJt1J2/zzpRIb\n\
bn99AgMBAAGjYDBeMB8GA1UdIwQYMBaAFFJEaISt+QJLn05x8h7kXmC5WaQpMB0G\n\
A1UdDgQWBBTDbhvXhcvLAL4IF3VFplJmYp6oAjAMBgNVHRMBAf8EAjAAMA4GA1Ud\n\
DwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAQEAkoyQM99ZVZKkgkzQN5pii64M\n\
2yZpWt2fWjpe6iyX5ljzCEi7WdX0un0bzTjPw/GKLSiBnQXnpNnKQfvdvxmHP8A+\n\
O4ecT5o+xuMxKlqHdnd1TR3vbvr+kdc82CMnIwL7FopGN6D6uWrDDtwL2H1bhx+B\n\
bGhXYcZjXAIzkKJcc/nTcn4kgZKUvT0TEE2HT6F/nw4IBstWuStq+mSszQZf5uMy\n\
zsW6qalZUWZf+BuAErKTw57UVFsJQG5IncSDWaObn70GCkrLNIHBrpPNIF5UO8Jt\n\
7oFF/5CFcihDKxuueTjBeaOlmnhXy951sQSG3tBo8SyxrM09IMK4krTUHVV/aQ==\n\
-----END CERTIFICATE-----";

static const char * private_key = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpAIBAAKCAQEAvR2SiU1zGB+uiRcHq29S3qMiSuw9IUFBuoqA6h2gqcLgFzwf\n\
rLclt5FM8aeU3xO7rdTKsEaMpVxqNP6s35i9PADBgApl2v1rG1Np4TSh/6vTG5bj\n\
S0/5PE275IQSeCbJV14LSMj/0DmlB4fGoxB/D/CScHBYPXUsVc8W/joM8kXIqnsU\n\
Pw4Gv8qtrvdSHv0FHZJ8p5NT3UrXsD5zDBxz2TviRScQOMAGexu2WNDWWN4v2oiR\n\
dE4Em8iDC9tdfJo1YdBhpxHhcULjebz9hJqnpYGdnY9QjMYyG9Eri0dc1ZAsbeBB\n\
o1nSUF25KEbUzufNnV/rBSbdSdv886USG25/fQIDAQABAoIBAHO5rPooUs3oVT2+\n\
wgq+TM/AtDN07NN0w2wLZWfeSXqYrdiKCjf+uy3h1FvsWMVJpgdxt7a29Uobi0Jy\n\
tgb9yI73R3G66yle+jP2j0wokRmLY9v2MZDcl3+3ccscptCvq3WzLuSTWzdojvxU\n\
sdEHPznZ1ULI/LZfBYpc940KqPF3hM5Y+ruc/ETdRtX4ekfdzt6FObv6wbphNMRG\n\
vW0UkNq52TclCIYij+W+hiaM3ZEv+/CcJZJDgp+sBLC8nSs+iuaygeQ+iaMJJmKd\n\
wMjod+0Nfc7qfcrJYkMwhWKLG22HqXUhmwDGQxtxTI37XIPwcWyPKPu++O5bzw7W\n\
aYwb5QECgYEA6gk52FqDaqPJFh3zstVw15DshFHus7BIcVQ1JP8D3Q9eAnxH7HDL\n\
HAAd8/heg4F2cyh5uRzEyrVPGLtPsddFzH7fK9P4aGbzzgb44D1FepyUw/NLM0zc\n\
+cTM5tttjrXZvzzqbcW8UvL6SDeQbm2N1fZ5+Qnaw3qyGeV07KztY7UCgYEAzt0e\n\
p5Bvfm1y1eYYthy1wTVMFxG+/bK8V0+NthoN7dzYsPMdi8joQ4orFQWuTSJjNd/Q\n\
TKHU+o5+foHEHPcDeuE49LjMEYRXgDSxZu0WxDWtM8VHWj3FfepT7fSId9DyfPC/\n\
zDC+nYjenYbMs0q/gYBjymLPka5ZI/78drbvGakCgYBlDqTOuo7inmS3SymvACFg\n\
w/CNVn+3UZiGbzEfj4qQixEyC45XF4FsztQgRBAzwtRt931QJI8JZO8Jo+BOz8ER\n\
A3vEhhxOoJ4ISdRvp6V3w2MtlcHUHg2RQJyl1vxg0j97J4em7Opb+xV915hjRqUn\n\
Te3vToULQdDkA8PQav96vQKBgQCVUMRUvQvNXSEbxjemE/kZmefvau7KXt5Vw2WN\n\
wSa2v8dlikaUZJNKVQwd43jZ0m18MK5A8jsyE/K4S+CL67yGUNV0x4L9TeJ+9wnq\n\
Ok5JmFkJ2mdTeuz3o1Grm+t5WMf/aSN4NuMQAQB3Ahr1e4nZ5xugtUwQYqGTOvVu\n\
l0Lk6QKBgQC2fJhM8deM1WLkMgVH+dSUB8J1lRCH48eys/nVE1DASl97xomV8zAa\n\
QWxXz9GeUY1+ExQNFqC/u294hIg6IY9aKktToraKk5tmyAaRQhqSl7CABzlQgWlQ\n\
jvRIj29HDnkQw0poT/1/1ePSL6xHkVWMwqraffRmLayFCfxVFxAwbQ==\n\
-----END RSA PRIVATE KEY-----";

//TLS
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt x509_root_ca;
static mbedtls_x509_crt x509_client_key;
static mbedtls_pk_context pk_private_key;
static mbedtls_ctr_drbg_context ctr_drbg;


static void my_debug(void *ctx, int level, const char *file, int line, const char *str) 
{
    ((void)level);
    DebugPrint("\r\n%s, at line %d in file %s\n", str, line, file);
}

static int mqtt_tls_verify(void *data, mbedtls_x509_crt *crt, int depth, int *flags) 
{
	char buf[1024]; 

	DebugPrint("\nVerify requested for (Depth %d):\n", depth ); 
	mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt ); 
//	DebugPrint("%s", buf ); 

	if ( ( (*flags) & MBEDTLS_X509_BADCERT_EXPIRED ) != 0 ) 
    {
        DebugPrint("  ! server certificate has expired\n" ); 
    }

	if ( ( (*flags) & MBEDTLS_X509_BADCERT_REVOKED ) != 0 ) 
		DebugPrint("  ! server certificate has been revoked\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCERT_CN_MISMATCH ) != 0 ) 
		DebugPrint("  ! CN mismatch\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCERT_NOT_TRUSTED ) != 0 ) 
		DebugPrint("  ! self-signed or not signed by a trusted CA\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCRL_NOT_TRUSTED ) != 0 ) 
		DebugPrint("  ! CRL not trusted\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCRL_EXPIRED ) != 0 ) 
		DebugPrint("  ! CRL expired\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCERT_OTHER ) != 0 ) 
		DebugPrint("  ! other (unknown) flag\n" ); 

//	if ( ( *flags ) == 0 ) 
//		DebugPrint("  This certificate has no flags\n" ); 

	return( 0 ); 
}


void MQTT_TlsClose(void) 
{ /* called from mqtt.c */
    /*! \todo This should be in a separate module */
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
}

static int TLS_Init(void) 
{
    DebugPrint("TLS initialize\r\n");

    /* inspired by https://tls.mbed.org/kb/how-to/mbedtls-tutorial */
    int ret;
    const char *pers = "HuyTV-PC123123";

    /* initialize the different descriptors */
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&x509_root_ca);
    mbedtls_x509_crt_init(&x509_client_key);
    mbedtls_pk_init(&pk_private_key);

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers ) ) ) != 0 )
    {
        DebugPrint(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%08X\n", -ret);
        return -1;
    }

    /*
     * First prepare the SSL configuration by setting the endpoint and transport type, and loading reasonable
     * defaults for security parameters. The endpoint determines if the SSL/TLS layer will act as a server (MBEDTLS_SSL_IS_SERVER)
     * or a client (MBEDTLS_SSL_IS_CLIENT). The transport type determines if we are using TLS (MBEDTLS_SSL_TRANSPORT_STREAM)
     * or DTLS (MBEDTLS_SSL_TRANSPORT_DATAGRAM).
     */
    if (( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0)
    {
        DebugPrint(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        return -1;
    }
  
  /* The authentication mode determines how strict the certificates that are presented are checked.  */
#if 1 // CONFIG_USE_SERVER_VERIFICATION
    ret = mbedtls_x509_crt_parse(&x509_root_ca, (const unsigned char *)root_ca, strlen(root_ca)+1);
    if (ret != 0)
    {
        DebugPrint("Parse root ca error -0x%08X\r\n", ret);
        assert_failed(__FILE__, __LINE__);
        return -1;
    }
    
    ret = mbedtls_x509_crt_parse(&x509_client_key, (const unsigned char *)client_key, strlen(client_key)+1);
    if (ret != 0)
    {
        DebugPrint("Parse client key error -0x%08X\r\n", ret);
        assert_failed(__FILE__, __LINE__);
        return -1;
    }

    ret = mbedtls_pk_parse_key(&pk_private_key, (const unsigned char *)private_key, strlen(private_key)+1, NULL, 0);
    if (ret != 0)
    {
        DebugPrint("Parse private key error -0x%08X\r\n", ret);
        assert_failed(__FILE__, __LINE__);
        return -1;
    }
    
    DebugPrint("Parse certificate success\r\n");
    mbedtls_ssl_conf_ca_chain(&conf, &x509_root_ca, NULL);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
//    mbedtls_ssl_conf_verify(&conf, (int (*)(void *, mbedtls_x509_crt *, int, uint32_t *))mqtt_tls_verify, NULL );
    
#else
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
#endif
    /* The library needs to know which random engine to use and which debug function to use as callback. */
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

//    mbedtls_ssl_setup(&ssl, &conf);

    if ((ret = mbedtls_ssl_set_hostname(&ssl, m_mqtt_broker)) != 0)
    {
        DebugPrint(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        assert_failed(__FILE__, __LINE__);
        return -1;
    }

    DebugPrint("Set host name success\r\n");
    /* the SSL context needs to know the input and output functions it needs to use for sending out network traffic. */
//    mbedtls_ssl_set_bio(&ssl, &mqtt_static_client, altcp_mbedtls_bio_send, altcp_mbedtls_bio_recv, NULL);

    return 0; /* no error */
}


static void mqtt_sub_request_cb(void *arg, err_t result)
{
   /* Just print the result code here for simplicity, 
   normal behaviour would be to take some action if subscribe fails like 
   notifying user, retry subscribe or disconnect from server */

    if (result != ERR_OK)
    {
        DebugPrint("Retry send subscribe...\r\n");
        m_sub_req_err_count++;
        if (m_sub_req_err_count >= 5)
        {
            /* Close mqtt connection */
            DebugPrint("Close mqtt connection\r\n");
            mqtt_disconnect(&m_mqtt_client);

            m_sub_req_err_count = 0;
            m_mqtt_state = APP_MQTT_DISCONNECTED;
        }
        else
        {
            mqtt_subscribe(&m_mqtt_client, m_mqtt_sub_topic, MQTT_CLIENT_SUB_QOS, mqtt_sub_request_cb, arg);
        }
    }
    else
    {
        m_sub_req_err_count = 0;
        DebugPrint("Subscribed\r\n");
    }
}

/* 3. Implementing callbacks for incoming publish and data */
/* The idea is to demultiplex topic and create some reference to be used in data callbacks
   Example here uses a global variable, better would be to use a member in arg
   If RAM and CPU budget allows it, the easiest implementation might be to just take a copy of
   the topic string and use it in mqtt_incoming_data_cb
*/
static void mqtt_incoming_publish_cb(void *arg, const char *topic, u32_t tot_len)
{
    DebugPrint("Incoming publish at topic %s with total length %u\r\n", topic, (unsigned int)tot_len);

    /* Decode topic string into a user defined reference */
    if (strcmp(topic, m_mqtt_sub_topic) == 0)
    {
        m_is_valid_sub_topic = 1;
    }
    else
    {
        /* For all other topics */
        m_is_valid_sub_topic = 0;
    }
}

static void mqtt_incoming_data_cb(void *arg, const u8_t *data, u16_t len, u8_t flags)
{
    DebugPrint("Incoming publish payload with length %d, flags %u\r\n", len, (unsigned int)flags);

    if (flags & MQTT_DATA_FLAG_LAST)
    {
        /* Last fragment of payload received (or whole part if payload fits receive buffer
          See MQTT_VAR_HEADER_BUFFER_LEN)  */

        DebugPrint("Payload data: %s\r\n", (const char *)data);
#if 0        
        if (m_is_valid_sub_topic == 1)
        {
            m_is_valid_sub_topic = 0;

            /* Update firmware message  */
            if (strstr((char *)data, "UDFW,"))
            {
             #if FILE_DOWNLOAD_ENABLE
                  ProcessUpdateFirmwareCommand((char *)data);
             #endif
            }
            else if (strstr((char *)data, "SET,"))
            {
                  /* Set command without encrypted */
                  // SET,10,(60)
                //   ProcessSetParameters((char*)data, PARAMETER_SET_FROM_SERVER);
            }
            else if (strstr((char *)data, "GET,"))
            {
                  /* Get command without encrypted */
                //   ProcessGetParameters((char*)data, PARAMETER_SET_FROM_SERVER);
            }
            else
            {
                  /* Process encrypted data */
                  ProcessCMDfromServer((uint8_t *)data, len);
            }
        }
#endif
        //clear received buffer of client -> du lieu nhan lan sau khong bi thua cua lan truoc, neu lan truoc gui length > MQTT_VAR_HEADER_BUFFER_LEN
        memset(m_mqtt_client.rx_buffer, 0, MQTT_VAR_HEADER_BUFFER_LEN);
    }
    else
    {
        /* Handle fragmented payload, store in buffer, write to file or whatever */
    }
}

static void mqtt_client_connection_callback(mqtt_client_t *client, void *arg, mqtt_connection_status_t status)
{
   DebugPrint("mqtt_client_connection_callback reason: %d\r\n", status);

    err_t err;
    if (status == MQTT_CONNECT_ACCEPTED)
    {
        //		ZIG_Prints("SERVER", "PASS");

        DebugPrint("mqtt_connection_cb: Successfully connected\r\n");
        m_mqtt_state = APP_MQTT_CONNTECTED;
        
        /* Setup MQTT subscribe topic */
        snprintf(m_mqtt_sub_topic, sizeof(m_mqtt_sub_topic), "%s%s", TOPIC_SUB_HEADER, m_mqtt_client_id);

        /* Setup callback for incoming publish requests */
        mqtt_set_inpub_callback(client, mqtt_incoming_publish_cb, mqtt_incoming_data_cb, arg);

        /* Subscribe to a topic named "fire/sub/IMEI" with QoS level 1, call mqtt_sub_request_cb with result */
        DebugPrint("Subscribe %s\r\n", m_mqtt_sub_topic);
        err = mqtt_subscribe(client, m_mqtt_sub_topic, MQTT_CLIENT_SUB_QOS, mqtt_sub_request_cb, arg);

        if (err != ERR_OK)
        {
           DebugPrint("mqtt_subscribe return: %d\r\n", err);
        }
    }
    else
    {
        /* Its more nice to be connected, so try to reconnect */
        m_mqtt_state = APP_MQTT_CONNECTING;
    }
}

/* -----------------------------------------------------------------
4. Using outgoing publish
*/
/* Called when publish is complete either with sucess or failure */
static void mqtt_pub_request_cb(void *arg, err_t result)
{
    if (result != ERR_OK)
    {
        DebugPrint("Publish result: %d\r\n", result);
    }
    else
    {
        DebugPrint("Publish: OK\r\n");
        m_mqtt_ping_s = 60;
    }
}

/*****************************************************************************/
/**
 * @brief	:  	BuildLoginMessage, ban tin dang ky T1 duoc gui moi khi thiet bi duoc bat (restart)
 * @param	:  
 * @retval	:
 * @author	:	
 * @created	:	15/03/2016
 * @version	:
 * @reviewer:	
 */
static uint16_t BuildLoginMessage(char * buffer, char * topic)
{ 
#if 0
    uint16_t Checksum;
    uint16_t idx = 0;
                    
    /* Add plain content */
    char NetworkKeyString[33];
    char PrivateKeyString[33];

    app_common_hex_to_str(SystemContext()->Parameters.mesh_pair_info.info.key.netkey, 
                          NetworkKeyString, 
                          sizeof(SystemContext()->Parameters.mesh_pair_info.info.key.netkey));

    app_common_hex_to_str(SystemContext()->Parameters.mesh_pair_info.info.key.appkey, 
                          PrivateKeyString, 
                          sizeof(SystemContext()->Parameters.mesh_pair_info.info.key.appkey));

    DateTime_t dateTime = SystemContext()->Rtc->GetDateTime();
    idx = sprintf(buffer,"%04u-%02u-%02u %02u:%02u:%02u,%s,T1,%s,%s,%s,%u,%s,%u,%u",
            dateTime.Year + 2000,dateTime.Month,dateTime.Day, dateTime.Hour,dateTime.Minute,dateTime.Second,
            m_mqtt_client_id, SystemContext()->Parameters.SIM_IMEI, NetworkKeyString, /* Network key: SFUL mesh (32 ki tu) */
            FIRMWARE_VERSION, SystemContext()->GLStatus.LoginReason,
            PrivateKeyString,   /* Private key: SFUL mesh (16 ki tu) */
            SystemContext()->Parameters.mesh_pair_info.info.exchange_pair_addr,   /* Mesh ID -> can khi gui lenh */
            m_msg_seq);  

    DebugPrint("MQTT: Raw payload %s\r\n", buffer);

    /* Ma hoa AES128: Buffer -> EncryptedBuffer */
    memset(AESBuffer, 0, sizeof(AESBuffer));
    memset(Base64Buffer, 0, sizeof(Base64Buffer));
            
    AES_ECB_encrypt(buffer, (uint8_t*)APP_AES_PUBLIC_KEY, AESBuffer, idx);
    idx = 16 * ((idx / 16) + 1);
    
    /* Ma hoa Base64 */
    b64_encode((char *)AESBuffer, idx, (char *)Base64Buffer);
    Checksum = CRC16(Base64Buffer, strlen((char*)Base64Buffer));	
    
    /* Add checksum : ban tin T1 -> {} */
    idx = sprintf(buffer, "{%s%05u}", Base64Buffer, Checksum);
    
    sprintf(topic, "%s%s", TOPIC_PUB_HEADER, m_mqtt_client_id);

    m_msg_seq++;
    if(m_msg_seq > 999) m_msg_seq = 0;
                                
    return idx;
#else
    return 1;
#endif
}


/*****************************************************************************/
/**
 * @brief	:  	BuildLoginMessage, ban tin dang ky T1 duoc gui moi khi thiet bi duoc bat (restart)
 * @param	:  
 * @retval	:
 * @author	:	
 * @created	:	15/03/2016
 * @version	:
 * @reviewer:	
 */
static uint16_t BuildDebugMessage(char * buffer)
{ 
#if 0
    uint16_t Checksum;
    uint16_t size = 0;
                    
    DebugPrint("MQTT: Raw payload %s\r\n", buffer);

    /* Ma hoa AES128: Buffer -> EncryptedBuffer */
    memset(AESBuffer, 0, sizeof(AESBuffer));
    memset(Base64Buffer, 0, sizeof(Base64Buffer));
   
    DateTime_t dateTime = SystemContext()->Rtc->GetDateTime();
    size = snprintf(m_mqtt_tx_buffer, sizeof(m_mqtt_tx_buffer), "%04u-%02u-%02u %02u:%02u:%02u,T8,%s,%u",
            dateTime.Year + 2000, dateTime.Month, dateTime.Day, dateTime.Hour,dateTime.Minute,dateTime.Second,
            buffer,
            m_msg_seq);  


    DebugPrint("MQTT: Raw payload %s\r\n", m_mqtt_tx_buffer);

    AES_ECB_encrypt(m_mqtt_tx_buffer, (uint8_t*)APP_AES_PUBLIC_KEY, AESBuffer, size);
    size = 16 * ((size / 16) + 1);
   

    /* Ma hoa Base64 */
    b64_encode((char *)AESBuffer, size, (char *)Base64Buffer);
    Checksum = CRC16(Base64Buffer, strlen((char*)Base64Buffer));	
    
    /* Add checksum : ban tin T1 -> {} */
    size = snprintf(m_mqtt_tx_buffer, sizeof(m_mqtt_tx_buffer), "{%s%05u}", Base64Buffer, Checksum);

    m_msg_seq++;
    if(m_msg_seq > 999) m_msg_seq = 0;
                                
    return size;
#else
    return 1;
#endif 
}

/*
* MQTT_SendLoginMessage
* Author: Phinht
*/
static void MQTT_SendLoginMessage(void)
{
    memset(m_mqtt_tx_buffer, 0, sizeof(m_mqtt_tx_buffer));
    memset(m_mqtt_pub_topic, 0, sizeof(m_mqtt_pub_topic));

    uint16_t size = BuildLoginMessage(m_mqtt_tx_buffer, m_mqtt_pub_topic);
    sprintf(m_mqtt_tx_buffer, "MQTT_SendLoginMessage %u - %s\r\n", 1, "T1");
    sprintf(m_mqtt_pub_topic, "%s", "huydeptrai");
    DebugPrint("Topic %s\r\n", m_mqtt_pub_topic);
#if 1       
    err_t err = mqtt_publish(&m_mqtt_client, m_mqtt_pub_topic, m_mqtt_tx_buffer, size, MQTT_CLIENT_PUB_QOS, MQTT_CLIENT_RETAIN, mqtt_pub_request_cb, NULL);
    if (err == ERR_OK)
    {
        DebugPrint("Publish msg success\r\n");
    }
    else
    {
        DebugPrint("Publish err: %d\r\n", err);
    }
#endif
}

/*
* MQTT_SendHeartBeat
* Author: Phinht
*/
static void MQTT_SendHeartBeat(void)
{
#if 0
    uint16_t Checksum;
    uint16_t BufferIndex = 0;
        
    /* Build data message */
    DateTime_t dateTime = SystemContext()->Rtc->GetDateTime();
	
    //2019-03-23 15:22:32,867322030010144,T3,0,22,0,100,14
    BufferIndex = sprintf((char *)m_mqtt_tx_buffer,"%04u-%02u-%02u %02u:%02u:%02u,%s,T3,%u,%u,%u,%u,%u",
            dateTime.Year + 2000,dateTime.Month,dateTime.Day, dateTime.Hour,dateTime.Minute,dateTime.Second,
            m_mqtt_client_id,
            SystemContext()->GLStatus.SystemAlarmState.Value,	/* Trang thai canh bao he thong */
            SystemContext()->GLStatus.GSMCSQ,
            SystemContext()->Parameters.mesh_pair_info.info.next_unicast_addr, /* Tong so sensor da pair */
            GetBateryPercent(),
            m_msg_seq);
        
    /* Ma hoa AES128: Buffer -> EncryptedBuffer */
    memset(AESBuffer, 0, sizeof(AESBuffer));
    memset(Base64Buffer, 0, sizeof(Base64Buffer));
            
    AES_ECB_encrypt(m_mqtt_tx_buffer, (uint8_t*)APP_AES_PUBLIC_KEY, AESBuffer, BufferIndex);
    BufferIndex = 16 * ((BufferIndex / 16) + 1);
    
    /* Ma hoa Base64 */
    b64_encode((char *)AESBuffer, BufferIndex, (char *)Base64Buffer);
    Checksum = CRC16(Base64Buffer, strlen((char*)Base64Buffer));	
    
    /* Add checksum : ban tin T3 -> [] */
    BufferIndex = sprintf((char *)m_mqtt_tx_buffer, "[%s%05u]", Base64Buffer,Checksum);
    
    DebugPrint("MQTT_SendHeartBeat: %u - %s\r\n", BufferIndex, "T3");

    err_t err = mqtt_publish(&m_mqtt_client, m_mqtt_pub_topic, m_mqtt_tx_buffer, BufferIndex, MQTT_CLIENT_PUB_QOS, MQTT_CLIENT_RETAIN, mqtt_pub_request_cb, NULL);
    if (err != ERR_OK) {
        DebugPrint("Publish err: %d\r\n", err);
        return;
    }

    m_msg_seq++;
    if(m_msg_seq > 999) m_msg_seq = 0;
#endif
}

uint16_t MQTT_SendBufferToServer(char* BufferToSend, char *LoaiBanTin)
{ 
#if 0
    uint16_t Checksum;
    uint16_t BufferIndex = 0;
 
    memset(mqttTempBuffer, 0, sizeof(mqttTempBuffer));

    DateTime_t dateTime = SystemContext()->Rtc->GetDateTime();
    BufferIndex = sprintf((char *)mqttTempBuffer,"%04u-%02u-%02u %02u:%02u:%02u,%s,%s,%s,%u",
      dateTime.Year + 2000,dateTime.Month,dateTime.Day, dateTime.Hour,dateTime.Minute,dateTime.Second,
      m_mqtt_client_id, LoaiBanTin, BufferToSend, m_msg_seq);
            
    /* Ma hoa AES128: Buffer -> EncryptedBuffer */
    memset(AESBuffer, 0, sizeof(AESBuffer));
    memset(Base64Buffer, 0, sizeof(Base64Buffer));
            
    AES_ECB_encrypt(mqttTempBuffer, (uint8_t*)APP_AES_PUBLIC_KEY, AESBuffer, BufferIndex);
    BufferIndex = 16 * ((BufferIndex / 16) + 1);
    
    /* Ma hoa Base64 */
    b64_encode((char *)AESBuffer, BufferIndex, (char *)Base64Buffer);
    Checksum = CRC16(Base64Buffer, strlen((char*)Base64Buffer));	
    
    /* Add checksum : ban tin Txx -> [] */
    BufferIndex = sprintf(mqttTempBuffer, "[%s%05u]", Base64Buffer, Checksum);
    
    if (strlen(m_mqtt_pub_topic) == 0)
    {
        DebugPrint("Invalid topic\r\n");
    }
    DebugPrint("MQTT: SendBuffer: %u - %s. Topic: %s\r\n", BufferIndex, LoaiBanTin, m_mqtt_pub_topic);

    err_t err = mqtt_publish(&m_mqtt_client, m_mqtt_pub_topic, mqttTempBuffer, BufferIndex, MQTT_CLIENT_PUB_QOS, MQTT_CLIENT_RETAIN, mqtt_pub_request_cb, NULL);
    if (err != ERR_OK) {
        DebugPrint("Publish err: %d\r\n", err);
        return 0;
    }

    m_msg_seq++;
    if(m_msg_seq > 999) m_msg_seq = 0;

    return BufferIndex;
#else
    DebugPrint("Send buffer to server\r\n");
    return 1;
#endif
}

/*
* MQTT_SendResetMessage : Chi send 1 lan sau khi reset
* Author: Phinht
*/
static void MQTT_SendResetMessage(void)
{
    static bool isSendReset = false;

    if (isSendReset) 
        return;
#if 0
//    memset(m_mqtt_tx_buffer, 0, sizeof(m_mqtt_tx_buffer));

    uint16_t index = 0;
//    memset(m_mqtt_pub_topic, 0, sizeof(m_mqtt_pub_topic));

    index += sprintf((char*)&m_mqtt_tx_buffer[index],"HW=%u,", SystemContext()->GLStatus.HardwareResetReason); 
    index += sprintf((char*)&m_mqtt_tx_buffer[index], "SW=%u,", SystemContext()->GLStatus.SelfResetReason);
    index += sprintf((char*)&m_mqtt_tx_buffer[index], "CNT=%u,", SystemContext()->GLStatus.SoLanReset);
    index += sprintf((char*)&m_mqtt_tx_buffer[index], "V=%u,CSQ=%u,", SystemContext()->GLStatus.VinVoltage, SystemContext()->GLStatus.GSMCSQ);
    index += sprintf((char*)&m_mqtt_tx_buffer[index], "Vbat=%u", SystemContext()->GLStatus.VSystem);

    DebugPrint("MQTT_SendResetMessage: %s\r\n", m_mqtt_tx_buffer);

    if (MQTT_SendBufferToServer((char*)m_mqtt_tx_buffer, "RESET"))
         isSendReset = true;
#else
    DebugPrint("Send reset msg to server\r\n");
    isSendReset = true;
#endif
}

/*****************************************************************************/
/**
 * @brief	:  	Gui tat ca cau hinh cua Gateway len server, gui 1 lan sau khi login
 * @param	:  
 * @retval	:
 * @author	:	Phinht
 * @created	:	15/05/2018
 * @version	:
 * @reviewer:	
 */
void MQTT_SendAllConfigToServer(void)
{
    uint16_t index = 0;

    if(m_config_sended) return;
    
//    memset(m_mqtt_tx_buffer, 0, sizeof(m_mqtt_tx_buffer));
//    
//    index += sprintf((char*)&m_mqtt_tx_buffer[index],"DOMAIN=%s,", SystemContext()->Parameters.BrokerHost.Name); 
//    index += sprintf((char*)&m_mqtt_tx_buffer[index], "FREQ1=%u,", SystemContext()->Parameters.Freq1);
//    index += sprintf((char*)&m_mqtt_tx_buffer[index], "FREQ2=%u,", SystemContext()->Parameters.Freq2);
//    index += sprintf((char*)&m_mqtt_tx_buffer[index], "SubFREQ=%u,", SystemContext()->Parameters.Time_SubRequest);
//    index += sprintf((char*)&m_mqtt_tx_buffer[index], "USER1=%s,", SystemContext()->Parameters.FlashStoreParam.info.ConfigCommon.info.OwnNumber1);
//    index += sprintf((char*)&m_mqtt_tx_buffer[index], "USER2=%s,", SystemContext()->Parameters.FlashStoreParam.info.ConfigCommon.info.OwnNumber2);
//    index += sprintf((char*)&m_mqtt_tx_buffer[index], "USER3=%s,", SystemContext()->Parameters.FlashStoreParam.info.ConfigCommon.info.OwnNumber3);
//    index += sprintf((char*)&m_mqtt_tx_buffer[index], "ALARM=%u", SystemContext()->Parameters.Alarm.Value);
//
//    if(MQTT_SendBufferToServer((char*)m_mqtt_tx_buffer, "T5"))
    m_config_sended = true;
    DebugPrint("Send all configuration to server\r\n");
}

static void MQTT_SendSubscribeRequest(void)
{
    /* Subscribe to a topic named "qrm/imei/st_data" with QoS level 1, call mqtt_sub_request_cb with result */
    err_t err = mqtt_subscribe(&m_mqtt_client, m_mqtt_sub_topic, MQTT_CLIENT_SUB_QOS, mqtt_sub_request_cb, NULL);

    DebugPrint("%s: topic %s\r\n", __FUNCTION__, m_mqtt_sub_topic);
}

//void MqttClientBuildSubTopic(char * topic)
//{
//    snprintf(m_mqtt_sub_topic, sizeof(m_mqtt_sub_topic), "%s", topic);
//}

/*****************************************************************************/
/**
 * @brief	:  	Ban tin canh bao khi co chay
 * @param	:  
 * @retval	:
 * @author	:	
 * @created	:
 * @version	:
 * @reviewer:	
 */
uint16_t FireAlarmMessage(void)
{
#if 0
    uint16_t Checksum;
    uint16_t BufferIndex = 0;

    memset(mqttTempBuffer, 0, sizeof(mqttTempBuffer));

    //2019-03-23 15:22:32,867322030010144,T25,1,14
    DateTime_t dateTime = SystemContext()->Rtc->GetDateTime();
    BufferIndex = sprintf((char *)mqttTempBuffer,"%04u-%02u-%02u %02u:%02u:%02u,%s,T25,%u,%u",
            dateTime.Year + 2000, dateTime.Month, dateTime.Day,dateTime.Hour, dateTime.Minute, dateTime.Second,
            m_mqtt_client_id,
            SystemContext()->GLStatus.SystemAlarmState.Value,   /* Bit trang thai cho Cac loai canh bao */
            m_msg_seq);
    
    /* Ma hoa AES128: Buffer -> EncryptedBuffer */
    memset(AESBuffer, 0, sizeof(AESBuffer));
    memset(Base64Buffer, 0, sizeof(Base64Buffer));
            
    AES_ECB_encrypt(mqttTempBuffer, (uint8_t*)APP_AES_PUBLIC_KEY, AESBuffer, BufferIndex);
    BufferIndex = 16 * ((BufferIndex / 16) + 1);
    
    /* Ma hoa Base64 */
    b64_encode((char *)AESBuffer, BufferIndex, (char *)Base64Buffer);
    Checksum = CRC16(Base64Buffer, strlen((char*)Base64Buffer));	
    
    /* Add checksum : ban tin T25 -> [] */
    BufferIndex = sprintf((char *)mqttTempBuffer, "[%s%05u]", Base64Buffer,Checksum);
        
    /* Timeout nhan phan hoi S25 */
    SystemContext()->GLStatus.FireAlarmConfirmFromServerTimeout = 15;	/* sec */
    
    DebugPrint("FireAlarmMessage T25 - %u\r\n", BufferIndex);

    err_t err = mqtt_publish(&m_mqtt_client, m_mqtt_pub_topic, mqttTempBuffer, BufferIndex, MQTT_CLIENT_PUB_QOS, MQTT_CLIENT_RETAIN, mqtt_pub_request_cb, NULL);
    if (err != ERR_OK)
        return 0;

    m_msg_seq++;
    if(m_msg_seq > 999) m_msg_seq = 0;

    return BufferIndex;
#else
    return 1;
#endif
}

/*****************************************************************************/
/**
 * @brief	:  	Ban tin trang thai cua Node khi update
 * @param	:  
 * @retval	:
 * @author	:	Phinht
 * @created	:	15/01/2014
 * @version	:
 * @reviewer:	
 */
uint16_t SendNodeStateMessage(void)
{
#if 0
    uint8_t index, foundNewMsg = 0, foundPairMsg = 0;
    char *msgType = NULL;
    
    //Tim xem co ban tin moi nhan duoc tu sensor khong
    for(index = 0; index < SystemContext()->GLStatus.NodeCount; index++)
    {
        if(SystemContext()->GLStatus.Node[index].Property.Name.isNewMsg)
        {
            foundNewMsg = 1;
            msgType = "T6";
            DebugPrint("[%s] MSG T6\r\n", __FUNCTION__);
            break;
        }
        if(SystemContext()->GLStatus.Node[index].Property.Name.isPairMsg)
        {
            foundPairMsg = 1;
            msgType = "T7";
            DebugPrint("[%s] MSG T7\r\n", __FUNCTION__);
            break;
        }
    }

    if(foundNewMsg == 0 && foundPairMsg == 0) 
        return 0;
    
    memset(m_mqtt_tx_buffer, 0, sizeof(m_mqtt_tx_buffer));
    uint8_t nodeMAC[7] = {0};
    uint16_t ViTri = 0;
    
    memcpy(nodeMAC, SystemContext()->GLStatus.Node[index].MAC, 6);
    
    //Dia chi MAC
    ViTri += sprintf((char*)&m_mqtt_tx_buffer[ViTri],"%02X%02X%02X%02X%02X%02X,", 
      nodeMAC[0], nodeMAC[1], nodeMAC[2], nodeMAC[3], nodeMAC[4], nodeMAC[5]);
    
    //Firmware code
    ViTri += sprintf((char*)&m_mqtt_tx_buffer[ViTri], 
                      "%s", 
                      app_mesh_msg_map_device_type_to_string_type(SystemContext()->GLStatus.Node[index].Property.Name.deviceType));

    //Firmware version
    ViTri += sprintf((char*)&m_mqtt_tx_buffer[ViTri], "%u,", SystemContext()->GLStatus.Node[index].Property.Name.fwVersion);
    
    //Trang thai canh bao
    ViTri += sprintf((char*)&m_mqtt_tx_buffer[ViTri], "%u,", SystemContext()->GLStatus.Node[index].Property.Name.alarmState);

//    //Batt voltage in mV  // hardcode = Batt in percent
//    ViTri += sprintf((char*)&m_mqtt_tx_buffer[ViTri], "%u,", SystemContext()->GLStatus.Node[index].batteryValue);

    //Batt in percent  // hardcode
    ViTri += sprintf((char*)&m_mqtt_tx_buffer[ViTri], "%u,", SystemContext()->GLStatus.Node[index].batteryValue);
        
    //Thoi gian ban tin sensor
    DateTime_t dateTime;
    SystemContext()->Rtc->GetTimeFromCounter(SystemContext()->GLStatus.Node[index].timeStamp, &dateTime, 1);
    ViTri += sprintf((char*)&m_mqtt_tx_buffer[ViTri],"%04u-%02u-%02u %02u:%02u:%02u",
            dateTime.Year + 2000, dateTime.Month, dateTime.Day, dateTime.Hour, dateTime.Minute, dateTime.Second);
    
    DebugPrint("Send Node state: %s\r\n", m_mqtt_tx_buffer);

    //Gui thanh cong thi xoa node trong buffer
    if(MQTT_SendBufferToServer(m_mqtt_tx_buffer, msgType)) 
    {
        memset(SystemContext()->GLStatus.Node[index].MAC, 0, 6);
        SystemContext()->GLStatus.Node[index].Property.Name.isNewMsg = 0;
        SystemContext()->GLStatus.Node[index].Property.Name.isPairMsg = 0;
        SystemContext()->GLStatus.Node[index].Property.Name.alarmState = 0;

        if(SystemContext()->GLStatus.NodeCount) 
            SystemContext()->GLStatus.NodeCount--;
    }
                    
    return ViTri;		
#else
    return 1;
#endif
}

/*****************************************************************************/
/**	Ham gui ban tin theo su kien, tick every 1000ms
*/
static void EventMessageTick(void)
{    	
#if 0
    static uint32_t LastTimeSendEvent = 0;
    static uint8_t sendEventTick = 0;

    if (LastTimeSendEvent == 0 || LastTimeSendEvent > osKernelSysTick())
       LastTimeSendEvent = osKernelSysTick();
    
    //Neu khong con canh bao nua thi khong can gui lai ban tin T25
    if(SystemContext()->GLStatus.SystemAlarmState.Value == 0) 
    {
        SystemContext()->GLStatus.FireAlarmConfirmFromServerTimeout = 0;
    }
    
    //Gui lai ban tin T25 neu khong gui duoc
    if(SystemContext()->GLStatus.FireAlarmConfirmFromServerTimeout)
    {
        SystemContext()->GLStatus.FireAlarmConfirmFromServerTimeout--;

        //Gui lai T25 sau moi 10s
        if(SystemContext()->GLStatus.FireAlarmConfirmFromServerTimeout == 5)
        {
            FireAlarmMessage();
        }
    }
                 
    /**
    * Gui ban tin RESET sau login 5s
    * Gui toan bo cau hinh len server sau 10s sau khi login 
    */
    if(osKernelSysTick() == LastTimeSendEvent + 5) {
        MQTT_SendResetMessage();
    }

    /* Gui toan bo cau hinh len server sau 10s sau khi login */
    if(osKernelSysTick() >= LastTimeSendEvent + 10)
    {
        LastTimeSendEvent = osKernelSysTick();
        MQTT_SendAllConfigToServer();
    }
    
#if 1
    /* Gui trang thai cua sensor len server khi co update sau moi 3s */

    static uint8_t TimeoutSendSensorState = 0;
    if(TimeoutSendSensorState++ >= 3)
    {
        TimeoutSendSensorState = 0;
        SendNodeStateMessage();
    }
#endif
#else

#endif
}

/*****************************************************************************/
/** Ham gui ban tin dinh ky hoac khi thay doi trang thai canh bao, tick every 1000ms
*/
static void HeartbeatMessageTick(void)
{
    static uint32_t LastSendHeartbeatTime = 0;
    static uint16_t LastFireState = 0xFFFF;
    uint16_t ThoiGianGuiTin;

    uint32_t Ticks = osKernelSysTick();

    if (LastSendHeartbeatTime == 0 || LastSendHeartbeatTime > Ticks)
       LastSendHeartbeatTime = Ticks;

    // /* Khi thay doi trang thai canh bao thi gui T3 luon de update state */
    // uint8_t NewEvent = 0;
    // if((LastFireState != 0xFFFF && LastFireState != SystemContext()->GLStatus.SystemAlarmState.Value) ||
    //   (LastFireState == 0xFFFF && SystemContext()->GLStatus.SystemAlarmState.Value))
    // {
    //     NewEvent = 1;
    // }
    // LastFireState = SystemContext()->GLStatus.SystemAlarmState.Value;
    
    // /* Gui nhanh khi dang co canh bao */
    // if(SystemContext()->GLStatus.SystemAlarmState.Value) 
    //     ThoiGianGuiTin = SystemContext()->Parameters.FlashStoreParam.info.ConfigCommon.info.Freq1;
    // else
    //     ThoiGianGuiTin = SystemContext()->Parameters.FlashStoreParam.info.ConfigCommon.info.Freq2;

    /* Gui ban tin heartbeat dinh ky hoac khi co su kien chuyen trang thai canh bao */
    // if((Ticks >= LastSendHeartbeatTime + ThoiGianGuiTin) || NewEvent)
    // {
    //     LastSendHeartbeatTime = Ticks;
    //     MQTT_SendHeartBeat();
    // }
}


/*****************************************************************************/
/** Ham gui ban tin dinh ky hoac khi thay doi trang thai canh bao, tick every 1000ms
*/
static void EventDebugMeshTick(void)
{
    // static uint32_t LastSendDebugtime = 0;
    // uint32_t CurrentTick = osKernelSysTick();
    // if (CurrentTick - LastSendDebugtime > 7200 || LastSendDebugtime == 0 || SystemContext()->GLStatus.isOTAUpdating)
    // {
    //     SystemContext()->GLStatus.isOTAUpdating = false;
    //     char tmp_buffer[64];

    //     snprintf(tmp_buffer, sizeof(tmp_buffer), "MAC %02X%02X%02X%02X%02X%02X, Reprovision %s, seq %d, iv_index %d, %s, %s, Updating : %d, Build %s, Bootloader %s",
    //                                               *app_common_get_ble_mac(),
    //                                               *(app_common_get_ble_mac()+1),
    //                                               *(app_common_get_ble_mac()+2),
    //                                               *(app_common_get_ble_mac()+3),
    //                                               *(app_common_get_ble_mac()+4),
    //                                               *(app_common_get_ble_mac()+5),
    //                                               SystemContext()->GLStatus.Reprovision ? "true" : "false",
    //                                               SystemContext()->GLStatus.MeshCore.seq, 
    //                                               SystemContext()->GLStatus.MeshCore.iv_index,
    //                                               FIRMWARE_VERSION,
    //                                               SystemContext()->GLStatus.isOTAUpdating ? 1 : 0,
    //                                               __DATE__,
    //                                               SystemContext()->ota.debug_info);

    //     if (SystemContext()->GLStatus.Reprovision)
    //         SystemContext()->GLStatus.Reprovision = false;

    //     BuildDebugMessage(tmp_buffer);

    //     if (MQTT_PubDebugMessage(m_mqtt_pub_topic, m_mqtt_tx_buffer, strlen(m_mqtt_tx_buffer)) == ERR_OK)
    //         LastSendDebugtime = CurrentTick;
    // }
}

/*****************************************************************************/
/**
 * @brief	:  	MQTT_ClientMessageTick, call evey 10ms
 * @param	:  
 * @retval	:
 * @author	:	
 * @created	:	10/03/2016
 * @version	:
 * @reviewer:	
 */
void MQTT_ClientMessageTick(void)
{
    HeartbeatMessageTick();
    EventMessageTick();
    EventDebugMeshTick();
    
}

int8_t MQTT_PubDebugMessage(char *topicSubName, char *msgContent, uint16_t msgLeng)
{
    if (!mqtt_client_is_connected(&m_mqtt_client))
        return -1;

    /* Publish mqtt */
    err_t err = mqtt_publish(&m_mqtt_client, m_mqtt_pub_topic, msgContent, msgLeng, MQTT_CLIENT_PUB_QOS, MQTT_CLIENT_RETAIN, mqtt_pub_request_cb, NULL);
    if (err != ERR_OK)
    {
        DebugPrint("Publish err: %d\r\n", err);
        return -1;
    }
    
    DebugPrint("Send dbg to topic %s, data %s\r\n", m_mqtt_pub_topic, msgContent);
    return err;
}

char client_id[32];
struct mqtt_connect_client_info_t client_info = 
{
    client_id,
    NULL, NULL,				  //User, pass
    MQTT_KEEP_ALIVE_INTERVAL, //Keep alive in seconds, 0 - disable
    NULL, NULL, 0, 0		  //Will topic, will msg, will QoS, will retain
};
    
static int8_t mqtt_connect_broker(mqtt_client_t *client)
{
    static uint32_t idx = 0;
    if (idx == 0)
        idx = osKernelSysTick();

    snprintf(client_id, sizeof(client_id), "%s_%d", m_mqtt_client_id, idx++ % 4096);


        if (client_info.tls_config == NULL) 
          client_info.tls_config = altcp_tls_create_config_client_2wayauth(root_ca, strlen(root_ca) + 1,
                                                                    private_key, strlen(private_key) + 1,
                                                                    NULL, NULL,
                                                                    client_key, strlen(client_key) + 1);

    if (client_info.tls_config == NULL)
    {
        assert_failed(__FILE__, __LINE__);
    }
    
//    /* Minimal amount of information required is client identifier, so set it here */
//    client_info.client_user = m_mqtt_username;
//    client_info.client_pass = m_mqtt_password;

     DebugPrint("Connecting to %s, port %d\r\n", m_mqtt_broker, m_mqtt_port);
    /* 
    * Initiate client and connect to server, if this fails immediately an error code is returned
    * otherwise mqtt_connection_cb will be called with connection result after attempting 
    * to establish a connection with the server. 
    * For now MQTT version 3.1.1 is always used 
    */
    err_t err = mqtt_client_connect(client, 
                                    &m_mqtt_server_address, 
                                    m_mqtt_port, 
                                    mqtt_client_connection_callback, 
                                    0, 
                                    &client_info);
    
    
    /* For now just print the result code if something goes wrong */
    if (err != ERR_OK)
    {
        DebugPrint("mqtt_connect return %d, mem %d\r\n", err, xPortGetFreeHeapSize());
        if (err == ERR_ISCONN)
        {
            DebugPrint("MQTT already connected\r\n");
        }
    }
    else
    {
        DebugPrint("Host %s, client id %s\r\n", ipaddr_ntoa(&m_mqtt_server_address), m_mqtt_client_id);
        DebugPrint("mqtt_client_connect: OK, mem %d\r\n", xPortGetFreeHeapSize());
    }

    return err;
}

/**
 * DNS found callback when using DNS names as server address.
 */
static void mqtt_dns_found(const char *hostname, const ip_addr_t *ipaddr, void *arg)
{
    DebugPrint("mqtt_dns_found: %s\r\n", hostname);

    LWIP_UNUSED_ARG(hostname);
    LWIP_UNUSED_ARG(arg);

    if (ipaddr != NULL)
    {
        /* Address resolved, send request */
        m_mqtt_server_address.addr = ipaddr->addr;
        DebugPrint("Server address resolved = %s\r\n", ipaddr_ntoa(&m_mqtt_server_address));
        m_DNS_resolved = 1;
    }
    else
    {
        /* DNS resolving failed -> try another server */
        DebugPrint("mqtt_dns_found: Failed to resolve server address resolved, trying next server\r\n");
        m_DNS_resolved = 0;
    }
}


uint32_t MQTT_ClientGetResponseBufferSize()
{
    return sizeof(m_mqtt_tx_buffer);
}

uint8_t * MQTT_ClientGetResponseBuffer()
{
    return m_mqtt_tx_buffer;
}

void MqttClientReconnectToNewServer(void)
{
    RenewServer = true;
}

bool MqttClientIsConnectedToServer(void)
{
    if (m_mqtt_state == APP_MQTT_CONNTECTED
        || m_mqtt_state == APP_MQTT_LOGINED)
        return 1;

    return 0;
}

app_mqtt_state_t app_mqtt_get_state(void)
{
    return m_mqtt_state;
}

/**
  * @brief  Initialize the MQTT client thread (start its thread) 
  * @param  none
  * @retval None
  */
void app_mqtt_client_init(void)
{
    // Initialize mqtt
    /* Create mqtt thread*/
    sys_thread_new("MQTT", mqtt_client_thread, NULL, DEFAULT_THREAD_STACKSIZE, MQTT_CLIENT_THREAD_PRIO);
}

/**
  * @brief  http server thread 
  * @param arg: pointer on argument(not used here) 
  * @retval None
  */
static void mqtt_client_thread(void *arg)
{ 
    DebugPrint("MQTT thread started\r\n");
    while (1)
    {
        static uint8_t mqttTick = 0;
        static uint32_t Ticks = 0, LastSendSubTime = 0;
        static uint32_t mqttLastActiveTime = 0;
        
        for (;;)
        {   
            if (app_ethernet_dhcp_ready())
            {
                mqttTick++;
                switch (m_mqtt_state)
                {
                    case APP_MQTT_DISCONNECTED:
                        /* init client info...*/
                        m_DNS_resolved = 0;
                        m_mqtt_state = APP_MQTT_RESOLVING_HOST_NAME;
                        mqttTick = 4;
                        static bool m_tls_init = false;
                        if (m_tls_init == false)
                        {
                            m_tls_init = true;
                            TLS_Init();
                        }

                        break;

                    case APP_MQTT_RESOLVING_HOST_NAME:
                        if (!m_DNS_resolved)
                        {
                            if (mqttTick >= 5)
                            {
                                mqttTick = 0;
                                err_t err = dns_gethostbyname(m_mqtt_broker, &m_mqtt_server_address, mqtt_dns_found, NULL);
                                if (err == ERR_INPROGRESS)
                                {
                                    /* DNS request sent, wait for sntp_dns_found being called */
                                    DebugPrint("sntp_request: %d - Waiting for server address to be resolved\r\n", err);
                                }
                                else if (err == ERR_OK)
                                {
                                    DebugPrint("dns resolved aready, host %s, mqtt_ipaddr = %s\r\n", m_mqtt_broker, 
                                                                                                    ipaddr_ntoa(&m_mqtt_server_address));
                                    m_DNS_resolved = 1;
                                }
                            }
                        }
                        else
                        {
                            mqttTick = 9;
                            m_mqtt_state = APP_MQTT_CONNECTING;
                        }
                        break;

                    case APP_MQTT_CONNECTING:
                        if (mqttTick >= 10)
                        {
                            if (mqtt_connect_broker(&m_mqtt_client) == ERR_OK)
                                mqttTick = 5; /* Gui login sau 5s */
                            else
                                mqttTick = 0;
                        }
                        break;

                    case APP_MQTT_CONNTECTED:
                        if (mqttTick >= 10)
                        {
                            mqttTick = 0;
                            MQTT_SendLoginMessage();
                        }
                        break;
                
                    case APP_MQTT_LOGINED:
                    {
                        Ticks = osKernelSysTick();

                        if (LastSendSubTime == 0 || LastSendSubTime > Ticks)
                            LastSendSubTime = Ticks;

                        if (mqtt_client_is_connected(&m_mqtt_client))
                        {
                            /* Send subscribe message periodic */
                            if (Ticks >= (LastSendSubTime + 30000))
                            {
                                LastSendSubTime = Ticks;
                                MQTT_SendSubscribeRequest();
                            }

                            /* Event, Heartbeat */
                            MQTT_ClientMessageTick();

                            // /* Check server changed status */
                            // if (RenewServer)
                            // {
                            //     DebugPrint("Disconnecting MQTT\r\n");
                            //     mqtt_disconnect(&m_mqtt_client);
                            //     m_mqtt_state = APP_MQTT_DISCONNECTED;
                            //     RenewServer = false;                   
                            // }
                        }
                        else
                            m_mqtt_state = APP_MQTT_DISCONNECTED;     
                    }
                        break;
                    default:
                            break;
                }
            }
            else 
            {
                // DebugPrint("DHCP not ready\r\n");
            }
            osDelay(1000);
        }
    }
    
//   struct netconn *conn, *newconn;
//   err_t err, accept_err;
  
//   /* Create a new TCP connection handle */
//   conn = netconn_new(NETCONN_TCP);
  
//   if (conn!= NULL)
//   {
//     /* Bind to port 80 (HTTP) with default IP address */
//     err = netconn_bind(conn, NULL, 80);
    
//     if (err == ERR_OK)
//     {
//       /* Put the connection into LISTEN state */
//       netconn_listen(conn);
  
//       while(1) 
//       {
//         /* accept any icoming connection */
//         accept_err = netconn_accept(conn, &newconn);
//         if(accept_err == ERR_OK)
//         {
//           /* serve connection */
//           http_server_serve(newconn);

//           /* delete connection */
//           netconn_delete(newconn);
//         }
//       }
//     }
//   }
}
