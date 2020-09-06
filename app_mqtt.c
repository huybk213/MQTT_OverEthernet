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
#include "mbedtls/debug.h"
#include "FreeRTOS.h"
#include "event_groups.h"
#include "aws_certificate.h"

#define MQTT_CLIENT_THREAD_PRIO    osPriorityAboveNormal
#define MQTT_CLIENT_SUB_QOS        1
#define MQTT_CLIENT_PUB_QOS        1
#define MQTT_CLIENT_RETAIN         0

/* MQTT event bits */

#define MQTT_EVENT_CONNTECTED (1 << 0)
#define MQTT_EVENT_PULISH_SUCCESS (1 << 1)

static void mqtt_client_thread(void *arg);
static app_mqtt_state_t m_mqtt_state = APP_MQTT_DISCONNECTED;
static EventGroupHandle_t m_mqtt_event = NULL;


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
static uint8_t m_DNS_resolved = 0;

char m_mqtt_tx_buffer[MQTT_TX_BUFFER_SIZE];

static uint32_t m_sub_req_err_count;
static bool m_mqtt_tls_init = false;

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
    DebugPrint("\r\n%s, at line %d in file %\r\n", str, line, file);
}
#if 0
static int mqtt_tls_verify(void *data, mbedtls_x509_crt *crt, int depth, int *flags) 
{
	char buf[1024]; 

	DebugPrint("Verify requested for (Depth %d):\r\n", depth ); 
	mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt ); 
//	DebugPrint("%s", buf ); 

	if ( ( (*flags) & MBEDTLS_X509_BADCERT_EXPIRED ) != 0 ) 
    {
        DebugPrint("  ! server certificate has expired\r\n" ); 
    }

	if ( ( (*flags) & MBEDTLS_X509_BADCERT_REVOKED ) != 0 ) 
		DebugPrint("  ! server certificate has been revoked\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCERT_CN_MISMATCH ) != 0 ) 
		DebugPrint("  ! CN mismatch\r\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCERT_NOT_TRUSTED ) != 0 ) 
		DebugPrint("  ! self-signed or not signed by a trusted CA\r\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCRL_NOT_TRUSTED ) != 0 ) 
		DebugPrint("  ! CRL not trusted\r\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCRL_EXPIRED ) != 0 ) 
		DebugPrint("  ! CRL expired\n" ); 

	if ( ( (*flags) &  MBEDTLS_X509_BADCERT_OTHER ) != 0 ) 
		DebugPrint("  ! other (unknown) flag\r\n" ); 

//	if ( ( *flags ) == 0 ) 
//		DebugPrint("  This certificate has no flags\r\n" ); 

	return( 0 ); 
}
#endif

//static void mqtt_tls_close(void) 
//{ /* called from mqtt.c */
//    /*! \todo This should be in a separate module */
//    mbedtls_ssl_free(&ssl);
//    mbedtls_ssl_config_free(&conf);
//    mbedtls_ctr_drbg_free(&ctr_drbg );
//    mbedtls_entropy_free(&entropy);
//}

static int mqtt_tls_init(void) 
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
    ret = mbedtls_x509_crt_parse(&x509_root_ca, 
                                aws_certificate_get_root_ca(), 
                                strlen((char*)aws_certificate_get_root_ca()) + 1);
    if (ret != 0)
    {
        DebugPrint("Parse root ca error -0x%08X\r\n", ret);
        assert_failed((uint8_t*)__FILE__, __LINE__);
        return -1;
    }
    
    ret = mbedtls_x509_crt_parse(&x509_client_key, 
                                aws_certificate_get_client_cert(), 
                                strlen((char*)aws_certificate_get_client_cert()) + 1);
    if (ret != 0)
    {
        DebugPrint("Parse client key error -0x%08X\r\n", ret);
        assert_failed((uint8_t*)__FILE__, __LINE__);
        return -1;
    }

    ret = mbedtls_pk_parse_key(&pk_private_key, 
                                aws_certificate_get_client_key(), 
                                strlen((char*)aws_certificate_get_client_key()) + 1, 
                                NULL, 
                                0);
    if (ret != 0)
    {
        DebugPrint("Parse private key error -0x%08X\r\n", ret);
        assert_failed((uint8_t*)__FILE__, __LINE__);
        return -1;
    }
    
    DebugPrint("Parse certificate success\r\n");
    mbedtls_ssl_conf_ca_chain(&conf, &x509_root_ca, NULL);
    mbedtls_debug_set_threshold(1);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
//    mbedtls_ssl_conf_verify(&conf, (int (*)(void *, mbedtls_x509_crt *, int, uint32_t *))mqtt_tls_verify, NULL );
    
#else
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
#endif
    /* The library needs to know which random engine to use and which debug function to use as callback. */
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

//    mbedtls_ssl_setup(&ssl, &conf);

    if ((ret = mbedtls_ssl_set_hostname(&ssl, aws_get_arn())) != 0)
    {
        DebugPrint(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        assert_failed((uint8_t*)__FILE__, __LINE__);
        return -1;
    }

    DebugPrint("Set host name success\r\n");
    /* the SSL context needs to know the input and output functions it needs to use for sending out network traffic. */
//    mbedtls_ssl_set_bio(&ssl, &mqtt_static_client, altcp_mbedtls_bio_send, altcp_mbedtls_bio_recv, NULL);

    return 0; /* no error */
}

void app_mqtt_disconnect(void)
{
    /* Close mqtt connection */
    DebugPrint("Close mqtt connection\r\n");
    mqtt_disconnect(&m_mqtt_client);
//    mqtt_tls_close();
//    m_mqtt_tls_init = false;
    m_sub_req_err_count = 0;
    m_mqtt_state = APP_MQTT_DISCONNECTED;
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
            app_mqtt_disconnect();
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
}

static void mqtt_incoming_data_cb(void *arg, const u8_t *data, u16_t len, u8_t flags)
{
    DebugPrint("Incoming publish payload with length %d, flags %u\r\n", len, (unsigned int)flags);

    if (flags & MQTT_DATA_FLAG_LAST)
    {
        /* Last fragment of payload received (or whole part if payload fits receive buffer
          See MQTT_VAR_HEADER_BUFFER_LEN)  */

        DebugPrint("Payload data: %s\r\n", (const char *)data);

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
        snprintf(m_mqtt_sub_topic, sizeof(m_mqtt_sub_topic), "%s%s", TOPIC_SUB_HEADER, "test");

        /* Setup callback for incoming publish requests */
        mqtt_set_inpub_callback(client, mqtt_incoming_publish_cb, mqtt_incoming_data_cb, arg);

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
        xEventGroupSetBits(m_mqtt_event, MQTT_EVENT_PULISH_SUCCESS);
    }
}


static void mqtt_send_login_msq(void)
{
    memset(m_mqtt_tx_buffer, 0, sizeof(m_mqtt_tx_buffer));
    memset(m_mqtt_pub_topic, 0, sizeof(m_mqtt_pub_topic));
    
    static uint32_t msg_cnt = 0;
    sprintf(m_mqtt_tx_buffer, "Test %d\r\n", msg_cnt++);
    sprintf(m_mqtt_pub_topic, "%s", "huydeptrai");
    uint16_t size = strlen(m_mqtt_tx_buffer);

    DebugPrint("Topic %s, data %s\r\n", m_mqtt_pub_topic, m_mqtt_tx_buffer);
     
    err_t err = mqtt_publish(&m_mqtt_client, m_mqtt_pub_topic, m_mqtt_tx_buffer, size, MQTT_CLIENT_PUB_QOS, MQTT_CLIENT_RETAIN, mqtt_pub_request_cb, NULL);
    if (err == ERR_OK)
    {
        DebugPrint("Wait for publish status OK\r\n");
        if (xEventGroupWaitBits(m_mqtt_event, MQTT_EVENT_PULISH_SUCCESS, pdTRUE, pdFALSE, 3000))
        {
            DebugPrint("Publish msg success\r\n");
        }
        else
        {
            DebugPrint("Publish msg failed\r\n");
        }
    }
    else
    {
        DebugPrint("Publish err: %d\r\n", err);
    }
}

static void mqtt_send_subscription_req(void)
{
    err_t err = mqtt_subscribe(&m_mqtt_client, m_mqtt_sub_topic, MQTT_CLIENT_SUB_QOS, mqtt_sub_request_cb, NULL);

    DebugPrint("%s: topic %s\r\n", __FUNCTION__, m_mqtt_sub_topic);
}


static char m_client_id[32];
struct mqtt_connect_client_info_t client_info = 
{
    m_client_id,
    NULL, NULL,				  //User, pass
    MQTT_KEEP_ALIVE_INTERVAL, //Keep alive in seconds, 0 - disable
    NULL, NULL, 0, 0		  //Will topic, will msg, will QoS, will retain
};
    
static int8_t mqtt_connect_broker(mqtt_client_t *client)
{
    static uint32_t idx = 0;
    if (idx == 0)
        idx = osKernelSysTick();

    snprintf(m_client_id, sizeof(m_client_id), "%s_%d", "test", idx++ % 4096);


    if (client_info.tls_config == NULL) 
        client_info.tls_config = altcp_tls_create_config_client_2wayauth((const u8_t*)aws_certificate_get_root_ca(), strlen((char*)aws_certificate_get_root_ca()) + 1,
                                                                (const u8_t*)aws_certificate_get_client_key(), strlen((char*)aws_certificate_get_client_key()) + 1,
                                                                NULL, NULL,
                                                                (const u8_t*)aws_certificate_get_client_cert(), strlen((char*)aws_certificate_get_client_cert()) + 1);

    if (client_info.tls_config == NULL)
    {
        assert_failed((uint8_t*)__FILE__, __LINE__);
    }
    
//    /* Minimal amount of information required is client identifier, so set it here */
//    client_info.client_user = m_mqtt_username;
//    client_info.client_pass = m_mqtt_password;

    DebugPrint("Connecting to broker %s, port %d\r\n", aws_get_arn(), aws_get_mqtt_port());
    /* 
    * Initiate client and connect to server, if this fails immediately an error code is returned
    * otherwise mqtt_connection_cb will be called with connection result after attempting 
    * to establish a connection with the server. 
    * For now MQTT version 3.1.1 is always used 
    */
    err_t err = mqtt_client_connect(client, 
                                    &m_mqtt_server_address, 
                                    aws_get_mqtt_port(), 
                                    mqtt_client_connection_callback, 
                                    0, 
                                    &client_info);
    
    
    /* For now just print the result code if something goes wrong */
    if (err != ERR_OK)
    {
        DebugPrint("mqtt_connect return %d, mem %d\r\n", err, xPortGetFreeHeapSize());
//        if (err == ERR_ISCONN)
//        {
//            DebugPrint("MQTT already connected\r\n");
//        }
    }
    else
    {
        DebugPrint("Host %s\r\n", ipaddr_ntoa(&m_mqtt_server_address));
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

    bool m_last_dhcp_state = false;

    m_mqtt_event = xEventGroupCreate();
    if (m_mqtt_event == NULL)
    {
        assert_failed((uint8_t*)__FILE__, __LINE__);
    }

    DebugPrint("Waiting for network ready\r\n");
    while (app_ethernet_dhcp_ready() == false)
    {
        osDelay(100);
    }
    m_last_dhcp_state = true;

    while (1)
    {
        static uint8_t mqtt_tick = 0;
        static uint32_t ticks = 0, last_time_send_subscribe_request = 0;

        bool ethernet_ready;
        for (;;)
        {   
            ethernet_ready = app_ethernet_dhcp_ready();
            if (ethernet_ready)
            {
                if (m_last_dhcp_state != ethernet_ready)
                {
                    m_last_dhcp_state = ethernet_ready;
                }
                mqtt_tick++;
                switch (m_mqtt_state)
                {
                    case APP_MQTT_DISCONNECTED:
                        /* init client info...*/
                        m_DNS_resolved = 0;
                        m_mqtt_state = APP_MQTT_RESOLVING_HOST_NAME;
                        mqtt_tick = 4;

                        if (m_mqtt_tls_init == false)
                        {
                            m_mqtt_tls_init = true;
                            mqtt_tls_init();
                        }
                        
                        break;

                    case APP_MQTT_RESOLVING_HOST_NAME:
                        if (!m_DNS_resolved)
                        {
                            if (mqtt_tick >= 5)
                            {
                                mqtt_tick = 0;
                                err_t err = dns_gethostbyname(aws_get_arn(), &m_mqtt_server_address, mqtt_dns_found, NULL);
                                if (err == ERR_INPROGRESS)
                                {
                                    /* DNS request sent, wait for sntp_dns_found being called */
                                    DebugPrint("sntp_request: %d - Waiting for server address to be resolved\r\n", err);
                                }
                                else if (err == ERR_OK)
                                {
                                    DebugPrint("dns resolved aready, host %s, mqtt_ipaddr = %s\r\n", aws_get_arn(), 
                                                                                                    ipaddr_ntoa(&m_mqtt_server_address));
                                    m_DNS_resolved = 1;
                                }
                            }
                        }
                        else
                        {
                            mqtt_tick = 9;
                            m_mqtt_state = APP_MQTT_CONNECTING;
                        }
                        break;

                    case APP_MQTT_CONNECTING:
                        if (mqtt_tick >= 10)
                        {
                            if (mqtt_connect_broker(&m_mqtt_client) == ERR_OK)
                                mqtt_tick = 5; /* Gui login sau 5s */
                            else
                                mqtt_tick = 0;
                        }
                        break;

                    case APP_MQTT_CONNTECTED:
                        if (mqtt_tick > 10)
                        {
                            mqtt_tick = 0;
                            mqtt_send_login_msq();
                        }
                    break;

                    case APP_MQTT_LOGINED:
                    {
                        ticks = osKernelSysTick();

                        if (last_time_send_subscribe_request == 0 || last_time_send_subscribe_request > ticks)
                            last_time_send_subscribe_request = ticks;

                        if (mqtt_client_is_connected(&m_mqtt_client))
                        {
                            /* Send subscribe message periodic */
                            if (ticks >= (last_time_send_subscribe_request + 30000))
                            {
                                last_time_send_subscribe_request = ticks;
                                mqtt_send_subscription_req();
                            }
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
                if (m_last_dhcp_state == true)
                {
                    app_mqtt_disconnect();
                    m_last_dhcp_state = ethernet_ready;
                }
            }
            osDelay(1000);
        }
    }
}
