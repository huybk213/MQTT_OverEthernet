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

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
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

#define TOPIC_SUB_HEADER    "test"


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
const char * m_mqtt_username = "bytech.sful";
const char * m_mqtt_password = "bytech.sful@2020";
const char * m_mqtt_broker = "dev-sful.bytech.vn";
const uint16_t m_mqtt_port = 2005;

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
                  ProcessSetParameters((char*)data, PARAMETER_SET_FROM_SERVER);
            }
            else if (strstr((char *)data, "GET,"))
            {
                  /* Get command without encrypted */
                  ProcessGetParameters((char*)data, PARAMETER_SET_FROM_SERVER);
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
    DebugPrint("MQTT_SendLoginMessage %u - %s\r\n", size, "T1");
    DebugPrint("Topic %s\r\n", m_mqtt_pub_topic);
#if 0       
    err_t err = mqtt_publish(&m_mqtt_client, m_mqtt_pub_topic, m_mqtt_tx_buffer, size, MQTT_CLIENT_PUB_QOS, MQTT_CLIENT_RETAIN, mqtt_pub_request_cb, NULL);
    if (err == ERR_OK)
    {
        SystemContext()->GLStatus.LoginReason = 0;
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

static int8_t mqtt_connect_broker(mqtt_client_t *client)
{
    static uint32_t idx = 0;
    if (idx == 0)
        idx = osKernelSysTick();
    char client_id[32];
    snprintf(client_id, sizeof(client_id), "%s_%d", m_mqtt_client_id, idx++ % 4096);
    struct mqtt_connect_client_info_t client_info = 
    {
        client_id,
        NULL, NULL,				  //User, pass
        MQTT_KEEP_ALIVE_INTERVAL, //Keep alive in seconds, 0 - disable
        NULL, NULL, 0, 0		  //Will topic, will msg, will QoS, will retain
    };

    /* Minimal amount of information required is client identifier, so set it here */
    client_info.client_user = m_mqtt_username;
    client_info.client_pass = m_mqtt_password;

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
        DebugPrint("mqtt_connect return %d\r\n", err);
        if (err == ERR_ISCONN)
        {
            DebugPrint("MQTT already connected\r\n", err);
        }
    }
    else
    {
        DebugPrint("Host %s, client id %s\r\n", ipaddr_ntoa(&m_mqtt_server_address), m_mqtt_client_id);
        DebugPrint("mqtt_client_connect: OK\r\n");
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
