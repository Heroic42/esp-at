/*
 * SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "esp_at.h"

#include "esp_bt_main.h"
#include "esp_gap_bt_api.h"
#include "esp_sdp_api.h"
#include "esp_spp_api.h"

#if (BT_CONTROLLER_INCLUDED == TRUE)
#include "esp_bt.h"
#endif

static bool bd_already_enable = false;
static bool bd_already_init = false;

static const esp_spp_sec_t sec_mask = ESP_SPP_SEC_AUTHENTICATE;
static const esp_spp_role_t role_slave = ESP_SPP_ROLE_SLAVE;
static const esp_spp_mode_t esp_spp_mode = ESP_SPP_MODE_CB;
static const bool esp_spp_enable_l2cap_ertm = true;
#define SPP_SERVER_NAME "GEODE-SPP"

static char* sdp_service_name = "GEODE-IAP2";
static const uint8_t  UUID_UNKNOWN[] = { 0x00, 0x00, 0x00, 0x00, 0xDE, 0xCA, 0xFA, 0xDE, 0xDE, 0xCA, 0xDE, 0xAF, 0xDE, 0xCA, 0xCA, 0xFF};
static const uint8_t UUID_SPP[] = {0x01, 0x11};

#define BT_L2CAP_DYNAMIC_PSM           0x0001
#define BT_UNKNOWN_PROFILE_VERSION     0x0102

static const char local_device_name[] = "EXAMPLE";

static void bt_app_gap_cb(esp_bt_gap_cb_event_t event, esp_bt_gap_cb_param_t* param);
static void bt_app_sdp_cb(esp_sdp_cb_event_t event, esp_sdp_cb_param_t* param);
static void esp_spp_cb(esp_spp_cb_event_t event, esp_spp_cb_param_t *param);

static uint8_t at_exe_cmd_gazelle_init(uint8_t *cmd_name)
{
    uint8_t buffer[64] = {0};
    
    //Register GAP Callback
    esp_bt_gap_register_callback(bt_app_gap_cb);

    //Register SPP Callback
    esp_spp_register_callback(esp_spp_cb);


    //Register SDP Callback
    esp_sdp_register_callback(bt_app_sdp_cb);

    //Initialize SDP
    if ((esp_sdp_init()) != ESP_OK) {
        snprintf((char *)buffer, 64, "BT SDP Init failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "BT SDP Init success!\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
    }

    esp_bluetooth_sdp_raw_record_t record = { 0 };

    record.hdr.type = ESP_SDP_TYPE_RAW;
    record.hdr.uuid.len = sizeof(UUID_UNKNOWN);
    memcpy(record.hdr.uuid.uuid.uuid128, UUID_UNKNOWN, sizeof(UUID_UNKNOWN));
    record.hdr.service_name_length = strlen(sdp_service_name)+1;
    record.hdr.service_name = sdp_service_name;
    record.hdr.rfcomm_channel_number = 1;
    record.hdr.l2cap_psm = BT_L2CAP_DYNAMIC_PSM;
    record.hdr.profile_version = BT_UNKNOWN_PROFILE_VERSION;
    record.hdr.user1_ptr = NULL;
    record.hdr.user1_ptr_len = 0;

    //Set SDP Record
    if (esp_sdp_create_record((esp_bluetooth_sdp_record_t*)&record) != ESP_OK)
    {
        snprintf((char *)buffer, 64, "BT iAP2 SDP Record failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "BT iAP2 SDP Record success!\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
    }

    //Configure EIR Data

    esp_bt_eir_data_t eir_data = { 0 };

    eir_data.fec_required = false;
    eir_data.include_txpower = true;
    eir_data.include_uuid = true;
    eir_data.include_name = true;
    eir_data.flag = 0;
    eir_data.manufacturer_len = 0;
    eir_data.url_len = 0;
    
    //Configure EIR Data
    if (esp_bt_gap_config_eir_data(&eir_data) != ESP_OK)
    {
        snprintf((char *)buffer, 64, "BT EIR Data failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "BT EIR Data success!\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
    }

    //Enable Secure Simple Pairing

    esp_bt_sp_param_t param_type = ESP_BT_SP_IOCAP_MODE;
    esp_bt_io_cap_t iocap = ESP_BT_IO_CAP_IO;


    if (esp_bt_gap_set_security_param(param_type, &iocap, sizeof(uint8_t)) != ESP_OK)
    {
        snprintf((char *)buffer, 64, "BT SSP Parameters failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "BT SSP Parameters success!\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
    }

    

    //Set Scan Mode
    if (esp_bt_gap_set_scan_mode(ESP_BT_CONNECTABLE, ESP_BT_GENERAL_DISCOVERABLE) != ESP_OK)
    {
        snprintf((char *)buffer, 64, "BT Scan set failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "BT Scan set success!\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
    }
    
    snprintf((char *)buffer, 64, "BT Init success!\r\n");
    esp_at_port_write_data(buffer, strlen((char *)buffer));

    return ESP_AT_RESULT_CODE_OK;
}

static const esp_at_cmd_struct at_custom_cmd_gazelle[] = {
    {"+GAZELLE_INIT", NULL, NULL, NULL, at_exe_cmd_gazelle_init},
    /**
     * @brief You can define your own AT commands here.
     */
};

bool esp_at_custom_cmd_register(void)
{

    return esp_at_custom_cmd_array_regist(at_custom_cmd_gazelle, sizeof(at_custom_cmd_gazelle) / sizeof(esp_at_cmd_struct));
}

ESP_AT_CMD_SET_INIT_FN(esp_at_custom_cmd_register, 1);



static void bt_app_gap_cb(esp_bt_gap_cb_event_t event, esp_bt_gap_cb_param_t* param)
{
    uint8_t* bda = NULL;
    uint8_t buffer[64] = { 0 };
    
    switch (event) {
        /* when authentication completed, this event comes */
    case ESP_BT_GAP_AUTH_CMPL_EVT: {
        if (param->auth_cmpl.stat == ESP_BT_STATUS_SUCCESS) {
            //ESP_LOGI(BT_AV_TAG, "authentication success: %s", param->auth_cmpl.device_name);
            //ESP_LOG_BUFFER_HEX(BT_AV_TAG, param->auth_cmpl.bda, ESP_BD_ADDR_LEN);
            snprintf((char*)buffer, 64, "ESP_BT_GAP_AUTH_CMPL_EVT: %s\r\n", param->auth_cmpl.device_name);
            esp_at_port_write_data(buffer, strlen((char*)buffer));
        }
        else {
            //ESP_LOGE(BT_AV_TAG, "authentication failed, status: %d", param->auth_cmpl.stat);
            snprintf((char*)buffer, 64, "ESP_BT_GAP_AUTH_CMPL_EVT - Authentication Failed: %d\r\n", param->auth_cmpl.stat);
            esp_at_port_write_data(buffer, strlen((char*)buffer));
        }
        //ESP_LOGI(BT_AV_TAG, "link key type of current link is: %d", param->auth_cmpl.lk_type);
        break;
    }
    case ESP_BT_GAP_ENC_CHG_EVT: {
        char* str_enc[3] = { "OFF", "E0", "AES" };
        bda = (uint8_t*)param->enc_chg.bda;
        //ESP_LOGI(BT_AV_TAG, "Encryption mode to [%02x:%02x:%02x:%02x:%02x:%02x] changed to %s",
        //    bda[0], bda[1], bda[2], bda[3], bda[4], bda[5], str_enc[param->enc_chg.enc_mode]);
        break;
    }


                               /* when Security Simple Pairing user confirmation requested, this event comes */
    case ESP_BT_GAP_CFM_REQ_EVT:
        //ESP_LOGI(BT_AV_TAG, "ESP_BT_GAP_CFM_REQ_EVT Please compare the numeric value: %06"PRIu32, param->cfm_req.num_val);
        snprintf((char*)buffer, 64, "ESP_BT_GAP_CFM_REQ_EVT Please compare the numeric value: %06u32\r\n", param->cfm_req.num_val);
        esp_at_port_write_data(buffer, strlen((char*)buffer));
        esp_bt_gap_ssp_confirm_reply(param->cfm_req.bda, true);
        break;
        /* when Security Simple Pairing passkey notified, this event comes */
    case ESP_BT_GAP_KEY_NOTIF_EVT:
        snprintf((char*)buffer, 64, "ESP_BT_GAP_KEY_NOTIF_EVT - SSP passkey notified \r\n");
        esp_at_port_write_data(buffer, strlen((char*)buffer));
        //ESP_LOGI(BT_AV_TAG, "ESP_BT_GAP_KEY_NOTIF_EVT passkey: %06"PRIu32, param->key_notif.passkey);
        break;
        /* when Security Simple Pairing passkey requested, this event comes */
    case ESP_BT_GAP_KEY_REQ_EVT:
        snprintf((char*)buffer, 64, "ESP_BT_GAP_KEY_REQ_EVT - SSP passkey required \r\n");
        esp_at_port_write_data(buffer, strlen((char*)buffer));
        //ESP_LOGI(BT_AV_TAG, "ESP_BT_GAP_KEY_REQ_EVT Please enter passkey!");
        break;


        /* when GAP mode changed, this event comes */
    case ESP_BT_GAP_MODE_CHG_EVT:
        //ESP_LOGI(BT_AV_TAG, "ESP_BT_GAP_MODE_CHG_EVT mode: %d, interval: %.2f ms",
        //    param->mode_chg.mode, param->mode_chg.interval * 0.625);
        break;
        /* when ACL connection completed, this event comes */
    case ESP_BT_GAP_ACL_CONN_CMPL_STAT_EVT:
        bda = (uint8_t*)param->acl_conn_cmpl_stat.bda;
        //ESP_LOGI(BT_AV_TAG, "ESP_BT_GAP_ACL_CONN_CMPL_STAT_EVT Connected to [%02x:%02x:%02x:%02x:%02x:%02x], status: 0x%x",
        //    bda[0], bda[1], bda[2], bda[3], bda[4], bda[5], param->acl_conn_cmpl_stat.stat);
        break;
        /* when ACL disconnection completed, this event comes */
    case ESP_BT_GAP_ACL_DISCONN_CMPL_STAT_EVT:
        bda = (uint8_t*)param->acl_disconn_cmpl_stat.bda;
        //ESP_LOGI(BT_AV_TAG, "ESP_BT_GAP_ACL_DISC_CMPL_STAT_EVT Disconnected from [%02x:%02x:%02x:%02x:%02x:%02x], reason: 0x%x",
        //    bda[0], bda[1], bda[2], bda[3], bda[4], bda[5], param->acl_disconn_cmpl_stat.reason);
        break;
        /* others */
    case ESP_BT_GAP_CONFIG_EIR_DATA_EVT:
        if (param->config_eir_data.stat == ESP_BT_STATUS_SUCCESS)
        {
            snprintf((char*)buffer, 64, "ESP_BT_GAP_CONFIG_EIR_DATA_EVT Success \r\n");
            esp_at_port_write_data(buffer, strlen((char*)buffer));
        }
        else
        {
            snprintf((char*)buffer, 64, "ESP_BT_GAP_CONFIG_EIR_DATA_EVT Fail \r\n");
            esp_at_port_write_data(buffer, strlen((char*)buffer));
        }
        break;
    default: {
        //ESP_LOGI(BT_AV_TAG, "event: %d", event);
        break;
    }
    }
}

static void bt_app_sdp_cb(esp_sdp_cb_event_t event, esp_sdp_cb_param_t* param) 
{
    uint8_t buffer[64] = { 0 };

    switch (event) {
    case ESP_SDP_INIT_EVT:
        snprintf((char*)buffer, 64, "ESP_SDP_CREATE_RECORD_COMP_EVT - SDP Initialized:\r\n");
        esp_at_port_write_data(buffer, strlen((char*)buffer));
        break;
    case ESP_SDP_DEINIT_EVT:
        break;
    case ESP_SDP_SEARCH_COMP_EVT:
        break;
    case ESP_SDP_CREATE_RECORD_COMP_EVT:
        snprintf((char*)buffer, 64, "ESP_SDP_CREATE_RECORD_COMP_EVT - SDP Record Created:\r\n");
        esp_at_port_write_data(buffer, strlen((char*)buffer));
        break;
    case ESP_SDP_REMOVE_RECORD_COMP_EVT:
        break;

    default: {
        //ESP_LOGI(BT_AV_TAG, "event: %d", event);
        break;
    }
    }
}

static void esp_spp_cb(esp_spp_cb_event_t event, esp_spp_cb_param_t *param)
{
    char bda_str[18] = {0};
    uint8_t buffer[64] = { 0 };

    switch (event) {
    case ESP_SPP_INIT_EVT:
        if (param->init.status == ESP_SPP_SUCCESS) {
            //ESP_LOGI(SPP_TAG, "ESP_SPP_INIT_EVT");
            snprintf((char *)buffer, 64, "ESP_SPP_INIT_EVT - Initialized\r\n");
            esp_at_port_write_data(buffer, strlen((char *)buffer));
            esp_spp_start_srv(sec_mask, role_slave, 2, SPP_SERVER_NAME);
        } else {
            snprintf((char *)buffer, 64, "ESP_SPP_INIT_EVT - Failed\r\n");
            esp_at_port_write_data(buffer, strlen((char *)buffer));
        }
        break;
    case ESP_SPP_DISCOVERY_COMP_EVT:
        //ESP_LOGI(SPP_TAG, "ESP_SPP_DISCOVERY_COMP_EVT");
        break;
    case ESP_SPP_OPEN_EVT:
        //ESP_LOGI(SPP_TAG, "ESP_SPP_OPEN_EVT");
        break;
    case ESP_SPP_CLOSE_EVT:
        //ESP_LOGI(SPP_TAG, "ESP_SPP_CLOSE_EVT status:%d handle:%"PRIu32" close_by_remote:%d", param->close.status,
        //         param->close.handle, param->close.async);
        break;
    case ESP_SPP_START_EVT:
        if (param->start.status == ESP_SPP_SUCCESS) {
            snprintf((char *)buffer, 64, "ESP_SPP_START_EVT - Success\r\n");
            esp_at_port_write_data(buffer, strlen((char *)buffer));
        } else {
            snprintf((char *)buffer, 64, "ESP_SPP_START_EVT - Failed\r\n");
            esp_at_port_write_data(buffer, strlen((char *)buffer));
        }
        break;
    case ESP_SPP_CL_INIT_EVT:
        //ESP_LOGI(SPP_TAG, "ESP_SPP_CL_INIT_EVT");
        break;
    case ESP_SPP_DATA_IND_EVT:
        //
        break;
    case ESP_SPP_CONG_EVT:
        //ESP_LOGI(SPP_TAG, "ESP_SPP_CONG_EVT");
        break;
    case ESP_SPP_WRITE_EVT:
        //ESP_LOGI(SPP_TAG, "ESP_SPP_WRITE_EVT");
        break;
    case ESP_SPP_SRV_OPEN_EVT:
        //ESP_LOGI(SPP_TAG, "ESP_SPP_SRV_OPEN_EVT status:%d handle:%"PRIu32", rem_bda:[%s]", param->srv_open.status,
        //         param->srv_open.handle, bda2str(param->srv_open.rem_bda, bda_str, sizeof(bda_str)));
        break;
    case ESP_SPP_SRV_STOP_EVT:
        //ESP_LOGI(SPP_TAG, "ESP_SPP_SRV_STOP_EVT");
        break;
    case ESP_SPP_UNINIT_EVT:
        //ESP_LOGI(SPP_TAG, "ESP_SPP_UNINIT_EVT");
        break;
    default:
        break;
    }
}