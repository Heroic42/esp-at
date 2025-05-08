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

#if (BT_CONTROLLER_INCLUDED == TRUE)
#include "esp_bt.h"
#endif

static bool bd_already_enable = false;
static bool bd_already_init = false;

static char* sdp_service_name = "GEODE-IAP2";
static const uint8_t  UUID_UNKNOWN[] = { 0x00, 0x00, 0x00, 0x00, 0xDE, 0xCA, 0xFA, 0xDE, 0xDE, 0xCA, 0xDE, 0xAF, 0xDE, 0xCA, 0xCA, 0xFF};

#define BT_L2CAP_DYNAMIC_PSM           0x1001
#define BT_UNKNOWN_PROFILE_VERSION     0x0100

static const char local_device_name[] = "EXAMPLE";

static uint8_t at_test_cmd_test(uint8_t *cmd_name)
{
    uint8_t buffer[64] = {0};
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    snprintf((char *)buffer, 64, "test command: <AT%s=?> is executed\r\n", cmd_name);
    esp_at_port_write_data(buffer, strlen((char *)buffer));

    //Initial Bluetooth Controller
    if(esp_bt_controller_init(&bt_cfg) != ESP_OK)
    {
        snprintf((char *)buffer, 64, "Bluetooth Controller Init failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "Bluetooth Controller Init success!\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
    }

    //Enable Bluetooth Controller
    if(esp_bt_controller_enable(ESP_BT_MODE_BTDM) != ESP_OK)
    {
        snprintf((char *)buffer, 64, "Bluetooth Controller Enable failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "Bluetooth Controller Enable success!\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
    }

    //Initialize Bluedroid
    if ((esp_bluedroid_init()) != ESP_OK) {
        snprintf((char *)buffer, 64, "Bluedroid Init failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "Bluedroid Init success!\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
    }

    //Enable Bluedroid
    if ((esp_bluedroid_enable()) != ESP_OK) {
        snprintf((char *)buffer, 64, "Bluedroid Enable failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "Bluedroid Enable success!\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
    }

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
    record.hdr.service_name_length = strlen(sdp_service_name) + 1;
    record.hdr.service_name = sdp_service_name;
    record.hdr.rfcomm_channel_number = 2;
    record.hdr.l2cap_psm = BT_L2CAP_DYNAMIC_PSM;
    record.hdr.profile_version = BT_UNKNOWN_PROFILE_VERSION;

    //Set SDP Record
    if (esp_sdp_create_record((esp_bluetooth_sdp_record_t*)&record) != ESP_OK)
    {
        snprintf((char *)buffer, 64, "BT SDP Record failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "BT SDP Record success!\r\n");
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

    //Set Device Name
    if (esp_bt_gap_set_device_name(local_device_name) != ESP_OK)
    {
        snprintf((char *)buffer, 64, "BT Device Name Set failed\r\n");
        esp_at_port_write_data(buffer, strlen((char *)buffer));
        return ESP_AT_RESULT_CODE_ERROR;
    }
    else
    {
        snprintf((char *)buffer, 64, "BT Device Name Set success!\r\n");
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

static uint8_t at_query_cmd_test(uint8_t *cmd_name)
{
    uint8_t buffer[64] = {0};
    snprintf((char *)buffer, 64, "query command: <AT%s?> is executed\r\n", cmd_name);
    esp_at_port_write_data(buffer, strlen((char *)buffer));

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_setup_cmd_test(uint8_t para_num)
{
    uint8_t index = 0;

    // get first parameter, and parse it into a digit
    int32_t digit = 0;
    if (esp_at_get_para_as_digit(index++, &digit) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    // get second parameter, and parse it into a string
    uint8_t *str = NULL;
    if (esp_at_get_para_as_str(index++, &str) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    // allocate a buffer and construct the data, then send the data to mcu via interface (uart/spi/sdio/socket)
    uint8_t *buffer = (uint8_t *)malloc(512);
    if (!buffer) {
        return ESP_AT_RESULT_CODE_ERROR;
    }
    int len = snprintf((char *)buffer, 512, "setup command: <AT%s=%d,\"%s\"> is executed\r\n",
                       esp_at_get_current_cmd_name(), digit, str);
    esp_at_port_write_data(buffer, len);

    // remember to free the buffer
    free(buffer);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_exe_cmd_test(uint8_t *cmd_name)
{
    uint8_t buffer[64] = {0};
    snprintf((char *)buffer, 64, "execute command: <AT%s> is executed\r\n", cmd_name);
    esp_at_port_write_data(buffer, strlen((char *)buffer));

    return ESP_AT_RESULT_CODE_OK;
}

static const esp_at_cmd_struct at_custom_cmd[] = {
    {"+TEST", at_test_cmd_test, at_query_cmd_test, at_setup_cmd_test, at_exe_cmd_test},
    /**
     * @brief You can define your own AT commands here.
     */
};

bool esp_at_custom_cmd_register(void)
{
    return esp_at_custom_cmd_array_regist(at_custom_cmd, sizeof(at_custom_cmd) / sizeof(esp_at_cmd_struct));
}

ESP_AT_CMD_SET_INIT_FN(esp_at_custom_cmd_register, 1);
