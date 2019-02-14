#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "driver/i2c.h"
#include <Arduino.h>

#define LED_GPIO_PIN                     0

#define DATA_LENGTH 512                  /*!< Data buffer length of test buffer */
#define RW_TEST_LENGTH 128               /*!< Data length for r/w test, [0,DATA_LENGTH] */
#define DELAY_TIME_BETWEEN_ITEMS_MS 1000 /*!< delay time between different test items */

#define I2C_SLAVE_SCL_IO GPIO_NUM_22           /*!< gpio number for i2c slave clock */
#define I2C_SLAVE_SDA_IO GPIO_NUM_21           /*!< gpio number for i2c slave data */
#define I2C_SLAVE_NUM I2C_NUM_0            /*!< I2C port number for slave dev */
#define I2C_SLAVE_TX_BUF_LEN (2 * DATA_LENGTH) /*!< I2C slave tx buffer size */
#define I2C_SLAVE_RX_BUF_LEN (2 * DATA_LENGTH) /*!< I2C slave rx buffer size */

#define I2C_MASTER_SCL_IO GPIO_NUM_19          /*!< gpio number for I2C master clock */
#define I2C_MASTER_SDA_IO GPIO_NUM_18          /*!< gpio number for I2C master data  */
#define I2C_MASTER_NUM I2C_NUM_1           /*!< I2C port number for master dev */
#define I2C_MASTER_FREQ_HZ 400000              /*!< I2C master clock frequency */
#define I2C_MASTER_TX_BUF_DISABLE 0            /*!< I2C master doesn't need buffer */
#define I2C_MASTER_RX_BUF_DISABLE 0            /*!< I2C master doesn't need buffer */

#define ESP_SLAVE_ADDR 0x28        /*!< ESP32 slave address, you can set any 7bit value */
#define WRITE_BIT I2C_MASTER_WRITE /*!< I2C master write */
#define READ_BIT I2C_MASTER_READ   /*!< I2C master read */
#define ACK_CHECK_EN 0x1           /*!< I2C master will check ack from slave*/
#define ACK_CHECK_DIS 0x0          /*!< I2C master will not check ack from slave */
#define ACK_VAL I2C_MASTER_ACK     /*!< I2C ack value */
#define NACK_VAL I2C_MASTER_NACK   /*!< I2C nack value */

#define WIFI_CHANNEL_SWITCH_INTERVAL  (200)
#define WIFI_CHANNEL_MAX               (14)
#define SKIP_EMPTY false

#define TYPE_MANAGEMENT 0x00
#define TYPE_CONTROL 0x01
#define TYPE_DATA 0x02
#define SUBTYPE_PROBE_REQUEST 0x04
#define SUBTYPE_PROBE_RESPONSE 0x05
#define SUBTYPE_BEACON 0x08

uint8_t channel = 1;

constexpr int mac_lru = 10;
static uint8_t macbuf[6 * mac_lru];
static int maccounter = 0;

typedef struct
{
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t src[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

typedef struct {
  char type;
  int8_t channel;
  int8_t rssi;
  uint8_t mac[6];
  uint8_t ssidlen;
  char ssid[24];
} report;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
// static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

static const char *table = "0123456789ABCDEFGHIJKLMNOPQRST";

int serialize(uint8_t *out, int counter, const uint8_t *p_data, int len) {
  for (int i = 0; i < len; i++) {
    int index0 = (p_data[i] >> 4) & 0x0F;
    int index1 = p_data[i] & 0x0F;
    out[counter++] = table[index0];
    out[counter++] = table[index1];
  }
  return counter;
}

esp_err_t event_handler(void *ctx, system_event_t *event)
{
  if (event->event_id == SYSTEM_EVENT_AP_PROBEREQRECVED) {
    char buf[255];
    system_event_ap_probe_req_rx_t probe_req = event->event_info.ap_probereqrecved;
    size_t written = sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x, %d\r\n",
            probe_req.mac[0],
            probe_req.mac[1],
            probe_req.mac[2],
            probe_req.mac[3],
            probe_req.mac[4],
            probe_req.mac[5],
            probe_req.rssi);
    if (written > 0)
      Serial.write(buf);
  }
  return ESP_OK;
}

void wifi_sniffer_init(void)
{
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  static wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  static wifi_promiscuous_filter_t filter = { WIFI_PROMIS_FILTER_MASK_MGMT };
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  // ESP_ERROR_CHECK( esp_wifi_set_country(wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  // ESP_ERROR_CHECK( esp_wifi_set_event_mask(SYSTEM_EVENT_AP_PROBEREQRECVED));
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_promiscuous_ctrl_filter(&filter);
  Serial.println("Set up wifi");
  // SYSTEM_EVENT_AP_PROBEREQRECVED;
}

void wifi_sniffer_set_channel(uint8_t channel)
{
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void print_report(const report & packet) {
  char buf[50];
  const uint8_t *src = packet.mac;
  size_t bufsize = snprintf(buf, sizeof(buf), "%c,%02d,%02d,"
                             "%02x%02x%02x%02x%02x%02x,%s",
           packet.type,
           packet.channel,
           packet.rssi,
           /* src */
           src[0], src[1], src[2], src[3], src[4], src[5],
           packet.ssid);

  Serial.println(buf);
  i2c_slave_write_buffer(I2C_SLAVE_NUM, (uint8_t *)buf, sizeof(buf), 1000 / portTICK_PERIOD_MS);
}

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT)
    return;

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const uint8_t *packetData = ppkt->payload;
  unsigned int frameControl = ((unsigned int)packetData[1] << 8) + packetData[0];
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;

  const uint8_t *ssid_start, *src;
  char packetType = '?';
  switch (frameSubType)
  {
  case (SUBTYPE_PROBE_REQUEST):
    ssid_start = packetData + 24;
    src = packetData + 10;
    // dst = packetData + 16;
    packetType = 'P';
    break;

  case (SUBTYPE_PROBE_RESPONSE):
    ssid_start = packetData + 36;
    src = packetData + 16;
    // dst = packetData + 10;
    packetType = 'R';
    break;

  case (SUBTYPE_BEACON):
    ssid_start = packetData + 36;
    src = packetData + 16;
    // dst = packetData + 10;
    packetType = 'B';
    break;

  default:
    ssid_start = packetData + 36;
    // dst = packetData + 10;
    src = packetData + 16;
    packetType = '?';
  }
  uint8_t ssid_type = ssid_start[0];
  uint8_t ssid_len = ssid_start[1];
  const uint8_t *ssid = ssid_start + 2;

  //still print malformatted
  if (ssid_type != 0)
    ssid_len = 0;

  for (int i = 0; i < mac_lru; i++)
    if (memcmp(macbuf + i * 6, src, 6) == 0)
      return;

  memcpy(macbuf + maccounter * 6, src, 6);
  maccounter = (maccounter >= mac_lru) ? 0 : maccounter + 1;

  report current;
  current.type = packetType;
  current.channel = ppkt->rx_ctrl.channel;
  current.rssi = ppkt->rx_ctrl.rssi;
  memcpy(&current.mac, src, 6);
  current.ssidlen = min(sizeof(current.ssid) - 1, ssid_len);
  memcpy(&current.ssid, ssid, current.ssidlen);
  current.ssid[current.ssidlen++] = 0;

  print_report(current);
}

// static esp_err_t i2c_master_read_slave(i2c_port_t i2c_num, uint8_t *data_rd, size_t size)
// {
//   if (size == 0)
//   {
//     return ESP_OK;
//   }
//   i2c_cmd_handle_t cmd = i2c_cmd_link_create();
//   i2c_master_start(cmd);
//   i2c_master_write_byte(cmd, (ESP_SLAVE_ADDR << 1) | READ_BIT, ACK_CHECK_EN);
//   if (size > 1)
//   {
//     i2c_master_read(cmd, data_rd, size - 1, ACK_VAL);
//   }
//   i2c_master_read_byte(cmd, data_rd + size - 1, NACK_VAL);
//   i2c_master_stop(cmd);
//   esp_err_t ret = i2c_master_cmd_begin(i2c_num, cmd, 1000 / portTICK_RATE_MS);
//   i2c_cmd_link_delete(cmd);
//   return ret;
// }
//
// static esp_err_t i2c_master_init()
// {
//   auto i2c_master_port = I2C_NUM_1;
//   i2c_config_t conf;
//   conf.mode = I2C_MODE_MASTER;
//   conf.sda_io_num = I2C_MASTER_SDA_IO;
//   conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
//   conf.scl_io_num = I2C_MASTER_SCL_IO;
//   conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
//   conf.master.clk_speed = I2C_MASTER_FREQ_HZ;
//   i2c_param_config(i2c_master_port, &conf);
//   return i2c_driver_install(i2c_master_port, conf.mode,
//                             I2C_MASTER_RX_BUF_DISABLE,
//                             I2C_MASTER_TX_BUF_DISABLE, 0);
// }

static esp_err_t i2c_slave_init() {
  i2c_port_t i2c_slave_port = I2C_SLAVE_NUM;
  i2c_config_t conf_slave;
  conf_slave.sda_io_num = I2C_SLAVE_SDA_IO;
  conf_slave.sda_pullup_en = GPIO_PULLUP_ENABLE;
  conf_slave.scl_io_num = I2C_SLAVE_SCL_IO;
  conf_slave.scl_pullup_en = GPIO_PULLUP_ENABLE;
  conf_slave.mode = I2C_MODE_SLAVE;
  conf_slave.slave.addr_10bit_en = 0;
  conf_slave.slave.slave_addr = ESP_SLAVE_ADDR;
  i2c_param_config(i2c_slave_port, &conf_slave);

  return i2c_driver_install(i2c_slave_port, conf_slave.mode,
                     I2C_SLAVE_RX_BUF_LEN,
                     I2C_SLAVE_TX_BUF_LEN, 0);
}

// the setup function runs once when you press reset or power the board
void setup() {
  // initialize digital pin 5 as an output.
  Serial.begin(115200);
  delay(10);
  Serial.println("Booted, hi!");
  wifi_sniffer_init();
  i2c_slave_init();

  pinMode(LED_GPIO_PIN, OUTPUT);
  pinMode(4, OUTPUT);
  pinMode(2, OUTPUT);
  digitalWrite(4, LOW);
  digitalWrite(2, LOW);

}

void loop() {
  if (digitalRead(LED_GPIO_PIN) == LOW)
    digitalWrite(LED_GPIO_PIN, HIGH);
  else
    digitalWrite(LED_GPIO_PIN, LOW);

  vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
  wifi_sniffer_set_channel(channel);
  channel = (channel > WIFI_CHANNEL_MAX) ? 1 : channel + 1;
}
