#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include <Arduino.h>

#define LED_GPIO_PIN                     0
#define WIFI_CHANNEL_SWITCH_INTERVAL  (200)
#define WIFI_CHANNEL_MAX               (13)
#define SKIP_EMPTY false

#define DATA_LENGTH 112

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

typedef struct {
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


static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
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

// void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
// {
//   if (type != WIFI_PKT_MGMT)
//     return;

//   char buf[255];
//   const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
//   const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
//   const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

//   sprintf(buf, "PACKET TYPE=%s, CHAN=%02d, RSSI=%02d, len = %3d, "
//                " src=%02x:%02x:%02x:%02x:%02x:%02x,"
//                " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
//                " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\r\n",
//           wifi_sniffer_packet_type2str(type),
//           ppkt->rx_ctrl.channel,
//           ppkt->rx_ctrl.rssi,
//           ppkt->rx_ctrl.sig_len,
//               /* src */
//               hdr->src[0],
//           hdr->src[1], hdr->src[2],
//           hdr->src[3], hdr->src[4], hdr->src[5],
//           /* ADDR2 */
//           hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
//           hdr->addr2[3], hdr->addr2[4], hdr->addr2[5],
//           /* ADDR3 */
//           hdr->addr3[0], hdr->addr3[1], hdr->addr3[2],
//           hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);
//   Serial.print(buf);
// }


void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT)
    return;

  char buf[40];
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const uint8_t *packetData = ppkt->payload;
  unsigned int frameControl = ((unsigned int)packetData[1] << 8) + packetData[0];
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;

  const uint8_t *ssid_start, *src, *dst;
  char packetType = '?';
  switch (frameSubType)
  {
  case (SUBTYPE_PROBE_REQUEST):
    ssid_start = packetData + 24;
    src = packetData + 10;
    dst = packetData + 16;
    packetType = 'P';
    break;

  case (SUBTYPE_PROBE_RESPONSE):
    ssid_start = packetData + 36;
    src = packetData + 16;
    dst = packetData + 10;
    packetType = 'R';
    break;

  case (SUBTYPE_BEACON):
    ssid_start = packetData + 36;
    src = packetData + 16;
    dst = packetData + 10;
    packetType = 'B';
    break;

  default:
    ssid_start = packetData + 36;
    dst = packetData + 10;
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

  for (int i = 0; i < sizeof(buf); i++) buf[i] = 0;

  size_t buflen = sprintf(buf, "%c,%02d,%02d,"
                               "%02x%02x%02x%02x%02x%02x,",
                          packetType,
                          ppkt->rx_ctrl.channel,
                          ppkt->rx_ctrl.rssi,
                          /* src */
                          src[0], src[1], src[2], src[3], src[4], src[5]);
  memccpy(buf + buflen, ssid, ssid_len, 40 - buflen);
  buflen += ssid_len;
  buf[buflen++] = '\r';
  buf[buflen++] = '\n';
  Serial.write((uint8_t*) buf, buflen);
}

// the setup function runs once when you press reset or power the board
void setup() {
  // initialize digital pin 5 as an output.
  Serial.begin(115200);
  delay(10);
  Serial.println("Booted, hi!");
  wifi_sniffer_init();
  pinMode(LED_GPIO_PIN, OUTPUT);
  pinMode(4, OUTPUT);
  pinMode(2, OUTPUT);
  digitalWrite(4, LOW);
  digitalWrite(2, LOW);
}

// the loop function runs over and over again forever
void loop() {
  if (digitalRead(LED_GPIO_PIN) == LOW)
    digitalWrite(LED_GPIO_PIN, HIGH);
  else
    digitalWrite(LED_GPIO_PIN, LOW);
  vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
  wifi_sniffer_set_channel(channel);
  channel = (channel > WIFI_CHANNEL_MAX) ? 1 : channel + 1;
}
