#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <WebSocketsClient.h>
#include <ImprovWiFiLibrary.h>
#include <esp_mac.h>

namespace {
constexpr uint32_t RETRY_MIN = 2000, RETRY_MAX = 60000;
constexpr uint32_t RETRY_JITTER = 5000, SERVER_TIMEOUT = 180000;

// Expose handshake state so failed attempts and active handshakes are distinct.
class DeviceSocket : public WebSocketsClient {
 public:
  bool idle() const { return _client.status == WSC_NOT_CONNECTED; }
};
DeviceSocket socket;
WiFiUDP udp;
WebServer web(80);
ImprovWiFi improv(&Serial);
#if ARDUINO_USB_CDC_ON_BOOT
// With native USB enabled, also accept provisioning through a USB-to-UART bridge.
ImprovWiFi improvUart(&Serial0);
#endif
char deviceMac[18], socketPath[40];
bool started = false;
uint32_t retryMs = RETRY_MIN, nextAttempt = 0, lastActivity = 0;

int hexValue(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

void wakePC(const uint8_t* text, size_t length) {
  if (!text || length != 17) return;
  uint8_t mac[6], packet[102];
  for (size_t i = 0; i < 6; ++i) {
    int high = hexValue(text[i * 3]), low = hexValue(text[i * 3 + 1]);
    if (high < 0 || low < 0 || (i < 5 && text[i * 3 + 2] != ':')) return;
    mac[i] = (high << 4) | low;
  }
  memset(packet, 0xff, 6);
  for (size_t i = 0; i < 16; ++i) memcpy(packet + 6 + i * 6, mac, 6);
  if (!udp.beginPacket(WiFi.broadcastIP(), 9)) return;
  udp.write(packet, sizeof(packet));
  udp.endPacket();
}

void scheduleRetry() {
  nextAttempt = millis() + retryMs + esp_random() % RETRY_JITTER;
}

void onSocketEvent(WStype_t type, uint8_t* data, size_t length) {
  if (type == WStype_CONNECTED) retryMs = RETRY_MIN;
  if (type == WStype_CONNECTED || type == WStype_PING || type == WStype_TEXT)
    lastActivity = millis();
  if (type == WStype_TEXT) wakePC(data, length);
}

void serviceConnection() {
  if (WiFi.status() != WL_CONNECTED) {
    if (started) { started = false; socket.disconnect(); }
    return;
  }
  if (!started) {
    socket.beginSSL("ewol.top", 443, socketPath); // TLS without CA verification.
    socket.setReconnectInterval(UINT32_MAX); // Retries are scheduled below.
    socket.disableHeartbeat(); // Server pings; the library replies with pong.
    retryMs = RETRY_MIN;
    scheduleRetry();
    started = true;
  }
  if (socket.isConnected() && millis() - lastActivity >= SERVER_TIMEOUT) {
    socket.disconnect();
    scheduleRetry();
    return;
  }
  if (socket.idle()) {
    if (int32_t(millis() - nextAttempt) < 0) return;
    socket.setReconnectInterval(0);
  }
  socket.loop();
  socket.setReconnectInterval(UINT32_MAX);
  if (socket.idle()) {
    scheduleRetry();
    retryMs = min(retryMs * 2, RETRY_MAX);
  }
}

const char DEVICE_PAGE[] PROGMEM =
    "<!DOCTYPE html><html lang=\"en\"><head>"
    "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">"
    "<title>ESP32 Device</title>"
    "<style>"
    "body{margin:0;height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;"
    "background:#0d1117;color:#c9d1d9;font-family:system-ui,sans-serif}"
    "h2{margin:.5rem 0;font-size:1.2rem;color:#8b949e}"
    "p.mac{font-family:monospace;font-size:2rem;background:#196f3d;color:#fff;padding:.5rem 1rem;"
    "border-radius:12px;border:1px solid #145a2e;margin:.25rem 0}"
    "p.note,a{font-size:.9rem;color:#8b949e;margin-top:.5rem}"
    "a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}"
    "</style></head><body>"
    "<h2>ESP32 MAC Address</h2>"
    "<p class=\"mac\">%s</p>"
    "<p class=\"note\">Copy this MAC for WOL site</p>"
    "<a href=\"https://ewol.top/\" target=\"_blank\">ewol.top</a>"
    "</body></html>";

void showDevicePage() {
  char page[sizeof(DEVICE_PAGE) + sizeof(deviceMac)];
  snprintf_P(page, sizeof(page), DEVICE_PAGE, deviceMac);
  web.send(200, "text/html", page);
}
} // namespace

void setup() {
  Serial.begin(115200);
#if ARDUINO_USB_CDC_ON_BOOT
  Serial0.begin(115200);
#endif
  uint8_t mac[6];
  if (esp_read_mac(mac, ESP_MAC_WIFI_STA) != ESP_OK) {
    delay(1000);
    ESP.restart();
    return;
  }
  snprintf(deviceMac, sizeof(deviceMac), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  snprintf(socketPath, sizeof(socketPath), "/device?deviceId=%02x%02x%02x%02x%02x%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  socket.onEvent(onSocketEvent);
  improv.setDeviceInfo((ImprovTypes::ChipFamily)0, deviceMac, "", "");
#if ARDUINO_USB_CDC_ON_BOOT
  improvUart.setDeviceInfo((ImprovTypes::ChipFamily)0, deviceMac, "", "");
#endif
  WiFi.begin();
  web.on("/", showDevicePage);
  web.begin();
}

void loop() {
  improv.handleSerial();
#if ARDUINO_USB_CDC_ON_BOOT
  improvUart.handleSerial();
#endif
  web.handleClient();
  serviceConnection();
}
