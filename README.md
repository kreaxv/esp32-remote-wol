# esp32-remote-wol

Remote **Wake-on-LAN** firmware for ESP32 boards.

Wake a PC remotely over the internet even if your home network is behind **CGNAT**
or has **no public IP**.

---

## How it works

1. ESP32 connects to Wi-Fi
2. ESP32 keeps an outbound connection to an MQTT broker
3. Device subscribes to its own topic
4. Valid message → local Wake-on-LAN packet

> Wake-on-LAN must already work inside your LAN.

---

## Official web interface

https://ewol.top/

You can:

- Flash firmware directly from browser (ESP Web Tools)
- Configure Wi-Fi
- Wake your PC using ESP32_MAC + PC_MAC

No configuration required.  
This is the default and recommended usage.

---

## Using your own MQTT broker (optional)

Only needed if you want full control instead of the hosted interface.

### Firmware setup

Change:

```text
#define USE_HASHED_ID 0
MQTT_HOST
MQTT_PORT
MQTT_USER
MQTT_PASS
```

### MQTT command format

**Topic**
```text
wol/<ESP32_MAC>
```

**Payload**
```text
AA:BB:CC:DD:EE:FF
```

**Example**
```text
Topic:   wol/1A:2B:3C:4C:5D:6F
Payload: 3C:52:82:11:9A:EF
```

Invalid topic or payload is ignored.

---

## Supported boards

Works on any board using these chips:

- ESP32
- ESP32-S2
- ESP32-S3
- ESP32-C2
- ESP32-C3
- ESP32-C5
- ESP32-C6
- ESP32-C61

Board brand does not matter.

---

## Security

- No open ports
- No inbound connections
- Subscribes only to its own topic
- Optional hashed identifiers

---

## License

MIT
