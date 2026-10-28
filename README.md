# esp32-remote-wol

Remote **Wake-on-LAN** firmware for  ESP32, S2, S3, C2, C3, C5, C6 and C61.
Works behind **CGNAT**, without a public IP or port forwarding.

## How it works

1. ESP32 connects to Wi-Fi and our server over **WSS**.
2. You enter your ESP32 and PC MAC addresses on the website.
3. ESP32 receives the command and sends a local WoL packet.

Wake-on-LAN must already work on your local network.

## Setup

Visit **https://ewol.top/** to:

- Flash firmware from your browser
- Configure Wi-Fi
- Wake your PC

No account or password required.

## License

MIT
