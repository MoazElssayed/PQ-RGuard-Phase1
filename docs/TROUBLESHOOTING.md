# Troubleshooting

## Common Issues

### 1. "liboqs not found"
```bash
sudo ldconfig
pkg-config --modversion liboqs
```

### 2. "Permission denied: /dev/ttyUSB0"
```bash
sudo usermod -a -G dialout $USER
# Logout and login again
```

### 3. "Broker connection refused"

Check Mosquitto:
```bash
sudo systemctl status mosquitto
sudo systemctl restart mosquitto
```

### 4. "Handshake failed"

Check network:
```bash
ping <broker_ip>
```
