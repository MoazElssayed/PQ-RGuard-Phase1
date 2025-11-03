# Makefile for Enhanced KEMTLS System
# Compile with: make all

CC = gcc
CFLAGS = -O3 -march=native -flto -fomit-frame-pointer
LDFLAGS = -flto -loqs -lssl -lcrypto -lpthread

# Source files
KEMTLS_SRC = kemtls.c
METRICS_SRC = kemtls_metrics.c
MQTT_SRC = mqtt_protocol.c

# Object files
KEMTLS_OBJ = $(KEMTLS_SRC:.c=.o)
METRICS_OBJ = $(METRICS_SRC:.c=.o)
MQTT_OBJ = $(MQTT_SRC:.c=.o)

COMMON_OBJ = $(KEMTLS_OBJ) $(METRICS_OBJ) $(MQTT_OBJ)

# Executables
CLIENT = kemtls_client_enhanced
BROKER = kemtls_broker_enhanced

.PHONY: all clean test

all: $(CLIENT) $(BROKER)

$(CLIENT): kemtls_client_enhanced.c $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Built $@"

$(BROKER): kemtls_broker_enhanced.c $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Built $@"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(KEMTLS_OBJ) $(METRICS_OBJ) $(MQTT_OBJ)
	rm -f $(CLIENT) $(BROKER)
	rm -f kemtls_performance.csv
	@echo "✓ Cleaned build artifacts"

test: all
	@echo "Starting test sequence..."
	@echo "1. Start Mosquitto in another terminal: mosquitto -v"
	@echo "2. Run broker: ./$(BROKER)"
	@echo "3. Run client: ./$(CLIENT) 127.0.0.1"

help:
	@echo "KEMTLS Enhanced Build System"
	@echo "============================="
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build client and broker (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  test      - Show testing instructions"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build everything"
	@echo "  make clean        # Clean build"
	@echo "  make test         # Test instructions"
