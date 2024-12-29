import asyncio
import sys
from scapy.layers.inet import IP, TCP
from scapy.all import send
import logging

logging.basicConfig(
    level=logging.INFO,  # Уровень логирования (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s [%(levelname)s] %(message)s",  # Формат сообщений
    handlers=[
        logging.FileHandler("client.log"),  # Логи записываются в файл server.log
        logging.StreamHandler()  # Логи выводятся в консоль
    ]
)

async def send_packet(packet):
        send(packet)

async def client(local_server_ip, local_server_port):
        try:
            while True:
                pkt = IP(dst=local_server_ip) / TCP(dport=local_server_port, flags="S")
                await send_packet(pkt)
                print(f"Отправлен пакет: {pkt.summary()}")
                logging.info('отправлен пакет')
                await asyncio.sleep(1)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Ошибка клиента: {e}")
        finally:
            print("Клиент завершил работу.")
            return 0

def read_config(filename):
        with open(filename, 'r') as file:
            return file.read().strip()

if __name__ == "__main__":
        if len(sys.argv) < 3:
            print("Использование: python client.py <ip_адрес_локального_сервера> <порт_локального_сервера>")
            sys.exit(1)
        local_server_ip = read_config("local_server_ip.txt")
        local_server_port = int(read_config("local_server_port.txt"))
        print(f"создан локальный сервер на: {local_server_ip}:{local_server_port}")
        asyncio.run(client(local_server_ip, local_server_port))