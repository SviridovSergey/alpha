import asyncio
import logging
import aiohttp
import sys
import ssl
# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("client.log"),
        logging.StreamHandler()
    ]
)

async def send_request(local_server_ip, local_server_port):
    """Отправляет HTTPS-запрос на локальный сервер."""
    try:
        # Отключаем проверку SSL, если используется самоподписанный сертификат
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://{local_server_ip}:{local_server_port}",
                ssl=ssl_context
            ) as response:
                logging.info(f"Ответ от локального сервера: {await response.text()}")
    except aiohttp.ClientError as e:
        logging.error(f"Ошибка клиента при отправке HTTPS-запроса: {e}")
    except Exception as e:
        logging.error(f"Сервер отключал вас от сервера: {e}")

async def main(local_server_ip, local_server_port):
    await send_request(local_server_ip, local_server_port)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Использование: python client.py <ip_адрес_локального_сервера> <порт_локального_сервера>")
        sys.exit(1)
    local_server_ip = sys.argv[1]
    local_server_port = int(sys.argv[2])
    asyncio.run(main(local_server_ip, local_server_port))