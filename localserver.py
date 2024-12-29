import asyncio
import random
import requests
import logging
# Настройка логирования
logging.basicConfig(
    level=logging.INFO,  # Уровень логирования (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s [%(levelname)s] %(message)s",  # Формат сообщений
    handlers=[
        logging.FileHandler("server.log"),  # Логи записываются в файл server.log
        logging.StreamHandler()  # Логи выводятся в консоль
    ]
)

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    logging.info(f"Подключение от {addr!r}")
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            logging.info(f"Получено от клиента: {data}")

            # Изменяем IP-адрес клиента на случайный
            random_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            logging.info(f"Измененный IP-адрес: {random_ip}")

            # Пересылаем пакет на прокси-сервер
            proxy_host = 'localhost'
            proxy_port = 8080
            proxies = {
                'http': f'http://{proxy_host}:{proxy_port}',
                'https': f'http://{proxy_host}:{proxy_port}'
            }
            try:
                # Отправляем данные на прокси-сервер
                response = requests.post('http://example.com', data=data, proxies=proxies)
                response.raise_for_status()
                logging.info(f"Ответ от прокси-сервера: {response.text}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Ошибка при отправке на прокси-сервер: {e}")

    except asyncio.CancelledError:
        pass
    except Exception as e:
        logging.error(f"Ошибка: {e}")
    finally:
        writer.close()
        await writer.wait_closed()
        logging.info(f"Клиент {addr!r} отключился.")

async def main():
    server = await asyncio.start_server(handle_client, '127.0.0.1', 8888)
    logging.info(f"Локальный сервер запущен на 127.0.0.1:8888")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())