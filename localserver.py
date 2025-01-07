import asyncio
import logging
import aiohttp
import ssl

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("local_server.log"),
        logging.StreamHandler()
    ]
)

async def forward_to_proxy(data, proxy_host, proxy_port):
    """Пересылает данные на прокси-сервер."""
    try:
        logging.info(f"Подключение к прокси-серверу {proxy_host}:{proxy_port}")
        timeout = aiohttp.ClientTimeout(total=10)  # Тайм-аут для соединения
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(f"http://{proxy_host}:{proxy_port}", data=data) as response:
                if response.status == 200:
                    logging.info(f"Ответ от прокси-сервера: {await response.text()}")
                else:
                    logging.error(f"Ошибка от прокси-сервера: {response.status}")
    except aiohttp.ClientError as e:
        logging.error(f"Ошибка при пересылке на прокси-сервер: {e}")
    except Exception as e:
        logging.error(f"Неизвестная ошибка: {e}")

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    logging.info(f"Подключение от {addr!r}")
    try:
        while True:
            # Чтение данных от клиента
            data = await reader.read(4096)
            if not data:
                break
            # Логируем данные как байты, а не как строку
            logging.info(f"Получено от клиента: {data}")

            # Пересылка данных на прокси-сервер
            proxy_host = "0.0.0.0"  # Адрес прокси-сервера
            proxy_port = 8080  # Порт прокси-сервера
            await forward_to_proxy(data, proxy_host, proxy_port)

    except Exception as e:
        logging.error(f"Ошибка: {e}")
    finally:
        writer.close()
        await writer.wait_closed()
        logging.info(f"Клиент {addr!r} отключился.")

async def main():
    # Создаем SSL-контекст
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")  # Укажите пути к сертификату и ключу

    # Запускаем сервер с поддержкой HTTPS
    server = await asyncio.start_server(
        handle_client, '127.0.0.1', 8888, ssl=ssl_context
    )
    logging.info(f"Локальный сервер запущен на https://127.0.0.1:8888")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())