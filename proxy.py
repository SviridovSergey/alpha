import socket
import threading
import ssl
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,  # Уровень логирования (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s [%(levelname)s] %(message)s",  # Формат сообщений
    handlers=[
        logging.FileHandler("server_proxy.log"),  # Логи записываются в файл server.log
        logging.StreamHandler()  # Логи выводятся в консоль
    ]
)

def handle_client(client_socket):
    """Обрабатывает соединение клиента."""
    try:
        # Получаем запрос от клиента
        request = client_socket.recv(4096)
        if not request:
            client_socket.close()
            return
        logging.info(f"Получен запрос от клиента: {request}")  # Логируем как байты

        # Парсим запрос, чтобы получить хост и порт
        request_lines = request.split(b"\r\n")
        host_line = next((line for line in request_lines if line.startswith(b"Host:")), None)
        if not host_line:
            logging.info("Запрос не содержит заголовок Host")
            client_socket.close()
            return
        logging.info("Заголовок Host найден")

        # Извлекаем хост и порт из заголовка Host
        host = host_line.split(b":")[1].strip().decode("utf-8")
        port = 443 if request.startswith(b"CONNECT") else 8888  # Определяем порт (HTTPS или HTTP)

        # Создаем соединение с целевым сервером
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.settimeout(30)  # Увеличиваем тайм-аут

        try:
            if port == 443:  # Если HTTPS
                ssl_context = ssl.create_default_context()
                server_socket = ssl_context.wrap_socket(server_socket, server_hostname=host)
                logging.info("Создано HTTPS-соединение с целевым сервером")
            else:
                logging.info('Создано HTTP-соединение с целевым сервером')

            server_socket.connect((host, port))

            # Если это HTTPS-запрос, отправляем клиенту подтверждение
            if port == 443:
                logging.info('Это HTTP запрос, не HTTPS')
            else:
                client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Отправляем запрос на целевой сервер
            logging.info(f"Отправка запроса на целевой сервер: {request}")
            server_socket.sendall(request)

            # Получаем ответ от целевого сервера
            while True:
                response = server_socket.recv(4096)
                if not response:
                    break
                client_socket.sendall(response)
                logging.info(f"Ответ отправлен клиенту: {response}")  # Логируем как байты

        except socket.timeout:
            logging.error(f"Тайм-аут при подключении к целевому серверу: {host}:{port}")
        except ConnectionRefusedError:
            logging.error(f"Целевой сервер отверг подключение: {host}:{port}")
        except Exception as e:
            logging.error(f"Ошибка при подключении к целевому серверу: {e}")

    except Exception as e:
        logging.error(f"Ошибка: {e}")
    

def start_proxy_server(host="127.0.0.1", port=8080):
    """Запускает прокси-сервер."""
    logging.info('creating SSL-Contex for server and start server')
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")  # Укажите пути к сертификату и ключу

    logging.info('creating server_soket')
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    logging.info(f"proxy-server is started on:{host}:{port}")

    try:
        while True:
            logging.info('accept connect from client')
            client_socket, addr = server_socket.accept()
            logging.info(f"Подключение от {addr}")

            # Определяем, является ли запрос HTTPS (CONNECT)
            peek_data = client_socket.recv(4096, socket.MSG_PEEK)
            if peek_data.startswith(b"CONNECT"):
                # Если это HTTPS, оборачиваем сокет в SSL
                logging.info('obert client_coket in SSL-CONTEX')
                client_socket = ssl_context.wrap_socket(client_socket, server_side=True)
            else:
                # Если это HTTP, оставляем сокет как есть
                logging.info('HTTP запрос, SSL не используется')

            # Обрабатываем клиента в отдельном потоке
            client_handler = threading.Thread(target=handle_client, args=(client_socket,))
            client_handler.start()

    except KeyboardInterrupt as e:
        logging.info(f"proxy server is stopped with exception: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_proxy_server(host="127.0.0.1", port=8080)