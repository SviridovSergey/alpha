import socket
import threading
import ssl
import logging
import random
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,  # Уровень логирования (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s [%(levelname)s] %(message)s",  # Формат сообщений
    handlers=[
        logging.FileHandler("server_proxy.log"),  # Логи записываются в файл server.log
        logging.StreamHandler()  # Логи выводятся в консоль
    ]
)

# Список разрешенных доменов
allowed_domains = []
with open('proxy_domens.txt', 'r') as f:
    allowed_domains = [line.strip() for line in f]

# Список разрешенных IP-адресов
allowed_ip = []
with open('proxy_ips.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if '/' in line:
            line = line.split('/')[0]
        try:
            # Проверяем, является ли строка валидным IP-адресом
            ipaddress.ip_address(line)
            allowed_ip.append(line)
        except ValueError:
            logging.warning(f"Invalid IP address skipped: {line}")

# Словарь для хранения доступных IP-адресов
available_proxy_ips = {}

def is_allowed(host, ip):
    """Проверяет, разрешен ли домен или IP-адрес."""
    logging.info('запущена проверка host,ip')
    if host in allowed_domains:
        logging.info('проверка пройдена host')
        return True
    if ip in allowed_ip:
        logging.info('проверка пройдена ip')
        return True
    return False

def is_ip_legit(ip, port, timeout=2):
    """Проверяет, доступен ли IP-адрес и порт."""
    logging.info(f'запущена проверка на легитимность ip: {ip}')
    try:
        # Создаем сокет
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)  # Устанавливаем тайм-аут
        # Пытаемся подключиться
        result = sock.connect_ex((ip, port))
        sock.close()
        # Если результат 0, IP-адрес доступен
        logging.info(f'ip {ip} прошел проверку')
        if result==0:
            return True
    except Exception as e:
        logging.warning(f'ip {ip} не прошел проверку: {e}')
        return False

def update_available_proxy_ips(port=80):
    """Обновляет словарь доступных IP-адресов с использованием многопоточности."""
    global available_proxy_ips
    
    logging.info('запущено обновление ip-адресов')
    # Используем ThreadPoolExecutor для многопоточной проверки
    with ThreadPoolExecutor(max_workers=50) as executor:
        # Создаем futures для каждого IP-адреса
        futures = {executor.submit(is_ip_legit, ip, port): ip for ip in allowed_ip}

        # Обрабатываем результаты по мере их завершения
        for future in as_completed(futures):
            ip = futures[future]
            try:
                is_available = future.result()
                available_proxy_ips[ip] = is_available
            except Exception as e:
                logging.error(f"Ошибка при проверке IP {ip}: {e}")
                available_proxy_ips[ip] = False

    logging.info('обновление ip-адресов завершено')

def get_legit_proxy_ip(port=80):
    """Возвращает случайный доступный IP-адрес из списка."""
    logging.info('запущена выборка случайного ip-адреса')
    update_available_proxy_ips(port)  # Обновляем список доступных IP-адресов
    legit_ips = [ip for ip, is_available in available_proxy_ips.items() if is_available]
    if legit_ips:
        logging.info('проверка окончена, выбран случайный IP')
        return random.choice(legit_ips)
    else:
        logging.error("Нет доступных IP-адресов прокси-серверов")
        raise ValueError("Нет доступных IP-адресов прокси-серверов")

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

        host = host_line.split(b":")[1].strip().decode("utf-8")
        port = 443 if request.startswith(b"CONNECT") else 80  # Определяем порт (HTTPS или HTTP)

        # Проверяем, разрешен ли домен
        if not is_allowed(host, ""):
            logging.info(f"Запрос к {host} запрещен")
            client_socket.close()
            return
        logging.info(f"Запрос к {host} разрешен")

        # Выбираем доступный IP-адрес прокси-сервера
        proxy_host = get_legit_proxy_ip()
        logging.info(f"Используется прокси-сервер: {proxy_host}")

        # Создаем соединение с целевым сервером
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if port == 443:  # Если HTTPS
            ssl_context = ssl.create_default_context()
            server_socket = ssl_context.wrap_socket(server_socket, server_hostname=host)
            logging.info("Создано HTTPS-соединение с целевым сервером")
        else:
            logging.info('HTTP-соединение с целевым сервером не создано')

        server_socket.connect((host, port))

        # Если это HTTPS-запрос, отправляем клиенту подтверждение
        if port == 443:
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Отправляем запрос на целевой сервер
        server_socket.sendall(request)

        # Получаем ответ от целевого сервера
        while True:
            response = server_socket.recv(4096)
            if not response:
                break
            client_socket.sendall(response)
            logging.info(f"Ответ отправлен клиенту: {response}")  # Логируем как байты

    except Exception as e:
        logging.error(f"Ошибка: {e}")
    finally:
        client_socket.close()

def start_proxy_server(host='0.0.0.0', port=80):
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
    start_proxy_server(host='0.0.0.0', port=80)    