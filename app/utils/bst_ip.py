class BSTNode:
    """Узел бинарного дерева поиска для хранения информации об IP-адресах."""

    def __init__(self, ip, region, ports):
        """
        Инициализирует узел дерева.

        Args:
            ip (tuple): IP-адрес в виде кортежа (напр. (192, 168, 1, 1))
            region (str): Код региона (напр. 'RU', 'FR')
            ports (list): Список портов
        """
        self.ip = ip
        self.region = region
        self.ports = ports
        self.left = None
        self.right = None


class BST:
    """Бинарное дерево поиска для хранения и поиска IP-адресов с регионами и портами."""

    def __init__(self):
        """Инициализирует пустое дерево."""
        self.root = None

    def insert(self, ip, region, port):
        """
        Добавляет новый IP-адрес в дерево или обновляет существующий.

        Args:
            ip (tuple): IP-адрес в виде кортежа
            region (str): Код региона
            port (int): Номер порта
        """
        if not self.root:
            self.root = BSTNode(ip, region, [port])
        else:
            self._insert_recursive(self.root, ip, region, port)

    def _insert_recursive(self, node, ip, region, port):
        """
        Рекурсивно вставляет новый узел в поддерево.

        Args:
            node (BSTNode): Текущий узел для сравнения
            ip (tuple): IP-адрес для вставки
            region (str): Код региона
            port (int): Номер порта
        """
        if ip < node.ip:
            if node.left is None:
                node.left = BSTNode(ip, region, [port])
            else:
                self._insert_recursive(node.left, ip, region, port)
        elif ip > node.ip:
            if node.right is None:
                node.right = BSTNode(ip, region, [port])
            else:
                self._insert_recursive(node.right, ip, region, port)
        else:
            # IP уже существует, добавляем порт если его нет
            if port not in node.ports:
                node.ports.append(port)

    def insert_many(self, ip, region, ports):
        """
        Добавляет IP-адрес с несколькими портами.

        Args:
            ip (tuple): IP-адрес в виде кортежа
            region (str): Код региона
            ports (list): Список портов
        """
        if not self.root:
            self.root = BSTNode(ip, region, ports)
        else:
            self._insert_many_recursive(self.root, ip, region, ports)

    def _insert_many_recursive(self, node, ip, region, ports):
        """
        Рекурсивно вставляет узел с несколькими портами.
        """
        if ip < node.ip:
            if node.left is None:
                node.left = BSTNode(ip, region, ports)
            else:
                self._insert_many_recursive(node.left, ip, region, ports)
        elif ip > node.ip:
            if node.right is None:
                node.right = BSTNode(ip, region, ports)
            else:
                self._insert_many_recursive(node.right, ip, region, ports)
        else:
            # IP уже существует, добавляем новые порты
            for port in ports:
                if port not in node.ports:
                    node.ports.append(port)

    def find_ip(self, target_ip):
        """
        Находит узел с заданным IP-адресом.

        Args:
            target_ip (tuple): Искомый IP-адрес в виде кортежа

        Returns:
            BSTNode: Найденный узел или None если не найден
        """
        return self._find_ip_recursive(self.root, target_ip)

    def _find_ip_recursive(self, node, target_ip_tuple):
        """
        Рекурсивно ищет IP-адрес в поддереве.
        """
        if node is None:
            return None

        if target_ip_tuple == node.ip:
            return node
        elif target_ip_tuple < node.ip:
            return self._find_ip_recursive(node.left, target_ip_tuple)
        else:
            return self._find_ip_recursive(node.right, target_ip_tuple)

    def get_ip_info(self, ip_str):
        """
        Возвращает информацию об IP-адресе в удобном формате.

        Args:
            ip_str (str): IP-адрес в строковом формате ('192.168.1.1')

        Returns:
            dict: {'region': str, 'ports': list} или None если не найден
        """
        ip_tuple = ip_to_tuple(ip_str)
        node = self.find_ip(ip_tuple)

        if node:
            return {"region": node.region, "ports": node.ports}
        return None

    def inorder_traversal(self):
        """
        Возвращает все узлы дерева в отсортированном порядке.

        Returns:
            list: Список узлов в порядке возрастания IP-адресов
        """
        result = []
        self._inorder_recursive(self.root, result)
        return result

    def _inorder_recursive(self, node, result):
        """
        Рекурсивный обход дерева в порядке возрастания.
        """
        if node:
            self._inorder_recursive(node.left, result)
            result.append(
                {
                    "ip": ".".join(map(str, node.ip)),
                    "region": node.region,
                    "ports": node.ports,
                }
            )
            self._inorder_recursive(node.right, result)


def ip_to_tuple(ip_str):
    """
    Преобразует строковый IP-адрес в кортеж чисел.

    Args:
        ip_str (str): IP-адрес (напр. '192.168.1.1')

    Returns:
        tuple: (192, 168, 1, 1)
    """
    return tuple(map(int, ip_str.split(".")))


def parse_ip_port(ip_port_str):
    """
    Парсит строку вида 'IP:PORT' в IP и порт.

    Args:
        ip_port_str (str): Строка формата '192.168.1.1:8080'

    Returns:
        tuple: (ip_str, port)
    """
    ip, port = ip_port_str.split(":")
    return ip, int(port)


def serialize_data_to_bst(data):
    """
    Строит BST из исходных данных формата:
    "FR - France (851)['51.91.109.83:80', '151.80.199.88:3128', ...]"

    Args:
        data (str): Многострочная строка с данными

    Returns:
        BST: Построенное бинарное дерево поиска
    """
    bst = BST()

    for line in data.split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            region_part, ips_part = line.split("[")
            region_code = region_part.split("-")[0].strip()
            ips_with_ports = (
                ips_part.rstrip("]").replace("'", "").replace(" ", "").split(",")
            )

            ip_ports = {}
            for ip_port in ips_with_ports:
                if not ip_port:
                    continue
                ip, port = parse_ip_port(ip_port)
                if ip not in ip_ports:
                    ip_ports[ip] = []
                ip_ports[ip].append(port)

            for ip, ports in ip_ports.items():
                bst.insert_many(ip_to_tuple(ip), region_code, ports)

        except Exception as e:
            print(f"Ошибка при обработке строки: {line}\n{str(e)}")

    return bst
