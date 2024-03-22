# smtp_scanner.py

import socket
from artemis.module_base import ArtemisBase
from artemis.task import Task
from artemis.binds import Service, TaskStatus, TaskType

class SmtpScanner(ArtemisBase):
    identity = "smtp_scanner"
    filters = [
        {"type": TaskType.IP.value},
    ]

    def run(self, current_task: Task) -> None:
        target_ip = current_task.payload.get("ip")
        open_smtp_ports = self.scan_smtp_ports(target_ip)
        
        for port in open_smtp_ports:
            new_task = Task(
                {
                    "type": TaskType.SERVICE,
                    "service": Service.SMTP,
                },
                payload={
                    "host": target_ip,
                    "port": port,
                },
            )
            self.add_task(current_task, new_task)
        
        if open_smtp_ports:
            status = TaskStatus.INTERESTING
            status_reason = "Detected open SMTP ports"
        else:
            status = TaskStatus.OK
            status_reason = "No open SMTP ports detected"
        
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=open_smtp_ports)

    def scan_smtp_ports(self, target_ip: str) -> List[int]:
        open_smtp_ports = []
        for port in range(1, 1025):  # Scan common port range
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)  # Set timeout for connection attempt
                    result = s.connect_ex((target_ip, port))
                    if result == 0:
                        open_smtp_ports.append(port)
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
        
        return open_smtp_ports
