# FtpPortScanner.py

from typing import List
from artemis.module_base import ArtemisBase
from artemis.task import Task
from artemis.binds import Service, TaskStatus, TaskType

class FtpPortScanner(ArtemisBase):
    identity = "ftp_port_scanner"
    filters = [
        {"type": TaskType.IP.value},
    ]

    def run(self, current_task: Task) -> None:
        target_ip = current_task.payload.get("ip")
        
        # Perform FTP port scanning logic here
        open_ftp_ports = self.scan_ftp_ports(target_ip)
        
        # Create tasks for detected FTP ports
        for port in open_ftp_ports:
            new_task = Task(
                {
                    "type": TaskType.SERVICE,
                    "service": Service.FTP,
                },
                payload={
                    "host": target_ip,
                    "port": port,
                },
            )
            self.add_task(current_task, new_task)
        
        # Update task status based on scan results
        if open_ftp_ports:
            status = TaskStatus.INTERESTING
            status_reason = "Detected open FTP ports"
        else:
            status = TaskStatus.OK
            status_reason = "No open FTP ports detected"
        
        # Save scan results
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=open_ftp_ports)

    def scan_ftp_ports(self, target_ip: str) -> List[int]:
        # Placeholder function for FTP port scanning logic
        # In a real scenario, this function would use a port scanning tool or library to identify open FTP ports
        # For demonstration purposes, we'll assume FTP ports 21 and 2121 are open on all target IPs
        open_ftp_ports = [21, 2121]
        return open_ftp_ports
