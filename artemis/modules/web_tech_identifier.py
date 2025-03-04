from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url

import re
import json
from typing import Generator, Dict, Any

@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class WebtechIdentifier(ArtemisBase):
    """Identify web technologies and their versions from a given URL response."""

    identity = "webtech_identifier"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]
    
    def __init__(self, json_path: str):
        self.json_path = json_path
        self.params = self.load_params()
    
    def load_params(self) -> Dict[str, Any]:
        """Load technology detection parameters from a JSON file."""
        with open(self.json_path, "r") as f:
            return json.load(f)
        
    def get_services(self) -> Generator[Dict[str, Any], None, None]:
        """Yield detection parameters for each service."""
        for service, details in self.params.items():
            yield {
                "name": service,
                "headers": details.get("headers", {}),
                "cookies": details.get("cookies", {}),
                "url": details.get("url", None)
            }

    def process(self, response) -> Dict[str, Any]:
        """Check response headers, cookies, and URL for known technologies."""
        detected_tech = {}
        headers = response.headers
        cookies = response.cookies
        response_url = response.url
        meta_tags = re.findall(r'<meta[^>]+>', response.text, re.IGNORECASE)

        for service in self.get_services():
            service_name = service["name"]
            detected = False
            version = None
            
            # Check headers
            for header, pattern in service["headers"].items():#the stored patterns and headers
                """Check regex against the response headers"""
                if header in headers:#match against fetched reponse headers
                    match = re.search(pattern, headers[header], re.IGNORECASE)
                    if match:
                        detected, version = True, match.group(1) or "Unknown"
            
            # Check cookies
            if any(cookie.name in service["cookies"] for cookie in cookies):
                detected = True
            
            # Check URL structure
            if service["url"] and re.search(service["url"], response_url, re.IGNORECASE):
                detected = True

            # Scan meta tags for PHP mentions
            service_meta_tags = [meta for meta in meta_tags if re.search(service_name, str(meta), re.IGNORECASE)]
            if service_meta_tags:
                detected = True
            
            if detected:
                detected_tech[service_name] = version or "Detected"
        
        return detected_tech

        
    def run(self,current_task:Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"webtech identifier scanning {url}")

        response = self.http_get(url)
        detected_tech = self.process(response)

        self.db.save_task_result(
            task=current_task,
            data={"detected_tech": detected_tech},
        )

if __name__ == "__main__":
    WebtechIdentifier().loop()

