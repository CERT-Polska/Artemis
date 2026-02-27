#!/usr/bin/env python3
import urllib.parse
from typing import Any, Dict, List

import xray
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class LeakScanner(ArtemisBase):
    """
    Scans websites for PDFs with bad censorship/redaction attempts
    (e.g. black rectangles that can be removed to reveal hidden text).
    Uses the x-ray library to detect improperly redacted content.
    """

    identity = "leak_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _discover_pdf_urls(self, base_url: str) -> List[str]:
        """Crawl the website and return URLs that point to PDF files."""
        all_links = get_links_and_resources_on_same_domain(base_url)
        pdf_urls = []
        for link in all_links:
            parsed = urllib.parse.urlparse(link)
            if parsed.path.lower().endswith(".pdf"):
                pdf_urls.append(link)
        return pdf_urls[: Config.Modules.LeakScanner.LEAK_SCANNER_MAX_PDFS_TO_CHECK]

    def _scan_pdf(self, pdf_url: str) -> Dict[str, Any]:
        """Download a PDF and scan it for bad redaction using x-ray."""
        response = self.http_get(
            pdf_url,
            max_size=Config.Modules.LeakScanner.LEAK_SCANNER_MAX_PDF_SIZE_BYTES,
        )

        if response.status_code != 200:
            self.log.info(f"Skipping {pdf_url}: HTTP {response.status_code}")
            return {}

        pdf_bytes = response.content_bytes

        try:
            findings = xray.inspect(pdf_bytes)
        except Exception as e:
            self.log.warning(f"x-ray failed on {pdf_url}: {e}")
            return {}

        leaked_items: List[Dict[str, Any]] = []
        if findings:
            for page_num, items in findings.items():
                for item in items:
                    leaked_items.append(
                        {
                            "page": page_num,
                            "bbox": list(item["bbox"]),
                            "text": item["text"],
                        }
                    )

        if leaked_items:
            return {"url": pdf_url, "leaked_items": leaked_items}
        return {}

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"LeakScanner scanning {url}")

        pdf_urls = self._discover_pdf_urls(url)
        self.log.info(f"Found {len(pdf_urls)} PDF URL(s) on {url}")

        pdfs_with_leaked_data: List[Dict[str, Any]] = []
        for pdf_url in pdf_urls:
            self.log.info(f"Scanning PDF: {pdf_url}")
            result = self._scan_pdf(pdf_url)
            if result:
                pdfs_with_leaked_data.append(result)

        if pdfs_with_leaked_data:
            status = TaskStatus.INTERESTING
            num_total_leaks = sum(len(pdf["leaked_items"]) for pdf in pdfs_with_leaked_data)
            status_reason = (
                f"Found {num_total_leaks} leaked sensitive data item(s) "
                f"in {len(pdfs_with_leaked_data)} PDF(s) with bad redaction"
            )
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "pdfs_checked": len(pdf_urls),
                "pdfs_with_leaked_data": pdfs_with_leaked_data,
            },
        )


if __name__ == "__main__":
    LeakScanner().loop()
