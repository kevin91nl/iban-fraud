# Steps:
# 1. Scrape URLs containing IBAN numbers, get a list of those URLs
# or:
# 1. Scrape IBAN snippets
# 2. Label IBAN snippets
# 3. Auto scrape malicious IBAN numbers (including the source)

import re

from collections import Counter

from sparkcc import CCSparkJob


class IBANScraperJob(CCSparkJob):
    """Get IBAN numbers from webpages."""

    name = "IBANScraper"

    # match HTML tags (element names) on binary HTML data
    # iban_pattern = re.compile('[A-Z]{2}[0-9]{2}[A-Z]{4}(?:[ ]?[0-9]){10,20}', flags=re.IGNORECASE)
    iban_pattern = re.compile('NL', flags=re.IGNORECASE)

    def html_to_text(self, page, record):
        try:
            encoding = EncodingDetector.find_declared_encoding(page,
                                                               is_html=True)
            soup = BeautifulSoup(page, "lxml", from_encoding=encoding)
            for script in soup(["script", "style"]):
                script.extract()
            return soup.get_text(" ", strip=True)
        except:
            return ""

    def process_record(self, record):
        if record.rec_type != 'response':
            # WARC request or metadata records
            return
        content_type = record.http_headers.get_header('content-type', None)
        if content_type is None or 'html' not in content_type:
            # skip non-HTML or unknown content types
            return
        page = record.content_stream().read()
        text = self.html_to_text(page, record)
        ibans = IBANScraperJob.iban_pattern.findall(text)
        for iban in ibans:
            yield iban


if __name__ == '__main__':
    job = IBANScraperJob()
    job.run()
