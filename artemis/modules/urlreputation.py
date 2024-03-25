import requests
from bs4 import BeautifulSoup
import re
import time

from karton.core import Task 
from artemis.binds import TaskStatus, TaskType 
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_ip, get_target_url

class URLReputation(ArtemisBase):
    identity = "url_reputation"  
    filters = [] 

    def remove_duplicates(self, link_list): 
        unique_links = [] 
        for item in link_list:
            match = re.search("(?P<url>https?://[^\s]+)", item)
            if match is not None and match.group("url") not in unique_links:
                unique_links.append(match.group("url"))
        return unique_links

    def check_url_status(self, url):
        api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        response = requests.post(api_endpoint, data={'url': url})

        if response.status_code == 200:
            data = response.json()
            return data.get('query_status') == 'ok' and 'threat' in data
        else:
            self.log.error(f"API request failed for {url}")
            return False

    def extract_and_check_urls(self, base_url, max_links=162):
        source_code = requests.get(base_url)
        soup = BeautifulSoup(source_code.content, 'lxml')

        links = [str(link.get('href')) for link in soup.find_all('a', href=True)]
        links = self.remove_duplicates(links)[:max_links]

        for url in links:
            if self.check_url_status(url):
                status = TaskStatus.VULNERABLE  # Mark task as vulnerable
                status_reason = "Malicious URL found on page"
                self.db.save_task_result(task, status, status_reason, data={'url': url})

    def run(self, task: Task) -> None:
        target = get_target_url(task) or get_target_ip(task)  # Works for URLs or IPs
        self.log.info(f"URL Reputation module running on {target}") 

        self.extract_and_check_urls(target)  

if __name__ == "__main__":
    URLReputation().loop()



# import requests
# from bs4 import BeautifulSoup
# import re
# import time
# from urllib.parse import urlparse

# def remove_duplicates(link_list): 
#     unique_links = [] 
#     for item in link_list:
#         match = re.search("(?P<url>https?://[^\s]+)", item)
#         if match is not None and match.group("url") not in unique_links:
#             unique_links.append(match.group("url"))
#     return unique_links  

# def check_url_status(url):
#     api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
#     response = requests.post(api_endpoint, data={'url': url})

#     if response.status_code == 200:
#         data = response.json()
#         return data.get('query_status') == 'ok' and 'threat' in data
#     else:
#         print(f"API request failed for {url}")
#         return False

# visited_url=[]
# urls=[]
# def extract_and_check_urls(url,hostname,max_links=162):
#     if url not in visited_url:
#         visited_url.append(url)
#         if hostname in url:
#             source_code=requests.get(url)
#             soup = BeautifulSoup(source_code.content, 'lxml')
#             for link in soup.find_all('a', href=True):
#                 get_link=str(link.get('href'))
#                 if(len(urlparse(get_link).netloc)==0):
#                     get_link="http://"+hostname+"/"+get_link
#                 if(hostname in get_link):
#                     extract_and_check_urls(get_link,hostname)
#                 else:
#                     urls.append(str(link.get('href')))
#                 if len(urls) >= max_links:
#                     break


# if __name__ == "__main__":
#     base_url = "http://127.0.0.1:5500/index.html" 
#     parsed_uri=urlparse(base_url)
#     extract_and_check_urls(base_url,parsed_uri.netloc)
#     print("bad url in your site")
#     for link in urls:
#         if(check_url_status(link)):
#             print(link)