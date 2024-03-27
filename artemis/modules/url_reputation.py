import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urlparse
from karton.core import Task 
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import  get_target_url

class URLReputation(ArtemisBase):
    identity = "url_reputation"  
    filters = [] 
    visited_url=[]
    urls=[]
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def remove_duplicates(self, link_list): 
        unique_links = [] 
        for item in link_list:
            match = re.search("(?P<url>https?://[^\s]+)", item)
            if match is not None and match.group("url") not in unique_links:
                unique_links.append(match.group("url"))
        return unique_links

    def check_url_status(url):
        api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        response = requests.post(api_endpoint, data={'url': url})

        if response.status_code == 200:
            data = response.json()
            return data.get('query_status') == 'ok' and 'threat' in data
        else:
            print(f"API request failed for {url}")
            return False


    def extract_and_check_urls(url,hostname,max_links=162):
        if url not in visited_url:
            visited_url.append(url)
            if hostname in url:
                source_code=requests.get(url)
                soup = BeautifulSoup(source_code.content, 'lxml')
                for link in soup.find_all('a', href=True):
                    get_link=str(link.get('href'))
                    if(len(urlparse(get_link).netloc)==0):
                        get_link="http://"+hostname+"/"+get_link
                    if(hostname in get_link):
                        extract_and_check_urls(get_link,hostname)
                    else:
                        urls.append(str(link.get('href')))
                    if len(urls) >= max_links:
                        break



    def run(self, task: Task) -> None:
        target = get_target_url(task) 
        self.log.info(f"URL Reputation module running on {target}") 
        self.extract_and_check_urls(target)  
        if len(urls) == 0:
            # On the default task result view only the interesting task results will be displayed
            status = TaskStatus.INTERESTING
            status_reason = "no url found"
        else:
            status = TaskStatus.OK
            status_reason = "some url found"
        print("UUUUURRRRRRLLLLL LIST",end=":")
        print(urls)
        self.db.save_task_result(
            task=task,
            status=status,
            status_reason=status_reason,
            # In the data dictionary, you may provide any additional results - the user will be able to view them
            # in the interface on the single task result page.
            data={"url":"someurl"},
        )



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