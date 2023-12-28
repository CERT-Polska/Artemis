import logging
import time
import urllib.parse
from re import search
from typing import Optional, Tuple

from karton.core import Task
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.wait import WebDriverWait

from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.passwords import get_passwords_for_url
from artemis.utils import remove_standard_ports_from_url


class AdminPanelBruterException(Exception):
    pass


class AdminPanelLoginBruter(ArtemisBase):
    """
    Tries to log into admin panels with easy passwords (needs "bruter" and "port_scanner" to be enabled as well to find URLs where admin panels reside)
    """

    identity = "admin_panel_login_bruter"
    filters = [{"type": TaskType.URL.value}]

    USERNAMES = ["admin"]

    LOGIN_FAILED_MSGS = [
        "Please enter the correct username and password for a staff account. "
        "Note that both fields may be case-sensitive.",
        "Unrecognized username or password. Forgot your password?",
        "Username and password do not match or you do not have an account yet.",
        "Invalid credentials",
        # rate limit
        "failed login attempts for this account",
        # pl_PL
        "Podano błędne dane logowania",
        "Nieprawidłowa nazwa użytkownika lub hasło",
        "Złe hasło",
        "Błędna nazwa użytkownika",
    ]

    def run(self, task: Task) -> None:
        url = task.get_payload(TaskType.URL)
        url_parsed = urllib.parse.urlparse(url)

        is_root_url = url_parsed.path in ["", "/"]

        if not is_root_url and not any([item in url.lower() for item in ["login", "admin", "cms", "backend", "panel"]]):
            self.db.save_task_result(
                task=task,
                status=TaskStatus.OK,
                status_reason=f"URL {url} doesn't look like an admin panel URL",
                data=None,
            )
            return

        if "admin" in url and not url.endswith("/admin") and "admin" in task.get_payload("found_urls"):
            self.db.save_task_result(
                task=task,
                status=TaskStatus.OK,
                status_reason=f"Requested to brute {url}, but /admin is also on the list of found URLs - skipping "
                "brute-forcing of this url so that we don't duplicate work",
                data=None,
            )
            return

        credentials = self._brute(url)

        if credentials:
            username, password = credentials

            self.db.save_task_result(
                task=task,
                status=TaskStatus.INTERESTING,
                status_reason=f"Found working credentials for {url}: username={username}, password={password}",
                data=credentials,
            )
        else:
            self.db.save_task_result(task=task, status=TaskStatus.OK, status_reason=None, data=None)

    def _brute(self, url: str) -> Optional[Tuple[str, str]]:
        working_credentials = []
        for username in self.USERNAMES:
            for password in get_passwords_for_url(url):
                driver = AdminPanelLoginBruter._get_webdriver()
                driver.get(url)

                try:
                    WebDriverWait(driver, Config.Modules.AdminPanelLoginBruter.WAIT_TIME_SECONDS).until(
                        expected_conditions.url_matches(remove_standard_ports_from_url(url))
                    )
                except TimeoutException:
                    self.log.info(
                        "Timeout occured when waiting for the URL to match, let's try "
                        f"to login even if the url doesn't match, url={driver.current_url}"
                    )

                # Ignore alerts
                driver.execute_script("window.alert = function() {};")  # type: ignore
                driver.implicitly_wait(Config.Modules.AdminPanelLoginBruter.WAIT_TIME_SECONDS)
                self._sleep_after_performing_requests(driver)

                inputs = AdminPanelLoginBruter._find_form_inputs(url, driver)

                if inputs:
                    user_input, password_input = inputs
                else:
                    driver.close()
                    driver.quit()
                    break

                AdminPanelLoginBruter._send_credentials(
                    user_input=user_input,
                    password_input=password_input,
                    username=username,
                    password=password,
                )
                driver.implicitly_wait(Config.Modules.AdminPanelLoginBruter.WAIT_TIME_SECONDS)
                result = AdminPanelLoginBruter._get_logging_in_result(driver, self.LOGIN_FAILED_MSGS)
                self._sleep_after_performing_requests(driver)

                if result:
                    self.log.info(f"Detected following 'login failed' messages: {result}")
                    continue
                else:
                    working_credentials.append((username, password))

                driver.close()
                driver.quit()

        if len(working_credentials) > 1:
            raise AdminPanelBruterException(
                f"Found more than one working credential pair: {working_credentials} - please check the heuristics"
            )
        elif len(working_credentials) == 0:
            return None
        else:
            return working_credentials[0]

    @staticmethod
    def _get_webdriver() -> WebDriver:
        service = Service(executable_path="/usr/bin/chromedriver")

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            chrome_options.add_argument("--user-agent=" + Config.Miscellaneous.CUSTOM_USER_AGENT)
        return webdriver.Chrome(service=service, options=chrome_options)  # type: ignore

    @staticmethod
    def _find_form_inputs(url: str, driver: WebDriver) -> Optional[tuple[WebElement, WebElement]]:
        user_input, password_input = None, None
        inputs = driver.find_elements(By.TAG_NAME, "input")
        if not inputs:
            logging.error(f"Login form has not been found on {url}")
            return None
        else:
            for field in inputs:
                if field.get_attribute("type").lower() == "text":  # type: ignore
                    tag_values = driver.execute_script(  # type: ignore
                        "var items = []; for (index = 0; index < arguments[0].attributes.length; ++index)"
                        "items.push(arguments[0].attributes[index].value); return items;",
                        field,
                    )
                    for value in tag_values:
                        if search(r"[Uu]ser", value) or search(r"[Ll]ogin", value) or search(r"[Nn]ame", value):
                            user_input = field
                            break
                elif field.get_attribute("type").lower() == "password":  # type: ignore
                    password_input = field
        if not password_input or not user_input:
            logging.error(f"Login form has not been found on {url}")
            return None
        return user_input, password_input

    @staticmethod
    def _send_credentials(user_input: WebElement, password_input: WebElement, username: str, password: str) -> None:
        if user_input:
            user_input.send_keys(username)
        if password_input:
            password_input.send_keys(password)
            password_input.send_keys(Keys.ENTER)

    @staticmethod
    def _get_logging_in_result(driver: WebDriver, login_failure_msgs: list[str]) -> Optional[list[str]]:
        try:
            web_content = driver.find_element(By.XPATH, "html/body").text
            print(web_content)
            result = [msg for msg in login_failure_msgs if (msg in web_content)]
            return result
        except NoSuchElementException:
            return None

    def _sleep_after_performing_requests(self, driver: WebDriver) -> None:
        # It is easier to limit requests that way than to hook into Selenium to limit every one.
        # This is not dangerous to servers as loading a page together with all resources in a burst
        # is how websites are normally used - and we have a lock so we know we are the only module
        # scanning this IP.
        num_requests = driver.execute_script('return 1 + window.performance.getEntriesByType("resource").length;')  # type: ignore
        if Config.Limits.REQUESTS_PER_SECOND > 0:
            sleep_time_seconds = max(
                0,
                num_requests * 1.0 / Config.Limits.REQUESTS_PER_SECOND
                - Config.Modules.AdminPanelLoginBruter.WAIT_TIME_SECONDS,
            )
        else:
            sleep_time_seconds = 0

        if sleep_time_seconds > 0:
            time.sleep(sleep_time_seconds)
            self.log.info(f"{num_requests} requests performed, sleeping {sleep_time_seconds} seconds")


if __name__ == "__main__":
    AdminPanelLoginBruter().loop()
