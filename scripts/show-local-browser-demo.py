"""Visible Chrome/Firefox round trip against the already running local harness."""
import argparse
import json
import os
import pathlib
import secrets
import sys
import threading
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait


def main():
    # PowerShell may redirect stdout through a legacy Windows code page.
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--keep-open', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    os.environ['SE_CACHE_PATH'] = str((args.output / 'driver-cache').resolve())
    os.environ['SE_AVOID_STATS'] = 'true'
    drivers = []
    started = time.monotonic()
    run_tag = secrets.token_hex(4)

    def progress(phase):
        print(phase, flush=True)
        (args.output / 'status.json').write_text(json.dumps({'phase': phase}), encoding='utf-8')

    def capture(driver, name):
        driver.save_screenshot(str(args.output / f'{name}.png'))
        (args.output / f'{name}.txt').write_text(driver.find_element(By.TAG_NAME, 'body').text, encoding='utf-8')

    def received(driver, text):
        return any(element.text == text for element in driver.find_elements(By.CSS_SELECTOR, '.message:not(.outgoing) > p'))

    def send(driver, text):
        composer = WebDriverWait(driver, 30).until(lambda current: current.find_element(By.CSS_SELECTOR, 'textarea[aria-label="Write a message"]'))
        composer.click()
        composer.send_keys(text)
        for attempt in range(2):
            button = WebDriverWait(driver, 30).until(lambda current: next((b for b in current.find_elements(By.CSS_SELECTOR, 'button[aria-label="Send message"]') if b.is_enabled()), None))
            button.click()
            queued = lambda current: any(e.text == text for e in current.find_elements(By.CSS_SELECTOR, '.message.outgoing > p'))
            rejected = lambda current: any(e.text.startswith('No delivery mailbox is available.') for e in current.find_elements(By.CSS_SELECTOR, '.messenger-error'))
            WebDriverWait(driver, 30).until(lambda current: queued(current) or rejected(current))
            if queued(driver):
                return
            if attempt:
                raise RuntimeError('mailbox still unavailable after explicit retry')
            # This specific native refusal occurs before committing any frame.
            # Never retry a send after a timeout or another uncertain result.
            if driver.find_element(By.CSS_SELECTOR, 'textarea[aria-label="Write a message"]').get_attribute('value') != text:
                raise RuntimeError('draft changed after mailbox refusal')
            remote_name = driver.find_element(By.CSS_SELECTOR, '.chat-title h2').text
            progress('Test user action: retrying a paused local mailbox in Settings')
            next(e for e in driver.find_elements(By.CSS_SELECTOR, '.rail button') if e.text == 'Settings').click()
            retries = WebDriverWait(driver, 10).until(lambda current: [e for e in current.find_elements(By.CSS_SELECTOR, '.settings-page button') if e.text.startswith('Retry ')])
            for retry in retries:
                retry.click()
                WebDriverWait(driver, 10).until(lambda current: any(e.text.startswith('Mailbox re-enabled.') for e in current.find_elements(By.CSS_SELECTOR, '[role="status"]')))
            next(e for e in driver.find_elements(By.CSS_SELECTOR, '.rail button') if e.text == 'Chats').click()
            next(e for e in driver.find_elements(By.CSS_SELECTOR, 'button.conversation') if remote_name in e.text).click()

    try:
        progress('Opening installed Chrome for Alice')
        chrome_options = webdriver.ChromeOptions()
        chrome_options.binary_location = 'C:/Program Files/Google/Chrome/Application/chrome.exe'
        chrome_options.accept_insecure_certs = False
        chrome_options.add_argument(f'--user-data-dir={(args.output / "chrome-profile").resolve()}')
        chrome_options.add_argument('--no-first-run')
        chrome = webdriver.Chrome(options=chrome_options)
        drivers.append(chrome)
        chrome.set_window_rect(x=0, y=0, width=1280, height=1300)
        chrome.get('http://127.0.0.1:4181/')
        progress('Opening installed Firefox for Bob')
        firefox_options = webdriver.FirefoxOptions()
        firefox_options.binary_location = 'C:/Program Files/Mozilla Firefox/firefox.exe'
        firefox_options.accept_insecure_certs = False
        firefox = webdriver.Firefox(options=firefox_options)
        drivers.append(firefox)
        firefox.set_window_rect(x=1280, y=0, width=1280, height=1300)
        firefox.get('http://127.0.0.1:4182/')
        versions = {name: {'browserName': driver.capabilities['browserName'],
                           'browserVersion': driver.capabilities['browserVersion']}
                    for name, driver in zip(('alice', 'bob'), drivers)}
        assert versions['alice']['browserName'] == 'chrome'
        assert versions['bob']['browserName'] == 'firefox'
        print(json.dumps(versions), flush=True)
        for name, driver in zip(('alice-start', 'bob-start'), drivers):
            capture(driver, name)
        progress('Both browser windows open; waiting for reciprocal contact queues')
        for driver, remote_name in ((chrome, 'Bob · Firefox'), (firefox, 'Alice · Chrome')):
            WebDriverWait(driver, 1800, poll_frequency=3).until(
                lambda current: current.find_element(By.CSS_SELECTOR, '.demo-progress').text.startswith('Ready'))
            contact = WebDriverWait(driver, 30).until(lambda current: next(
                (element for element in current.find_elements(By.CSS_SELECTOR, 'button.conversation') if remote_name in element.text), None))
            contact.click()
            WebDriverWait(driver, 30).until(lambda current: current.find_element(By.CSS_SELECTOR, '.chat-title h2').text == remote_name)
        first = f'Alice → Bob: hello from Chrome. This is a real encrypted test message. [{run_tag}]'
        second = f'Bob → Alice: received in Firefox. The reply is flowing back through Tor. [{run_tag}]'
        send(chrome, first)
        capture(chrome, 'alice-queued')
        progress('Alice sent from Chrome; waiting for Firefox to receive through the mailbox')
        WebDriverWait(firefox, 1200, poll_frequency=3).until(lambda current: received(current, first))
        capture(firefox, 'bob-received')
        progress('Firefox received the Chrome message; sending Bob’s reply')
        send(firefox, second)
        WebDriverWait(chrome, 1200, poll_frequency=3).until(lambda current: received(current, second))
        for name, driver in zip(('alice-final', 'bob-final'), drivers):
            capture(driver, name)
        proof = {'passed': True, 'run_tag': run_tag, 'browsers': versions, 'alice_to_bob': first, 'bob_to_alice': second,
                 'elapsed_seconds': round(time.monotonic() - started, 1)}
        (args.output / 'proof.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2), encoding='utf-8')
        progress('PASS: Chrome → Firefox and Firefox → Chrome delivered through the local Docker onion mailbox')
    except Exception as error:
        progress(f'Demo failed: {type(error).__name__}')
        print(str(error), flush=True)
        for index, driver in enumerate(drivers):
            try:
                capture(driver, f'failure-{index}')
            except Exception:
                pass
        raise
    finally:
        if args.keep_open and drivers:
            print('Keeping both test windows open for interaction; stop this runner to close them.', flush=True)
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                pass
        for driver in drivers:
            driver.quit()


if __name__ == '__main__':
    main()
