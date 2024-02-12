import unittest
import json
import base64
import logging

from math import log2, ceil
from pathlib import Path

from selenium import webdriver
from Crypto.PublicKey import RSA


class IntegrationTest(unittest.TestCase):

    __slots__ = ["opts_dict", "firefox_options", "firefox_driver"]

    @classmethod
    def setUp(cls):
        cls.opts_dict = {
            "general.warnOnAboutConfig": False,
            "browser.aboutConfig.showWarning": False,
            "security.fileuri.strict_origin_policy": False
        }

        cls.firefox_options = webdriver.FirefoxOptions()
        # cls.firefox_options.add_argument("--headless")

        firefox_profile = webdriver.FirefoxProfile()
        for key, value in cls.opts_dict.items():
            firefox_profile.set_preference(key, value)
        cls.firefox_options.profile = firefox_profile
        cls.firefox_driver = webdriver.Firefox(options=cls.firefox_options)

    def test_trivial(self):

        root_file = Path("../client/integration_glue.html")
        self.assertTrue(root_file.exists())

        abs_path = root_file.absolute()
        self.firefox_driver.get("file://" + str(abs_path))
        self.assertTrue("HTML" in self.firefox_driver.title.lower())

    def test_createAnalysisRequestData(self):
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        data_idx = ["2024-01-24T12:00:00", "2024-01-24T12:00:01", "2024-01-24T12:00:02", "2024-01-24T12:00:03",
         "2024-01-24T12:00:04", "2024-01-24T12:00:05", "2024-01-24T12:00:06", "2024-01-24T12:00:07",
         "2024-01-24T12:00:08", "2024-01-24T12:00:09"]

        # normal values that are not part of the key don need urlsafe base64 unlike the key. We love consistency :)))
        iot_key = base64.b64encode(bytes([0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01])).decode("ascii").rstrip("=")
        algorithm = "AES-GCM-128"
        key_path = Path("./assets/integration_keys")
        p1_key_path = key_path / "pub1.pem"
        p2_key_path = key_path / "pub2.pem"
        p3_key_path = key_path / "pub3.pem"

        p1_json = self.pem_to_jwt(p1_key_path)
        p2_json = self.pem_to_jwt(p2_key_path)
        p3_json = self.pem_to_jwt(p3_key_path)

        script_template = """
            window.integration.createAnalysisRequestData(
                "{uid}",
                "{iot_key}",
                "{alg}",
                {p1},
                {p2},
                {p3},
                "Heartbeat-Demo-1",
                {data_idx}
            );
        """

        script = script_template.format(
            uid=user_id,
            iot_key=iot_key,
            alg=algorithm,
            p1=json.dumps(p1_json),
            p2=json.dumps(p2_json),
            p3=json.dumps(p3_json),
            data_idx=data_idx
        )

        root_file = Path("../client/integration_glue.html")
        self.assertTrue(root_file.exists())

        abs_path = root_file.absolute()
        self.firefox_driver.get("file://" + str(abs_path))
        try:
            self.firefox_driver.execute_script(script)
        except:
            self.assertTrue(False,msg=script)

        c1_b64 = self.firefox_driver.execute_script("return window.integration.results.createAnalysisRequestData.c1;")
        c2_b64 = self.firefox_driver.execute_script("return window.integration.results.createAnalysisRequestData.c2;")
        c3_b64 = self.firefox_driver.execute_script("return window.integration.results.createAnalysisRequestData.c3;")

    @staticmethod
    def pem_to_jwt(pem_path: Path):
        assert pem_path.exists()

        with pem_path.open() as pem:
            pem_raw = pem.read()
            pem_parsed = RSA.import_key(pem_raw)
            e_width = ceil(log2(pem_parsed.e) / 8)
            n_width = ceil(log2(pem_parsed.n) / 8)
            e_bytes = pem_parsed.e.to_bytes(length=e_width, byteorder="big")
            n_bytes = pem_parsed.n.to_bytes(length=n_width, byteorder="big")

            e_64 = base64.urlsafe_b64encode(e_bytes).decode("ascii")
            n_64 = base64.urlsafe_b64encode(n_bytes).decode("ascii")

            # the python urlsafe bas64 is not actually url safe
            # as '=' is not stripped with breaks the crypto API in JS.
            # Yet, the crypto API is not compliant with RFC 7517, which allows "=" in the encoding...
            e_64 = e_64.rstrip("=")
            n_64 = n_64.rstrip("=")

            return {
                "kty": "RSA",
                "alg": "RSA-OAEP-256",
                "kid": "integration_test_key",
                "key_ops": ["encrypt"],
                "e": e_64,
                "n": n_64,
                "ext": True
            }