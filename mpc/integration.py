import unittest
import json
import base64

from datetime import datetime
from typing import Dict, Tuple
from math import log2, ceil
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from Crypto.PublicKey import RSA
from key_share import MpcPartyKeys, decrypt_key_share


class IntegrationTest(unittest.TestCase):
    __slots__ = ["opts_dict", "firefox_options", "firefox_driver"]

    @classmethod
    def setUp(cls):
        cls.opts_dict = {
            "general.warnOnAboutConfig": False,
            "browser.aboutConfig.showWarning": False,
            "security.fileuri.strict_origin_policy": False
        }

        cls.firefox_options = Options()
        cls.firefox_options.add_argument("--headless")
        cls.firefox_options.add_argument('window-size=1920x1080')

        firefox_profile = webdriver.FirefoxProfile()
        for key, value in cls.opts_dict.items():
            firefox_profile.set_preference(key, value)
        cls.firefox_options.profile = firefox_profile
        cls.firefox_driver = webdriver.Firefox(options=cls.firefox_options)

    def test_trivial(self):
        """
        Checks whether the webdriver works and can load the glue html file
        :return:
        """
        root_file = Path("assets/integration_test_glue/integration_glue.html")
        self.assertTrue(root_file.exists())

        abs_path = root_file.absolute()
        self.firefox_driver.get("file://" + str(abs_path))
        self.assertTrue("html" in self.firefox_driver.title.lower())

    def test_createAnalysisRequestData(self):
        """
        Checks whether the key shares created by the client can be decrypted by the server side
        and checks whether the shares were set up properly
        """
        user_id = "4d14750e-2353-4d30-ac2b-e893818076d2"
        data_idx = ["2024-01-24T12:00:00", "2024-01-24T12:00:01", "2024-01-24T12:00:02", "2024-01-24T12:00:03",
                    "2024-01-24T12:00:04", "2024-01-24T12:00:05", "2024-01-24T12:00:06", "2024-01-24T12:00:07",
                    "2024-01-24T12:00:08", "2024-01-24T12:00:09"]
        date_format = "%Y-%m-%dT%H:%M:%S"
        date_parsed = [datetime.strptime(date, date_format) for date in data_idx]
        date_timestamps = [round(date.timestamp()) for date in date_parsed]

        # normal values that are not part of the key dont need urlsafe base64 unlike the key. We love consistency :)))
        iot_key_bytes = bytes(
            [0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01])
        iot_key = base64.b64encode(iot_key_bytes).decode("ascii").rstrip("=")

        algorithm = "AES-GCM-128"
        key_path = Path("assets/integration_test_keys")
        analysis_type="Heartbeat-Demo-1"

        p1_key_path = key_path / "party_key_1.pem"
        p2_key_path = key_path / "party_key_2.pem"
        p3_key_path = key_path / "party_key_3.pem"

        key1, p1_json = self.pem_to_jwt(p1_key_path)
        key2, p2_json = self.pem_to_jwt(p2_key_path)
        key3, p3_json = self.pem_to_jwt(p3_key_path)

        c1, c2, c3 = self.createAnalysisRequestHook(user_id, iot_key, algorithm, p1_json, p2_json, p3_json, analysis_type, data_idx)

        ciphertexts = [c1,c2,c3]
        shares = []
        for i in range(3):
            keys = MpcPartyKeys(IntegrationTest.get_config(i))
            ct = ciphertexts[i]
            key_share = decrypt_key_share(keys, user_id, "AES-GCM-128", date_timestamps, analysis_type, ct)
            shares.append(key_share)

        result = [a ^ b ^ c for a, b, c in zip(*shares)]
        self.assertListEqual(list(result), list(iot_key_bytes))


        # TODO: here comes decrypt_key_share

    def createAnalysisRequestHook(self, user_id, iot_key, algorithm, p1_key_json, p2_key_json,
                                  p3_key_json, analysis_type, data_indices) -> Tuple[bytes,bytes,bytes]:
        """
        Function that calls the method of the same name in JS and recovers the (hopefully correct) outputs
        :param _: all parameters play the same role as in the JS equivalent
        :return: three encrypted shared 1 per party
        """
        script_template = """
            window.integration.createAnalysisRequestData(
                "{uid}",
                "{iot_key}",
                "{alg}",
                {p1},
                {p2},
                {p3},
                "{analysis_type}",
                {data_idx}
            );
        """

        script = script_template.format(
            uid=user_id,
            iot_key=iot_key,
            alg=algorithm,
            p1=json.dumps(p1_key_json),
            p2=json.dumps(p2_key_json),
            p3=json.dumps(p3_key_json),
            analysis_type=analysis_type,
            data_idx=data_indices
        )

        root_file = Path("assets/integration_test_glue/integration_glue.html")
        self.assertTrue(root_file.exists())

        abs_path = root_file.absolute()
        self.firefox_driver.get("file://" + str(abs_path))

        try:
            self.firefox_driver.execute_script(script)
        except Exception as e:
            import sys
            sys.stderr.write(script)
            sys.stderr.flush()
            self.firefox_driver.close()
            self.fail(msg="Webdriver threw exception :( {}".format(e))

        c1_b64: str = self.firefox_driver.execute_script(
            "return window.integration.results.createAnalysisRequestData.c1;")
        c2_b64: str = self.firefox_driver.execute_script(
            "return window.integration.results.createAnalysisRequestData.c2;")
        c3_b64: str = self.firefox_driver.execute_script(
            "return window.integration.results.createAnalysisRequestData.c3;")

        # Restore correct padding
        c1_b64 = c1_b64.strip()
        c1_b64 += "=" * ((4 - len(c1_b64)) % 4)
        c1: bytes = base64.urlsafe_b64decode(c1_b64)

        c2_b64 = c2_b64.strip()
        c2_b64 += "=" * ((4 - len(c2_b64)) % 4)
        c2: bytes = base64.urlsafe_b64decode(c2_b64)

        c3_b64 = c3_b64.strip()
        c3_b64 += "=" * ((4 - len(c3_b64)) % 4)
        c3: bytes = base64.urlsafe_b64decode(c3_b64)

        return c1, c2, c3

    @staticmethod
    def pem_to_jwt(pem_path: Path) -> Tuple[RSA.RsaKey, Dict]:
        """
        Takes a Path object parses the file it points to, and returns the RSAKey object and a JWK containing the public part
        :param pem_path: the path to the PEM file
        :return: RSAKey object containing the key and a json/dict containing the public info of the key
        """
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

            return pem_parsed, {
                "kty": "RSA",
                "alg": "RSA-OAEP-256",
                "kid": "integration_test_key",
                "key_ops": ["encrypt"],
                "e": e_64,
                "n": n_64,
                "ext": True
            }
    @staticmethod
    def get_config(party_index):
        party_keys = ['assets/integration_test_keys/party_key_pub_1.pem',
                      'assets/integration_test_keys/party_key_pub_2.pem',
                      'assets/integration_test_keys/party_key_pub_3.pem']
        return {
            "server_key": f'assets/integration_test_keys/party_key_{party_index+1}.pem',
            "server_cert": f'assets/integration_test_keys/party_key_pub_{party_index+1}.pem',
            "party_index": party_index,
            "party_certs": party_keys
        }