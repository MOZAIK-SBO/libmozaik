import requests
import base64
import time
from config import ProcessException

class MozaikObelisk:
    """
    MozaikObelisk class interacts with the Mozaik Obelisk.

    Attributes:
        base_url : The IP address of the Mozaik Obelisk node.
    """
    def __init__(self, base_url, server_id, server_secret):
        """
        Initialize MozaikObelisk with the provided base URL.

        Args:
            base_url (str) : The base URL of the Mozaik Obelisk.
            auth_token (str) : The JWT token to authorise to Obelisk
        """
        self.base_url = base_url
        self.server_id = server_id
        self.server_secret = server_secret
        self.auth_token = self.request_jwt_token(server_id, server_secret)
        self.token_timestamp = time.time()

    def request_jwt_token(self, server_id, server_secret):
        """
        Function for requesting JWT token for authorization in future HTTP calls to Obelisk

        Arguments:
            server_id (str) : The id of the server 
            server_secret (str) : The secret used to generate JWT
        """
        # Encode the server ID and server secret for the Authorization header
        auth_header = base64.b64encode(f"{server_id}:{server_secret}".encode()).decode()

        # Define the URL for token request
        token_url = "https://mozaik.ilabt.imec.be/auth/realms/obelisk/protocol/openid-connect/token"

        # Define the headers
        headers = {
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        # Define the data for the POST request
        data = {
            "grant_type": "client_credentials"
        }

        try:
            # Make the POST request to get the token
            response = requests.post(token_url, headers=headers, data=data)

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse and return the JWT token from the JSON response
                return f"Bearer {response.json().get('access_token')}"
            else:
                raise Exception(f"Failed to request JWT token: {response.status_code} - {response.text}")
        except requests.RequestException as e:
            raise Exception(f"Error requesting JWT token: {e}")
        
    def check_token(self):
        """
        Check if the JWT token has expired, if it has request a new one.
        """
        # Check if the token has been initialized and if it's been more than 5 minutes since its creation
        if time.time() - self.token_timestamp > 240:
            # Token is about to expire, generate a new one
            self.auth_token = self.request_jwt_token(self.server_id, self.server_secret)
            self.token_timestamp = time.time()  # Update the token timestamp

    def get_data(self, analysis_ids, user_ids, data_indeces):
        """
        Get data for inference from the Mozaik Obelisk.

        Arguments:
            analysis_id (list) : The list of ID(s) of the analyses(s).
            user_id (list) : The list of ID(s) of the user(s).
            data_index (list) : A list of lists of 2 elements, starting and end index of the data requested.

        Returns:
            A list of lists containing the user data (each sublist corresponds to data from a different user_id).
        """

        # Check token expiry before making the request
        self.check_token()

        # Construct the endpoint with the analysis ID

        endpoint = f"/analysis/data/query"

        # Prepare the request body
        payload = {
            'analysis_id':analysis_ids,
            "user_id": user_ids,
            "data_index": data_indeces
        }

        # Make the POST request to the endpoint
        try:
            response = requests.post(
                f"{self.base_url}{endpoint}",
                json=payload,
                headers={
                    "authorization": self.auth_token  
                }
            )

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse and return the user data from the JSON response
                user_data = response.json().get('user_data')
                if isinstance(user_data, list):
                    batch_size = sum(len(sub_array) for sub_array in user_data)
                    try:
                        assert batch_size == 1 or batch_size == 2 or batch_size == 4 or batch_size == 64 or batch_size == 128
                    except AssertionError as e:
                        raise ProcessException(analysis_ids, 500, f'The current supported batch_size are: 1,2,4,64 and 128. Received number of samples: {batch_size}. {e}')
                    return user_data
                else:
                    raise ProcessException(analysis_ids, 500, f'ERROR: User data is not in the expected format (array)')
                    # return "Error", "ERROR: User data is not in the expected format (array)"
            else:
                # Return an error message if the request was not successful
                raise ProcessException(analysis_ids, 500, f'ERROR: {response}')
                # return "Error", response
        except requests.RequestException as e:
            # Return an error message if the request encountered an exception
            raise ProcessException(analysis_ids, 500, f'ERROR: {e}')
            # return "Exception", e

    def get_key_share(self, analysis_ids):
        """
        Get key share from the Mozaik Obelisk. 

        Arguments:
            analysis_id (list) : The list of ID(s) of the analyses(s).

        Returns:
            A list containing the key shares in bytes form (each item corresponds to share for a different user_id).
        """

        # Check token expiry before making the request
        self.check_token()

        endpoint = f'/mpc/keys/share'

        # Construct the full URL with parameters
        url = f'{self.base_url}{endpoint}'

        payload = {
            'analysis_id':analysis_ids,
        }

        try:
            # Make the GET request
            response = requests.post(url, json=payload, headers={"authorization": self.auth_token})

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse and return the user_data from the JSON response
                key_shares = response.json().get('key_share')
                if isinstance(key_shares, list) and all(isinstance(share, str) for share in key_shares):
                    # Convert each string in the list to bytes
                    key_shares = [bytes.fromhex(share) for share in key_shares]
                elif not all(isinstance(share, bytes) for share in key_shares):
                        # If key_shares is not all bytes or strings, raise an error
                        raise ProcessException(analysis_ids, 500, f"ValueError: key_shares obtained in wrong format: {type(key_shares)}, or individual key shares: {type(key_shares[0])}")

                return key_shares
            else:
                # Return an error message if the request was not successful
                raise ProcessException(analysis_ids, 500, f"ERROR: {response}")
                # return "Error", response
        except requests.RequestException as e:
            # Return an error message if the request encountered an exception
            raise ProcessException(analysis_ids, 500, f"ERROR: {e}")
            # return "Exception", e

    def store_result(self, analysis_ids, user_ids, results):
        """
        POST method to store result in the Mozaik Obelisk service.

        Arguments:
            analysis_id (list) : The list of ID(s) of the analyses(s).
            user_id (list) : The list of ID(s) of the user(s).
            result (list) : List of results to store (each item corresponds to a ciphertext corresponding to result for a specific user_id).
        """
        endpoint = f'/analysis/result'

        # Construct the full URL
        url = f'{self.base_url}{endpoint}'

        # Define the payload (data to be sent in the POST request)
        payload = {
            'analysis_id':analysis_ids,
            'user_id': user_ids,
            'result': results,
            'is_combined': True
        }

        try:
            # Make the POST request
            response = requests.post(url, json=payload, headers={"authorization": self.auth_token})

            # Check if the request was successful (status code 200)
            if response.status_code != 204:
                # Return an error message if the request was not successful
                raise ProcessException(analysis_ids, 500, f"ERROR: {response}")
                # return "Error", response
        except requests.RequestException as e:
            # Return an error message if the request encountered an exception
            raise ProcessException(analysis_ids, 500, f"ERROR: {e}")
            # return "Exception", e

