import requests
import base64
import time

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

    def get_data(self, analysis_id, user_id, data_index):
        """
        Get data for inference from the Mozaik Obelisk.

        Arguments:
            user_id (str) : The ID of the user.
            data_index (list) : A list of 2 elements, starting and end index of the data requested.

        Returns:
            A tuple containing the status and the user data.
        """

        # Check token expiry before making the request
        self.check_token()

        # Construct the endpoint with the analysis ID

        endpoint = f"/analysis/data/query/{analysis_id}"

        # Prepare the request body
        request_body = {
            "user_id": user_id,
            "data_index": data_index
        }

        # Make the POST request to the endpoint
        try:
            response = requests.post(
                f"{self.base_url}{endpoint}",
                json=request_body,
                headers={
                    "authorization": self.auth_token  
                }
            )

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse and return the user data from the JSON response
                user_data = response.json().get('user_data')
                if isinstance(user_data, list):
                    return "OK", user_data
                else:
                    return "Error", "ERROR: User data is not in the expected format (array)"
            else:
                # Return an error message if the request was not successful
                return "Error", response
        except requests.RequestException as e:
            # Return an error message if the request encountered an exception
            return "Exception", e

    def get_key_share(self, analysis_id):
        """
        Get key share from the Mozaik Obelisk. 

        Arguments:
            analysis_id (str) : The ID of the analysis.

        Returns:
            A tuple containing the status and the key share in bytes form.
        """

        # Check token expiry before making the request
        self.check_token()

        endpoint = f'/mpc/keys/share/{analysis_id}'

        # Construct the full URL with parameters
        url = f'{self.base_url}{endpoint}'

        try:
            # Make the GET request
            response = requests.get(url, headers={"authorization": self.auth_token})

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse and return the user_data from the JSON response
                key_share = response.json().get('key_share')
                if isinstance(key_share, str):
                    # If key_share is a string, assume it's a hexadecimal representation and convert to bytes
                    key_share = bytes.fromhex(key_share)
                elif not isinstance(key_share, bytes):
                    # If key_share is not bytes or a string, raise an error
                    return "Error", f"ValueError: key_share obtained in wrong format: {type(key_share)}"
                
                return "OK", key_share
            else:
                # Return an error message if the request was not successful
                return "Error", response
        except requests.RequestException as e:
            # Return an error message if the request encountered an exception
            return "Exception", e

    def store_result(self, analysis_id, user_id, result):
        """
        POST method to store result in the Mozaik Obelisk service.

        Arguments:
            analysis_id (str) : The ID of the analysis.
            user_id (str) : The ID of the user.
            result (str) : The result to store.

        Returns:
            A tuple containing the status and the response.
        """
        endpoint = f'/analysis/result/{analysis_id}'

        # Construct the full URL
        url = f'{self.base_url}{endpoint}'

        # Define the payload (data to be sent in the POST request)
        payload = {
            'user_id': user_id,
            'result': result,
            'is_combined': True
        }

        try:
            # Make the POST request
            response = requests.post(url, json=payload, headers={"authorization": self.auth_token})

            # Check if the request was successful (status code 200)
            if response.status_code == 204:
                # Parse and return any relevant information from the JSON response
                return "OK", response
            else:
                # Return an error message if the request was not successful
                return "Error", response
        except requests.RequestException as e:
            # Return an error message if the request encountered an exception
            return "Exception", e

