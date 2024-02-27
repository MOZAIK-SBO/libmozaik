import requests
import urllib.parse

class MozaikObelisk:
    """
    MozaikObelisk class interacts with the Mozaik Obelisk.

    Attributes:
        base_url : The IP address of the Mozaik Obelisk node.
    """
    def __init__(self, base_url):
        """
        Initialize MozaikObelisk with the provided base URL.

        Args:
            base_url (str) : The base URL of the Mozaik Obelisk.
        """
        self.base_url = base_url

    def get_data(self, user_id, data_index):
        """
        Get data for inference from the Mozaik Obelisk. The GET identifier data are sent as query parameters in the URL.

        Arguments:
            user_id (str) : The ID of the user.
            data_index (list) : A list of 2 elements, starting and end index of the data requested.

        Returns:
            A tuple containing the status and the user data.
        """
        endpoint = '/getData'

        # Encode the data_index list as a UTF-8 string
        data_index_encoded = urllib.parse.urlencode({'data_index': data_index}, doseq=True)

        # Construct the full URL with parameters
        url = f'{self.base_url}{endpoint}?user_id={user_id}&data_index={data_index_encoded}'

        try:
            # Make the GET request
            response = requests.get(url)

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse and return the user_data from the JSON response
                return "OK", response.json().get('user_data')
            else:
                # Returnn an error message if the request was not successful
                return "Error", response
        except requests.RequestException as e:
            # Return an error message if the request encountered an exception
            return "Exception", e

    def get_key_share(self, analysis_id):
        """
        Get key share from the Mozaik Obelisk. 

        Argumentss:
            analysis_id (str) : The ID of the analysis.

        Returns:
            A tuple containing the status and the key share.
        """
        endpoint = f'/getKeyShare/{analysis_id}'

        # Construct the full URL with parameters
        url = f'{self.base_url}{endpoint}'

        try:
            # Make the GET request
            response = requests.get(url)

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse and return the user_data from the JSON response
                return "OK", response.json().get('key_share')
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
        endpoint = '/storeResult'

        # Construct the full URL
        url = f'{self.base_url}{endpoint}'

        # Define the payload (data to be sent in the POST request)
        payload = {
            'analysis_id': analysis_id,
            'user_id': user_id,
            'result': result
        }

        try:
            # Make the POST request
            response = requests.post(url, json=payload)

            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse and return any relevant information from the JSON response
                return "OK", response.json()
            else:
                # Return an error message if the request was not successful
                return "Error", response
        except requests.RequestException as e:
            # Return an error message if the request encountered an exception
            return "Exception", e

