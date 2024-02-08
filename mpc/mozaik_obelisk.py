import requests

class MozaikObelisk:
    def __init__(self, base_url):
        self.base_url = base_url

    def get_data(self, user_id, data_index):
        endpoint = '/getData'

        # Construct the full URL with parameters
        url = f'{self.base_url}{endpoint}?user_id={user_id}&data_index={data_index}'

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
        endpoint = '/getKeyShare'

        # Construct the full URL with parameters
        url = f'{self.base_url}{endpoint}?user_id={analysis_id}'

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

