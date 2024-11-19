#!python3
import click
import requests
import json
import os

from elasticsearch import Elasticsearch, helpers
from common.panopto_oauth2 import PanoptoOAuth2  # Import the OAuth2 module
#from prometheus_client import start_http_server, Summary


# Constants for Elasticsearch configuration
ELASTICSEARCH_HOST = "localhost"
ELASTICSEARCH_PORT = 9200
ELASTICSEARCH_INDEX = "panopto_sessions"
TEMP_PAGE_FILE = "current_page.txt"

# Oauth2 authentication variable
oauth2: PanoptoOAuth2

# Global Panopto vars
server: str

# Create a metric to track time spent and requests made.
#REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')

def save_current_page(page_number: int):
    """
    Save the current page number to a temporary file.

    Args:
        page_number (int): The current page number to save.
    """
    with open(TEMP_PAGE_FILE, 'w') as f:
        f.write(str(page_number))

def load_current_page():
    """
    Load the current page number from a temporary file.

    Returns:
        int: The current page number, or 0 if the file does not exist.
    """
    if os.path.exists(TEMP_PAGE_FILE):
        with open(TEMP_PAGE_FILE, 'r') as f:
            return int(f.read().strip())
    return 0

def remove_current_page_file():
    """
    Remove the temporary file that stores the current page number.
    """
    if os.path.exists(TEMP_PAGE_FILE):
        os.remove(TEMP_PAGE_FILE)

#@REQUEST_TIME.time()
def get_all_sessions(requests_session, server:str, dry_run:bool=False, debug:bool=False):
    """
    Retrieve all sessions from the Panopto API and index them to Elasticsearch.

    Args:
        requests_session (requests.Session): The session object to make HTTP requests.
        oauth2 (PanoptoOAuth2): The OAuth2 authentication object.
        server (str): The Panopto server URL (without https://).
        dry_run (bool): If True, outputs data to stdout instead of sending to Elasticsearch.
        debug (bool): If True, enables debug output.

    Returns:
        list: A list of sessions retrieved from the API.
    """
    sessions_url = f"https://{server}/Panopto/api/v1/sessions/search"
    
    sessions = []
    page_number = load_current_page()

    while True:
        response = requests_session.get(sessions_url, params={
            'searchQuery': '*',
            'pageNumber': page_number,
            'sortField': 'CreatedDate',
            'sortOrder': 'Asc'
        })
        
        # When 401 unauthenticated is returned reauthenticate and return to start of loop
        if inspect_response_is_unauthorized(response):
            authorization(requests_session, oauth2)
            continue
        
        if debug:
            print("Sessions API Response:", json.dumps(response.json(), indent=2))
        
        data = response.json()
        sessions = data.get('Results', [])
        
        # Check if we have more pages
        if not sessions:  # If no more sessions, break the loop
            remove_current_page_file()
            break
        else:
            save_current_page(page_number)
            index_sessions_to_elasticsearch(sessions, requests_session, server, dry_run, debug)
        
        
        page_number += 1

    return sessions

def get_recording_info(session_id: str, server:str, requests_session, debug:bool=False):
    """
    Retrieve recording information for a specific session.

    Args:
        session_id (str): The ID of the session to retrieve recording info for.
        requests_session (requests.Session): The session object to make HTTP requests.
        server (str): The Panopto server URL (without https://).
        debug (bool): If True, enables debug output.

    Returns:
        dict: The recording information for the session.
    """
    recording_url = f"https://{server}/Panopto/api/v1/scheduledRecordings/{session_id}"
    response = requests_session.get(recording_url)

    # When 401 unauthenticated is returned reauthenticate and retry request
    if inspect_response_is_unauthorized(response):
        authorization(requests_session, oauth2)
        response = requests_session.get(recording_url)
            

    if debug:
        print(f"Recording Info for session {session_id}:", json.dumps(response.json(), indent=2))
        
    return response.json()

def index_sessions_to_elasticsearch(sessions, server:str, requests_session, dry_run, debug=False):
    """
    Index the retrieved sessions into Elasticsearch.

    Args:
        sessions (list): A list of session dictionaries to index.
        requests_session (requests.Session): The session object to make HTTP requests.
        server (str): The Panopto server URL (without https://).
        dry_run (bool): If True, outputs session data to stdout instead of sending to Elasticsearch.
        debug (bool): If True, enables debug output.
    """
    for session in sessions:
        # Fetch recording info for each session
        recording_info = get_recording_info(session['Id'], requests_session, server, debug)
        session['recordings'] = recording_info  # Attach recording info to session
        
        if dry_run:
            # Output the session data to stdout instead of sending to Elasticsearch
            print(json.dumps(session, indent=2))
        else:
            # Send to Elasticsearch
            es = Elasticsearch([
                {
                    'host': ELASTICSEARCH_HOST, 
                    'port': ELASTICSEARCH_PORT,
                    'scheme': 'https'
                }], verify_certs=False, basic_auth=['elastic', 'changeme'])
            action = {
                "_index": ELASTICSEARCH_INDEX,
                "_id": session['Id'],
                "_source": session
            }
            helpers.bulk(es, [action])

def authorization(requests_session):
    """
    Update the request session headers with an OAuth2 access token.

    Args:
        requests_session (requests.Session): The session object to make HTTP requests.
        oauth2 (PanoptoOAuth2): The OAuth2 authentication object.
    """
    access_token = oauth2.get_access_token_authorization_code_grant()
    requests_session.headers.update({'Authorization': 'Bearer ' + access_token})

def inspect_response_is_unauthorized(response):
    '''
    Inspect the response of a request's call, and return True if the response was Unauthorized.
    An exception is thrown at other error responses.
    Reference: https://stackoverflow.com/a/24519419
    '''
    if response.status_code // 100 == 2:
        # Success on 2xx response.
        return False

    if response.status_code == requests.codes.unauthorized:
        print('Unauthorized. Access token is invalid.')
        return True

    # Throw unhandled cases.
    # response.raise_for_status()

@click.command()
@click.option('--server', required=True, help='Panopto Server URL (without https://)')
@click.option('--client_id', required=True, help='Panopto API Client ID')
@click.option('--client_secret', required=True, help='Panopto API Client Secret')
@click.option('--es_host', required=False, help='Elasticsearch host to connect to')
@click.option('--debug', is_flag=True, help='Enable debug output')
@click.option('--dry_run', is_flag=True, help='Output data to stdout instead of sending to Elasticsearch')
def main(server, client_id, client_secret, es_host, debug, dry_run):
    """
    Main entry point for the script to retrieve sessions from Panopto and index them to Elasticsearch.

    Args:
        server (str): The Panopto server URL (without https://).
        client_id (str): The Panopto API Client ID.
        client_secret (str): The Panopto API Client Secret.
        debug (bool): If True, enables debug output.
        dry_run (bool): If True, outputs data to stdout instead of sending to Elasticsearch.
    """
    global oauth2
    global ELASTICSEARCH_HOST

    if es_host is not None:
        ELASTICSEARCH_HOST = es_host
        
    print(ELASTICSEARCH_HOST)

    requests_session = requests.Session()
    requests_session.verify = True
     
    print(client_id + ' secret ' + client_secret)
    oauth2 = PanoptoOAuth2(server, client_id, client_secret, ssl_verify=True)

    authorization(requests_session)
    get_all_sessions(requests_session, server, dry_run, debug)

if __name__ == "__main__":
    #start_http_server(8000)
    main(auto_envvar_prefix='PANOPTO')
