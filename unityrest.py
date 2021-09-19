import json
import pandas as pd
import requests, urllib3
from datetime import datetime
from ldap3 import Server, Connection, SUBTREE, SAFE_SYNC

urllib3.disable_warnings()

HOST = '10.54.162.110'
USERNAME = 'admin'
PASSWORD = 'P@ssw0rd'

LDAP_SERVER = '10.54.162.184'
LDAP_USERNAME = 'RDC\Administrator'
LDAP_PASSWORD = 'P@ssw0rd'
LDAP_BASE = 'CN=Users,DC=RDC,DC=IL'

def start_unity_rest_session(host, username, password):
    global BASE_URL
    BASE_URL = 'https://' + host

    cookieJar = requests.cookies.RequestsCookieJar()
    session = requests.Session()
    headers = {'Content-type': 'application/json','Accept': 'application/json','X-EMC-REST-CLIENT': 'true'}
    login_url = '/api/types/loginSessionInfo'
    url = BASE_URL + login_url

    response = session.get(url, verify=False, auth=(username, password), headers=headers, cookies=cookieJar)
    CSRFT = response.headers['EMC-CSRF-TOKEN']
    headers['EMC-CSRF-TOKEN'] = CSRFT
    
    return cookieJar, session, headers

def get_fs_details(cookieJar, session, headers):
    out = {}
    Fields = 'id,name'
    url = BASE_URL + '/api/types/filesystem/instances?fields=' + Fields
    
    response = session.get(url, verify=False, headers=headers, cookies=cookieJar)
    json_response = json.loads(response.text)

    for fs_ent in json_response['entries']:
        id = fs_ent['content']['id']
        name = fs_ent['content']['name']
        out[id] = name
    
    return out

def get_username(uid, ldap_server, ldap_username, ldap_password, ldap_base):
    server = Server(ldap_server)
    connection = Connection(server, ldap_username, ldap_password, client_strategy=SAFE_SYNC, auto_bind=True)
    results = connection.extend.standard.paged_search(  search_base = ldap_base,
                                                        search_filter = '(uidNumber=' + uid +')',
                                                        search_scope = SUBTREE,
                                                        attributes = ['cn'],
                                                        paged_size = 5,
                                                        generator=False)
    return results[0]['attributes']['cn']


def get_quota_details(cookieJar, session, headers):
    out = []
    fs = get_fs_details(cookieJar, session, headers)
    Fields = 'filesystem,uid,hardLimit,softLimit,sizeUsed'
    url = BASE_URL + '/api/types/userQuota/instances?fields=' + Fields
    
    response = session.get(url, verify=False, headers=headers, cookies=cookieJar)
    json_response = json.loads(response.text)

    for q_ent in json_response['entries']:
        fsName = fs[q_ent['content']['filesystem']['id']]
        q_ent['content']['filesystem'] = fsName
        q_ent['content']['hardLimit'] = int(q_ent['content']['hardLimit']) / pow(1024,3)
        q_ent['content']['softLimit'] = int(q_ent['content']['softLimit']) / pow(1024,3)
        q_ent['content']['sizeUsed'] = int(q_ent['content']['sizeUsed']) / pow(1024,3)
        q_ent['content']['username'] = get_username(str(q_ent['content']['uid']), LDAP_SERVER, LDAP_USERNAME, LDAP_PASSWORD, LDAP_BASE)
        out.append(q_ent['content'])
    return out

def main():
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%dT%H_%M")
    cookieJar, session, headers = start_unity_rest_session(HOST, USERNAME, PASSWORD)
    df = pd.DataFrame(get_quota_details(cookieJar, session, headers))
    df.to_csv(timestamp + '.csv', index=False)
    

if __name__ == '__main__':
    main()