from requests_oauthlib import OAuth2Session
import imaplib
import re
import json
import sys

TOKENS_FILENAME = 'oauth_tokens.json'
# download from google cloud console
OAUTH_CONF_FILENAME = 'client_secret.json'

# TODO refresh token

oauth = None
imap = imaplib.IMAP4_SSL('imap.gmail.com')


def configure_oauth(conf):
    global oauth
    oauth = OAuth2Session(
            conf.get('client_id'),
            redirect_uri=conf.get('redirect_uris')[0],
            scope='https://mail.google.com/'
    )


def get_auth_tokens(secret):
    authorization_url, state = oauth.authorization_url(
            'https://accounts.google.com/o/oauth2/v2/auth',
            access_type="offline"
    )
    print(f'To authorize access go to \n\n{authorization_url}\n')
    auth_res = input('Enter the full callback URL\n')
    token = oauth.fetch_token(
            'https://accounts.google.com/o/oauth2/token',
            authorization_response=auth_res,
            client_secret=secret
    )
    return token


def save_json_to_file(tokens_data, filename):
    with open(filename, 'w') as f:
        json.dump(tokens_data, f)


def load_json_from_file(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None


# Gmail API instead of IMAP has the advantage of using a narrower
# auth scope for the same functionality.
# IMAP logic is reusable for many providers though.
def connect_to_gmail(email_address, access_token):
    """Connect to Gmail using IMAP with OAuth2."""
    # XOAUTH2 string
    auth_string = f"user={email_address}\x01auth=Bearer {access_token}\x01\x01"
    try:
        imap.authenticate('XOAUTH2', lambda x: auth_string)
        print('Successfully authenticated with Gmail!')
    except imaplib.IMAP4.error as e:
        print(f"IMAP authentication failed: {e}")


def get_senders(folder='INBOX', *, batch_size=100):
    """return all email addresses in the 'from' field"""
    status, data = imap.select(folder, readonly='True')
    if status != 'OK':
        print('imap select error')
        return
    status, data = imap.search(None, 'ALL')
    if status != 'OK':
        print('imap search error')
        return
    senders = set()
    ids = data[0].split()
    print(f"Analyzing {len(ids)} emails...\n")
    for i in range(0, len(ids), batch_size):
        batch_ids = b','.join(ids[i:i+batch_size]).decode('UTF-8')
        typ, data = imap.fetch(batch_ids, 'BODY.PEEK[HEADER.FIELDS (FROM)]')
        for d in data:
            if not isinstance(d, tuple):
                # fetching multiple messages returns an array containing
                # 'separator elements' like `b')'`
                continue
            from_field = d[1].decode('UTF-8')
            email = extract_email(from_field)
            if email is None:
                print(f"warning: no email found in {from_field}")
                continue
            senders.add(email)
    return senders


def extract_email(text):
    pattern = r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'
    match = re.search(pattern, text)
    if match:
        return match.group(1)
    else:
        return None


if __name__ == "__main__":
    if len(sys.argv) == 1 or extract_email(sys.argv[1]) is None:
        print('usage: python mail.py EMAIL')
        sys.exit()
    oauth_config = load_json_from_file(OAUTH_CONF_FILENAME).get('installed')
    configure_oauth(oauth_config)
    tokens = load_json_from_file(TOKENS_FILENAME)
    if tokens is None:
        tokens = get_auth_tokens(oauth_config.get('client_secret'))
        save_json_to_file(tokens, TOKENS_FILENAME)
    connect_to_gmail(sys.argv[1], tokens['access_token'])
    senders = get_senders()
    for s in senders:
        print(s)
    print(f"\nFound {len(senders)} senders")
    imap.close()
    imap.logout()
