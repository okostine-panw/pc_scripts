import requests
import os
import datetime
import csv
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# token =''
never_login_after_days = 900
not_active_days = 1220
instance_url = 'https://api2.prismacloud.io'
def get_token(instance_url):
    # Path to your CSV file
    file_path = './access_key.csv'
    # Read the keys from the file
    keys = read_access_keys(file_path)
    # Extract the specific keys
    prisma_user = keys.get('Access Key ID')
    api_key = keys.get('Secret Key')
    login_url = f"{instance_url}/login"
    headers = {
        "Content-Type": "application/json",
    }
    data_post = {
        "username": prisma_user,
        "password": api_key,
    }
    try:
        response_post = requests.post(login_url, headers=headers, json=data_post, verify=False)
        response_post.raise_for_status()
        post_response_data = response_post.json()
        token = post_response_data.get('token')
        return token
    except requests.exceptions.RequestException as e:
        print(Fore.RED + "Error during API call:", e)
        return None

def read_access_keys(file_path):
    with open(file_path, mode='r') as file:
        reader = csv.reader(file)
        keys = {rows[0]: rows[1] for rows in reader}
    return keys
def get_user_details(token, user_id):
    url = f"https://api2.prismacloud.io/user/{user_id}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": token
    }
    response = requests.get(url, headers=headers)
    # print(response)
    return response.json()

def get_users(token):
    url = f"https://api2.prismacloud.io/user/name"
    headers = {
        "Content-Type": "application/json",
        "Authorization": token
    }
    response = requests.get(url, headers=headers)
    # print(response)
    return response.json()


def delete_user(token, user_login):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': token
    }
    url = f"https://api2.prismacloud.io/user/{user_login}"
    # run print first for testing
    # print(url, headers)

    # Delete users
    try:
        response = requests.delete(url, headers=headers)
        if response.status_code == 200:
            print(f"User {user_login} deleted successfully.")
        else:
            response.raise_for_status()  # This will raise an HTTPError for bad responses
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err} - {response.text}")
    except Exception as err:
        print(f"Other error occurred: {err}")

def check_inactivity(last_login):
    if str(last_login) == "-1":
        return False  # Retain users with lastLoginTs as "-1"
    last_login_time = datetime.datetime.fromtimestamp(last_login / 1000.0)
    threshold = datetime.timedelta(days=never_login_after_days)  # Adjust threshold as needed
    return (datetime.datetime.now() - last_login_time) > threshold

def check_never_logged_on_and_old(last_modified):
    last_modified_time = datetime.datetime.fromtimestamp(last_modified / 1000.0)
    threshold = datetime.timedelta(days=not_active_days)
    return (datetime.datetime.now() - last_modified_time) > threshold

def main():
    token = get_token(instance_url)
    users = get_users(token)
    for user in users:
        user_id = user["id"]
        user_details = get_user_details(token, user_id)
        user_login = user_details.get("email")
        last_login = user_details.get("lastLoginTs")
        last_modified = user_details.get("lastModifiedTs")

        if user_login:
            if str(last_login) == "-1" and last_modified and check_never_logged_on_and_old(last_modified):
                last_modified_time = datetime.datetime.fromtimestamp(last_modified / 1000.0)
                print(f"Deleting User: {user_login}, never logged on, last modified {last_modified_time}.")
                confirm = input("Are you sure you want to delete this user? (yes/no): ").strip().lower()
                if confirm == 'yes':
                    delete_user(token, user_login)
                else:
                    print("Deletion cancelled.")
            elif last_login not in (None, "-1") and check_inactivity(last_login):
                last_login_time = datetime.datetime.fromtimestamp(last_login / 1000.0)
                print(f"Deleting User: {user_login} who last logged in {last_login_time}.")
                confirm = input("Are you sure you want to delete this user? (yes/no): ").strip().lower()
                if confirm == 'yes':
                    delete_user(token, user_login)
                else:
                    print("Deletion cancelled.")
        else:
            print(f"User with ID {user_login} not found")


if __name__ == "__main__":
    main()
