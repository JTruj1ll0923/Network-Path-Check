import requests
import asyncio
import aiohttp
import json
from prettytable import PrettyTable
import datetime
import arrow
import sys
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def save_secret(token):
    while True:
        c = input("Would you like to save this token for future use? (y/n): ")
        if c == 'y' or c == 'Y':
            try:
                tmp_secret = open('secrets.json', 'w')
                json.dump({"user_token": token}, tmp_secret)
                tmp_secret.close()
                print("Saved!")
                break
            except Exception as err:
                print("Error: " + str(err))
                c2 = input("Could not save correctly, try again? (y/n): ")
                while True:
                    if c2 == 'y' or c2 == 'Y':
                        break
                    elif c2 == 'n' or c2 == 'N':
                        print("Cannot continue... press ENTER to exit")
                        input()
                        sys.exit()
                    else:
                        print("Invalid input...")
            break
        elif c == 'n' or c == 'N':
            print("Continuing without saving")
            break
        else:
            print("Invalid input")


def verify_api_key(token, email=""):
    ###
    # This verifies the API key
    ###
    verification_code = input(f"Enter Eero verification code delivered to your email ({email}): ")
    url = "https://api-user.e2ro.com/2.2/login/verify"
    verify_payload = {'code': f'{verification_code}'}
    verify_header = {"X-User-Token": f'{token}'}
    response = requests.post(url, headers=verify_header, data=verify_payload)
    if response.status_code == 200:
        # print("Account Verified? " + str(response.json()['data']['email']['verified']))
        return 0
    else:
        return "Potentially incorrect verification code... Try again? (y/n): "


def generate_eero_api_key():
    while True:
        email = input("Enter Eero account email address: ")
        login_payload = {"login": f"{email}"}
        response = requests.post("https://api-user.e2ro.com/2.2/pro/login", login_payload)
        # print(response.status_code)
        # print(response.json())
        if response.status_code == 200:
            token = response.json()["data"]["user_token"]
    # print("Unverified Access Token: " + token)
            verify = verify_api_key(token, email)
            if verify == 0:
                print("Verified, continuing...")
                save_secret(token)
                break
            else:
                print(verify)
                continue





try:
    ###
    # This is where we load the API key from the secrets.json file
    # This file and/or API key should never be shared with anyone
    # This file is not in the repo, but is in the same directory as this program
    ###
    secret_file = open('secrets.json', 'r')
    secrets = json.load(secret_file)
    secret_file.close()
    base_url = "https://api-user.e2ro.com/2.2"
    user_token = secrets['user_token']
    headers = {
        "Content-Type": "application/json",
        "X-Lang": "en-US",
        "User-Agent": "WeLink/0.1",
        "X-User-Token": user_token
    }
except Exception as e:
    ###
    # If we can't load the API key, let's ask for one
    # In the future it would be better to have a secure way to store the API key
    # Also in the future we should continue without the API key, may cause problems without it currently
    ###
    # print("Error: " + str(e))
    print("Could not load Eero API key")
    user_token = None
    while True:
        try:
            c = int(input("Should we..."
                      "\n1. Generate a new API key?"
                      "\n2. Enter API key manually?"
                      "\n3. Exit?"
                      "\nChoice: "))
        except TypeError:
            print("Invalid input")
            continue
        if c == 1:
            generate_eero_api_key()
        elif c == 2:
            user_token = input("Enter your user token: ")
            save_secret(user_token)
            break
        elif c == 3:
            print("Cannot continue... press ENTER to exit")
            input()
            sys.exit()
        else:
            print("Invalid input")
            continue
    ###
    # Generate the headers
    ###
    headers = {
        "Content-Type": "application/json",
        "X-Lang": "en-US",
        "User-Agent": "WeLink/0.1",
        "X-User-Token": user_token
    }
    base_url = "https://api-user.e2ro.com/2.2"


def slow_day_report():
    ###
    # Not implemented, but this could be used to get a list of all 'slow' networks
    ###
    report_url = f"{base_url}/organizations/self/slow_network_counts_by_day"
    start = input("Enter start date (YYYY-MM-DD): ")
    print(start)
    threshold = 0.75
    result = requests.get(report_url, headers=headers, params={"start": start, "thresholds": threshold})
    result = result.json()
    return result


def format_tests(tests):
    ###
    # This converts the speed test date/time from GMT to MST
    ###
    tests = tests['data']
    i = 1
    test_results = {}
    for test in tests:
        # print(f"{i}:\n{test}")
        test_results[i] = {}
        test_results[i]['down'] = test['down_mbps']
        test_results[i]['up'] = test['up_mbps']
        date = test['date']
        date = arrow.get(date)
        try:
            date = date - datetime.timedelta(hours=6)
        except Exception as err:
            logger.exception(err)
            print(f"{err} -- Unable to convert time")
        test_results[i]['date'] = date
        i += 1
    return test_results


async def speed_test_list(customer_id=None):
    ###
    # This gives us a list of all speed tests for an Eero network
    ###
    if customer_id is None:
        while True:
            try:
                customer_id = int(input("Enter Customer ID: "))
                if type(customer_id) is int:
                    break
            except ValueError:
                print("Invalid Customer ID")
                continue
    network_url = f"{base_url}/networks/{customer_id}/speedtest"
    data = {"limit": 100}  # API limit is 100
    result = requests.get(network_url, headers=headers, params=data)
    if result.status_code == 200:
        result = result.json()
        return result
    else:
        print(f"Error: {result.status_code}")
        return None


def list_networks(params=None):
    ###
    # This gives us a list of all Eero networks
    # This is half of the work to generate routers.json
    ###
    networks_url = f"{base_url}/organizations/self/networks/administered"
    if params is None:
        result = requests.get(networks_url, headers=headers)
    else:
        result = requests.get(networks_url, headers=headers, params=params)
    result = result.json()
    return result


async def grab_eeros():
    ###
    # This gives us a list of all Eero networks
    # This is the other half of the work to generate routers.json
    ###
    network_list = []
    networks = list_networks()
    i = 1
    print("Grabbing network page", end=":\n")
    done = False
    while True:
        if (i - 1) % 10 == 0:
            print("\n")
        print(f"{i}", end="...")
        i += 1
        for network in networks['data']['networks']:
            network_list.append(network)
        if done:
            print("That's all folks!")
            break
        else:
            try:  # If there are more pages, keep going
                if networks['pagination']['next'] is not None:
                    offset = networks['pagination']['next']
                    offset = offset.split('?')[1]
                    offset = offset.split('=')[1]
                    networks = list_networks(params={"offset": offset})
                else:
                    break
            except KeyError:
                done = True
                networks = list_networks()
                continue
    i = 1
    network_dict = {}
    router_dict = {}
    time = arrow.now().format('YYYY-MM-DD_HH:mm:ss')
    router_dict['date'] = time  # This is the date of the routers.json file
    for network in network_list:  # Combine all Eero network dictionaries into one dictionary
        network_dict[i] = {}
        network_dict[i]['url'] = network['url']
        network_dict[i]['name'] = network['name']
        network_dict[i]['owner'] = network['owner']
        network_dict[i]['status'] = network['status']
        network_dict[i]['health'] = {}
        network_dict[i]['health']['internet'] = {}
        network_dict[i]['health']['internet']['status'] = network['health']['internet']['status']
        network_dict[i]['health']['internet']['isp_up'] = network['health']['internet']['isp_up']
        network_dict[i]['health']['eero_network'] = {}
        network_dict[i]['health']['eero_network']['status'] = \
            network['health']['eero_network']['status']
        network_dict[i]['eeros'] = []
        for eero in network['eeros']:  # Gathering list of routers and associated account url (allow searching for mac)
            network_dict[i]['eeros'].append(eero)
            router_dict[eero['mac_address']] = {
                'serial': eero['serial'],
                'url': network['url'],
            }
        i += 1

    routers = open('routers.json', 'w')
    routers.write(json.dumps(router_dict))
    routers.close()


async def single_eero_results(customer_id=None):
    ###
    # This requests the results of a single Eero network and builds a table
    ###
    if customer_id is None:
        return
    tests = await speed_test_list(customer_id)
    if tests is None:
        return "No results found"
    test_results = format_tests(tests)
    table = PrettyTable(["Num", "Date", "Down", "Up"])
    i = 1
    for test in test_results:
        table.add_row([i, test_results[test]['date'], test_results[test]['down'], test_results[test]['up']])
        i += 1
    return table


def search_by_mac(mac=None):
    ###
    # This is where we will search for the MAC address in the router.json file
    #   We are returned the Serial Number and the Network ID registered to the MAC
    ###
    if mac is None:  # If no mac is provided, return error. We should not reach this point. May want to change this
        return "No MAC address entered"
    mac = mac[:-1].strip() + '0'  # Change last digit to 0 to search for MAC registered with Eero
    try:
        with open('routers.json') as json_file:
            data = json.load(json_file)
            customer_id = data[mac]['url']
            customer_id = customer_id.split('/')
            customer_id = customer_id[len(customer_id) - 1]
            serial = data[mac]['serial']
        json_file.close()
        return customer_id, serial  # Return the customer ID and serial number
    except Exception as err:
        print(err)
        return "Missing Network", "Missing Serial"  # Return missing network and serial number if not found


def search_by_serial():
    ###
    # Not as useful as search_by_mac, but maybe useful later
    ###
    serial = input("Enter the serial of the router you want to search for: ")
    try:
        with open('routers.json') as json_file:
            data = json.load(json_file)
            data = data[serial]['url']
            data = data.split('/')
            data = data[len(data) - 1]
        json_file.close()
        result = asyncio.run(single_eero_results(data))
        return result
    except Exception as err:
        print(err)
        print("No router with that MAC address found.")
        return


async def async_tasker(session, customer_id):
    result = None

    while True:
        try:
            network_url = f"{base_url}/networks/{customer_id}/speedtest"
            data = {'limit': 100}
            result = await session.get(url=network_url, headers=headers, params=data)
            if result is not None:
                break
            else:
                print("No results found.")
                break
        except Exception as err:
            logger.exception(err)
            print(f"Error: {err}")  # Add possible error retry logic here
            continue
    return result


def get_tasks(session):
    tasks = []
    with open('routers.json') as json_file:
        data = json.load(json_file)
        for router in data:
            url = data[router]['url']
            url = url.split('/')
            url = url[len(url) - 1]
            tasks.append(asyncio.create_task(async_tasker(session, url)))
        json_file.close()
    return tasks


async def async_runner():
    results = []
    sem = asyncio.Semaphore(100)
    async with sem, aiohttp.ClientSession() as session:
        tasks = get_tasks(session)
        responses = await asyncio.gather(*tasks)
        for response in responses:
            if response is not None:
                results.append(response)
    return results


def mass_test():
    customer_id = input("Enter the customer ID of the customer you want to test: ")
    test_nums = int(input("Enter the number of tests you want to run: "))
    test_interval = input("Enter the interval between tests in seconds: ")
    last_test_time = arrow.now("US/Mountain")
    last_test = None
    speedtest_url = f"{base_url}/networks/{customer_id}/speedtest"
    tests_done = 0
    while True:
        try:
            if tests_done < int(test_nums):
                if arrow.now("UTC") > last_test_time.shift(seconds=int(test_interval)):
                    if requests.get(speedtest_url, headers=headers,
                                    params={'limit': 1}).json()['data'][0]['date'] != last_test:
                        last_test = requests.get(speedtest_url, headers=headers, params={'limit': 1})
                        last_test = last_test.json()
                        last_test_time = last_test['data'][0]['date']
                        requests.post(speedtest_url, headers=headers)
                        last_test = requests.get(speedtest_url, headers=headers, params={'limit': 1})
                        last_test = last_test.json()
                        last_test = last_test['data'][0]['date']
                        tests_done += 1

        except Exception as err:
            logger.exception(err)
            print(f"Error: {err}")
            continue


def main():
    while True:
        try:
            print("What would you like to do?")
            print("1. Grab New Eero List")
            print("2. Grab Full Eero Tests List")
            print("3. Grab Specific Eero Test")
            print("4. Mass Tester")
            print("0. Exit")
            try:
                choice = int(input("Enter your choice: "))
            except ValueError:
                print("Invalid Choice")
                continue
            if choice == 1:
                print("Grabbing New Eero List")
                asyncio.run(grab_eeros())
                print("\n")
            elif choice == 2:
                choice = input("Not fully implemented yet... Continue? (y/n): ")
                if choice == 'y':
                    print("Too bad... Will crash... Not implemented yet")
                else:
                    print("Exiting...")
                    break
            elif choice == 3:
                print("1. Search by MAC")
                print("2. Search by Serial")
                print("3. Search by Eero Network #")
                try:
                    sub_choice = int(input("Search by MAC, Serial, or Eero Network #: "))
                except ValueError:
                    print("Invalid Choice")
                    continue
                if sub_choice == 1:
                    table = PrettyTable(['MAC', 'Serial', 'URL'])
                    mac = input("Enter the MAC address of the router you want to search for: ")
                    url, serial = search_by_mac(mac)
                    url = f"https://dashboard.eero.com/networks/{url}"
                    table.add_row([mac, serial, url])
                    print(table)
                elif sub_choice == 2:
                    print("Not working yet...")  # TODO
                elif sub_choice == 3:
                    network_id = input("Enter the Eero network ID of the customer you want to test: ")
                    result = asyncio.run(single_eero_results(network_id))
                    print(result)
                elif sub_choice == 0:
                    print("back to main menu")
                    break
            elif choice == 4:
                print("Not working yet...")  # TODO
                continue
            elif choice == 0:
                print("Exiting")
                break
        except TypeError:
            print("Invalid choice")
            continue
