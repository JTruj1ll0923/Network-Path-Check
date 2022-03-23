import requests
import asyncio
import aiohttp
import json
from prettytable import PrettyTable
import pandas as pd
import openpyxl
import datetime
import arrow

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


def slow_day_report(base_url, headers):
    report_url = f"{base_url}/organizations/self/slow_network_counts_by_day"
    start = input("Enter start date (YYYY-MM-DD): ")
    print(start)
    threshold = 0.75
    result = requests.get(report_url, headers=headers, params={"start": start, "thresholds": threshold})
    result = result.json()
    return result


def format_tests(tests):
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
        date = date.to('US/Mountain')
        test_results[i]['date'] = date
        i += 1
    return test_results


async def speed_test_list(base_url, headers, customer_id=None):
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
    data = {"limit": 100}
    # print(data)
    result = requests.get(network_url, headers=headers, params=data)
    # print(result.json())
    result = result.json()
    # result = json.loads(result)
    return result
    # return result.json()


def list_networks(base_url, headers, params=None):
    networks_url = f"{base_url}/organizations/self/networks/administered"
    if params is None:
        result = requests.get(networks_url, headers=headers)
    else:
        result = requests.get(networks_url, headers=headers, params=params)
    result = result.json()
    return result


async def grab_eeros(base_url, headers):
    network_list = []
    networks = list_networks(base_url, headers)
    # print(list_networks(base_url, headers)['data']['networks'])
    while True:
        for network in networks['data']['networks']:
            network_list.append(network)
        try:
            if networks['pagination']['next'] is not None:
                offset = networks['pagination']['next']
                offset = offset.split('?')[1]
                offset = offset.split('=')[1]
                networks = list_networks(base_url, headers, params={"offset": offset})
            else:
                print("That's all folks!")
                break
        except KeyError:
            print("That's all folks!")
            break
    df = pd.DataFrame()
    i = 1
    network_dict = {}
    router_dict = {}
    time = arrow.now().format('YYYY-MM-DD_HH:mm:ss')
    # network_dict['date'] = time
    router_dict['date'] = time
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
            # print(f"Eero\t---\t{eero}")
            router_dict[eero['mac_address']] = {
                'serial': eero['serial'],
                'url': network['url'],
            }
        i += 1

    df = pd.DataFrame.from_dict(network_dict, orient='index')
    df.to_csv('networks.xlsx', index=False)
    df = pd.DataFrame.from_dict(router_dict, orient='index')
    df.to_csv('routers.xlsx', index=False)
    df.to_json('routers.json', orient='index')


async def single_eero_results(base_url, headers, customer_id):
    # print("Grabbing Eero results for customer ID: {}".format(customer_id))
    tests = await speed_test_list(base_url, headers, customer_id)
    # print(f"Grabbed Eero result for customer ID: {customer_id}\t---\t{tests}")
    test_results = format_tests(tests)
    table = PrettyTable(["Num", "Date", "Down", "Up"])
    i = 1
    for test in test_results:
        table.add_row([i, test_results[test]['date'], test_results[test]['down'], test_results[test]['up']])
        i += 1
    return table


def search_by_mac(base_url, headers, mac=None):
    if mac is None:
        # mac = input("Enter the MAC address of the router you want to search for: ")
        return "No MAC address entered"
    mac = mac[:-1].strip() + '0'
    data = None
    try:
        with open('routers.json') as json_file:
            data = json.load(json_file)
            id = data[mac]["0"]['url']
            # print(data)
            id = id.split('/')
            id = id[len(id) - 1]
            # print(mac)
            serial = data[mac]["0"]['serial']
            # print(serial)
            # data = f"https://dashboard.eero.com/networks/{data}"
        json_file.close()
        return id, serial
    except Exception as e:
        # print("No network with that MAC address found.")
        return "Missing Network", "Missing Serial"


def search_by_serial(base_url, headers):
    serial = input("Enter the serial of the router you want to search for: ")
    data = None
    try:
        with open('routers.json') as json_file:
            data = json.load(json_file)
            data = data[serial]['url']
            data = data.split('/')
            data = data[len(data) - 1]
        json_file.close()
        result = asyncio.run(single_eero_results(base_url, headers, data))
        return result
    except Exception as e:
        print("No router with that MAC address found.")
        return


async def async_tasker(session, base_url, headers, customer_id):
    result = None

    while True:
        try:
            network_url = f"{base_url}/networks/{customer_id}/speedtest"
            data = {'limit': 100}
            result = await session.get(url=network_url, headers=headers, params=data)
            if result is not None:
            # result = result.json()
            # print(result)
            # async with session.get(url=network_url, headers=headers, params=data) as resp:
            #     if resp is not None:
                    # print(f"Successfully grabbed results from these variables {customer_id}")
                    # print(f"{resp.json()}")

                break
            else:
                print("No results found.")
                break
        except Exception as e:
            print(f"Error: {e}")  # Add possible error retry logic here
            continue
    # return resp
    return result


def get_tasks(session, base_url, headers):
    tasks = []
    with open('routers.json') as json_file:
        data = json.load(json_file)
        # print(data)
        for router in data:
            url = data[router]['url']
            url = url.split('/')
            url = url[len(url) - 1]
            # print(url)
            tasks.append(asyncio.create_task(async_tasker(session, base_url, headers, url)))
        json_file.close()
    return tasks


async def async_runner(base_url, headers):
    results = []
    sem = asyncio.Semaphore(100)
    async with sem, aiohttp.ClientSession() as session:
        tasks = get_tasks(session, base_url, headers)
        responses = await asyncio.gather(*tasks)
        for response in responses:
            if response is not None:
                results.append(response)
    return results


def mass_test(base_url, headers):
    customer_id = input("Enter the customer ID of the customer you want to test: ")
    test_nums = int(input("Enter the number of tests you want to run: "))
    test_interval = input("Enter the interval between tests in seconds: ")
    last_test_time = arrow.now("US/Mountain")
    last_test = None
    results = []
    speedtest_url = f"{base_url}/networks/{customer_id}/speedtest"
    tests_done = 0
    while True:
        try:
            if tests_done < int(test_nums):
                if arrow.now("UTC") > last_test_time.shift(seconds=int(test_interval)):
                    if requests.get(speedtest_url, headers=headers, params={'limit': 1}).json()['data'][0]['date'] != last_test:
                        last_test = requests.get(speedtest_url, headers=headers, params={'limit': 1})
                        last_test = last_test.json()
                        last_test_time = last_test['data'][0]['date']
                        requests.post(speedtest_url, headers=headers)
                        last_test = requests.get(speedtest_url, headers=headers, params={'limit': 1})
                        last_test = last_test.json()
                        last_test = last_test['data'][0]['date']
                        tests_done += 1


        except Exception as e:
            print(f"Error: {e}")
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
            choice = int(input("Enter your choice: "))
            if choice == 1:
                print("Grabbing New Eero List")
                result = asyncio.run(grab_eeros(base_url, headers))
                print(result)
            elif choice == 2:
                choice = input("Not fully implemented yet... Continue? (y/n): ")
                if choice == 'y':
                    print("Too bad... Will crash... Not implemented yet")
                #     print("Grabbing Full Eero Tests Results")
                #     result = asyncio.run(grab_eeros(base_url, headers))
                #     print(result)
                else:
                    print("Exiting...")
                    break
            elif choice == 3:
                print("1. Search by MAC")
                print("2. Search by Serial")
                print("3. Search by Eero Network #")
                sub_choice = int(input("Search by MAC, Serial, or Eero Network #: "))
                if sub_choice == 1:
                    table = PrettyTable(['MAC', 'Serial', 'URL'])
                    mac = input("Enter the MAC address of the router you want to search for: ")
                    url, serial = search_by_mac(base_url, headers, mac)
                    url = f"https://dashboard.eero.com/networks/url"
                    table.add_row([mac, serial, url])
                    print(table)
                elif sub_choice == 2:
                    print("Not working yet...")  # TODO
                elif sub_choice == 3:
                    result = asyncio.run(single_eero_results(base_url, headers, None))
                    print(result)
                    # print(single_eero_results(base_url, headers, None))
                elif sub_choice == 0:
                    print("back to main menu")
                    break
            elif choice == 4:
                print("Not working yet...")  # TODO
                continue
                # mass_test(base_url, headers)
            elif choice == 0:
                print("Exiting")
                break
        except TypeError:
            print("Invalid choice")
            continue

