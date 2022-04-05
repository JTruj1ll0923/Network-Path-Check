import paramiko
import asyncssh
from icmplib import ping, multiping, traceroute, resolve
from icmplib import async_ping, async_multiping, async_resolve
from mac_vendor_lookup import MacLookup
import ipaddress
import asyncio
from aiotraceroute import aiotraceroute
from prettytable import PrettyTable
import threading
import logging
import sys
import requests
import asyncio
import aiohttp
import json
from prettytable import PrettyTable
import pandas as pd
import openpyxl
import datetime
import arrow

import EeroTests

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# try:
#     secret_file = open('secrets.json', 'r')
#     secrets = json.load(secret_file)
#     secret_file.close()
#     base_url = "https://api-user.e2ro.com/2.2"
#     user_token = secrets['user_token']
#     headers = {
#         "Content-Type": "application/json",
#         "X-Lang": "en-US",
#         "User-Agent": "WeLink/0.1",
#         "X-User-Token": user_token
#     }
# except Exception as e:
#     print("Could not load secrets.json")
#     while True:
#         c = input("Would you like to enter your credentials manually? (y/n)")
#         if c == 'y' or c == 'Y':
#             user_token = input("Enter your user token: ")
#             headers = {
#                 "Content-Type": "application/json",
#                 "X-Lang": "en-US",
#                 "User-Agent": "WeLink/0.1",
#                 "X-User-Token": user_token
#             }
#             base_url = "https://api-user.e2ro.com/2.2"
#             break
#         elif c == 'n' or c == 'N':
#             print("Press any key to exit")
#             input()
#             sys.exit()
#     logger.error("Could not load secrets.json")
#     logger.error(e)
#     sys.exit(1)


def ip_check():
    target_ip = ""
    while True:
        try:
            target_ip = str(input("What is the target MBU IPv6? (0 to exit) ")).strip()
            # traceroute_start(target_ip, None, None)
            if target_ip == 0 or target_ip == "0":
                return 0
            if ipaddress.IPv6Address(target_ip):
                break
            else:
                print("Invalid IPv6")
                continue
        except ValueError:
            # print(ValueError)
            print("Invalid IPv6")
    return target_ip


async def quick_traceroute(target_ip, prefix=None, ip_list=None):
    async for n, addr, host in aiotraceroute(target_ip):
        print(n, addr, host)


def traceroute_start(target_ip, prefix, ip_list):
    asyncio.get_event_loop().run_until_complete(quick_traceroute("google.com"))


def hop_to_ip(hops, prefix):
    ip_list = []
    for hop in hops:
        if prefix not in hop.address:
            continue
        ip_list.append(hop.address)
    return ip_list


def ip_format(imported_ip_list, prefix):
    ip_list = imported_ip_list
    formatted_ip_list = []
    for ip in ip_list:
        ip_split = ip.split(":")

        if len(ip_split[len(ip_split) - 3]) > 1:
            ip_split[len(ip_split) - 3] = ip_split[len(ip_split) - 3][:-2] + "00"

        formatted_ip_list.append(":".join(ip_split))
        # print(ip_split[len(ip_split) - 3][:-2] + "00")
    return formatted_ip_list


def ptmp_check(myconn, ip=None, user="root", pswd="admin", port=22):
    if myconn is None:
        myconn = paramiko.SSHClient()
        myconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        session = myconn.connect(ip, username=user, password=pswd, port=port)
    # target_address = get_address(None, ip)
    remote_cmd = 'grep -B 2 -ci ptmp /tmp/run/lldp_server.json'
    stdin, stdout, stderr = myconn.exec_command(remote_cmd)
    out = "{}".format(stdout.read())
    out = out[2:-3]
    # print(out)
    ptmp_list = []
    ptmp_table = PrettyTable(['IPv6', 'Eth Port', 'Address'])
    if out == 0:
        return "No PTMP"
    else:
        remote_cmd = 'grep -i -B 2 ptmp /tmp/run/lldp_server.json | grep -io eth[0-4]'

        stdin, stdout, stderr = myconn.exec_command(remote_cmd)
        out = "{}".format(stdout.read())
        # print(out)
        out = out[2:-3]
        out = out.split("\\n") # We now have ethernet ports
        # print(out)

        eths = {}
        ips = []
        for eth in out:
            remote_cmd = f'ip -6 neigh | grep -i \"{eth}\" | grep -v \"fe80\" | grep -i ll'
            stdin, stdout, stderr = myconn.exec_command(remote_cmd)
            output = "{}".format(stdout.read())
            output = output[2:-3]
            # print(output)
            output = output.split("\\n") # We now have IPv6 addresses

            for ip in output:
                new_ip = ip.split(" ")[0]
                ips.append(new_ip)
                eths[new_ip] = ip.split(" ")[2]

        for ip in ips:
            ptmp_table.add_row([ip, eths[ip], get_address(None, ip)])

        return ptmp_table


def get_mac(myconn, ip=None, user="root", pswd="admin", port=22):
    if myconn is None:
        myconn = paramiko.SSHClient()
        myconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        session = myconn.connect(ip, username=user, password=pswd, port=port)
    remote_cmd = 'bridge fdb show | grep -iE \"dev (ghn0|eth[0-4]) master br\" | grep -v \"c4:93:00\"'
    (stdin, stdout, stderr) = myconn.exec_command(remote_cmd)
    out = "{}".format(stdout.read())
    out = str(out[2:].split()[0])
    return out


def get_address(myconn, ip=None, user="root", pswd="admin", port=22):
    if myconn is None:
        myconn = paramiko.SSHClient()
        myconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        session = myconn.connect(ip, username=user, password=pswd, port=port)
    remote_cmd = 'grep hostname /tmp/config.json'
    (stdin, stdout, stderr) = myconn.exec_command(remote_cmd)
    out = "{}".format(stdout.read())
    out = out.split()
    out = out[len(out) - 1]
    out = out.split(",")[0]
    out = out.split(".")[1]
    if out[len(out) - 1] == "\"":
        out = out[:-1]
    # out = f"\n\nAddress: {out}"
    return out


def get_tasks():
    tasks = []

    """
    for var in variables:
        # print(f"Var: {var}")
        # print(f"Grabbing extras")
        tasks.append(asyncio.create_task(async_test_maker(session, query, var, failed_list)))
        # tasks.append(asyncio.create_task(session.execute(query, var)))
        # tasks.append(asyncio.create_task(asyncio.sleep(0.5)))
    return tasks
    """


async def async_mtr(ips, hop_info, target_ip, prefix):
    mtr_results = {}
    for ip in ips:
        mtr_results[ip] = {}
    total_pings = 1
    while total_pings != 0:
        try:
            total_pings = int(input("How many pings would you like to send? "))
            if total_pings == 0:
                return "Cancelled MTR"
            else:
                break
        except ValueError:
            print("Please enter a number.")
            continue
    print("Initializing MTR...")
    for ip in ips:  # Initialize
        mtr_results[ip]['address'] = 0
        mtr_results[ip]['rtt'] = 0
        mtr_results[ip]['packets_sent'] = 0
        mtr_results[ip]['packets_received'] = 0
        mtr_results[ip]['packet_loss'] = 0
        mtr_results[ip]['jitter'] = 0

    pingnum = 1
    # while pingnum <= total_pings:
    while True:
        try:
            if pingnum > total_pings:
                break
            await asyncio.sleep(0.25)
            # print(route_change_check(target_ip, prefix, ips, hop_info))
            response = await async_multiping(ips, count=1)
            print(f"\n\n\n\n\n\n\n\n\n\n")
            mtr_table = PrettyTable(['IP', 'Address', 'RTT', 'Packets Sent', 'Packets Received', 'Packet Loss', 'Jitter'])
            for host in response:
                ip = host.address
                mtr_results[ip]['address'] = hop_info[ip]['address']
                mtr_results[ip]['rtt'] = host.avg_rtt
                mtr_results[ip]['packets_sent'] = mtr_results[ip]['packets_sent'] + host.packets_sent
                mtr_results[ip]['packets_received'] = mtr_results[ip]['packets_received'] + host.packets_received
                mtr_results[ip]['packet_loss'] = mtr_results[ip]['packet_loss'] + host.packet_loss
                mtr_results[ip]['jitter'] = (mtr_results[ip]['jitter'] + host.jitter) / pingnum
                mtr_table.add_row([ip, mtr_results[ip]['address'], mtr_results[ip]['rtt'],
                                   mtr_results[ip]['packets_sent'], mtr_results[ip]['packets_received'],
                                   mtr_results[ip]['packet_loss'], mtr_results[ip]['jitter']])

            print(mtr_table)
            pingnum += 1

        except KeyboardInterrupt:
            print("\n\n\t\tFinished MTR\n\n")


def mtr(ips, hop_info, target_ip, prefix):
    asyncio.run(async_mtr(ips, hop_info, target_ip, prefix))


def get_version(myconn):

    remote_cmd = 'grep rev /usr/lib/release/firmux'
    (stdin, stdout, stderr) = myconn.exec_command(remote_cmd)
    version = "{}".format(stdout.read())
    version = version[2:-3]
    # print(out)
    # print("{}".format(type(myconn)))
    # print("Options available to deal with the connectios are many like\n{}".format(dir(myconn)))
    #     myconn.close()
    return version


def route_print(hop_info, routers):
    j = 1
    for ip in hop_info:
        print(f"Hop {j} = {ip}\n"
              f"\tAddress = {hop_info[ip]['address']}\n"
              f"\tMBU Version = {hop_info[ip]['version']}\n"
              f"\tRouter MAC = {hop_info[ip]['router']['mac']}\n"
              f"\tRouter OUI = {hop_info[ip]['router']['oui']}")
        if hop_info[ip]['router']['url'] != "N/A":
            print(f"\tRouter URL = https://dashboard.eero.com/networks/{hop_info[ip]['router']['url']}")
        j += 1


def gather_route(traceroute_hops, prefix, myconn, ip_list,
                 hop_info=None, routers=None, user="root", pswd="admin", port=22):
    if routers is None:
        routers = {}
    if hop_info is None:
        hop_info = {}
    if ip_list is None:
        ip_list = []
    i = 1

    def go_check(ip):
        while True:
            try:
                myconn.connect(ip, username=user, password=pswd, port=port)
                hop_info[ip] = {}
                hop_info[ip]["address"] = get_address(myconn)
                hop_info[ip]["router"] = {}
                mac = str(get_mac(myconn))
                hop_info[ip]["router"]["mac"] = mac
                # print(mac)
                if mac == "\'":
                    hop_info[ip]["router"]["mac"] = "N/A"
                    hop_info[ip]["router"]["oui"] = "N/A"
                    hop_info[ip]["router"]["url"] = "N/A"
                else:
                    oui = MacLookup().lookup(mac)
                    hop_info[ip]["router"]["oui"] = oui
                    if hop_info[ip]["router"]["oui"] == "eero inc.":
                        url, serial = EeroTests.search_by_mac(mac=mac)
                        # print(url)
                        # print(serial)
                        if url != "Missing Network" and serial != "Missing Serial":

                            hop_info[ip]["router"]["url"] = url
                            hop_info[ip]["router"]["serial"] = serial
                            hop_info[ip]["router"]["results"] = \
                                asyncio.run(EeroTests.single_eero_results(customer_id=url))
                        else:
                            hop_info[ip]["router"]["url"] = "N/A"
                            hop_info[ip]["router"]["serial"] = "N/A"
                            hop_info[ip]["router"]["results"] = "N/A"
                    else:
                        hop_info[ip]["router"]["url"] = "N/A"
                        hop_info[ip]["router"]["serial"] = "N/A"
                        hop_info[ip]["router"]["results"] = "N/A"
                hop_info[ip]["version"] = get_version(myconn)
                myconn.close()
                break
            except Exception as e:
                print(e)
                print(f"{ip} was not reachable... retrying...")
                continue

    threads = []
    for ip in ip_list:
        try:
            t = threading.Thread(target=go_check, args=(ip,))
            threads.append(t)
        except Exception as e:
            print(e)
            return "Error"
        i += 1
    for thread in threads:
        # print(thread)
        thread.start()
        # print(thread)
        thread.join()
        # print(thread)



def route_change_check(target_ip, prefix, ip_list, hop_info):
    new_traceroute = traceroute(target_ip)
    new_ip_list = hop_to_ip(new_traceroute, prefix)
    # print(new_ip_list)
    new_ip_list = ip_format(new_ip_list, prefix)
    # print(new_ip_list)
    route_change = PrettyTable(["Hop Number", "Original Route", "Original Address", "New Route", "New Address"])
    if new_ip_list != ip_list:
        if len(new_ip_list) > len(ip_list):
            for i in range(len(new_ip_list)):
                try:
                    route_change.add_row([i + 1, ip_list[i], hop_info[ip_list[i]]['address'],
                                          new_ip_list[i], get_address(None, new_ip_list[i])])
                except IndexError:
                    try:
                        route_change.add_row([i + 1, "", "", new_ip_list[i], get_address(None, new_ip_list[i])])
                    except Exception as e:
                        print(e)
                        logger.exception()
                        print(f"{new_ip_list[i]} is not reachable")
                        return
                except Exception as e:
                    print(e)
                    logger.exception()
                    print(f"{new_ip_list[i]} is not reachable")
                    return

        else:
            for i in range(len(ip_list)):
                try:
                    route_change.add_row([i + 1, ip_list[i], hop_info[ip_list[i]]['address'],
                                          new_ip_list[i], get_address(None, new_ip_list[i])])
                except IndexError:
                    route_change.add_row([i + 1, ip_list[i], hop_info[ip_list[i]]['address'], "", ""])
        print(ip_list)
        ip_list = new_ip_list
        print(ip_list)
        return route_change
    else:
        return "No Route Change"


def route_tests(hop_info, target_ip, prefix, ip_list):
    i = 1
    for ip in ip_list:
        try:
            if hop_info[ip]['router']['oui'] == "eero inc.":
                print(f"{i} -- {hop_info[ip]['address']} -- "
                      f"https://dashboard.eero.com/networks/{hop_info[ip]['router']['url']}\n"
                      f"{hop_info[ip]['router']['results']}")
                i += 1
            else:
                print(f"{i} -- {hop_info[ip]['address']} does not have an Eero. No tests available.")
                i += 1

        except Exception as e:
            print(e)
            print(f"{ip} is not reachable")


def path_check():
    try:
        target_ip = ip_check()
        if target_ip == 0 or target_ip == '0':
            return
        prefix = str(target_ip.split(":")[0] + ":" + target_ip.split(":")[1])
        # print(prefix)

        # sec_key = '/mycert.ppk'

        try:
            myconn = paramiko.SSHClient()
            myconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(f"Running traceroute to {target_ip}")
            ip_list = []
            traceroute_hops = traceroute(target_ip)
        except Exception as e:
            print(f"\n{e}\n")
            print(f"Traceroute to {target_ip} failed.\n")
            return
        hop_info = {}
        routers = {}
        print(f"Formatting traceroute output for {target_ip}")
        ip_list = hop_to_ip(traceroute_hops, prefix)
        ip_list = ip_format(ip_list, prefix)
        # print(ip_list)
        print(f"Gathering information for hops in traceroute to {target_ip}")
        i = 1
        while True:
            try:
                gather_route(traceroute_hops, prefix, myconn, ip_list, hop_info, routers)
                break
            except Exception as e:
                print(f"\n{e}\n")
                print(f"Gathering information for hops in traceroute to {target_ip} failed.\n")
                i += 1
                if i <= 5:
                    print(f"Retrying...\n")
                    continue
                else:
                    print(f"Unable to reach {target_ip}.\n, check your connection and try again.")
                    return 1
        # print(ip_list)


        while True:
            try:
                print("\n")
                print("What would you like to do?")
                print("1. Print all IPs")
                print("2. Print all Routers")
                print("3. Print all MBU Versions")
                print("4. MTR all IPs")
                print("5. Print full route information")
                print("6. Route Change Check")
                print("7. Print Eero Test Results")
                print("0. Exit")
                choice = int(input("Choice: "))
                if choice == 1:
                    print("\n\n")
                    i = 1
                    table = PrettyTable(["Hop", "IP"])
                    for ip in hop_info:
                        table.add_row([i, ip])
                        i += 1
                elif choice == 2:
                    print("\n\n")
                    table = PrettyTable(["IP", "MAC", "OUI", "Serial", "URL"])
                    for hop in hop_info:
                        mac = hop_info[hop]['router']['mac']
                        oui = hop_info[hop]['router']['oui']
                        if oui == "eero inc.":
                            url, serial = EeroTests.search_by_mac(mac=mac)
                            if url == "Missing Network" or serial == "Missing Serial":
                                pass
                            else:
                                url = f"https://dashboard.eero.com/networks/" \
                                      f"{url}"
                        else:
                            url, serial = "N/A", "N/A"
                        table.add_row([hop, mac, oui, serial, url])
                    print(table)

                elif choice == 3:
                    print("\n\n")
                    i = 1
                    for ip in hop_info:
                        print(f"{i}: {hop_info[ip]['version']}")
                        i += 1
                elif choice == 4:
                    print("\n\n")
                    mtr(ip_list, hop_info, target_ip, prefix)
                elif choice == 5:
                    print("\n\n")
                    route_print(hop_info, routers)
                elif choice == 6:
                    print(f"\n{route_change_check(target_ip, prefix, ip_list, hop_info)}")
                elif choice == 7:
                    route_tests(hop_info, target_ip, prefix, ip_list)
                elif choice == 0:
                    print("Exiting...")
                    break
                else:
                    print("Invalid Choice")
            except ValueError:
                print("Invalid Choice")
    except KeyboardInterrupt:
        while True:
            try:
                choice = "Y"
                choice = input("Exiting...\tWould you like to restart? (Y/n): ")
                try:
                    if choice == "Y" or choice == "y":
                        print("Restarting...")
                        main()
                    else:
                        print("Exiting...")
                        break
                except Exception as e:
                    print("Exiting...")
                    break
            except Exception as e:
                continue
    except Exception as e:
        logger.exception(e)
        print("Exiting...")


def main():

    try:
        with open("routers.json", "r") as f: # Check if routers.json exists and if date is older than 1 week
            routers = json.load(f)
            time = routers['date']
            time = time.format("%Y-%m-%d_%H:%M:%S")
            time = arrow.get(time, "YYYY-MM-DD_HH:mm:ss")
            # time = time - datetime.timedelta(days=6)
            # print(time)
            # print(time.humanize())
            # if time.humanize(routers['date']) > "1 week":
            if time <= arrow.now() - datetime.timedelta(days=1):
                choice = input("Your router list is older than 1 day. Would you like to update? (Y/n)")
                # choice = input("Choice: ")
                if choice == "N" or choice == "n":
                    print("Using old router list...")
                else:
                    print("Updating router list...")
                    result = asyncio.run(EeroTests.grab_eeros())
                    print(result)
            else:
                pass

            # if arrow.now().format("YYYY-MM-DD")!= routers['date']['0']:
    except FileNotFoundError:
        print("No router list found. Create new list?")
        while True:
            choice = input("(y/n): ")
            if choice == "Y" or choice == "y":
                print("Creating new router list...")
                asyncio.run(EeroTests.grab_eeros())
                print("Done!")
                break
            elif choice == "n" or choice == "N":
                print("Starting program without router list...")
                break
            else:
                print("Invalid Choice")
                continue
    #     # print("-------------------------------------------------------")
    #     # print("")
    first_run = True
    while True:
        if not first_run:
            print("\n\n")
        else:
            first_run = False
        try:
            print("What would you like to do?")
            print("1. Single Site Check")
            print("2. Path Check")
            print("3. Eero Check")
            print("4. Check for program update")
            print("0. Exit")
            choice = int(input("Choice: "))
            if choice == 1:
                while True:
                    try:
                        print("\n\n")
                        print("What would you like to do?")
                        print("1. MAC Lookup")
                        print("2. PTMP Check")
                        print("3. Address Lookup")
                        print("0. Exit")
                        choice = int(input("Choice: "))
                        if choice == 1:
                            # print("\n\n")
                            table = PrettyTable(["IP", "MAC", "OUI", "Serial", "URL"])
                            ip = ip_check()
                            if ip == 0:
                                break
                            mac = get_mac(None, ip)
                            # print(f"\n\tRouter MAC = {mac}")
                            if mac == '\'':
                                table.add_row([ip, "None Found", "N/A", "N/A", "N/A"])
                                print(table)
                            else:
                                oui = MacLookup().lookup(mac)
                                # print(f"\tOUI = {oui}")
                                if oui == "eero inc.":
                                    url, serial = EeroTests.search_by_mac(mac=mac)
                                    if url == "Missing Network" or serial == "Missing Serial":
                                        pass
                                    else:
                                        url = f"https://dashboard.eero.com/networks/" \
                                              f"{url}"
                                else:
                                    url = "N/A"
                                    serial = "N/A"
                                table.add_row([ip, mac, oui, serial, url])
                                print(table)
                            # more = input("Eero test? (Y/n): ")
                            # if more == "Y" or more == "y":
                            #     EeroTests.eero_test(base_url, headers, ip)
                        elif choice == 2:
                            # print("\n\n")
                            ip = ip_check()
                            print(ptmp_check(None, ip))
                        elif choice == 3:
                            ip = ip_check()
                            print(get_address(None, ip))
                        elif choice == 0:
                            print("Exiting...")
                            break
                        else:
                            print("Invalid Choice")
                    except:
                        continue
            elif choice == 2:
                result = path_check()
            elif choice == 3:
                EeroTests.main()
            elif choice == 4:
                print("Almost there... Not quite ready yet.")
                # import auto_updater
                # auto_updater.main()
            elif choice == 0:
                print("Exiting...")
                break
            else:
                print("Invalid Choice")
        except ValueError:
            print("Invalid Choice")


if __name__ == '__main__':
    main()
