import paramiko
from icmplib import ping, multiping, traceroute, resolve
from icmplib import async_ping, async_multiping, async_resolve
from mac_vendor_lookup import MacLookup
import ipaddress
import asyncio
from prettytable import PrettyTable






async def async_mtr(ips, hop_info):
    mtr_results = {}
    for ip in ips:
        mtr_results[ip] = {}

    print("Initializing MTR...")
    for ip in ips:  # Initialize
        mtr_results[ip]['address'] = 0
        mtr_results[ip]['rtt'] = 0
        mtr_results[ip]['packets_sent'] = 0
        mtr_results[ip]['packets_received'] = 0
        mtr_results[ip]['packet_loss'] = 0
        mtr_results[ip]['jitter'] = 0

    from prettytable import PrettyTable
    pingnum = 1
    while True:
        await asyncio.sleep(0.25)
        response = await async_multiping(ips, count=1)
        print(f"\n\n\n\n\n")
        mtr_table = PrettyTable(['IP', 'Address', 'RTT', 'Packets Sent', 'Packets Received', 'Packet Loss', 'Jitter'])
        for host in response:
            ip = host.address
            mtr_results[ip]['address'] = hop_info[ip]['address']
            mtr_results[ip]['rtt'] = host.avg_rtt
            mtr_results[ip]['packets_sent'] = mtr_results[ip]['packets_sent'] + host.packets_sent
            mtr_results[ip]['packets_received'] = mtr_results[ip]['packets_received'] + host.packets_received
            mtr_results[ip]['packet_loss'] = mtr_results[ip]['packet_loss'] + host.packet_loss
            mtr_results[ip]['jitter'] = (mtr_results[ip]['jitter'] + host.jitter) / pingnum
            mtr_table.add_row([ip, mtr_results[ip]['address'], mtr_results[ip]['rtt'], mtr_results[ip]['packets_sent'],
                               mtr_results[ip]['packets_received'], mtr_results[ip]['packet_loss'],
                               mtr_results[ip]['jitter']])

            # print(f"{ip} - {pingnum}"
            #       f"\tRTT = {mtr_results[ip]['rtt']}"
            #       f"\tPackets Sent = {mtr_results[ip]['packets_sent']}"
            #       f"\tPackets Received = {mtr_results[ip]['packets_received']}"
            #       f"\tPacket Loss = {mtr_results[ip]['packet_loss']}"
            #       f"\tJitter = {mtr_results[ip]['jitter']}")
        print(mtr_table)
        pingnum += 1

        # print(f"\t\tmtr\t\t{mtr_results}\n")


def mtr(ips, hop_info):
    asyncio.run(async_mtr(ips, hop_info))
    # hosts = multiping(ips)
    # for host in hosts:
    #     if host.is_alive:
    #         print(f"{host.address} is up!")
    #     else:
    #         print(f"{host.address} is down!")





def get_address(myconn):
    remote_cmd = 'grep hostname /tmp/config.json'
    (stdin, stdout, stderr) = myconn.exec_command(remote_cmd)
    out = "{}".format(stdout.read())
    out = str(out.split()[2])
    out = str(out[6:].split(",")[0])
    out = str(out.split("\"")[0])
    # print(out)
    # print("{}".format(type(myconn)))
    # print("Options available to deal with the connectios are many like\n{}".format(dir(myconn)))
    #     myconn.close()
    return out


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


def get_mac(myconn):
    remote_cmd = 'bridge fdb show | grep -iE \"dev (ghn0|eth[0-4]) master br-lan\" | grep -v \"c4:93:00\"'
    (stdin, stdout, stderr) = myconn.exec_command(remote_cmd)
    out = "{}".format(stdout.read())
    out = str(out[2:].split()[0])
    # print(out)
    # print("{}".format(type(myconn)))
    # print("Options available to deal with the connectios are many like\n{}".format(dir(myconn)))
    #     myconn.close()
    return out
    # except Exception as e:
    #     print(e)
    #     return "Error"


def route_print(hop_info, routers):
    j = 1
    for ip in hop_info:
        print(f"Hop {j} = {ip}\n"
              f"\tAddress = {hop_info[ip]['address']}\n"
              f"\tMBU Version = {hop_info[ip]['version']}\n"
              f"\tRouter MAC = {hop_info[ip]['router']}\n"
              f"\tRouter OUI = {routers[ip]}")
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
    for hop in traceroute_hops:
        # if i < 5:  # ignoring the first two hops
        #     i += 1
        #     continue
        ip = hop.address
        if prefix not in ip:
            i += 1
            continue
        try:
            if ip not in ip_list:
                ip_list.append(ip)
            # print(ip)
            session = myconn.connect(ip, username=user, password=pswd, port=port)
            hop_info[ip] = {}
            hop_info[ip]["address"] = get_address(myconn)
            hop_info[ip]["router"] = get_mac(myconn)
            hop_info[ip]["version"] = get_version(myconn)
            myconn.close()
            if hop_info[ip]['router'] == "\'":
                routers[ip] = "No Router"
            else:
                routers[ip] = MacLookup().lookup(hop_info[ip]['router'])

            # print(f"Hop {j} = {ip}\n"
            #       f"\tAddress = {hop_info[ip]['address']}\n"
            #       f"\tMBU Version = {hop_info[ip]['version']}\n"
            #       f"\tRouter MAC = {hop_info[ip]['router']}\n"
            #       f"\tRouter OUI = {routers[ip]}")
            # j += 1
        # print(f"Hop {i} = {hop.address} --- "
        #       f"\t{get_address(hop.address)}\n"
        #       f"\tRouter = {get_mac(hop.address)}\n")
              # f"\tVersion = {get_version(hop.address)}\n")
        except Exception as e:
            print(e)
            return "Error"
        # hop_info[hop.address] = {}
        # hop_info[hop.address]["address"] = get_address(hop.address)
        # hop_info[hop.address]["router"] = get_mac(hop.address)
        i += 1


def main():
    target_ip = ""
    while True:
        try:
            target_ip = str(input("What is the target MBU IPv6?"))
            if ipaddress.IPv6Address(target_ip):
                break
            else:
                print("Invalid IPv6")
                continue
        except ValueError:
            print(ValueError)
            "Invalid IPv6"
    prefix = str(target_ip.split(":")[0] + ":" + target_ip.split(":")[1])
    # print(prefix)

    # sec_key = '/mycert.ppk'

    myconn = paramiko.SSHClient()
    myconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    traceroute_hops = traceroute(target_ip)
    # print('Distance/TTL    Address    Average round-trip time')
    # last_distance = 0
    # i = 1
    # j = 1
    hop_info = {}
    routers = {}
    ip_list = []
    gather_route(traceroute_hops, prefix, myconn, ip_list, hop_info, routers)

    while True:
        try:
            # print("\n\n")
            print("What would you like to do?")
            print("1. Print all IPs")
            print("2. Print all Routers")
            print("3. Print all Versions")
            print("4. MTR all IPs")
            print("5. Print full route information")
            print("6. Exit")
            choice = int(input("Choice: "))
            if choice == 1:
                print("\n\n")
                for ip in hop_info:
                    print(ip)
            elif choice == 2:
                print("\n\n")
                for router in routers:
                    print(routers[router])
            elif choice == 3:
                print("\n\n")
                i = 1
                for ip in hop_info:
                    print(f"{i}: {hop_info[ip]['version']}")
                    i += 1
            elif choice == 4:
                print("\n\n")
                mtr(ip_list, hop_info)
            elif choice == 5:
                print("\n\n")
                route_print(hop_info, routers)
            elif choice == 6:
                break
            else:
                print("Invalid Choice")
        except ValueError:
            print("Invalid Choice")
    # routers = {}
    # for ip in hop_info:
    #     if hop_info[ip]['router'] == "\'":
    #         routers[ip] = "No Router"
    #     else:
    #         routers[ip] = MacLookup().lookup(hop_info[ip]['router'])
    # j = 1
    # for ip in hop_info:
    #     print(f"Hop {j} = {ip}\t---\t{hop_info[ip]['address']}\n"
    #           f"\tRouter = {hop_info[ip]['router']}\t---\t{routers[ip]}\n")
    #     j += 1
    # print(hop_info)
    # print(hop_info["fd8d:1900:2729:7415::1"])


if __name__ == '__main__':
    main()
