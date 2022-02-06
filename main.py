import paramiko
from icmplib import ping, multiping, traceroute, resolve
from icmplib import async_ping, async_multiping, async_resolve
from mac_vendor_lookup import MacLookup
import ipaddress


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


def route_print(ip_hops, routers):
    j = 1
    for ip in ip_hops:
        print(f"Hop {j} = {ip}\n"
              f"\tAddress = {ip_hops[ip]['address']}\n"
              f"\tMBU Version = {ip_hops[ip]['version']}\n"
              f"\tRouter MAC = {ip_hops[ip]['router']}\n"
              f"\tRouter OUI = {routers[ip]}")
        j += 1


def gather_route(hops, prefix, myconn, ip_hops=None, routers=None, user="root", pswd="admin", port=22):
    if routers is None:
        routers = {}
    if ip_hops is None:
        ip_hops = {}
    i = 1
    for hop in hops:
        # if i < 5:  # ignoring the first two hops
        #     i += 1
        #     continue
        ip = hop.address
        if prefix not in ip:
            i += 1
            continue
        try:
            # print(ip)
            session = myconn.connect(ip, username=user, password=pswd, port=port)
            ip_hops[ip] = {}
            ip_hops[ip]["address"] = get_address(myconn)
            ip_hops[ip]["router"] = get_mac(myconn)
            ip_hops[ip]["version"] = get_version(myconn)
            myconn.close()
            if ip_hops[ip]['router'] == "\'":
                routers[ip] = "No Router"
            else:
                routers[ip] = MacLookup().lookup(ip_hops[ip]['router'])

            # print(f"Hop {j} = {ip}\n"
            #       f"\tAddress = {ip_hops[ip]['address']}\n"
            #       f"\tMBU Version = {ip_hops[ip]['version']}\n"
            #       f"\tRouter MAC = {ip_hops[ip]['router']}\n"
            #       f"\tRouter OUI = {routers[ip]}")
            # j += 1
        # print(f"Hop {i} = {hop.address} --- "
        #       f"\t{get_address(hop.address)}\n"
        #       f"\tRouter = {get_mac(hop.address)}\n")
              # f"\tVersion = {get_version(hop.address)}\n")
        except Exception as e:
            print(e)
            return "Error"
        # ip_hops[hop.address] = {}
        # ip_hops[hop.address]["address"] = get_address(hop.address)
        # ip_hops[hop.address]["router"] = get_mac(hop.address)
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
    hops = traceroute(target_ip)
    # print('Distance/TTL    Address    Average round-trip time')
    # last_distance = 0
    # i = 1
    # j = 1
    ip_hops = {}
    routers = {}
    gather_route(hops, prefix, myconn, ip_hops, routers)

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
                for ip in ip_hops:
                    print(ip)
            elif choice == 2:
                print("\n\n")
                for ip in routers:
                    print(ip)
            elif choice == 3:
                print("\n\n")
                for ip in ip_hops:
                    print(ip_hops[ip]['version'])
            elif choice == 4:
                print("\n\n")
                # mtr(ip_hops)
            elif choice == 5:
                print("\n\n")
                route_print(ip_hops, routers)
            elif choice == 6:
                break
            else:
                print("Invalid Choice")
        except ValueError:
            print("Invalid Choice")
    # routers = {}
    # for ip in ip_hops:
    #     if ip_hops[ip]['router'] == "\'":
    #         routers[ip] = "No Router"
    #     else:
    #         routers[ip] = MacLookup().lookup(ip_hops[ip]['router'])
    # j = 1
    # for ip in ip_hops:
    #     print(f"Hop {j} = {ip}\t---\t{ip_hops[ip]['address']}\n"
    #           f"\tRouter = {ip_hops[ip]['router']}\t---\t{routers[ip]}\n")
    #     j += 1
    # print(ip_hops)
    # print(ip_hops["fd8d:1900:2729:7415::1"])


if __name__ == '__main__':
    main()
