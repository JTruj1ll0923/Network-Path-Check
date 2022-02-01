import paramiko
from icmplib import ping, multiping, traceroute, resolve
from icmplib import async_ping, async_multiping, async_resolve


def get_address(myconn):
    remote_cmd = 'grep hostname /tmp/config.json'
    (stdin, stdout, stderr) = myconn.exec_command(remote_cmd)
    out = "{}".format(stdout.read())
    print(out)
    # print("{}".format(type(myconn)))
    # print("Options available to deal with the connectios are many like\n{}".format(dir(myconn)))
    #     myconn.close()
    return out


def get_version(ip):
    if ip == "" or ip == " " or ip == "\n":
        return "No IP"
    user = 'root'
    pswd = 'admin'
    port = 22
    myconn = paramiko.SSHClient()
    myconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # my_rsa_key = paramiko.RSAKey.from_private_key_file(sec_key)

    try:
        session = myconn.connect(ip, username=user, password=pswd, port=port)

        remote_cmd = 'cat /etc/banner | grep -i rev'
        (stdin, stdout, stderr) = myconn.exec_command(remote_cmd)
        out = "{}".format(stdout.read())
        # sys = out.find("CPU")
        # print(sys)
        # print(out)
        # print("{}".format(type(myconn)))
        # print("Options available to deal with the connectios are many like\n{}".format(dir(myconn)))
        myconn.close()
        return out
    except Exception as e:
        print(e)
        return "Error"


def get_mac(myconn):
    remote_cmd = 'bridge fdb show | grep -iE \"dev (ghn0|eth[0-4]) master br-lan\" | grep -v \"c4:93:00\"'
    (stdin, stdout, stderr) = myconn.exec_command(remote_cmd)
    out = "{}".format(stdout.read())
    out = str(out[2:].split()[0])
    print(out)
    # print("{}".format(type(myconn)))
    # print("Options available to deal with the connectios are many like\n{}".format(dir(myconn)))
    #     myconn.close()
    return out
    # except Exception as e:
    #     print(e)
    #     return "Error"


def main():
    user = 'root'
    pswd = 'admin'
    port = 22
    final_ip = "fd8d:1900:2729:7415::1"
    # sec_key = '/mycert.ppk'

    myconn = paramiko.SSHClient()
    myconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    hops = traceroute(final_ip)
    # print('Distance/TTL    Address    Average round-trip time')
    # last_distance = 0
    i = 1
    ip_hops = {}
    for hop in hops:
        if i == 1 or i == 2:  # ignoring the first two hops
            i += 1
            continue
        ip = hop.address
        try:
            session = myconn.connect(ip, username=user, password=pswd, port=port)
            ip_hops[ip] = {}
            ip_hops[ip]["address"] = get_address(myconn)
            ip_hops[ip]["router"] = get_mac(myconn)
            myconn.close()
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
    print(ip_hops)
    print(ip_hops["fd8d:1900:2729:7415::1"])


if __name__ == '__main__':
    main()
