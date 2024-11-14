
import socket
import struct
import shlex
import subprocess

from pycrate_mobile import PPP, TS24008_IE


def nas_pco(pdp_type, pcscf_restoration):

    has_4 = pdp_type in (1, 3)
    has_6 = pdp_type in (2, 3)

    ipcpopt = [
        {"Type": int(PPP.NCPOPTTYPE.PRIM_DNS), "Data": b"\00" * 4},
        {"Type": int(PPP.NCPOPTTYPE.SEC_DNS), "Data": b"\00" * 4},
        {"Type": int(PPP.NCPOPTTYPE.PRIM_NBNS), "Data": b"\00" * 4},
        {"Type": int(PPP.NCPOPTTYPE.SEC_NBNS), "Data": b"\00" * 4},
    ]

    cfg =  []
    if (has_4):
        cfg +=[{"ID": int(TS24008_IE.PCOMS.IPCP), "Cont": {"Code": int(PPP.NCPCODE.CONFIG_REQ), "Id": 0, "Data": ipcpopt}}]
        cfg +=[{"ID": int(TS24008_IE.PCOMS.DNSServerIPv4AddrReq),"Cont": b''}]
        cfg +=[{"ID": int(TS24008_IE.PCOMS.PCSCFIPv4AddrReq), "Cont": b''}]
        cfg +=[{"ID": int(TS24008_IE.PCOMS.IPv4LinkMTUReq), "Cont": b''}]

    if (has_6):
            cfg += [{"ID": int(TS24008_IE.PCOMS.DNSServerIPv6AddrReq), "Cont": b''}]
            cfg += [{"ID": int(TS24008_IE.PCOMS.PCSCFIPv6AddrReq), "Cont": b''}]

    cfg += [{"ID": int(TS24008_IE.PCOMS.PCSCFReselectionSupport), "Cont": b''}] if pcscf_restoration else []
                
    vv = {
        "Config": [
            *cfg,
            {"ID": int(TS24008_IE.PCOMS.IPAddrAllocationViaNASSignalling), "Cont": b''},
            {"ID": int(TS24008_IE.PCOMS.MSISDNReq), "Cont": b''},
            
        ]
    }

    return TS24008_IE.ProtConfig(val=vv).to_bytes()


def helper_print_pco(data):
    _pco = TS24008_IE.ProtConfig()
    _pco.from_bytes(data)
    # _rec_pr2(_pco)
    for i in _pco["Config"]:
        if i.count("ID"):
            val = i["Cont"].get_val()
            v = None
            if i["ID"]._val in [12, 13]:
                v = ".".join(f"{c}" for c in val)
            elif i["ID"]._val in [16]:
                v = int.from_bytes(val, "big")  # ok : be -> int
            elif i["ID"]._val in [int(TS24008_IE.PCOMS.IPCP)]:
                v = "\n\t"+"\n\t".join(f"{c['Type']} {'.'.join(f'{c}' for c in c['Data'].get_val())}" for c in i["Cont"]["Data"])

            if v:
                print(i.count("ID"), i["ID"], v)  # , i.__dict__)
            else:
                print(i)


def _cidr_expand(cidr):
    str_ip, str_prefix = cidr.split('/')
    assert str_prefix != None

    prefixbits = (1 << 32) - (1 << (32 - int(str_prefix)))

    ip = socket.inet_aton(str_ip)
    # ip_u = struct.unpack('!I', ip)[0]
    mask = struct.pack('!I', prefixbits)

    int_mask = int.from_bytes(mask, 'big')
    int_ip = int.from_bytes(ip, 'big')
    masked = struct.pack('!I', int_mask & int_ip)

    return f"-c {str_ip} -r {socket.inet_ntoa(masked)} -p {str_prefix}"


def do_tun_ss(dic):
    print(dic['GTP-U'])
    if dic['GTP-U'] == b'\x01':
        if dic.get("gtp-srv-proc") is not None:
            print(dic["gtp-srv-proc"])
            return dic
        print("start!")
    else:
        if dic.get("gtp-srv-proc") is None:
            print("xdddd")
            return dic
        print("stop!")
        dic["gtp-srv-proc"].kill()
        return dic

    locaddr = '.'.join(
        f'{c}' for c in dic['ENB-GTP-ADDRESS-INT2'].to_bytes(4, 'big'))
    cliaddr = dic['PDN-ADDRESS-IPV4']
    gtpua = '.'.join(f'{c}' for c in dic['SGW-GTP-ADDRESS'][-1])
    lteid = int.from_bytes(dic['SGW-TEID'][-1], "big")  # ok : be -> int
    assert lteid.to_bytes(4, 'big') == dic['SGW-TEID'][-1]

    if cliaddr == None:
        print("no cl", cliaddr)
        return dic

    # y = f"tun_dev/server -e {locaddr} -g 172.22.0.6 {_cidr_expand(cliaddr+"/24")} -t {lteid} -d"  # -n bernd
    # y = f"tun_dev/tunsrv -e {locaddr} -g 172.22.0.113 {_cidr_expand(cliaddr+"/24")} -t {lteid} -d"  # -n bernd

    # proxy
    # y = f"tun_dev/server -e {locaddr} -g 172.22.0.113 {_cidr_expand(cliaddr+"/24")} -t {lteid} -d"  # -n bernd
    y = f"gtpu-range-extender/server -e {locaddr} -g 172.25.54.120 {_cidr_expand(cliaddr+'/24')} -t {lteid} -d"  # -n bernd

    print(y)

    p = subprocess.Popen(shlex.split(y)
                         # ,start_new_session=True
                         )
    print(p)
    dic["gtp-srv-proc"] = p

    return dic
