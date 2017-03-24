#!/usr/bin/env python
# -------------------------------------------------------
# DNSentriesFromECU.py
# version 0.6
# date: Feb 16th 2016
# changes:
#	support for Oracle Public Cloud Machine 16.1.1
#
# known issues:
#       various exceptions are not trapped
#       rack name cannot contain "-"
#       reverse DNS to be improved, only /16 zone supported
#       SDI control VM is not listed because it is not required
# author: Greg Verstraeten
# -------------------------------------------------------

import json
import sys, getopt

separator = "_"
ecu_dir = "./config"
rack_name = "NoName"
domain = "mydomain"

# Zone Dictionaries
eth_admin_network = {}  # eth_admin + ilom
EoIB_management_network = {}
EoIB_OMS_network = {}
EoIB_public_network = {}
IPoIB_default_network = {}
IPoIB_management_network = {}
IPoIB_storage_network = {}
IPoIB_instance_storage_network = {}
IPoIB_virt_admin_network = {}
IPoIB_ldap_internal_network = {}
IPoIB_load_balancer_network = {}
IPoIB_private_network = {}


def storeDNSzoneEntry(hostname, ip, DNSzone_dic):
    DNSzone_dic[hostname] = ip
    return


def printAllDNSzone(DNSzone_dic):
    for DNSentry in sorted(DNSzone_dic):
        print DNSentry + "\t\tIN\tA\t" + DNSzone_dic[DNSentry]
    return


def printAllReverseDNSzone(DNSzone_dic):
    for DNSentry in sorted(DNSzone_dic):
        print DNSzone_dic[DNSentry].split(".")[3] + "." + DNSzone_dic[DNSentry].split(".")[
            2] + "\t\tIN\tPTR\t" + DNSentry + "." + domain + "."
    return


def printMinDNSzone():
    for DNSentry in sorted(DNSzone_dic):
        print DNSentry + "\t\tIN\tA\t" + DNSzone_dic[DNSentry]
    return


def collectHWdataFromECUfiles():
    global rack_name
    global domain
    ### rack_info ###
    with open(ecu_dir + "/rack_info.json") as rack_info_file:
        rack_info_data = json.load(rack_info_file)
        rack_name = rack_info_data['name']
    ### domain ###
    with open(ecu_dir + "/common_host_config.json") as common_host_config_file:
        common_host_config_data = json.load(common_host_config_file)
        domain = common_host_config_data['domain']
    ### cnode_target ###
    with open(ecu_dir + "/cnodes_target.json") as cnodes_target_file:
        cnodes_target_data = json.load(cnodes_target_file)
        for cn in cnodes_target_data:
            if fullconf: storeDNSzoneEntry(cn['host'] + "-ilom", cn['ilom']['ip'], eth_admin_network)
            storeDNSzoneEntry(cn['host'], cn['eth-admin']['ip'], eth_admin_network)
            if fullconf: storeDNSzoneEntry(cn['host'] + separator + "IPoIB-default", cn['IPoIB-default']['ip'],
                              IPoIB_default_network)
            if cn.get('EoIB-management', None):
                if fullconf: storeDNSzoneEntry(cn['host'] + separator + "EoIB-management", cn['EoIB-management']['ip'],
                                  EoIB_management_network)
            if cn.get('IPoIB-management', None):
                if fullconf: storeDNSzoneEntry(cn['host'] + separator + "IPoIB-management", cn['IPoIB-management']['ip'],
                                  IPoIB_management_network)
            if cn.get('IPoIB-storage', None):
                if fullconf: storeDNSzoneEntry(cn['host'] + separator + "IPoIB-storage", cn['IPoIB-storage']['ip'],
                                  IPoIB_storage_network)
                # the IPoIB-instance-storage NIC on the seed node is ignored
                # if cn.get('IPoIB-instance-storage',None):
                #    storeDNSzoneEntry( cn['host']+separator+"IPoIB-instance-storage", cn['IPoIB-instance-storage']['ip'], IPoIB_instance_storage_network)
    ### eth_switch ###
    with open(ecu_dir + "/eth_switch.json") as eth_switch_file:
        eth_switch_data = json.load(eth_switch_file)
        if fullconf: storeDNSzoneEntry(eth_switch_data['hostname'], eth_switch_data['ip'], eth_admin_network)
    ### pdu ###
    with open(ecu_dir + "/pdu.json") as pdu_file:
        pdu_data = json.load(pdu_file)
        for pdunet in pdu_data['pdu_networks']:
            if fullconf: storeDNSzoneEntry(pdunet['pdu_hostname'], pdunet['pdu_ip'], eth_admin_network)
    ### storage_target ###
    with open(ecu_dir + "/storage_target.json") as storage_target_file:
        storage_target_data = json.load(storage_target_file)
        for ipoibnet in storage_target_data["ipoib"]:
            if ipoibnet.get('IPoIB-default'):
                if fullconf: storeDNSzoneEntry(ipoibnet['host'].split('-')[0] + separator + "IPoIB-default",
                                  ipoibnet['IPoIB-default']['ip'], IPoIB_default_network)
            if ipoibnet.get('IPoIB-management'):
                if fullconf: storeDNSzoneEntry(ipoibnet['host'].split('-')[0] + separator + "IPoIB-management",
                                  ipoibnet['IPoIB-management']['ip'], IPoIB_management_network)
            if ipoibnet.get('IPoIB-storage'):
                if fullconf: storeDNSzoneEntry(ipoibnet['host'].split('-')[0] + separator + "IPoIB-storage",
                                  ipoibnet['IPoIB-storage']['ip'], IPoIB_storage_network)
            if ipoibnet.get('IPoIB-instance-storage'):
                if fullconf: storeDNSzoneEntry(ipoibnet['host'].split('-')[0] + separator + "IPoIB-instance-storage",
                                  ipoibnet['IPoIB-instance-storage']['ip'], IPoIB_instance_storage_network)
        for node in storage_target_data["nodes"]:
            if fullconf: storeDNSzoneEntry(node['host'], node['eth-admin']['ip'], eth_admin_network)
            if fullconf: storeDNSzoneEntry(node['ilom-host'], node['ilom']['ip'], eth_admin_network)
    ### switches_target ###
    with open(ecu_dir + "/switches_target.json") as switches_target_file:
        switches_target_data = json.load(switches_target_file)
        for switch in switches_target_data:
            if fullconf: storeDNSzoneEntry(switch['ilom']['host'], switch['ilom']['ip'], eth_admin_network)
    ### spine ###
    with open(ecu_dir + "/spine_switch.json") as spine_switch_file:
        spine_switch_data = json.load(spine_switch_file)
        for switch in spine_switch_data:
            if fullconf: storeDNSzoneEntry(switch['ilom']['host'], switch['ilom']['ip'], eth_admin_network)
    return


def collectVMdataFromECUfiles(service):
    try:
        with open(ecu_dir + "/" + service + "_vms.json") as vms_file:
            vms_data = json.load(vms_file)
            for vm in vms_data['control_vms']:
                for net in vm['networks']:
                    if net['name'] == "EoIB-management":
                        if service == 'control' or service == 'psm' or service == 'grill':  # privileged control and PSM hostname need to resolve on the EoIB-management IP address, we do not append the network name
                            storeDNSzoneEntry(vm['hostname'].split(".")[0], net['ip'], EoIB_management_network)
                        else:
                            if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "EoIB-management", net['ip'],
                                              EoIB_management_network)
                    elif net['name'] == "eth-admin":
                        if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "eth-admin", net['ip'], eth_admin_network)
                    elif net['name'] == "IPoIB-virt-admin":
                        if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "IPoIB-virt-admin", net['ip'],
                                          IPoIB_virt_admin_network)
                    elif net['name'] == "EoIB-OMS":
                        if service == 'db' or service == 'sim' or service == 'routing_internal' :  # DB,SIM,Routing VM hostnames need to resolve on the EoIB-OMS IP address, we do not append the network name
                            storeDNSzoneEntry(vm['hostname'].split(".")[0], net['ip'], EoIB_OMS_network)
                        else:
                            if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "EoIB-OMS", net['ip'],
                                              EoIB_OMS_network)
                    elif net['name'] == "EoIB-public":
                        if service == 'routing_external' :  # Routing VM hostnames need to resolve on the EoIB-public IP address, we do not append the network name
                            storeDNSzoneEntry(vm['hostname'].split(".")[0], net['ip'], EoIB_public_network)
                        else:
                            if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "EoIB-public", net['ip'],
                                              EoIB_public_network)
                    elif net['name'] == "IPoIB-management":
                        if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "IPoIB-management", net['ip'],
                                          IPoIB_management_network)
                    elif net['name'] == "IPoIB-private":
                        if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "IPoIB-private", net['ip'],
                                          IPoIB_private_network)
                    elif net['name'] == "IPoIB-instance-storage":
                        if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "IPoIB-instance-storage",
                                          net['ip'], IPoIB_instance_storage_network)
                    elif net['name'] == "IPoIB-load-balancer":
                        if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "IPoIB-load-balancer", net['ip'],
                                          IPoIB_load_balancer_network)
                    elif net['name'] == "IPoIB-ldap-internal":
                        if fullconf: storeDNSzoneEntry(vm['hostname'].split(".")[0] + separator + "IPoIB-ldap-internal", net['ip'],
                                          IPoIB_ldap_internal_network)
                    else:
                        print "Warning: File " + ecu_dir + "/" + service + "_vms.json contains an unsupported network: " + net['name']
        return
    except IOError:
        print "Warning: File " + ecu_dir + "/" + service + "_vms.json does not exist"
        return


def usage():
    print("Usage: %s [options]" % sys.argv[0])
    print("options:")
    print("  -h,--help       Display this usage help and exit")
    print("  -c,--config     path to the ECU config directory")
    print("  -z,--zone    prints zone file entries (default)")
    print(
    "  -r,--reverse    prints reverse name resolution zone file entries, this option cannot be specified along with the zone option")
    print("  -m,--minimum    prints only zone file entries that are required by ECU")
    return


######## MAIN #########
def main(argv):
    global ecu_dir
    global fullconf
    fullconf = False
    reverse = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hzrfc:", ["help", "zone", "reverse", "full", "config"])
    except getopt.GetoptError as e:
        print (str(e))
        usage()
        sys.exit(2)
    if opts == []:
        usage()
        sys.exit(1)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-z", "--zone"):
            reverse = False
        elif opt in ("-r", "--reverse"):
            reverse = True
        elif opt in ("-f", "--full"):
            fullconf = True
        elif opt in ("-c", "--config"):
            ecu_dir = arg
        else:
            usage()
            sys.exit()

    collectHWdataFromECUfiles()
    collectVMdataFromECUfiles("control")
    collectVMdataFromECUfiles("psm")
    collectVMdataFromECUfiles("db")
    collectVMdataFromECUfiles("sim")
    collectVMdataFromECUfiles("grill")
#    collectVMdataFromECUfiles("sdi")
    collectVMdataFromECUfiles("routing_internal")
    collectVMdataFromECUfiles("routing_external")

    if reverse == True:
        ### Print Reverse DNS zones ###
        print "; DNS Reverse zone eth-admin"
        printAllReverseDNSzone(eth_admin_network)
        print "\n; DNS Reverse zone EoIB-management"
        printAllReverseDNSzone(EoIB_management_network)
        print "\n; DNS Reverse zone EoIB-OMS"
        printAllReverseDNSzone(EoIB_OMS_network)
        print "\n; DNS Reverse zone EoIB-public"
        printAllReverseDNSzone(EoIB_public_network)
        if IPoIB_default_network:
            print "\n; DNS Reverse zone IPoIB-default"
            printAllReverseDNSzone(IPoIB_default_network)
        if IPoIB_management_network:
            print "\n; DNS Reverse zone IPoIB-management"
            printAllReverseDNSzone(IPoIB_management_network)
        if IPoIB_storage_network:
            print "\n; DNS Reverse zone IPoIB-storage"
            printAllReverseDNSzone(IPoIB_storage_network)
        if IPoIB_instance_storage_network:
            print "\n; DNS Reverse zone IPoIB-instance-storage"
            printAllReverseDNSzone(IPoIB_instance_storage_network)
        if IPoIB_virt_admin_network:
            print "\n; DNS Reverse zone IPoIB-virt-admin"
            printAllReverseDNSzone(IPoIB_virt_admin_network)
        if IPoIB_ldap_internal_network:
            print "\n; DNS Reverse zone IPoIB-ldap-internal"
            printAllReverseDNSzone(IPoIB_ldap_internal_network)
        if IPoIB_load_balancer_network:
            print "\n; DNS Reverse zone IPoIB-load-balancer"
            printAllReverseDNSzone(IPoIB_load_balancer_network)
        if IPoIB_private_network:
            print "\n; DNS Reverse zone IPoIB-private"
            printAllReverseDNSzone(IPoIB_private_network)
    else:
        ### Print DNS zones ###
        print "; DNS zone eth-admin"
        printAllDNSzone(eth_admin_network)
        print "\n; DNS zone EoIB-management"
        printAllDNSzone(EoIB_management_network)
        print "\n; DNS zone EoIB-OMS"
        printAllDNSzone(EoIB_OMS_network)
        print "\n; DNS zone EoIB-public"
        printAllDNSzone(EoIB_public_network)
        if IPoIB_default_network:
            print "\n; DNS zone IPoIB-default"
            printAllDNSzone(IPoIB_default_network)
        if IPoIB_management_network:
            print "\n; DNS zone IPoIB-management"
            printAllDNSzone(IPoIB_management_network)
        if IPoIB_storage_network:
            print "\n; DNS zone IPoIB-storage"
            printAllDNSzone(IPoIB_storage_network)
        if IPoIB_instance_storage_network:
            print "\n; DNS zone IPoIB-instance-storage"
            printAllDNSzone(IPoIB_instance_storage_network)
        if IPoIB_virt_admin_network:
            print "\n; DNS zone IPoIB-virt-admin"
            printAllDNSzone(IPoIB_virt_admin_network)
        if IPoIB_ldap_internal_network:
            print "\n; DNS zone IPoIB-ldap-internal"
            printAllDNSzone(IPoIB_ldap_internal_network)
        if IPoIB_load_balancer_network:
            print "\n; DNS zone IPoIB-load-balancer"
            printAllDNSzone(IPoIB_load_balancer_network)
        if IPoIB_private_network:
            print "\n; DNS zone IPoIB-private"
            printAllDNSzone(IPoIB_private_network)
    return

if __name__ == "__main__":
    main(sys.argv[1:])
