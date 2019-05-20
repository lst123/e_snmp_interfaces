# coding=utf-8

import diamond.collector
from easysnmp import Session, exceptions
import yaml

class esnmpdiscoveryCollector(diamond.collector.Collector):
    # Perform SNMP walk
    IF_MIB_NAME_OID = '1.3.6.1.2.1.31.1.1.1.1'
    IF_MIB_TYPE_OID = '1.3.6.1.2.1.2.2.1.3'
    IF_MIB_STATUS_OID = '1.3.6.1.2.1.2.2.1.8'
    IF_TYPES = ['6','161']
    IF_STATUS = ['1']
    IF_D = '/etc/diamond/collectors/iface_discovered.yml'

    def collect_snmp(self, device, host, community):
        # Get snmp data
        session = Session(hostname=host, 
                        community=community, 
                        version=2, timeout=4)
        try:
            snmp_items = session.walk([self.IF_MIB_NAME_OID, 
                                    self.IF_MIB_STATUS_OID, 
                                    self.IF_MIB_TYPE_OID])
        except exceptions.EasySNMPTimeoutError:
            self.log.info('Failed for: %s', device)
            return(None)

        d = {}
        for item in snmp_items:
            # Get oid index
            oid_index = int(item.oid_index)
            # If id not in a dict, then create it
            # and add the first value to tuple (interface)
            # d = dict('id': (ifname, if_status, if_type)) e.g.
            # d = {'209': (u'Ten-GigabitEthernet2/0/48', u'1', u'6')}
            if not oid_index in d.keys():
                d[oid_index] = (item.value,)
            # Else add other values to tuple (if_status, if_type)
            else:
                d[oid_index] = d[oid_index] + (item.value,)
                # If we have three elements in tuple
                # then do some checks (remove items,
                # if they not in IF_TYPES, IF_STATUS lists)
                if len(d[oid_index]) == 3:
                    # Get if_t(ype) and if_s(tatus) from tuple
                    if_s = d[oid_index][1]
                    if_t = d[oid_index][2]
                    # Remove unnecessary interfaces
                    if not if_t in self.IF_TYPES or not if_s in self.IF_STATUS:
                        del d[oid_index]
        # Return only iface indexes
        return(sorted(d.keys()))

    def collect(self):
        data = {}
        # Run collect_snmp() for every device in config
        for device in self.config['devices']:
            self.log.info('Discovering active SNMP interfaces for: %s', device)
            host = self.config['devices'][device]['host']
            community = self.config['devices'][device]['community']
            iface_list = self.collect_snmp(device, host, community)
            # If iface_list != None (snmpwalk was successful
            # add to dict
            if iface_list:
                data[device] = iface_list
                self.log.info('%s -  %s ifaces have been discovered', 
                              device, len(iface_list))
            else:
                self.log.info('%s -  0 ifaces have been discovered', device)
        # Dump to YAML (IF_D)
        with open(self.IF_D, 'w') as outf:
            yaml.dump(data, outf, default_flow_style=False)
