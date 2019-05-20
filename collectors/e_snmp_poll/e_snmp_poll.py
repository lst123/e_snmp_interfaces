# coding=utf-8

import yaml
import diamond.collector
import concurrent.futures 
from configobj import ConfigObj
from easysnmp import Session, exceptions

COUNTER_MAX_32 = 4294967295
COUNTER_MAX_64 = 18446744073709551616

class esnmppollCollector(diamond.collector.Collector):
    f = '/etc/diamond/collectors/iface_discovered.yml'
    d_f = '/etc/diamond/collectors/esnmpdiscoveryCollector.conf'
    IF_MIB_INFO = {'ifName': "1.3.6.1.2.1.31.1.1.1.1",
               'ifAlias': "1.3.6.1.2.1.31.1.1.1.18",
               'ifHCInOctets': "1.3.6.1.2.1.31.1.1.1.6",
               'ifHCOutOctets': "1.3.6.1.2.1.31.1.1.1.10",
               'ifHCInUcastPkts': "1.3.6.1.2.1.31.1.1.1.7",
               'ifHCOutUcastPkts': "1.3.6.1.2.1.31.1.1.1.11",
               'ifHCInMulticastPkts': "1.3.6.1.2.1.31.1.1.1.8",
               'ifHCOutMulticastPkts': "1.3.6.1.2.1.31.1.1.1.12",
               'ifHCInBroadcastPkts': "1.3.6.1.2.1.31.1.1.1.9",
               'ifHCOutBroadcastPkts': "1.3.6.1.2.1.31.1.1.1.13",
               'ifInDiscards': "1.3.6.1.2.1.2.2.1.13",
               'ifOutDiscards': "1.3.6.1.2.1.2.2.1.19",
               'ifInErrors': "1.3.6.1.2.1.2.2.1.14",
               'ifOutErrors': "1.3.6.1.2.1.2.2.1.20"}
    IF_MIB_COUNTER64 = ['ifHCInOctets', 'ifHCOutOctets', 
                      'ifHCInUcastPkts', 'ifHCOutUcastPkts', 
                      'ifHCInMulticastPkts', 'ifHCOutMulticastPkts',
                      'ifHCInBroadcastPkts', 'ifHCOutBroadcastPkts']
    IF_MIB_COUNTER32 = ['ifInDiscards', 'ifOutDiscards', 
                    'ifInErrors', 'ifOutErrors']

    def get_default_config(self):
        default_config = super(esnmppollCollector,
                               self).get_default_config()
        default_config['path'] = ''
        return default_config

    def parse_snmp_val(self, device, snmp_val):
        # Normalize ifName
        if_name = snmp_val[0].value.replace('-', '_')
        if_name = if_name.replace('/', '_')
        # Normalize ifAlias, if alias not empty: 
        # -i- sw1 to -i-_sw1
        # if iface doesn't have alias then set to '_'
        if snmp_val[1].value: 
            if_alias = snmp_val[1].value.replace(' ', '_')
            if 'Interface' in if_alias:
                if_alias = '_'
            else:
                if_alias = if_alias.replace('.', '_')
        else:
            if_alias = '_'
        for item in snmp_val[2:]:
            metricName = if_name + '.' + if_alias \
                         + '.' + item.oid
            metricPath = '.'.join([device,
                                   'if',
                                   metricName])
            if item.oid in self.IF_MIB_COUNTER64:
                self.publish_counter(metricPath,
                                     int(item.value),
                                     max_value=COUNTER_MAX_64,
                                     )
                #self.log.debug('%s %s', metricPath, item.value)
            elif item.oid in self.IF_MIB_COUNTER32:
                if 'NOSUCHINSTANCE' in item.value:
                    continue
                else:
                    self.publish_counter(metricPath,
                                        int(item.value),
                                        max_value=COUNTER_MAX_32,
                                        )
                    #self.log.debug('%s %s', metricPath, item.value)

    def collect_snmp(self, device, host, community, if_list):
        # Logging
        self.log.debug('Poll metrics for: %s', device)
        # Create SNMP session
        snmp_session = Session(hostname=host,
                               community=community,
                               version=2, timeout=3)
        # For every interface in if_list create a list for 
        # query and poll from device
        for i in if_list:
            if_param = [self.IF_MIB_INFO['ifName'] + '.'+str(i),
                        self.IF_MIB_INFO['ifAlias'] + '.'+str(i),
                        self.IF_MIB_INFO['ifHCInOctets'] +'.'+ str(i),
                        self.IF_MIB_INFO['ifHCOutOctets'] +'.'+str(i),
                        self.IF_MIB_INFO['ifHCInUcastPkts'] +'.'+str(i),
                        self.IF_MIB_INFO['ifHCOutUcastPkts'] +'.'+str(i),
                        self.IF_MIB_INFO['ifHCInMulticastPkts'] +'.'+str(i),
                        self.IF_MIB_INFO['ifHCOutMulticastPkts'] +'.'+str(i),
                        self.IF_MIB_INFO['ifHCInBroadcastPkts'] +'.'+str(i),
                        self.IF_MIB_INFO['ifHCOutBroadcastPkts'] +'.'+str(i),
                        self.IF_MIB_INFO['ifInDiscards'] +'.'+str(i),
                        self.IF_MIB_INFO['ifOutDiscards'] +'.'+str(i),
                        self.IF_MIB_INFO['ifInErrors'] +'.'+str(i),
                        self.IF_MIB_INFO['ifOutErrors'] +'.'+str(i)] 
            try:
                snmp_val = snmp_session.get(if_param)
            except exceptions.EasySNMPTimeoutError:
                self.log.debug('Failed for: %s', device)
                return(None)
            # Parse values and publish metrics
            self.parse_snmp_val(device, snmp_val)

    def collect(self):
        # Get interface OIDS 
        d = yaml.load(open(self.f))
        # Parse esnmpdiscoveryCollector.conf
        # get [[device]] section
        cfg = ConfigObj(self.d_f)['devices']
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_t_snmp = {executor.submit(self.collect_snmp, device, 
                                             cfg[device]['host'],
                                             cfg[device]['community'],
                                             d[device]): device for device in d 
                                             if device in cfg.keys()}
