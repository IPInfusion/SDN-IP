SDN-IP
======

SDN-IP solution with BGP protocol

This contains of BGP protocol module supporting REST APIs whcih can be working with ONOS provided by ON.Lab. BGP can exchange the routing updates and then provide them to ONOS (SDN Controller).

## Build

1. Build BGP binary with REST API extention
   ```sh
   cd BGP_SDN
   sh ./Build.sh
   ```

   The bgp binary with REST API extention will be created in BGP_SDN/platform/linux/bin.
   
## Specification
BGP supports the following REST APIs.

1. POST/DELETE method for routing update to ONOS
   These methods are invoked when BGP detects the routing updates. BGP sends out the following message to ONOS.
   ```sh
   http://<Address>:<Port>/wm/bgp/<Sysuptime>/<Seq>/<Router-ID>/<Prefix>/<Prefix-Length>/<Nexthop>
   ```

2. POST method for initiating BGP instance to ONOS
   This method is invoked when BGP instance is created. BGP sends out the following message to ONOS.
   ```sh
   http://<Address>:<Port>/wm/bgp/<Router-id>/<Capability>

3. POST/DELETE methods for installing/uninstalling a routing entry from ONOS
   These methods are used in order for ONOS to install/uninstall the routing entry to BGP. The following message must be sent out to BGP.
   ```sh
   http://<Address>:<Port>/wm/bgp/<Router-ID>/<Prefix>/<Prefix-Length>/<Nexthop>
   ```

4. GET method for retrieving all routing information from ONOS
   This method is used in order for ONOS to retrieve all routing information from BGP. The following message must be sent out to BGP. When receiving this message, BGP provides JSON file containing of all routing information.
   ```sh
   http://<Address>:<Port>/wm/bgp/<Router-ID>/json
   ```
   The following is JSON format provided by BGP.
   ```sh
   {
     "rib" : [
       {
         "prefix" : <string> (i.e., 10.0.0.0/8)
         "nexthop" : <string> (i.e, 172.168.0.1)
       }
     ],
     "router-id" : <string> (i.e., 10.0.0.1)
   }
   ```
### Configuration
  User needs to log in BGP in order to configure BGP protocol.
  ```sh
  # telnet localhost 2605
  bgpd> enable
  bgpd# configuration terminal
  bgpd(config)#
  ```

  In order to configure REST interface in BGP, the following command needs to be configured.
  ```sh
  bgpd(config)# router bgp <AS-Number>
  bgpd(config-router)# bgp sdn-engine <1-2> <ONOS Address> <ONOS Port>
  bgpd(config-router)# bgp rest-server <Local Address> <Local Port>
  ```
### License
    
### Acknowledge
  HTTP Server library named as libonion which is licensed under LGPLv3 and AGPLv3 licenses is used for HTTP Server interface in BGP. 
  
