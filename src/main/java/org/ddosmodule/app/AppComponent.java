/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ddosmodule.app;
/*
  Importing required packages. for project.
 */
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import com.google.common.collect.Iterables;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onlab.packet.MacAddress;
import org.onosproject.net.Host;
import org.onosproject.net.HostLocation;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flowobjective.FlowObjectiveService;

import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Semaphore;
import java.util.*;
// import java.lang.Object;

@Component(immediate = true)
public class AppComponent {
        //Logging entity
        private final Logger log = LoggerFactory.getLogger(getClass());

        @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
        protected CoreService coreService;
        @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
        protected PacketService packetService;
        @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
        protected HostService hostService;
        @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
        protected DeviceService deviceService;
        @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
        protected FlowRuleService flowRuleService;
        @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
        protected LinkService linkService;
        @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
        protected FlowObjectiveService flowObjectiveService;

        //PacketProcessor for application
        private final PacketProcessor packetProcessor = new InPacketProcessor();
        //Traffic selector for intercepting traffic for detecting attack
        private final TrafficSelector intercept = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .build();

        private ApplicationId appId;
        private static final int PRIORITY = 128;
        private static final int TIME_SEC = 1;
        //Maps for keeping count of source ips, destination ips and ip protocols
        private Map<Integer, Integer> srcIps = new HashMap<Integer, Integer>(); //Count of Source Ips
        private Map<Integer, Integer> dstIps = new HashMap<Integer, Integer>(); //Count of Destination Ips
        private Map<Integer, Integer> srcIps_dstVictimIps = new HashMap<Integer, Integer>(); //Count of Server IPs in Network , just initiallized after Attack Detection
        private Map<Byte, Integer> ipProtocols = new HashMap<Byte, Integer>(); //Count of Ip Protocols
        private HashMap<Integer, HashMap<Byte,Integer>> ipProtocols_per_Srv = new HashMap<Integer, HashMap<Byte,Integer>>(); //Count of Ip Protocols
        private HashMap<Integer, HashMap<Integer,Integer>> ipSrc_per_Srv = new HashMap<Integer, HashMap<Integer,Integer>>(); //Count of Ip Protocols
        private HashMap<Integer, HashMap<Integer,Integer>> ipSrc_per_Srv2 = new HashMap<Integer, HashMap<Integer,Integer>>(); // temp DS taken

        //public java.util.HashMap<Integer, Hashmap<Integer,Integer>> temp3_mapL2 = new java.util.HashMap <Integer,Hashmap<Integer,Integer>>();
        //public java.util.HashMap<Integer, Hashmap<Integer,Integer>> temp5_mapL2 = new java.util.HashMap <Integer,Hashmap<Integer,Integer>>();

        private HashMap<Integer, HashMap<Integer,HashMap<Integer,Integer> >> ipSrcPort_per_Srv = new HashMap<Integer,HashMap<Integer,HashMap<Integer,Integer>>>();// Count of Server Ip to be monitored
        // private HashMap<Integer,HashMap<Integer,HashMap>> tempL1 = new HashMap<Integer,Integer>();
        // temp. container for revceiving Level2 map
        private HashMap<Integer,Integer> tempL2 = new HashMap<Integer,Integer>();
        int mitigationFlag = 0;
        private Map<String,Integer> srv_under_mitPhase = new HashMap<String,Integer>();
        /*
           Flow feature variables.
         */
        private long bytes_in = 0; //bytes_in
        private long bytes_out = 0; //bytes_out
        private long frames = 0; //frames
        private int flows = 0; //number of flows
        private double srcIpEntropy = 0.0; //source ip entropy
        private double dstIpEntropy = 0.0; //destination ip entropy
        private double ipProtocolEntropy = 0.0; //ip protocol entropy
        private double ipProtocolEntropy2 = 0.0; //ip protocol entropy
        private int attack = 0; //attack
        private int iteration = 0; //number of detection cycle.

        private DeviceId deviceId;
        private MacAddress macAddress;
        private String stringIp;

        //Timer to schedule detection cycles.
        private final Timer timer = new Timer("DDOS-Module Flow Info Writer");
        //Semaphore for mutual exclusion
        static Semaphore semaphore = new Semaphore(1);

        /*
          activate() initilizes application parameters.
          It is like a constructor.
         */
        @Activate
        protected void activate() {
                //Asking to register appliaction by name "org.ddosmodule.app"
                appId = coreService.registerApplication("org.ddosmodule.app");
                //Adding packetprocessor in onos packetservice.
                packetService.addProcessor(packetProcessor, PRIORITY);
                //Requesting for matched packets. "PacketPriority.REACTIVE" allows
                // only first packet to controller and other follow flow-rule.
                packetService.requestPackets(intercept, PacketPriority.REACTIVE, appId,
                                             Optional.empty());
                //Scheduling detection threads.
                timer.scheduleAtFixedRate(new FlowInfoProcessor(),
                                          TIME_SEC*1000, TIME_SEC*1000);

                log.info("Started ddos-app with id {} ", appId.id());
        }//end of activate()

        /*
          deactivate() acts like destrcutor.
          It removes packetprocessor, flow rules added and cancel threads scheduled.
         */
        @Deactivate
        protected void deactivate() {
                //removing packetprocessor
                packetService.removeProcessor(packetProcessor);
                //canceling threads
                timer.cancel();
                //Removing installed flow rules
                flowRuleService.removeFlowRulesById(appId);
                log.info("Stopped app with id {} ", appId.id());

        }//end of deactivate()

        /*
          Class InPacketProcessor implements PacketProcessor interface.
          It is for intercepting traffic for flow features calculation
         */
        private class InPacketProcessor implements PacketProcessor {

                //process() process packet_ins.
                @Override
                public void process(PacketContext context) {
                        //if packet_in is already handled abort.
                        if (context.isHandled()) {
                                return;
                        }

                        //Getting ethernet frame from packet_in
                        Ethernet eth = context.inPacket().parsed();
                        //checking whether frame contains IPv4 packet

                        if (eth.getEtherType() == Ethernet.TYPE_IPV4) {
                                //Getting IPv4 packet from ethernet frame
                                IPv4 ipPacket = (IPv4)eth.getPayload();
                                //TCP tcpPacket = (TCP)eth.getPayload();
                                /*
                                Putting count of source ip, destination ip and
                                ip protocol in
                                 Map for calculation of entropies.
                                 */
                                if (ipPacket != null) {
                                        try {
                                                //Acquiring access  to critical section.
                                                semaphore.acquire();
                                        } catch (InterruptedException e) {
                                                e.printStackTrace();
                                        }
                                        /*
                                          If value in map then get present count and
                                          put replace with
                                          increased value .
                                          else put value=1 in map.
                                         */
                                        // Packet_IN for Victim Srv.IP are to be sergregared in Different Block
                                        // Yet to decalre mitigationFlag var

                                        if (srcIps.get(ipPacket.getSourceAddress()) == null) {
                                                srcIps.put(ipPacket.getSourceAddress(), 1);
                                        } else {
                                                srcIps.put(ipPacket.getSourceAddress(),
                                                        srcIps.get(ipPacket.getSourceAddress())+1);
                                        }
                                        if (dstIps.get(ipPacket.getDestinationAddress()) == null) {
                                                dstIps.put(
                                                        ipPacket.getDestinationAddress(), 1);
                                        } else {
                                                dstIps.put(ipPacket.getDestinationAddress(),
                                                        dstIps.get(ipPacket.getDestinationAddress())+1);
                                        }
                                        if (ipProtocols.get(ipPacket.getProtocol()) == null) {
                                                ipProtocols.put(
                                                        ipPacket.getProtocol(), 1);
                                        } else {
                                                ipProtocols.put(ipPacket.getProtocol(),
                                                ipProtocols.get(ipPacket.getProtocol())+1);
                                        }// @@ Still at Both - ML1 and ML2 server entropy data for these servers will be sent
                                        // Step: 1) Entropy calc 2) check if Map has Srv.Ip's Key then in Map2 recheck if it has this Src.IP as Key if true then in Map3 check if this has Src.Port as Key the
                                        
                                        int dst_ip = ipPacket.getDestinationAddress();
                                        if (mitigationFlag == 1)
                                        {
                                                if (ipSrc_per_Srv.containsKey(dst_ip))//whether pckt for this dstIP is under Monitoring
                                                {
                                                        //Goal 1 :Handle insertion for Protocol Entropy
                                                        //Handle insertion for Source Host(IP) Entropy
                                                        //Handle insertion for Source Host's TransportLayer Port (1st we will just consider TCP and !!!not UDP)
                                                        
                                                        //Goal 1: s1. Load map at level 2 of Key=dst_ip into a temp Variable ; in case not existing then Initialize with key = dst_ip ,Val = an Empty Map ,
                                                                // s2. Update its info. using new Count Values and then replace Map_L1 with same key= dst_ip but val=this updated Map_L2
                                                        HashMap <Byte,Integer> temp_mapL2 = ipProtocols_per_Srv.get(dst_ip);//
                                                        if(temp_mapL2 == null)
                                                        {
                                                                // temp_mapL2 = new HashMap<Byte,Integer>();
                                                                temp_mapL2.put(ipPacket.getProtocol(),1);
                                                                ipProtocols_per_Srv.put(dst_ip, temp_mapL2);
                                                        }
                                                        else{
                                                                temp_mapL2 = ipProtocols_per_Srv.get(dst_ip);//return mapL2
                                                                temp_mapL2.put(ipPacket.getProtocol(),temp_mapL2.get(ipPacket.getProtocol())+1);
                                                                ipProtocols_per_Srv.put(dst_ip,temp_mapL2);//replace with updated val
                                                        }
                                                        
                                                        // Goal2 : for calc. of src ip entropy        
                                                        HashMap <Integer,Integer> temp2_mapL2 = ipSrc_per_Srv.get(dst_ip);//returns mapL2 
                                                        if(temp2_mapL2 == null)
                                                        {
                                                                // temp_mapL2 = new HashMap<Byte,Integer>();
                                                                temp2_mapL2.put(ipPacket.getSourceAddress(),1);
                                                                ipSrc_per_Srv.put(dst_ip, temp2_mapL2);
                                                        }
                                                        else{
                                                                temp2_mapL2 = ipSrc_per_Srv.get(dst_ip);//return mapL2
                                                                temp2_mapL2.put(ipPacket.getSourceAddress(),temp2_mapL2.get(ipPacket.getSourceAddress())+1);
                                                                ipSrc_per_Srv.put(dst_ip,temp2_mapL2);//replace with updated val
                                                        }

                                                        // Goal 3 :entropy of ports per IP
                                                        // Level 
                                                        // for Level 3 we will Reuse temp2_mapL2 which has suitable structure for Port(<int,int>) same as used earlier for IP's entropy calc.
                                                        
                                                        ipSrc_per_Srv2 =ipSrcPort_per_Srv.get(dst_ip);//returns mapL2
                                                        if (ipSrc_per_Srv2 == null)
                                                        {
                                                                // temp3_mapL2 = new  HashMap<int,Hashmap<int,int>>()
                                                                // first we will generate map for Base level i.e. mapL3 -> then we will insert this into temp3_mapL2 at Level 2 
                                                                //which will then insert into Top mapLevel 1 i.e. ipSrcPort_per_Srv itself
                                                                
                                                                temp2_mapL2.clear();/* clearing this for Reusability as compatible for layer 3rd*/
                                                                temp2_mapL2.put(555,1);// ex. key =port 555 ,val 1
                                                                ipSrc_per_Srv2.put(ipPacket.getSourceAddress(),temp2_mapL2);// key = srcIP , val = temp2_map_L2
                                                                ipSrcPort_per_Srv.put(dst_ip,ipSrc_per_Srv2);
                                                                // tcpPacket.getSourcePort() replaced with 555
                                                        }
                                                        else
                                                        {
                                                                // we will unpack and store mapL2 . Following this , we will extract mapL3 out of mapL3 which can be directly modified
                                                                // since we alredy have mapL2 ie temp3_mapL2 <key=srcIP,val =mapL3<key=srcPort>>
                                                                temp2_mapL2 = ipSrc_per_Srv2.get(ipPacket.getSourceAddress());// Note: don't confuse with name mapL2 with Level2 as intended for reusabilty
                                                                temp2_mapL2.put(555,temp2_mapL2.get(555)+1);// updated mapL3
                                                                ipSrc_per_Srv2.put(ipPacket.getSourceAddress(),temp2_mapL2);//updated mapL2
                                                                ipSrcPort_per_Srv.put(dst_ip,ipSrc_per_Srv2);
                                                        }
                                                }
                                        }
                                        //releasing critical section
                                        semaphore.release();
                                }
                        }
                }//end of process() 
        }//end of InPacketProcessor

        /*
           Class FlowInfoProcessor extend TimerTask for threading detection cycle.
           It computes flow features and send them to ML Server.
           On basis of value from ML server, it calls for Mitigation.
         */
        private class FlowInfoProcessor extends TimerTask {

                /*
                 * getFlowInfo gets bytes_in , bytes_out, frames count from edge devices and
                 * number of flows in system and computes entropies for source ips,
                 * destination ips and ip protocols from maps.
                 */
                /*
                        For our purpose of sending to ML_Model2 we have to calc. for all Traffics destined to Servers(Attack/non-attack):
                        1.) Entropy of srcIP for only those Host IP whose traffics are destined to servers [src IP entropy]
                Task2   2.) Calc. of protocol entr. " "" " [Protocol Entropy]
                                 {Goal : to find a way to separate/identify those appropriate flow entries which belong to Victim servers and corrosponding Hosts under
                                  scanning : [implementation using TrafficBuilder ]}
                                  {For dealing bytes IN and Out both ,  We have to make 2 traffic builder to cover Bi-directional informatn. }

                Task3 (different Context)  3.) Bytes IN_OUT for selective flows(whose SrcIPs belong to Host under scanning ) under Monitoring for ML_Model2 - flow stats
                                        flwstats  - vs Delta_Flow Stasts ???? http://api.onosproject.org/1.7.1/org/onosproject/net/flow/FlowEntry.html
                        4.) No. of frames / Packets belonging to these Flows whose endpoints are all Host_IP communicating to Srv.(s)
                                        .packet()
                        5.) No. of Flows in Total belonging to these group of Hosts whose traffic are being sent to Server IP under Monitoring under Mitigation Phase1
                        6.) Entropy for all TcPPorts in terms of number of packets matched for Indivisual Src.IP using DS - created earlier(recursive Map_1-2-3)


                */
                String entries_To_be_Sent = "";
                public void getFlowInfo() {
                        //getting hosts in Topology
                        Iterable<Host> hosts = hostService.getHosts();

                        //computing bytes_in, bytes_out and frames from counters at port of hosts.
                        for( Host host : hosts) {
                                HostLocation hostLocation = host.location();
                                PortStatistics portStat =
                                        deviceService.getDeltaStatisticsForPort(
                                                hostLocation.deviceId(),
                                                hostLocation.port());
                                bytes_in += portStat.bytesReceived();
                                bytes_out += portStat.bytesSent();
                                frames += portStat.packetsReceived() + portStat.packetsSent();
                        }

                        //getting flow rule count
                        flows = flowRuleService.getFlowRuleCount();

                        //Compu2ting shannon entropy for source IpAddress
                        double sumOfEntries = 0.0;
                        for( Integer i : srcIps.keySet()) {
                                sumOfEntries += srcIps.get(i);
                        }
                        for( Integer i : srcIps.keySet()) {
                                double value = (srcIps.get(i)/ sumOfEntries);
                                srcIpEntropy += -1*value*(Math.log(value)/Math.log(2));
                        }
                        //Computing shannon entropy for destination IpAddress
                        sumOfEntries = 0;
                        for( Integer i : dstIps.keySet()) {
                                sumOfEntries += dstIps.get(i);
                        }
                        for( Integer i : dstIps.keySet()) {
                                double value = (dstIps.get(i)/ sumOfEntries);
                                dstIpEntropy += -1*value*(Math.log(value)/Math.log(2));
                        }
                        //Computing shannon entropy for IP Protocols
                        sumOfEntries = 0;
                        for( Byte i : ipProtocols.keySet()) {
                                sumOfEntries += ipProtocols.get(i);
                        }
                        for( Byte i : ipProtocols.keySet()) {
                                double value = (ipProtocols.get(i)/ sumOfEntries);
                                ipProtocolEntropy += -1*value*(Math.log(value)/Math.log(2));
                        }
                        //-------------------------------------------------------------------------------------------------------------------
                        // List<String> entries_To_be_Sent = new List<String>();// corrospond to all victim iPs
                        String entry_To_be_Sent = "";// corros. to Single Victim IP
                        long bytes_In_Out_srv = Long.MIN_VALUE;
                        int pckt_count = 0;
                        int flowCount = 0;

                        if (mitigationFlag ==1)
                        {
                                // lets get the mapL2 at once 
                                // Part1{All flow related Informations} and Part2(calc. out of DataStructure for Entropies)
                                // 

                                for (int srvIP : ipSrc_per_Srv.keySet())
                                {
                                        //converting string to IpAddress
                                        //     IpAddress ipAddress = IpAddress.valueOf(stringIp);
                                        //getting host from IpAddress
                                        entry_To_be_Sent = String.valueOf(srvIP);//appending current ServerIP
                                        IpAddress ipAddress = IpAddress.valueOf(srvIP);
                                        Set<Host>  hostSet = hostService.getHostsByIp(ipAddress);///!!!!!this is from where Things get Right
                                        for (Host host : hostSet) {
                                        //Getting immediate device to server(location in term of switch)
                                        MacAddress macAddress = host.mac();
                                        HostLocation hostLocation = host.location();
                                        DeviceId deviceId = hostLocation.deviceId();// edge Switch identification
                                        }
                                        //getting MacAddress of server


                                        //------ Remember to accomodate Bidirectional Traffic Selector ----

                                        Iterable<FlowEntry> flowEntries = Iterables.concat(
                                                flowRuleService.getFlowEntriesByState(deviceId, FlowEntry.FlowEntryState.ADDED),
                                                flowRuleService.getFlowEntriesByState(deviceId, FlowEntry.FlowEntryState.PENDING_ADD));
                                        //Loop to check flow entry match
                                        for (FlowEntry flowEntry : flowEntries) {
                                                //log.info("flow-entry from system: "+flowEntry.toString());

                                                //traffic selector for flow rule checking(Empty)
                                                TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();// should be declare upfront and regularly flushed/cleared for Reusanitliy
                                                TrafficSelector.Builder selectorBuilder_bck_flow = DefaultTrafficSelector.builder();// should be declare upfront and regularly flushed/cleared for Reusanitliy

                                                Set<Criterion> criteria = flowEntry.selector().criteria();

                                                //Setting all parameters same(cpy as it is) except one that determines traffic (so in 2nd case we would skip src.Port and later on Add things there)
                                                for (Criterion criterion : criteria) {
                                                        //1ST block corrosponds to traffic destined to server
                                                        if (criterion.type() != Criterion.Type.ETH_DST &&
                                                                criterion.type() != Criterion.Type.IPV4_DST) {
                                                        selectorBuilder.add(criterion);
                                                        }//TCP_SRC : matchTcpSrc(TpPort tcpPort)

                                                        //2nd block corrosponds to traffic originating from server
                                                        if (criterion.type() != Criterion.Type.ETH_SRC &&
                                                                criterion.type() != Criterion.Type.IPV4_SRC) {
                                                        selectorBuilder_bck_flow.add(criterion);
                                                        }//TCP_SRC : matchTcpSrc(TpPort tcpPort)
                                                }

                                                //Adding required criterias
                                                selectorBuilder.add(Criteria.matchEthDst(macAddress));
                                                selectorBuilder.add(Criteria.matchIPDst(Ip4Prefix.valueOf(srvIP,32)));//.valueOf(java.lang.String address) : Converts a CIDR (slash) notation string (e.g., "10.1.0.0/16") into an IPv4 prefix.
                                                //Adding required criterias
                                                selectorBuilder_bck_flow.add(Criteria.matchEthSrc(macAddress));
                                                selectorBuilder_bck_flow.add(Criteria.matchIPSrc(Ip4Prefix.valueOf(srvIP,32)));//.valueOf(java.lang.String address) : Converts a CIDR (slash) notation string (e.g., "10.1.0.0/16") into an IPv4 prefix.
                                                /*
                                                /*
                                                valueOf(int address, int prefixLength)
                                                Converts an integer and a prefix length into an IPv4 prefix.
                                                */

                                                // @Kamal we will add the criteria for Source Ports here itself
                                                //Building required traffic selector
                                                TrafficSelector trafficSelector = selectorBuilder.build();//------??? yet to build a reverse traffic selector for Bytes_OUT
                                                TrafficSelector trafficSelector_bck_flow = selectorBuilder_bck_flow.build();//------??? yet to build a reverse traffic selector for Bytes_OUT
                                                // to calc. No. of Frames , Bytes_IN && Bytes_OUT and No. of Flows
                                                if (deviceId.equals(flowEntry.deviceId()) &&
                                                        (trafficSelector.equals(flowEntry.selector()) || trafficSelector_bck_flow.equals(flowEntry.selector()) ) ) { // Match implies current Flow entry is relevant to us for Further Calc.
                                                        //selecting flowEntry with maximum bytes_in     //Input port Field for portCriterion should not be null
                                                        // Now from this flow entry , we are going to extract required Features such as (Bytes)
                                                        bytes_In_Out_srv += flowEntry.bytes();
                                                        pckt_count += flowEntry.packets();
                                                        flowCount += 1;
                                                        //setting that flow rule match found
                                                        // flag = 1;
                                                        }
                                                        // log.info("flow rule match found at port: "+portCriterion.port().toString());
                                                }
                                                /*              If not found Jhol marr dena hai () using flowEntry.packets(); used above
                                                */
                                                // flowEntry.packets()
                                                // Part 2 : calc of Entopies
                                                
                                                sumOfEntries = 0.0;
                                                Map <Integer,Integer>temp_mapL1 = new HashMap<Integer,Integer>(); 
                                                temp_mapL1 = ipSrc_per_Srv.get(srvIP);
                                                for( Integer i : temp_mapL1.keySet()) {
                                                        sumOfEntries += temp_mapL1.get(i);
                                                }
                                                for( Integer i : temp_mapL1.keySet()) {
                                                        double value = (temp_mapL1.get(i)/ sumOfEntries);
                                                        srcIpEntropy += -1*value*(Math.log(value)/Math.log(2));
                                                }
                                                
                                                //Computing shannon entropy for IP Protocols
                                                sumOfEntries = 0;
                                                Map <Byte,Integer>temp_mapL2 = new HashMap<Byte,Integer>(); 
                                                temp_mapL2 = ipProtocols_per_Srv.get(srvIP);
                                                for( Byte i : temp_mapL2.keySet()) {
                                                        sumOfEntries += temp_mapL2.get(i);
                                                }
                                                for( Byte i : temp_mapL2.keySet()) {
                                                        double value = (temp_mapL2.get(i)/ sumOfEntries);
                                                        ipProtocolEntropy2 += -1*value*(Math.log(value)/Math.log(2));
                                                }
                                                //append these calculated components separately for each string
                                        entry_To_be_Sent = entry_To_be_Sent + "," + bytes_In_Out_srv + "," + pckt_count + "," + flowCount;
                                        if (entries_To_be_Sent == "")
                                        {
                                                entries_To_be_Sent = entry_To_be_Sent;
                                        }
                                        else{
                                                entries_To_be_Sent = "|" + entry_To_be_Sent;
                                        }
                                }
                        }
                }//end of getFlowInfo()

                //writeTOCSVFIle writes flow info to csv file and log
                public void writeToCSVFile() throws IOException {
                        //Opening file for append
                        //FileWriter fileWriter = n2ew FileWriter("/home/ashu/Desktop/"
                        // +"Project_final-sem/onos/ddos−app/src/main/java/org/ddosmodule"
                        // +"/app/dataset_attack_dns.csv", true);
                        //converting values to string
                        String record = String.valueOf(frames)+","
                                +String.valueOf(dstIpEntropy)
                                +","+String.valueOf(srcIpEntropy)+","
                                +String.valueOf(ipProtocolEntropy)
                                +","+String.valueOf(bytes_in)+","
                                +String.valueOf(bytes_out)
                                +","+String.valueOf(flows)+","
                                +String.valueOf(attack);
                        iteration++;
                        //writing values to log
                        log.info("flow_info-"+iteration+": "+record);
                        //writing value to file
                        //fileWriter.write(record+"\n");
                        //fileWriter.close();
                        //log.info("flow info written to file");

                }//end of writeToCSVFile()

                @Override
                public void run() {
                        try {
                                //Getting access to critical section
                                semaphore.acquire();
                        } catch (InterruptedException e) {
                                e.printStackTrace();
                        }
                        //calling getFlowInfo() to compute flow features value
                        getFlowInfo();
                        try {
                                //calling writeTOCSVFile() to write flow features to file/log
                                writeToCSVFile();
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        //converting flow features to string
                        String data_item = String.valueOf(frames)+","
                                +String.valueOf(dstIpEntropy)
                                +","+String.valueOf(srcIpEntropy)+","
                                +String.valueOf(ipProtocolEntropy)
                                +","+String.valueOf(bytes_in)+","
                                +String.valueOf(bytes_out)
                                +","+String.valueOf(flows);

                        InetAddress localhost = null;
                        try {
                                //Getting Server Address
                                localhost = InetAddress.getByName("localhost");
                        } catch (UnknownHostException e) {
                                e.printStackTrace();
                        }
                        Socket socket = null;
                        try {
                                //Getting socket for connection
                                socket = new Socket(localhost, 12121);
                        } catch (IOException e) {
                                e.printStackTrace();
                        }

                        //Getting Output and Input stream for sending and
                        // receiving data to/from server
                        OutputStreamWriter out = null;
                        try {
                                out = new OutputStreamWriter(socket.getOutputStream());
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        BufferedReader in  = null;
                        try {
                                in = new BufferedReader(new InputStreamReader(
                                        socket.getInputStream()));
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        try {
                                //Sending flow features to ML server
                                out.write(data_item);
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        try {
                                out.flush();
                        } catch (IOException e) {
                                e.printStackTrace();
                        }

                        String line1 = null;
                        try {
                                //Getting prediction from ML Server             //
                                line1= in.readLine();
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        try {
                                socket.close();
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        log.info(line1);

                        //Inferrring value of attack from prediction
                        if (line1.equals("attack detected")) {
                                attack = 1;
                        }

                        //Writing attack value in log
                        log.info("attack_value: "+attack);

                        // If attack detected then calling for Mitigation
                        if (attack == 1) {
                                //IF Mitigation Phase_I is already in Execution, DO_NOTHING
                            int ip_key = 0;
                            String [] split_stringIp = new String[4];
                                if (mitigationFlag == 0){
                                        mitigationFlag = 1;
                                        String[] stringIps = Servers.getServerIpAddresses();
                                        for (String stringIp : stringIps){
                                                //IpAddress ipAddress = IpAddress.valueOf(stringIp);
                                                log.info("This is original IP string :" + stringIp);
                                                split_stringIp = stringIp.split(".");
                                                stringIp = "";
                                                for(String temp_ip : split_stringIp){
                                                    stringIp = stringIp + temp_ip; 
                                                }
                                                ip_key = Integer.parseInt(stringIp);
                                                log.info("This is parsed IP from String to Integer  :" + String.valueOf(ip_key));
                                                // error previously found was :  incompatible types: org.onlab.packet.IpAddress cannot be converted to java.lang.Integer
                                                srv_under_mitPhase.put(stringIp,0);
                                                ipSrc_per_Srv.put(ip_key,null);// map 3 layer
                                }
                        }
                        // -----------------------------------------------------------------------------
                        // try {
                        //         //calling writeTOCSVFile() to write flow features to file/log
                        //         writeToCSVFile();
                        // } catch (IOException e) {
                        //         e.printStackTrace();
                        // }

                        // Iterating over list of strings representing data to be send for indivisual ServerIPs , for each 
                        //converting flow features to string
                        
                        localhost = null;
                        try {
                                //Getting Server Address
                                localhost = InetAddress.getByName("localhost");
                        } catch (UnknownHostException e) {
                                e.printStackTrace();
                        }
                        socket = null;
                        try {
                                //Getting socket for connection
                                socket = new Socket(localhost, 12128);
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        //Getting Output and Input stream for sending and
                        // receiving data to/from server
                        out = null;
                        try {
                                out = new OutputStreamWriter(socket.getOutputStream());
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        try {
                                //Sending flow features to ML server
                                out.write(entries_To_be_Sent);
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        try {
                                out.flush();
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        
                        // ----------------------
                        in  = null;
                        try {
                                in = new BufferedReader(new InputStreamReader(
                                        socket.getInputStream()));
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        line1 = null;
                        try {
                                //Getting prediction from ML Server             //
                                line1= in.readLine();
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        try {
                                socket.close();
                        } catch (IOException e) {
                                e.printStackTrace();
                        }
                        log.info(line1);

                        //Inferrring value of attack from prediction
                        String[] result_parameters = new String[2];//!!!!
                        String[] results = line1.split("|");
                        int servUnderMonitorin_count = srv_under_mitPhase.size();
                        for (String result : results){
                                result_parameters = result.split(",");
                                if (result_parameters[1] == "attack_detected")
                                {// result = "IP"+"attack_detected/attack_not_detected"
                                        // 1.call mitigation 2. remove IP from Monitoring
                                        log.info("Attack Found on ServerIP : " + result_parameters[1]);
                                        servUnderMonitorin_count -= 1; 
                                        Mitigation_flow mitigation = new Mitigation_flow(
                                        appId,
                                        deviceService,
                                        hostService,
                                        flowRuleService,
                                        linkService,
                                        flowObjectiveService,
                                        log,result_parameters[0]);
                                        // remove IP of this server from ipSrc_per_Srv which will automatically stop monitoring process for it(Mit_Phase1)
                                        ipSrc_per_Srv.remove(result_parameters[0]);//basically removes the key values pair 
                                        srv_under_mitPhase.remove(result_parameters[0]);//basically removes the key values pair 
                                }
                                if (result_parameters[1] == "attack_not_detected")
                                {//
                                        //srv_under_mitPhase step 1: check the value of Counter and in case if exceeding 50 iteration
                                        if (srv_under_mitPhase.get(result_parameters[0]) == 50)
                                        {
                                                // remove from monitoring
                                                ipSrc_per_Srv.remove(result_parameters[0]);//basically removes the key values pair 
                                                srv_under_mitPhase.remove(result_parameters[0]);//basically removes the key values pair
                                                servUnderMonitorin_count -= 1;
                                        }
                                }// case of flag requ. to be  -1 for 1st iteration on servUnderMonitorin_count being = 0
                                //possible cases : 1.Attack on Network : False and No. of times VictimSrv identified/sent4rMit.{2.servUnderMonitorin_count >0 } [10, 01 ,00 ,11 ]
                                //case 1: [MLSrv1_result,MLSrv2_result] = 10
                                //case 1: [MLSrv1_result,MLSrv2_result] = 10
                                if(attack==1 && servUnderMonitorin_count==0)
                                {//servUnderMonitorin_count is some +ve val. greter than 1 => either no attack detected by ML2
                                        //or Minm. safe iteration of 50 is still running for any one of server
                                        log.info("Warning !!! : ML Server2 has failed to identify IP address on which DDos has occured, even after 50 iterations");
                                        log.info("Warning !!! : ML Server2 has failed to identify IP address on which DDos has occured, even after 50 iterations");
                                        log.info("Warning !!! : ML Server2 has failed to identify IP address on which DDos has occured, even after 50 iterations");
                                        mitigationFlag = 0;
                                }
                                //case 2: [MLSrv1_result,MLSrv2_result(servUnderMonitorin_count>0)] = 01(False,True)
                                if (attack==0 && servUnderMonitorin_count>0)
                                {
                                        // possible that attack on Network has stopped but ML_server2's 50 iterations have not completed or ML_server2 has sent
                                        // result from previous Iteration since it is one step behind
                                        continue;
                                        // waiting for servUnderMonitorin_count to reduce to 0 automatically after completing 50 Iteration or upon calling mitigation on founding Attack
                                }
                                //case 3: [MLSrv1_result,MLSrv2_result(servUnderMonitorin_count>0)] = 00(False,True)
                                if (attack==0 && servUnderMonitorin_count>0){
                                        // all attack have been succesfully Mitigated
                                        log.info("Cheers ,!!! DDos attack has been Averted. !!! ");
                                        mitigationFlag = 0;

                                }
                                //case 4: [MLSrv1_result,MLSrv2_result(servUnderMonitorin_count>0)] = 11(False,True)
                                if (attack==1 && servUnderMonitorin_count>0)
                                {
                                        log.info("Result from Attack detection at each Server are on the Way...");
                                }
                                

                        }

                        //Resetting flow features values and maps
                        frames = 0;
                        srcIpEntropy = 0.0;
                        dstIpEntropy = 0.0;
                        bytes_in= 0;
                        bytes_out = 0;
                        ipProtocolEntropy = 0.0;
                        flows = 0;
                        attack = 0;
                        srcIps.clear();
                        dstIps.clear();
                        ipProtocols.clear();

                        //
                        /*
                                                -----------------   !!!!!! for some Key and values both may be cleared while for some ONLY Values may be cleared(ex. serverIp to be Monitored)
                        */
                        semaphore.release();
                }//end of run()
        }//end of FlowInfoProcessor

}}//end of AppComponent