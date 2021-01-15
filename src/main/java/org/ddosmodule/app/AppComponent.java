/*
        ### Note : The entire app module has been primarily coded as two components : 
                    1. one required for identification of attack at network being monitored under current controller (done by seniors graduated in June 2020)
                    2. second one (identified as version 2.0) required for detection of attack at Server level i.e. exactly
                        which server is under attack (done by seniors graduating in June 2021)

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
import org.onlab.packet.UDP;
import org.onlab.packet.ICMP;
import org.onlab.packet.IPacket;
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
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.IcmpTypeCriterion;
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
import java.util.concurrent.Semaphore;
import java.util.*;

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
        private Map<Byte, Integer> ipProtocols = new HashMap<Byte, Integer>(); //Count of Ip Protocols
        /*
           Flow feature variables.
         */



        // ----- for Version 2.0  --------------------------------------------------------------------------------------------

        private HashMap<Integer, HashMap<Byte,Integer>> ipProtocols_per_Srv = new HashMap<Integer, HashMap<Byte,Integer>>(); // keeps Count of Ip Protocols per ServerIPs
        private HashMap<Integer, HashMap<Integer,Integer>> ipSrc_per_Srv = new HashMap<Integer, HashMap<Integer,Integer>>(); //keeps Count of SourceIp addresses connected to each server in curr. iteration

        private HashMap<Integer, HashMap<Integer,Integer>> icmp_per_Src_per_Srv = new HashMap<Integer, HashMap<Integer,Integer>>(); //Count of Ip Protocols
        private HashMap<Integer, HashMap<Integer,HashMap<Integer,Integer> >> ipSrcPort_per_Srv = new HashMap<Integer,HashMap<Integer,HashMap<Integer,Integer>>>();// Count of Server Ip to be monitored

        private HashMap<Integer, HashMap<Integer,Integer>> tcpSrcPort_per_SrcIP = new HashMap<Integer, HashMap<Integer,Integer>>(); // just a temporary data structure with 2 level hashmaps

        private HashMap<Integer,Integer> tempL2 = new HashMap<Integer,Integer>();
        int mitigationFlag = 0;
        private Map<String,Integer> srv_under_mitPhase = new HashMap<String,Integer>();
        public int counter_debug = 0;
        /*
           Flow feature variables.
         */

        private double ipProtocolEntropy2 = 0.0; //ip protocol entropy
        private double srcIpIcmpEntropy = 0.0; //icmp protocol entropy
        private double srcPortEntropyPerIP = 0.0;
        private double avgSrcPortEntropyPerIP = 0.0;

        private DeviceId deviceId;
        private HostLocation hostLocation;
        private MacAddress macAddress;
        private String stringIp;

        private int servUnderMonitorin_count = 0;

        private int just_once=1;
        private int test = 0;

        private int test_count_flowRuleService = 0;
        private int exception_free_flowRuleService = 1;

        private int iterationSize = 1;// used for setting how much data to collect : useful in case for Version 2 Blocks , yield of Data is too less using Test Attack traffic
        private int iterationCount = 0;// accompanied to iterationSize

        private int debuggMode = 0;// this can be set or reset so as to enable extended display of logs for debugging purposes

        // ------------------------ end of Declaration for V2


        private long bytes_in = 0; //bytes_in
        private long bytes_out = 0; //bytes_out
        private long frames = 0; //frames
        private int flows = 0; //number of flows
        private double srcIpEntropy = 0.0; //source ip entropy
        private double dstIpEntropy = 0.0; //destination ip entropy
        private double ipProtocolEntropy = 0.0; //ip protocol entropy
        private int attack = 0; //attack
        private int iteration = 0; //number of detection cycle.

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
        private class InPacketProcessor implements PacketProcessor
        {

                //process() process packet_ins.
                @Override
                public void process(PacketContext context) 
                {
                        //if packet_in is already handled abort.
                        if (context.isHandled()) {
                                return;
                        }

                        //Getting ethernet frame from packet_in
                        Ethernet eth = context.inPacket().parsed();
                        //checking whether frame contains IPv4 packet
                    try
                    {
                        if (eth.getEtherType() == Ethernet.TYPE_IPV4) 
                        {
                                //Getting IPv4 packet from ethernet frame
                                IPv4 ipPacket = (IPv4)eth.getPayload();

                                        if (debuggMode == 1)
                                        {
                                            if (ipPacket.getProtocol() ==IPv4.PROTOCOL_TCP)
                                            {
                                                    IPacket pkt2 = eth.getPayload();
                                                    IPacket payload2 = pkt2.getPayload();
                                                    // test = 
                                                    log.info("!!!!!!!++++++++++++Value of Source Port : {}",String.valueOf(((TCP) payload2).getSourcePort()));
                                            }
                                            // if (ipPacket.getProtocol() ==IPv4.PROTOCOL_ICMP)
                                            // {
                                            //         // test = ((TCP) payload2).getSourcePort();
                                            //         log.info("Got an ICMP pckt : {}",String.valueOf(test));
                                            //         test += 1; 
                                            // }
                                        }


                                /*
                                Putting count of source ip, destination ip and
                                ip protocol in
                                 Map for calculation of entropies.
                                 */
                                if (ipPacket != null)
                                {
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
                                        }
                                        if(debuggMode==1){log.info("!!!!!!!++++++++++++Senior's block 1 exeuted in  PacketProcessor");}

                                        // ---------- Block_2 Code for version - 2.0

                                try
                                  {
                                        if (mitigationFlag == 1 ) // can be set to /*true*/ for debugging or testing purposes
                                        {
                                            int dst_ip = ipPacket.getDestinationAddress();
                                                //         if (payload instanceof TCP) {
                                                
                                                if (srv_under_mitPhase.containsKey(IPv4.fromIPv4Address(dst_ip)) /*ipSrc_per_Srv.containsKey(dst_ip)*/)// chekcing if it is Relevant //whether pckt for this dstIP is under Monitoring [31-12] zzz.. Replace with the String one so that we can effectively clear things up
                                                {
                                                    IPacket pkt = eth.getPayload();
                                                    IPacket payload = pkt.getPayload();
                                                    //log.info("Created 2 object for Ip packets");
                                                        // log.info("Found required Values in ipSrc_per_Srv MAP");
                                                        if(debuggMode == 1){log.info("!!!!!!!++++++++++++Got flow for Server : {}",IPv4.fromIPv4Address(dst_ip));}

                                                        if (debuggMode == 1){log.info("!!!!!!!++++++++++++Protocol Number is: {}",ipPacket.getProtocol());}// outputs the current protocol number
                                                        
                                                        //Goal 1 :Handle insertion for Protocol Entropy
                                                        //Goal 1: step1. Load map at level 2 of Key=dst_ip into a temp Variable ; in case not existing then Initialize with key = dst_ip ,Val = an Empty Map ,
                                                                // s2. Update its info. using new Count Values and then replace Map_L1 with same key= dst_ip but val=this updated Map_L2

                                                        HashMap <Byte,Integer> temp_mapL2 = null;//ipProtocols_per_Srv.get(dst_ip) // Retruns Value: null or a MAP 
                                                        if(ipProtocols_per_Srv.get(dst_ip) == null) // 2 cases > either Key is Non Existing or > Key exists but value is NULL
                                                        {
                                                                temp_mapL2 = new HashMap<Byte,Integer>();
                                                                temp_mapL2.put(ipPacket.getProtocol(),1);
                                                                ipProtocols_per_Srv.put(dst_ip, temp_mapL2);
                                                                // log.info("Value ipProtocol for srv. initialized");
                                                                // log.info("Inserted a new Key value for ipProtocols_per_Srv");
                                                        }
                                                        else{
                                                                temp_mapL2 = ipProtocols_per_Srv.get(dst_ip);//return map Level 2
                                                                if (temp_mapL2.containsKey(ipPacket.getProtocol()))
                                                                {
                                                                        temp_mapL2.put(ipPacket.getProtocol(),temp_mapL2.get(ipPacket.getProtocol()) +1);
                                                                }else{
                                                                        temp_mapL2.put(ipPacket.getProtocol(), 1);
                                                                }
                                                                ipProtocols_per_Srv.put(dst_ip,temp_mapL2);//replace with updated val
                                                                // log.info("Value ipProtocol for srv. updated");
                                                                // log.info("updated ipProtocols_per_Srv with count value ");
                                                        }

                                                        // ------------ Part 2
                                                        // Goal2 : for calc. of src ip entropy        
                                                        HashMap <Integer,Integer> temp2_mapL2 = null; // returns map at Level2 
                                                        if(ipSrc_per_Srv.get(dst_ip) == null)
                                                        {
                                                                temp2_mapL2 = new HashMap<Integer,Integer>();
                                                                temp2_mapL2.put(ipPacket.getSourceAddress(),1);
                                                                ipSrc_per_Srv.put(dst_ip, temp2_mapL2);
                                                                // log.info("Value ipSrc_per_Srv for srv. initialized");
                                                                // log.info("Inserted a new Key value for ipSrc_per_Srv");
                                                        }
                                                        else{
                                                                temp2_mapL2 = ipSrc_per_Srv.get(dst_ip);//return mapL2
                                                                if (temp2_mapL2.containsKey(ipPacket.getSourceAddress()))
                                                                {
                                                                        temp2_mapL2.put(ipPacket.getSourceAddress(),temp2_mapL2.get(ipPacket.getSourceAddress())+1);
                                                                }else{
                                                                        temp2_mapL2.put(ipPacket.getSourceAddress(),1);
                                                                }

                                                                
                                                                ipSrc_per_Srv.put(dst_ip,temp2_mapL2);//replace with updated val
                                                                // log.info("Value ipSrc_per_Srv for srv. updated");
                                                                // log.info("updated ipSrc_per_Srv with count value ");
                                                        }

                                                        // ------------------------------------------------------------------- ICMP-----------------
                                                        if (ipPacket.getProtocol() ==IPv4.PROTOCOL_ICMP)
                                                        {
                                                                // log.info("Got an ICMP packet");
                                                                
                                                                temp2_mapL2.clear();
                                                                // temp2_mapL2 = icmp_per_Src_per_Srv.get(dst_ip);// returns map at base level of type <int = src_IP, count>

                                                                if(icmp_per_Src_per_Srv.get(dst_ip) == null)
                                                                {
                                                                        temp2_mapL2 = new HashMap<Integer,Integer>();// !!! Good as if was Null then has been dealt with Recovery of loss of Object
                                                                        temp2_mapL2.put(ipPacket.getSourceAddress(),1);
                                                                        icmp_per_Src_per_Srv.put(dst_ip, temp2_mapL2);
                                                                        // log.info("Value icmp_per_Src_per_Srv for srv. initialized");
                                                                        // log.info("Inserted a new Key value for icmp_per_Src_per_Srv");
                                                                }
                                                                else{
                                                                        temp2_mapL2 = icmp_per_Src_per_Srv.get(dst_ip);//return mapL2
                                                                        if (temp2_mapL2.containsKey(ipPacket.getSourceAddress()))
                                                                        {
                                                                                temp2_mapL2.put(ipPacket.getSourceAddress(),temp2_mapL2.get(ipPacket.getSourceAddress())+1);
                                                                        }else{
                                                                                temp2_mapL2.put(ipPacket.getSourceAddress(),1);
                                                                        }

                                                                        icmp_per_Src_per_Srv.put(dst_ip,temp2_mapL2);//replace with updated val
                                                                        // log.info("Value icmp_per_Src_per_Srv for srv. updated");
                                                                        // log.info("updated icmp_per_Src_per_Srv with count value ");
                                                                }
                                                                
                                                        }

                                                        //-----------------------------TCP-port------------------------------- 


                                                        if (ipPacket.getProtocol() ==IPv4.PROTOCOL_TCP)
                                                        {
                                                                        int test1 = 0;
                                                                        TCP tcpPacket = (TCP) payload;
                                                                        test1  = tcpPacket.getSourcePort();
                                                                        if(debuggMode ==1){log.info("!!!!!!!++++++++++++ Got TCP packet from Source Port : {}",String.valueOf(test1) + " from Source: " + IPv4.fromIPv4Address(ipPacket.getSourceAddress()));}
                                                                        
                                                                        HashMap <Integer,Integer> temp3_mapL2 = new HashMap <Integer,Integer>();
                                                                        temp3_mapL2.clear();
                                                                        tcpSrcPort_per_SrcIP.clear();//  since intermediate DS , so could be cleared
                                                                        if (ipSrcPort_per_Srv.get(dst_ip) == null)//!!!!!!!!! if serverIP exists them => Value if Null
                                                                        {
                                                                                
                                                                                // log.info("!!! ++++++++++++Found ipSrcPort_per_Srv.get(dst_ip) AS null for dst_ip:  {}",IPv4.fromIPv4Address(dst_ip));
                                                                                temp3_mapL2.put(tcpPacket.getSourcePort(),1);// ex. key =port 555 ,val 1
                                                                                
                                                                                
                                                                                tcpSrcPort_per_SrcIP.put(ipPacket.getSourceAddress(),temp3_mapL2);// key = srcIP , val = temp2_map_L2
                                                                                ipSrcPort_per_Srv.put(dst_ip,tcpSrcPort_per_SrcIP);
                                                                                // log.info("++++++++++++Value ipSrcPort_per_Srv for srv. initialized");
                                                                                // log.info("++++++++++++Inserted a new Key value for ipSrcPort_per_Srv");
                                                                        }
                                                                        else
                                                                        {
                                                                                tcpSrcPort_per_SrcIP =ipSrcPort_per_Srv.get(dst_ip);// !!! if this is set to NULL then => we loose property of holding an Object , and also that obj will be flushed
                                                                                // we will unpack and store mapL2 . Following this , we will extract mapL3 out of mapL3 which can be directly modified
                                                                                // since we alredy have mapL2 ie temp3_mapL2 <key=srcIP,val =mapL3<key=srcPort>>
                                                                                if (tcpSrcPort_per_SrcIP.containsKey(ipPacket.getSourceAddress()))
                                                                                {      
                                                                                                temp3_mapL2 = tcpSrcPort_per_SrcIP.get(ipPacket.getSourceAddress());// Note: don't confuse with name mapL2 with Level2 as intended for reusabilty
                                                                                                if(temp3_mapL2.containsKey(tcpPacket.getSourcePort())){
                                                                                                        // log.info("++++++++++++Value Updated in block TCP - map");
                                                                                                        //log.info("Already initialized .. so won't be done again to stop overriding Values inserted by getFlowInfo() at TcpPortCriterion");
                                                                                                }
                                                                                                else{
                                                                                                        temp3_mapL2.put(tcpPacket.getSourcePort(),1);
                                                                                                        // log.info("++++++++++++New Port inserted");
                                                                                                }
                                                                                }else
                                                                                {
                                                                                                temp3_mapL2.put(tcpPacket.getSourcePort(),1);
                                                                                                // log.info("++++++++++++New Port inserted");          
                                                                                }
                                                                                tcpSrcPort_per_SrcIP.put(ipPacket.getSourceAddress(),temp3_mapL2);
                                                                                ipSrcPort_per_Srv.put(dst_ip,tcpSrcPort_per_SrcIP);
                                                                        }
                                                                
                                                        }// just grab the packet from here  // IPv4.PROTOCOL_TCP

                                                }//if (ipSrc_per_Srv.containsKey(dst_ip)) ends here
                                                else{
                                                        if(debuggMode==1){log.info("!!!!!!!++++++++++++Not found Server's iP address in Packet_IN as Destined to : " + IPv4.fromIPv4Address(dst_ip));}
                                                    }
                                        }// mitigation flag ends
                                   }catch(Exception e){
                                           log.info("caught exception in Block_2 Code for version - 2.0 under PacketProcessor");
                                   }

                                        //releasing critical section
                                        semaphore.release();
                                }//ipPacket != null ends here
                                else{
                                    log.info("IP Packet was NULL");
                                }
                        }// if Ethernet.TYPE_IPV4 ends here
                    }catch(Exception e){
                        log.info("Caught exception in Packet Processor Block 1(older DDOS_1.0) : {}",e);
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
                String entries_To_be_Sent = "";// used to collect Information to be sent corresponding to individual servers to ML server 2
                public void getFlowInfo() 
                {
                    entries_To_be_Sent = "";
                        try
                        {
                            //getting hosts in Topology
                            Iterable<Host> hosts = hostService.getHosts();

                            //computing bytes_in, bytes_out and frames from counters at port of hosts.
                            for( Host host : hosts) 
                            {
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
                        }catch(Exception e){
                            log.info("Received Exception due to lack of traffic and thus No flow entry being present when calling getFlowRuleCount(). Tip: try running Traffic : {}",e);
                        }

                            //Computing shannon entropy for source IpAddress
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
       
                        // ---------- Block_2 Code for version - 2.0
                    if(mitigationFlag == 1)
                    {
                        log.info("Found mitigationFlag set to 1 : Executing Block 2.0 ");
                        String entry_To_be_Sent = "";// corros. to Single Victim IP
                        long bytes_In_srv = 0;// at the server
                        long bytes_Out_srv = 0;// from the server
                        long pckt_count = 0;
                        int flowCount = 0;

                        // For ICMP traffic
                        /*
                        long bytes_In_srv2 = 0;// at the server
                        long bytes_Out_srv2 = 0;// from the server
                        long pckt_count2 = 0;
                        int flowCount2 = 0;*/

                        for (String srvIP_string : srv_under_mitPhase.keySet() /*int srvIP : ipSrc_per_Srv.keySet()*/ )// say 5 serv.
                        {
                            int srvIP = IPv4.toIPv4Address(srvIP_string);
                            // log.info("bloody :  {}",srvIP_string);
                                try
                                {
                                        entry_To_be_Sent = String.valueOf(srvIP);//appending current ServerIP
                                        String stringIp = (IPv4.fromIPv4Address(srvIP));



                                        IpAddress ipAddress = IpAddress.valueOf(stringIp);
                                        Set<Host>  hostSet = hostService.getHostsByIp(ipAddress);

                                        for (Host host : hostSet) 
                                        {
                                        //Getting immediate device to server(location in term of switch)
                                        // edge Switch identification
                                        // !!!!!!!!!!!!!!  Note that since in present scenario , one Host is behind one IP for server so below alternative will work but 

                                        macAddress = host.mac();
                                        hostLocation = host.location();
                                        deviceId = hostLocation.deviceId();// (adjacent to edge) Switch identification
                                        }
                                                //------ Remember to accomodate Bidirectional Traffic Selector ----
                                                // log.info("Going to fetch FLOW entries !!!App may Crash if Traffic is not running and thus flowRuleService is DOWN ");// if app does not crashes , then we should not face errors
                                                // /*
                                                Iterable<FlowEntry> flowEntries = null;
                                                try
                                                {
                                                    /*Iterable<FlowEntry> */flowEntries = Iterables.concat(
                                                            flowRuleService.getFlowEntriesByState(deviceId, FlowEntry.FlowEntryState.ADDED),
                                                            flowRuleService.getFlowEntriesByState(deviceId, FlowEntry.FlowEntryState.PENDING_ADD));//!! Sometimes raises error else fine(In that case use :getFlowEntriesById(fwd,ddos2))
                                                        // try using try catch just for this Block and you could use CLEAR in finally BLOCK 
                                                    exception_free_flowRuleService = 1;
                                                        // */
                                                }catch(Exception e)
                                                {
                                                    // log.info("flowRuleService returned Exception for this iteration {}",e);
                                                    test_count_flowRuleService += 1;
                                                    log.info("!!! Warning !!! No traffic running or Flow Entry not found in System - Suggestion(run traffic) : error count_flowRuleService risen to {}",test_count_flowRuleService);
                                                    exception_free_flowRuleService = 0;
                                                }

                                                //Loop to check flow entry match
                                                // log.info("Entering Flow Block");
                                                // /*
                                            if(exception_free_flowRuleService != 0)
                                            {
                                                int countFlowEntry = 0;
                                                for (FlowEntry flowEntry : flowEntries)
                                                {       countFlowEntry += 1;

                                                    //    log.info("flow-entry from system: #{} " + flowEntry.toString() , countFlowEntry);
                                                        // try
                                                        // {
                                                                //traffic selector for flow rule checking(Empty)
                                                                TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();// for traffic from client to server
                                                                TrafficSelector.Builder selectorBuilder_bck_flow = DefaultTrafficSelector.builder();//for traffic from server to client

                                                                Set<Criterion> criteria = flowEntry.selector().criteria();

                                                                //Setting all parameters same(cpy as it is) except one that determines traffic (so in 2nd case we would skip src.Port and later on Add things there)
                                                                for (Criterion criterion : criteria) 
                                                                {
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
                                                                // log.info("Accumulated criterias");

                                                                //Adding required criterias
                                                                selectorBuilder.add(Criteria.matchEthDst(macAddress));
                                                                selectorBuilder.add(Criteria.matchIPDst(Ip4Prefix.valueOf(srvIP,32)));//.valueOf(java.lang.String address) : Converts a CIDR (slash) notation string (e.g., "10.1.0.0/16") into an IPv4 prefix.
                                                                //Adding required criterias
                                                                selectorBuilder_bck_flow.add(Criteria.matchEthSrc(macAddress));
                                                                selectorBuilder_bck_flow.add(Criteria.matchIPSrc(Ip4Prefix.valueOf(srvIP,32)));//.valueOf(java.lang.String address) : Converts a CIDR (slash) notation string (e.g., "10.1.0.0/16") into an IPv4 prefix.                    

                                                                // we will add the criteria for Source Ports here itself
                                                                //Building required traffic selector
                                                                TrafficSelector trafficSelector = selectorBuilder.build();
                                                                TrafficSelector trafficSelector_bck_flow = selectorBuilder_bck_flow.build();//--- a reverse traffic selector for Bytes_OUT
                                                                
                                                                // to calc. No. of Frames , Bytes_IN && Bytes_OUT and No. of Flows we will iterate and find out flows being relevent
                                                                long curr_flow_pckt = 0;
                                                                // long curr_flow_life_pckt = 0;
                                                                if (deviceId.equals(flowEntry.deviceId()) &&
                                                                        trafficSelector.equals(flowEntry.selector()))
                                                                { // Match implies current Flow entry is relevant to us for Further Calc.
                                                                        //selecting flowEntry with maximum bytes_in     //Input port Field for portCriterion should not be null
                                                                        // Now from this flow entry , we are going to extract required Features such as (Bytes)
                                                                        bytes_In_srv += flowEntry.bytes();
                                                                        curr_flow_pckt = flowEntry.packets();
                                                                        pckt_count += curr_flow_pckt;
                                                                        flowCount += 1;

                                                                        // TcpPortCriterion tcpCrit;
                                                                        //££££££££££££££££££££££££££££££££££3  CODE INSERTED for icmp/tcp feture inserted below ££££££££££££££££/*
                                                                        TcpPortCriterion tcpCrit = (TcpPortCriterion) flowEntry.selector().getCriterion(Criterion.Type.TCP_SRC);
                                                                            int srcPort = (tcpCrit == null) ? 0 : tcpCrit.tcpPort().toInt();
                                                                        if(srcPort != 0)
                                                                        {
                                                                            HashMap<Integer, HashMap<Integer,Integer>> tcpSrcPort_per_SrcIP = ipSrcPort_per_Srv.get(srvIP);// Null or Not NULL
                                                                                        // IP Criterion check
                                                                                            IPCriterion srcIpCrit = (IPCriterion) flowEntry.selector().getCriterion(Criterion.Type.IPV4_SRC);
                                                                                            String[] extractNetwID = (srcIpCrit.toString()).split("/");
                                                                                            String ip_addr = extractNetwID[0];
                                                                                            if (debuggMode == 1 ){log.info("!!!!!!!++++++++++++ £££ Converting IP to String : {}",IPv4.toIPv4Address(ip_addr) );}// ££ Confirm this ONCE
                                                                                            /*
                                                                                            log.info("!!!!!!!++++++++++++ £££ Converting IP to String : {}",srcIpCrit.toString() );
                                                                                            log.info("!!!!!!!++++++++++++ £££ Converting IP to String : {}", extractNetwID.length );
                                                                                            log.info("!!!!!!!++++++++++++ £££ Converting IP to String : {}", extractNetwID[0] );
                                                                                            log.info("!!!!!!!++++++++++++ £££ Converting IP to String : {}", ip_addr );
                                                                                            log.info("!!!!!!!++++++++++++ £££ Converting IP to String : {}", IPv4.toIPv4Address("192.156.0.5") );// !!!!! ^^^^ This came to be in -VE , so be cautious when deriving IPs out of this VS from PAcket_IN as might be cause of Inconsistency
                                                                                            // */
                                                                                            log.info("!!!!!!!++++++++++++ £££ Converting IP to String : {}",(int)IPv4.toIPv4Address(ip_addr));

                                                                                            //"Ip4Prefix.valueOf()"

                                                                            if(tcpSrcPort_per_SrcIP != null)
                                                                            {
                                                                                HashMap <Integer,Integer> temp4_mapL3 = null;
                                                                                try{temp4_mapL3 = tcpSrcPort_per_SrcIP.get((int)IPv4.toIPv4Address(extractNetwID[0]) );
                                                                                }catch(Exception e){
                                                                                    log.info("{}",e);
                                                                                }
                                                                                if(temp4_mapL3 != null)
                                                                                {
                                                                                    temp4_mapL3.put(srcPort,(int)curr_flow_pckt);// long conversion might lead to loss of data but for unit FlowEntry should be fine
                                                                                    tcpSrcPort_per_SrcIP.put((int)IPv4.toIPv4Address(extractNetwID[0]),temp4_mapL3);
                                                                                    ipSrcPort_per_Srv.put(srvIP,tcpSrcPort_per_SrcIP);
                                                                                }
                                                                            }
                                                                        }
                                                                        IcmpTypeCriterion icmpTypeCrit = (IcmpTypeCriterion) flowEntry.selector().getCriterion(Criterion.Type.ICMPV4_TYPE);
                                                                        if(icmpTypeCrit != null)
                                                                        {
                                                                            bytes_In_srv += flowEntry.bytes();
                                                                            curr_flow_pckt = flowEntry.packets();
                                                                            pckt_count += curr_flow_pckt;
                                                                            flowCount += 1;
                                                                        }

                                                                            /*
                                                                            // ICMP
                                                                                    IcmpTypeCriterion icmpTypeCrit = (IcmpTypeCriterion) entry.selector().getCriterion(Type.ICMPV4_TYPE);
                                                                                            Short icmpType = (icmpTypeCrit == null) ? 0 : icmpTypeCrit.icmpType();
                                                                                            IcmpCodeCriterion icmpCodeCrit = (IcmpCodeCriterion) entry.selector().getCriterion(Type.ICMPV4_CODE);
                                                                                            Short icmpCode = (icmpCodeCrit == null) ? 0 : icmpCodeCrit.icmpCode(); 
                                                                                            

                                                                                IPCriterion dstIpCrit = (IPCriterion) entry.selector().getCriterion(Type.IPV4_DST);

                                                                            // Tcp Port Criteria
                                                                                TcpPortCriterion tcpCrit;
                                                                                tcpCrit = (TcpPortCriterion) entry.selector().getCriterion(Type.TCP_SRC);
                                                                                int srcPort = (tcpCrit == null) ? 0 : tcpCrit.tcpPort().toInt();
                                                                                        tcpCrit = (TcpPortCriterion) entry.selector().getCriterion(Type.TCP_DST);
                                                                                        int dstPort = (tcpCrit == null) ? 0 : tcpCrit.tcpPort().toInt();

                                                                            // UDP
                                                                                UdpPortCriterion udpCrit;
                                                                                    udpCrit = (UdpPortCriterion) entry.selector().getCriterion(Type.UDP_SRC);
                                                                                    srcPort = (udpCrit == null) ? 0 : udpCrit.udpPort().toInt();
                                                                                    udpCrit = (UdpPortCriterion) entry.selector().getCriterion(Type.UDP_DST);
                                                                                    dstPort = (udpCrit == null) ? 0 : udpCrit.udpPort().toInt();
                                                                            */

                                                                        if(debuggMode == 1){log.info("!!!!!!!++++++++++++ Wow.. Traffic and flow selector for 1ST from current set Matched..");}
                                                                }
                                                                // else{
                                                                //     log.info("Ooops.. Traffic and flow selector failed to match for 1ST... will Get : bytes_Out_srv , pckt_count , flowCount = 0");
                                                                // }
                                                                if (deviceId.equals(flowEntry.deviceId()) && trafficSelector_bck_flow.equals(flowEntry.selector()) /*&& tcpPortCriterion != null*/)
                                                                { 
                                                                // Match implies current Flow entry is relevant to us for Further Calc.
                                                                        //selecting flowEntry with maximum bytes_in     //Input port Field for portCriterion should not be null
                                                                        // Now from this flow entry , we are going to extract required Features such as (Bytes)
                                                                        bytes_Out_srv += flowEntry.bytes();
                                                                        pckt_count += flowEntry.packets();
                                                                        flowCount += 1;
                                                                        
                                                                        if(debuggMode == 1){log.info("!!!!!!!++++++++++++ Wow.. Traffic and flow selector for 2ND from current set Matched..");}
                                                                }
                                                                // else{
                                                                //     log.info("Ooops.. Traffic and flow selector failed to match for 2ND... will Get : bytes_Out_srv , pckt_count , flowCount = 0");

                                                        // }catch(Exception e){
                                                        //         log.info("Faced exception while iterating on FlowEntry: {}",e);
                                                        // }
                                                }//end of for iterating over FlowEntries
                                                // */
                                            }else{
                                                log.info("Received Exception in flowRuleService .. may be traffic does not exists .. skipping current Iteration");
                                            }

                                }catch (Exception e){
                                    log.info("Faced exception while iterating on FlowEntry: {}",e);
                                    e.printStackTrace();
                                    exception_free_flowRuleService = 0;
                                //     log.info("!!! caught exception in Line 532");
                                }

                                // --------------------------------- Now calculation of other Values start here
                            if(exception_free_flowRuleService != 0)
                            {
                                HashMap <Integer,Integer>temp_mapL1 = new HashMap<Integer,Integer>();// declaring outside try block to be visible to other locations when reusing
                                try
                                {    sumOfEntries = 0.0;
                                            //temp_mapL1 = ipSrc_per_Srv.get(srvIP);
                                        if (ipSrc_per_Srv.get(srvIP)!= null)
                                        {    
                                                for( Integer i : temp_mapL1.keySet()) {
                                                        sumOfEntries += temp_mapL1.get(i);
                                                }
                                                for( Integer i : temp_mapL1.keySet()) {
                                                        double value = (temp_mapL1.get(i)/ sumOfEntries);
                                                        srcIpEntropy += -1*value*(Math.log(value)/Math.log(2));
                                                }
                                                //Computing shannon entropy for IP Protocols [B]-------------------------------
                                        }
                                        if (ipProtocols_per_Srv.get(srvIP)!= null)
                                        {
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
                                        }//end of part B
                                }
                                catch(Exception e)
                                {
                                            log.info("Got exception in block A or B of getFlowInfo() : {}",e);
                                }

                                //------------------------------------------PART [C] ----------------------

                                try 
                                {
                                    HashMap <Integer,Integer>temp_mapL3_icmp = new HashMap<Integer,Integer>();
                                    sumOfEntries = 0.0;
                                    if (icmp_per_Src_per_Srv.get(srvIP)!= null)
                                    {    
                                            temp_mapL3_icmp = icmp_per_Src_per_Srv.get(srvIP);
                                                   for( Integer i : temp_mapL3_icmp.keySet()) 
                                                   {
                                                           sumOfEntries += temp_mapL3_icmp.get(i);
                                                   }
                                                   for( Integer i : temp_mapL3_icmp.keySet()) 
                                                   {
                                                           if (sumOfEntries == 0){
                                                                   break;
                                                           }
                                                           double value = (temp_mapL3_icmp.get(i)/ sumOfEntries);
                                                           srcIpIcmpEntropy += -1*value*(Math.log(value)/Math.log(2));
                                                   }
                                                   //Computing shannon entropy for icmp Protocols [C]
                                           // }
                                    }
                                }catch(Exception e){
                                    log.info("{}",e);
                                }
                                
                                // -----------------------------------------------------------Part [C] ends 


                                //------------------------------------------PART [D] ----------------------

                                try
                                {
                                    temp_mapL1.clear();// reuse

                                    if (ipSrcPort_per_Srv.containsKey(srvIP))
                                    {
                                        HashMap <Integer, HashMap <Integer, Integer>> temp_mapL22 = ipSrcPort_per_Srv.get(srvIP);
                                        for (int i : temp_mapL22.keySet())//src ip address
                                        {
                                            sumOfEntries = 0.0;
                                            temp_mapL1 = temp_mapL22.get(i);
                                            for (int j : temp_mapL1.keySet())
                                            {
                                                sumOfEntries += temp_mapL1.get(j);
                                            }
                                            for(int j : temp_mapL1.keySet())
                                            {
                                                double value = temp_mapL1.get(j)/sumOfEntries;
                                                srcPortEntropyPerIP += -1*value*(Math.log(value)/Math.log(2));
                                            }
                                        }
                                        avgSrcPortEntropyPerIP = srcPortEntropyPerIP / temp_mapL22.size();// dividing by no. of Src IP
                                    }
                                }catch(Exception e){
                                    log.info("Caught an excepion in Port Entropy block in GetFlowINfo : {}",e);
                                }

                                // log.info("Average Entropy for this iteration is : {}",avgSrcPortEntropyPerIP);

                                //------------------------------------------- Part [D] ends here ------------------------

                                //calling writeTOCSVFile() to write flow features to file/log
                                        try
                                        {
                                            FileWriter fileWriter2 = new FileWriter("/home/kamal/Desktop/CS-06_8-Sem_project_all/dataset22", true);
                                                //converting values to string
                                                String record = String.valueOf(pckt_count)+","
                                                        +String.valueOf(srcIpIcmpEntropy)
                                                        +","+String.valueOf(srcIpEntropy)+","
                                                        +String.valueOf(ipProtocolEntropy2)
                                                        +","+String.valueOf(bytes_In_srv)+","
                                                        +String.valueOf(bytes_Out_srv)
                                                        +","+String.valueOf(flowCount)+","
                                                        +String.valueOf(0);//parameter passed corrosponds to attack value (0 or 1 for normal or attack traffic dataset collection)
                                                iteration++;
                                                //writing values to log
                                                log.info("flow_info for Version 2 - "+iteration+ " : "+record);
                                                //writing value to file
                                                fileWriter2.write(record+"\n");
                                                fileWriter2.close();
                                                log.info("flow info written to file");
                                        } catch (IOException e) {
                                                e.printStackTrace();
                                                log.info("exception: {}",e);
                                        }

                                entry_To_be_Sent = IPv4.fromIPv4Address(srvIP) + "," + String.valueOf(pckt_count) + "," + String.valueOf(srcIpIcmpEntropy) +"," + String.valueOf(srcIpEntropy) + "," + String.valueOf(ipProtocolEntropy2) + "," + String.valueOf(bytes_In_srv) + ","+ String.valueOf(bytes_Out_srv) +"," + String.valueOf(flowCount);
                                //log.info(" $%£$%^&^*(&)(*()");// just to seperate this Above Output
                                log.info("Entry_To_be_Sent has Value of  : " + entry_To_be_Sent);
                                //log.info(" $£$%^&)*&*(*()*)()()*");// just to seperate this Above Output

                                        if (entries_To_be_Sent == "")
                                        {
                                                entries_To_be_Sent = entry_To_be_Sent;
                                        }
                                        else{
                                                // entries_To_be_Sent = "|" + entry_To_be_Sent + "|";
                                                entries_To_be_Sent = "|" + entry_To_be_Sent;
                                        }
                            }// end of exception_free_flowRuleService = 0 for tackling Errors

                                        //Clear all values for Next Server's iterations
                                        entry_To_be_Sent = "";// corros. to Single Victim IP

                                        bytes_In_srv = 0;
                                        bytes_Out_srv = 0;
                                        pckt_count = 0;
                                        flowCount = 0;
                                        srcIpIcmpEntropy=0;
                                        srcPortEntropyPerIP =0;
                                        srcIpEntropy=0;
                                        ipProtocolEntropy2 = 0;

                                        if(iterationCount >= iterationSize)//Need to be careful in case exception occurs and if Code is not reaching to this staze then
                                        // a large value might accumulate
                                        {
                                            ipSrc_per_Srv.clear();
                                            ipProtocols_per_Srv.clear();
                                            icmp_per_Src_per_Srv.clear();
                                            tcpSrcPort_per_SrcIP.clear();

                                            iterationCount =0;// reset
                                            if(debuggMode==1){log.info("Cleared at OverFlow");}
                                        }
                                        else{
                                            iterationCount += 1;
                                        }
                            log.info("Block 2 executed for ServerIP : " + srvIP_string);
                        }       //END of : srvIP : ipSrc_per_Srv.keySet()
                    }//end of if mitigationFlag ==1
                }//end of getFlowInfo()

                //writeTOCSVFIle writes flow info to csv file and log
                public void writeToCSVFile() throws IOException {
                        //Opening file for append
                        //FileWriter fileWriter = new FileWriter("/home/ashu/Desktop/"
                        // +"Project_final-sem/onos/ddos−app/src/main/java/org/ddosmodule"
                        // +"/app/dataset_attack_dns.csv", true);
                        FileWriter fileWriter = new FileWriter("/home/kamal/Desktop/CS-06_8-Sem_project_all/dataset", true);


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
                        fileWriter.write(record+"\n");
                        fileWriter.close();
                        log.info("flow info written to file");

                }//end of writeToCSVFile()

                @Override
                public void run() 
                {
                        try {
                                //Getting access to critical section
                                semaphore.acquire();
                        } catch (InterruptedException e) {
                                e.printStackTrace();
                        }

                        /*
                        try{
                                if (just_once==1) // could be kept true for debugging
                                {       

                                        String[] stringIps = Servers.getServerIpAddresses();
                                        for (String stringIp : stringIps)
                                        {
                                                //IpAddress ipAddress = IpAddress.valueOf(stringIp);
                                                log.info("Inserted following Server's IP as key for DDos_Phase_2 : " + stringIp);
                                                
                                                srv_under_mitPhase.put(stringIp,0);
                                                // ipSrc_per_Srv.put(IPv4.toIPv4Address(stringIp),null);//-- initialize for Just once
                                                // ipProtocols_per_Srv.put(IPv4.toIPv4Address(stringIp),null);

                                                // [31-12]
                                                // try to set dependencies on just one Monitoring Variable ie String case
                                        }
                                        just_once = 0;
                                }
                        }catch(Exception e)
                            {
                                log.info("Error while initializing Map with Server's IP");
                            }*/

                        //calling getFlowInfo() to compute flow features value  -----  !!!!!!
                        log.info("Calling getFlowInfo of FlowInfoProcessor in Run");
                        getFlowInfo();
                        

                        try {
                                //calling writeTOCSVFile() to write flow features to file/log
                                writeToCSVFile();
                        } catch (IOException e) {
                                e.printStackTrace();
                                log.info("eewww..Error on calling for Writer operation :{}",e);
                        }

                        // ------------------------ Sending to ML server-------------------------------------------------------------

                        InetAddress localhost = null;
                        Socket socket = null;
                        Socket socket2 = null;
                        OutputStreamWriter out = null;
                        BufferedReader in  = null;
                        String line1 = "";
                        
                        //converting flow features to string
                        String data_item = String.valueOf(frames)+","
                                +String.valueOf(dstIpEntropy)
                                +","+String.valueOf(srcIpEntropy)+","
                                +String.valueOf(ipProtocolEntropy)
                                +","+String.valueOf(bytes_in)+","
                                +String.valueOf(bytes_out)
                                +","+String.valueOf(flows);

                        try
                        { 
                            try {
                                    //Getting Server Address
                                    localhost = InetAddress.getByName("localhost");
                            } catch (UnknownHostException e) {
                                    e.printStackTrace();
                            }
                            try {
                                    //Getting socket for connection
                                    socket = new Socket(localhost, 12121);
                                    // socket2 = new Socket(localhost, 12148);// new Experiment !!!!!!!!!! can be Rmvd Later
                            } catch (IOException e) {
                                    e.printStackTrace();
                                    log.info("xxxxxxxxxxxxx--------Caught exception at Socket establishment to ML_sr1 :{}",e);
                            }

                            //Getting Output and Input stream for sending and
                            // receiving data to/from server
                            try {
                                    out = new OutputStreamWriter(socket.getOutputStream());
                            } catch (IOException e) {
                                    e.printStackTrace();
                            }
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

                            try {
                                    //Getting prediction from ML Server
                                    line1 = in.readLine();
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
                            else{
                                    attack = 0;
                            }

                            //Writing attack value in log
                            log.info("attack_value: "+attack);
                        }catch(Exception e){
                            log.info("xxxxxxxxxxxxx-------Failed to establish conncetion to ML Server 1, may be server is not running or stopped due to error.");
                        }
                        
                    try
                    {
                                // If attack detected then calling for Mitigation

                        // ----------------- -----------------------------------------Version 2.0--- begins--------------------------

                        /*For test only*/ // at line 675 - (int)IPv4.toIPv4Address(ip_addr)// !!!!! ^^^^ This came to be in -VE , so be cautious when deriving IPs out of this VS from PAcket_IN as might be cause of Inconsistency
                        //attack = 1;

                        int sendingEnabled = mitigationFlag;// 1st iteration upon Detection val will be Zero
                        if (attack == 1) 
                        {
                                //IF Mitigation Phase_I is already in Execution, DO_NOTHING

                                if (mitigationFlag == 0)
                                {// if mitigation is not running then enable system , else if Flag value is already 1 then don't Interfere/OverRide
                                        mitigationFlag = 1;
                                        String[] stringIps = Servers.getServerIpAddresses();
                                        for (String stringIp : stringIps)
                                        {
                                                //IpAddress ipAddress = IpAddress.valueOf(stringIp);
                                                log.info("Inserted following Server's IP as key for DDos_Phase_2 : " + stringIp);
                                                
                                                srv_under_mitPhase.put(stringIp,0);

                                        }
                                        servUnderMonitorin_count = srv_under_mitPhase.size();
                                }
                        }
                        if (sendingEnabled == 1 && exception_free_flowRuleService!=0)// this enables skipping 1st most iteration where value of features are still zero but allows from 2nd iterations onward
                        {
                                if (debuggMode ==1){log.info("!!!!!!!++++++++++++Entering Block for ML_server2 after finding SendingFLAG = 1");}
                                
                                localhost = null;
                                try {
                                        //Getting Server Address
                                        localhost = InetAddress.getByName("localhost");
                                } catch (UnknownHostException e) {
                                        e.printStackTrace();
                                }
                                socket2 = null;
                                try {
                                        //Getting socket for connection
                                        log.info("Establishing Connction with ML_SERVER 2 !!!! at PORT : 12148");
                                        socket2 = new Socket(localhost, 12148);
                                } catch (IOException e) {
                                        e.printStackTrace();
                                        log.info("xxxxxxxxxxxxx-------Caught exception at Socket establishment to ML_SRV_2 :{}",e);
                                }
                                //Getting Output and Input stream for sending and
                                // receiving data to/from server
                                out = null;
                                try {
                                        out = new OutputStreamWriter(socket2.getOutputStream());
                                } catch (IOException e) {
                                        e.printStackTrace();

                                }
                                try {
                                        //Sending flow features to ML server 2
                                        out.write(entries_To_be_Sent);
                                } catch (IOException e) {
                                        e.printStackTrace();
                                        log.info("Caught exception at writing Outputs to ML_SRV_2 :{}",e);

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
                                                socket2.getInputStream()));
                                } catch (IOException e) {
                                        e.printStackTrace();
                                        log.info("Caught exception at Reading Outputs to ML_SRV_2 :{}",e);
                                }
                                line1 = "";// dont keep them Null which can raises Null Pointer otherwise
                                try {
                                        //Getting prediction from ML Server             //
                                        line1= in.readLine();
                                } catch (IOException e) {
                                        e.printStackTrace();
                                }
                                try {
                                        socket2.close();
                                } catch (IOException e) {
                                        e.printStackTrace();
                                }
                                log.info(line1);
                                

                                //Inferrring value of attack from prediction
                                                                        /*for Testing only //  String line1 = "10.0.0.1,attack_detected";*/

                                String[] result_parameters = null;//!!!!
                                // String[] result_parameters = new String[2];//!!!!
                                String[] results = null;//%%%%%%%%%%%%%%%%%%%%%%%%%%%  Make sure to Double check from Server's side its double/Single encapsulated
                                if (line1.indexOf("|") == -1)
                                {
                                    results = new String[1];
                                    results[0] = line1; // as Single server/item only // otherwise using splits by char.
                                    // log.info("d");
                                }else{
                                    results = line1.split("|");
                                }
                                if(debuggMode == 1){log.info("!!!!!!!++++++++++++size of result(s) : {}",results.length);}
                                
                                if((line1 != null) || (line1 != ""))// 1st most reply from ML
                                {
                                        for (String result : results)
                                        {                                                
                                              result_parameters = result.split(",");// Verify compatibility
                                                if(debuggMode == 1){
                                                    log.info("!!!!!!!++++++++++++ size of result: {}",result_parameters.length);
                                                    log.info("!!!!!!!++++++++++++ result for serverIP : {}",result_parameters[1]);}
                                                String breachValue = result_parameters[1];// may return exception while debugging only if Traffic is not Running

                                                if (breachValue.equals("attack_detected"))// result_parameters[1] == attack_detected : would be wrong when comparing Primitive and Non-Primitive
                                                {// result = "IP"+"attack_detected/attack_not_detected"
                                                // 1.call mitigation 2. remove IP from Monitoring
                                                        if(debuggMode == 1){log.info("!!!!!!!++++++++++++£££££ $$$$$ Attack Found on ServerIP : " + result_parameters[0]);}
                                                        Mitigation_flow mitigation = new Mitigation_flow(
                                                        appId,
                                                        deviceService,
                                                        hostService,
                                                        flowRuleService,
                                                        linkService,
                                                        flowObjectiveService,
                                                        log,result_parameters[0]);
                                                        // remove IP of this server from ipSrc_per_Srv which will automatically stop monitoring process for it(Mit_Phase1)
                                                        //ipSrc_per_Srv.remove(result_parameters[0]);//basically removes the key values pair 

                                                        srv_under_mitPhase.remove(result_parameters[0]);//basically removes the key values pair 
                                                        if(debuggMode == 1){log.info("!!!!!!!++++++++++++servUnderMonitorin_count Before: {}",servUnderMonitorin_count);}
                                                        servUnderMonitorin_count -= 1; 
                                                        if(debuggMode == 1){log.info("!!!!!!!++++++++++++servUnderMonitorin_count After: {}",servUnderMonitorin_count);}
                                                }
                                                else if(breachValue.equals("attack_not_detected"))
                                                {//
                                                        //srv_under_mitPhase step 1: check the value of Counter and in case if exceeding 50 iteration
                                                        if (srv_under_mitPhase.get(result_parameters[0]) >= 50)
                                                        {
                                                                // remove from monitoring
                                                                // ipSrc_per_Srv.remove(result_parameters[0]);//basically removes the key values pair 
                                                                srv_under_mitPhase.remove(result_parameters[0]);//basically removes the key values pair
                                                                servUnderMonitorin_count -= 1;
                                                        }
                                                        else{
                                                            srv_under_mitPhase.put(result_parameters[0],srv_under_mitPhase.get(result_parameters[0])+1);
                                                            if(debuggMode == 1){log.info("!!!!!!!++++++++++++$$$$ Value updated");}
                                                        }
                                                }
                                                else{
                                                    // boolean check = (breachValue.equals("attack_detected") /*result_parameters[1]*/) ? true : false;
                                                    log.info("xxxxxxxxxxxxx-------Something is fishy..Incompatible reply sent by ML Server 2");
                                                }// case of flag requ. to be  -1 for 1st iteration on servUnderMonitorin_count being = 0
                                                //possible cases : 1.Attack on Network : False and No. of times VictimSrv identified/sent4rMit.{2.servUnderMonitorin_count >0 } [10, 01 ,00 ,11 ]
                                                //case 1: [MLSrv1_result,MLSrv2_result] = 10 ,say
                                                //case 1: [MLSrv1_result,MLSrv2_result] = 10
                                                if(attack==1 && servUnderMonitorin_count==0)
                                                {//servUnderMonitorin_count is some +ve val. greter than 1 => either no attack detected by ML2
                                                        //or Minm. safe iteration of 50 is still running for any one of server
                                                        log.info("Warning !!! : ML Server2 has failed to identify IP address on which DDos has occured, even after 50 iterations");
                                                        // log.info("Warning !!! : ML Server2 has failed to identify IP address on which DDos has occured, even after 50 iterations");
                                                        // log.info("Warning !!! : ML Server2 has failed to identify IP address on which DDos has occured, even after 50 iterations");
                                                        mitigationFlag = 0;
                                                        log.info("$$$ Reseting MitigationFlag to 0");
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
                                                if (attack==0 && servUnderMonitorin_count==0){
                                                        // all attack have been succesfully Mitigated
                                                        log.info("Cheers ,!!! DDos attack has been Averted. !!! ");
                                                        mitigationFlag = 0;
                                                        log.info("Reseting MitigationFlag to 0");

                                                }
                                                //case 4: [MLSrv1_result,MLSrv2_result(servUnderMonitorin_count>0)] = 11(False,True)
                                                if (attack==1 && servUnderMonitorin_count>0)
                                                {
                                                        log.info("£££Result from Attack detection at each Server are on the Way...");
                                                }
                                                // if Mitigation flag = 0 and serverUnderMonitoring_count =0 then clear
                                                
                                        }
                                }
                        }// end of sending enabled
                    }catch(Exception e){
                        log.info("xxxxxxxxxxxxx-------Phewww..Exception: {}",e);
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
                        semaphore.release();
                }//end of run()
        }//end of FlowInfoProcessor

}//end of AppComponent
