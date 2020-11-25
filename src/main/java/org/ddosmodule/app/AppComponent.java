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
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Host;
import org.onosproject.net.HostLocation;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.PortStatistics;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
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
        private Map<Byte, Integer> dstSrvProtocols = new HashMap<Byte, Integer>(); //Count of Ip Protocols
        /* 
                              !!! %%%%                          */
        private Map<Integer,new HashMap<Integer,Map<new HashMap<Integer,Map<Integer,Integer>>>>> dstSrvIp_srcPort = new HashMap<Integer,new HashMap<Integer,Map<new HashMap<Integer,Map<Integer,Integer>>>>>();// Count of Server Ip to be monitored
        private Map<Integer,HashMap<Integer,Map>> tempL1 = {};
        // temp. container for revceiving Level2 map
        private Map<Integer,Integer> tempL2 = {};
        int mitigationFlag = 0;
        // flagbbb=
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
                                        // Yet to decalre mitig_flag var

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
                                        if (mitigationFlag) {
                                                // information to be gathered : {Destination_IP , Src_IP , Src_Port } in recursive Map , Protocol count
                                                if (srcIps_dstVictimIps.get(ipPacket.getSourceAddress()) == null) {
                                                        srcIps_dstVictimIps.put(ipPacket.getSourceAddress(), 1);
                                                } else {
                                                        srcIps_dstVictimIps.put(ipPacket.getSourceAddress(),
                                                                srcIps_dstVictimIps.get(ipPacket.getSourceAddress())+1);
                                                }
                                          	if (dstSrvProtocols.get(ipPacket.getProtocol()) == null) {
                                                        dstSrvProtocols.put(
                                                                ipPacket.getProtocol(), 1);
                                                } else {
                                                        dstSrvProtocols.put(ipPacket.getProtocol(),
                                                                        dstSrvProtocols.get(ipPacket.getProtocol())+1);     
                                                }
                                                // ddf
                                                if (dstSrvIp_srcPort.containsKey(ipPacket.getDestinationAddress()))
                                                {
                                                        tempL1 = dstSrvIp_srcPort.get(ipPacket.getDestinationAddress())
                                                        //
                                                        if (tempL1.containsKey(ipPacket.getSourceAddress())){
                                                                tempL2 = tempL1.get(ipPacket.getSourceAddress())// it is a Map with Key as Port
                                                                if (tempL2.containsKey(ipPacket.getSourcePort())){
                                                                        continue;
                                                                }
                                                                else{
                                                                        dstSrvIp_srcPort[ipPacket.getDestinationAddress()].[ipPacket.getSourcePort()].put(ipPacket.getSourcePort(),0);
                                                                        // ?????? !!! verify this
                                                                }
                                                        }
                                                        else{
                                                                dstSrvIp_srcPort[ipPacket.getDestinationAddress()].put(ipPacket.getSourceAddress(),new HashMap<Integer,Map<Integer,Integer>>);
                                                        }
                                                        // http://api.onosproject.org/1.8.9/org/onlab/packet/TCP.html ?????????
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
                }//end of getFlowInfo()

                //writeTOCSVFIle writes flow info to csv file and log
                public void writeToCSVFile() throws IOException {
                        //Opening file for append
                        //FileWriter fileWriter = new FileWriter("/home/ashu/Desktop/"
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

                        //Writing attack value in log
                        log.info("attack_value: "+attack);

                        // If attack detected then calling for Mitigation
                        if (attack == 1) {
                                Mitigation_flow mitigation = new Mitigation_flow(
                                        appId,
                                        deviceService,
                                        hostService,
                                        flowRuleService,
                                        linkService,
                                        flowObjectiveService,
                                        log);
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

}//end of AppComponenthttps://codeshare.io/5z8XdW