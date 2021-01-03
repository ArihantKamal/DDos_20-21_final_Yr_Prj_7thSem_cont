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
  importing packages
 */
import com.google.common.collect.Iterables;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.IpAddress;
import org.slf4j.Logger;
import org.onlab.packet.MacAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostLocation;
import org.onosproject.net.Link;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criteria;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.PortCriterion;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkService;
import java.util.Set;

/*
  Class Mitigation_flow for Mitigation on basis of Flow rules
 */
public class Mitigation_flow {
    ApplicationId appId;
    DeviceService deviceService;
    HostService hostService;
    FlowRuleService flowRuleService;
    LinkService linkService;
    FlowObjectiveService flowObjectiveService;
    Logger log;
    String result_IP;

    //Priority for flow rule to drop traffic
    private static final int DROP_PRIORITY = 128;
    //TTL value of flow-rule in seconds
    private static final int TIMEOUT_SEC = 10; // seconds

    //Constructor for Mitigation_flow
    Mitigation_flow(ApplicationId appId, DeviceService deviceService, HostService hostService,
                    FlowRuleService flowRuleService, LinkService linkService,
                    FlowObjectiveService flowObjectiveService, Logger log , String result_IP) {
        this.appId = appId;
        this.deviceService = deviceService;
        this.hostService = hostService;
        this.flowRuleService = flowRuleService;
        this.linkService = linkService;
        this.flowObjectiveService = flowObjectiveService;
        this.log = log;
        this.result_IP = result_IP;

        //calling to start traceback of traffic
        initiateTraceBackToSource();
    }//end of Mitigation_flow()

    /*
      initiateTraceBackToSource() gets ServerIpAddresses and make thread for
      mitigation of attack at each server.
     */
    public void initiateTraceBackToSource() {
        //Getting serverIpAddresses
        // String[] stringIps = Servers.getServerIpAddresses();
        //converting string to IpAddress


        IpAddress ipAddress = IpAddress.valueOf(result_IP);// !!!!!!!!!!!!!!  IPv4.fromIPv4address()




        //getting host from IpAddress
        Set<Host>  hostSet = hostService.getHostsByIp(ipAddress);
        for (Host host : hostSet) {
            //Getting immediate device to server(location in term of switch)
            HostLocation hostLocation = host.location();
            DeviceId deviceId = hostLocation.deviceId();
            //getting MacAddress of server
            MacAddress macAddress = host.mac();
            //Initializing thread for a server
            ThreadedTraceBack threadedTraceBack = new ThreadedTraceBack(
                    deviceId, macAddress, result_IP);
            //starting thread
            threadedTraceBack.start();
        }
    }//end of initiateTraceBackToSource()

    /*
      Class ThreadedTraceBack implements thread for backtracking traffic for a
      server and calls to make flow-rule if end-host is found.
     */
    private class ThreadedTraceBack extends Thread {
        private DeviceId deviceId;
        private MacAddress macAddress;
        private String stringIp;

        //Constructor for ThreadedTraceBack
        ThreadedTraceBack(DeviceId deviceId, MacAddress macAddress, String stringIp) {
            this.deviceId = deviceId;
            this.macAddress = macAddress;
            this.stringIp = stringIp;
        }//end of ThreadedTraceBack()

        public void run() {
            //Recursive function for trace backing
            traceBackToSource(deviceId, macAddress, stringIp);
        }//end of run()

        /*
          traceBackToSource() is recursive function which checks for follow rules
          on deviceId.
          If match found then gets in_port of flow-rule traffic
          Then it checks whether device at in_port is host or switch.
          If host make flow rule
          else call traceBackToSource() with new deviceId
         */
        public void traceBackToSource(DeviceId deviceId, MacAddress macAddress,
                                      String stringIp) {
            log.info("checking at device: "+ deviceId.toString());

            //Getting flowenteries from device
            Iterable<FlowEntry> flowEntries = Iterables.concat(
                    flowRuleService.getFlowEntriesByState(deviceId, FlowEntry.FlowEntryState.ADDED),
                    flowRuleService.getFlowEntriesByState(deviceId, FlowEntry.FlowEntryState.PENDING_ADD));

            long max_bytes = Long.MIN_VALUE; //Stores count of max_bytes
            PortNumber portNumber_max_bytes = PortNumber.ANY; //Stores in_port

            int flag = 0; //flag to indicate whether flow rule match found.

            //Loop to check flow entry match
            for (FlowEntry flowEntry : flowEntries) {
                //log.info("flow-entry from system: "+flowEntry.toString());

                //traffic selector for flow rule checking(Empty)
                TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

                Set<Criterion> criteria = flowEntry.selector().criteria();

                //Setting all parameters same(cpy as it is) except one that determines traffic (so in 2nd case we would skip src.Port and later on Add things there)
                for (Criterion criterion : criteria) {
                    if (criterion.type() != Criterion.Type.ETH_DST &&
                            criterion.type() != Criterion.Type.IPV4_DST) {
                        selectorBuilder.add(criterion);
                    }//TCP_SRC : matchTcpSrc(TpPort tcpPort)
                }

                //Adding required criterias
                selectorBuilder.add(Criteria.matchEthDst(macAddress));
                selectorBuilder.add(Criteria.matchIPDst(Ip4Prefix.valueOf(stringIp + "/32")));
                // @Kamal we will add the criteria for Source Ports here itself
                //Building required traffic selector
                TrafficSelector trafficSelector = selectorBuilder.build();

                //PortCriterion for in_port
                PortCriterion portCriterion = (PortCriterion) flowEntry.selector()
                        .getCriterion(Criterion.Type.IN_PORT);
                        // May be in similar to above use :Class TcpPortCriterion ie (TcpPortCriterion) , as org.onosproject.net.flow.criteria Class PortCriterion -- (PortCriterion) is used
                        // org.onosproject.net.flow.criteria - and similarly use/force : Class IPCriterion --- (IPCriterion)flowEntry.selector();
                /*
                  checking if flowEntry belongs to device in considration and
                  portCriterion is not null
                 */
                if (deviceId.equals(flowEntry.deviceId()) &&
                        trafficSelector.equals(flowEntry.selector()) && portCriterion != null) {
                    //selecting flowEntry with maximum bytes_in     //Input port Field for portCriterion should not be null
                    if (flowEntry.bytes() > max_bytes) {
                        max_bytes = flowEntry.bytes();
                        portNumber_max_bytes = portCriterion.port();//Port number of one which matched max bytes // Similarly we can use this TcpPortCriterion for getting Port number out of that
                        // http://api.onosproject.org/1.9.1/org/onosproject/net/flow/criteria/TcpPortCriterion.html
                        http://api.onosproject.org/1.9.1/org/onosproject/net/flow/criteria/UdpPortCriterion.html
                        // http://api.onosproject.org/1.9.1/org/onosproject/net/flow/criteria/IPCriterion.html
                        // May be IP prefix is what I am looking for as for corporate we have Network Address / IP
                        // http://api.onosproject.org/1.9.1/org/onosproject/net/flow/criteria/IPProtocolCriterion.html -------- useful for matching ICMP packet undrlying if any
                        //  more at https://blog.pages.kr/1818 ----- 1 is for ICMP , 4 for Ipv4 , 6 for TCP , 17 for UDP
                        //setting that flow rule match found
                        flag = 1;
                    }
                    log.info("flow rule match found at port: "+portCriterion.port().toString());// but see here its blank => takes no input just ops the result
                }
                // flowEntry.packets()
                //Returns the number of packets this flow rule has matched.
                //http://api.onosproject.org/1.8.4/org/onosproject/net/flow/FlowEntry.html


            }//end of flowEntries

            if (flag == 1) {
                //flag to indicate whether end-host is found at portNumber_max_bytes
                int flag_2 = 0;

                //Checking for end hosts
                //Getting all hosts connected to device
                Set<Host> hosts = hostService.getConnectedHosts(deviceId);
                log.info("checking for end hosts");
                for (Host host : hosts) {
                    //getting host location
                    HostLocation hostLocation = host.location();
                    //checking whether port is same as portNumber_max_bytes
                    if ( deviceId.equals(hostLocation.deviceId()) &&
                            portNumber_max_bytes.equals(hostLocation.port())) {

                        log.info("end host: "+host.mac()+" detected at: "+deviceId.toString()
                                 +":"+portNumber_max_bytes.toString());

                        //Calling for making flow rules
                        setFlowRule(deviceId, host, macAddress, portNumber_max_bytes, stringIp);
                        flag_2 = 1;
                    }
                }

                //if end-host not found
                if (flag_2 == 0) {
                    log.info("no end host found");

                    //Getting all Ingress(Input) link to device at portNumber_max_bytes
                    ConnectPoint connectPoint = new ConnectPoint(deviceId,
                                                                 portNumber_max_bytes);
                    Set<Link> links = linkService.getIngressLinks(connectPoint);
                    for (Link link : links) {
                        ConnectPoint srcConnectPoint = link.src();
                        log.info("tracing back to device: "+srcConnectPoint.deviceId());
                        //Recursive call to traceBackToSource()
                        traceBackToSource(srcConnectPoint.deviceId(), macAddress, stringIp);
                    }
                }
            }

        }//end of traceBackToSource()

        /*
          SetFlowRule() is used to set flow rules for mitigation at switch
          immediate to attacker
         */
        public void setFlowRule(DeviceId deviceId, Host host, MacAddress macAddress, PortNumber portNumber,
                                String stringIp) {

                /*
                traffic selector for required traffic (from attacker to server)
                 Doesn't depend on Attacker IpAddress. So works in case of spoofed ips.
                 */
                TrafficSelector trafficSelector = DefaultTrafficSelector.builder()
                        .matchEthSrc(host.mac())
                        .matchEthDst(macAddress)
                        .matchInPort(portNumber)
                        .matchIPDst(Ip4Prefix.valueOf(stringIp + "/32"))
                        .build();
                //treatment for traffic
                TrafficTreatment drop = DefaultTrafficTreatment.builder().drop().build();

                //Making and installing flow-rule on device
                flowObjectiveService.forward(deviceId, DefaultForwardingObjective.builder()
                        .fromApp(appId)
                        .withSelector(trafficSelector)
                        .withTreatment(drop)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .withPriority(DROP_PRIORITY)
                        .makeTemporary(TIMEOUT_SEC).add());

                log.info("flow rule made");
        }//end of setFlowRule()
    }//end of ThreadedTraceBack
}//end of Mitigation_flow
