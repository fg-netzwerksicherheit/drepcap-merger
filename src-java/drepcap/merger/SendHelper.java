/*
 *   Copyright 2014, Frankfurt University of Applied Sciences
 *
 *   This software is released under the terms of the Eclipse Public License 
 *   (EPL) 1.0. You can find a copy of the EPL at: 
 *   http://opensource.org/licenses/eclipse-1.0.php
 */

package drepcap.merger;

import clj_net_pcap.Counter;
import clj_jms_activemq_toolkit.BytesMessagePayloadPart;
import clj_jms_activemq_toolkit.PooledBytesMessageProducer;

import java.util.concurrent.BlockingQueue;
import java.util.List;
import java.util.ArrayList;

/**
 * Helper for sending data from the intermediate queue via JMS.
 *
 * @author Ruediger Gad
 */
public class SendHelper {

    private static List buffer = new ArrayList();

    public static void sendData(PooledBytesMessageProducer producer, BlockingQueue queue,
                                int minSendLimit, Counter sendCounter) throws Exception {
        if (queue.size() > minSendLimit) {
           queue.drainTo(buffer);
           
           for (Object obj : buffer) {
               producer.send((BytesMessagePayloadPart) obj);
               sendCounter.inc();
           }

           buffer.clear();
        } else {
           Thread.sleep(100);
        }
    }

}
