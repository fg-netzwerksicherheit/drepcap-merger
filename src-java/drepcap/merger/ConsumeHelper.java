/*
 *   Copyright 2014, Frankfurt University of Applied Sciences
 *
 *   This software is released under the terms of the Eclipse Public License 
 *   (EPL) 1.0. You can find a copy of the EPL at: 
 *   http://opensource.org/licenses/eclipse-1.0.php
 */

package drepcap.merger;

import clj_jms_activemq_toolkit.ByteArrayWrapper;
import clj_net_pcap.ByteArrayHelper;
import clj_net_pcap.Counter;
import java.util.concurrent.BlockingQueue;

/**
 * Helper class for consuming data and forwarding it to the target queue.
 *
 * @author Ruediger Gad
 */
public class ConsumeHelper {

    public static void consumeData(byte[] receivedData, BlockingQueue queue, int maxQueueSize, 
                                   Counter pushCntr, Counter dropCntr) {
        int idx = 0;
        int caplen = ByteArrayHelper.getInt(receivedData, idx + 8);
        int len = caplen + 16;
        int nextIdx = idx + len;
        
        while ((caplen > 0) && (nextIdx < receivedData.length)) {
            if (queue.size() < maxQueueSize) {
                if (queue.offer(new ByteArrayWrapper(receivedData, idx, len))) {
                    pushCntr.inc();
                } else {
                    dropCntr.inc();
                }
            } else {
                dropCntr.inc();
            }

            idx = nextIdx;
            caplen = ByteArrayHelper.getInt(receivedData, idx + 8);
            len = caplen + 16;
            nextIdx = idx + caplen + 16;
        }
    }
}
