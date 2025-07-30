/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper.server.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MessageTrackerTest {
    private static final int BUFFERED_MESSAGE_SIZE = 5;
    private static final Logger LOG = LoggerFactory.getLogger(MessageTrackerTest.class);

    @BeforeEach
    public void setup() {
        System.setProperty(MessageTracker.MESSAGE_TRACKER_ENABLED, "true");
    }

    @AfterEach
    public void tearDown() throws Exception {
        System.clearProperty(MessageTracker.MESSAGE_TRACKER_ENABLED);
    }

    @Test
    public void testTrackSend() throws InterruptedException {
        long timestamp1 = System.currentTimeMillis();
        MessageTracker messageTracker = new MessageTracker(BUFFERED_MESSAGE_SIZE);

        // First timestamp is added
        messageTracker.trackSent(timestamp1);
        assertEquals(messageTracker.peekSentTimestamp(), timestamp1);

        Thread.sleep(2);

        // Second timestamp is added
        long timestamp2 = System.currentTimeMillis();
        messageTracker.trackSent(timestamp2);
        assertEquals(messageTracker.peekSentTimestamp(), timestamp1);
    }

    @Test
    public void testTrackReceived() throws InterruptedException {
        long timestamp1 = System.currentTimeMillis();
        MessageTracker messageTracker = new MessageTracker(BUFFERED_MESSAGE_SIZE);

        // First timestamp is added
        messageTracker.trackReceived(timestamp1);
        assertEquals(messageTracker.peekReceivedTimestamp(), timestamp1);

        Thread.sleep(2);

        // Second timestamp is added
        long timestamp2 = System.currentTimeMillis();
        messageTracker.trackReceived(timestamp2);
        assertEquals(messageTracker.peekReceivedTimestamp(), timestamp1);
    }

    @Test
    public void testMessageTrackerFull() throws InterruptedException {
        MessageTracker messageTracker = new MessageTracker(BUFFERED_MESSAGE_SIZE);

        // Add up to capacity + 1
        long timestampSent = 0;
        long timestampReceived = 0;
        for (int i = 0; i <= BUFFERED_MESSAGE_SIZE; i++) {
            if (i == 1) {
                timestampSent = System.currentTimeMillis();
                messageTracker.trackSent(timestampSent);
                Thread.sleep(2);
                timestampReceived = System.currentTimeMillis();
                messageTracker.trackReceived(timestampReceived);
            } else {
                messageTracker.trackSent(System.currentTimeMillis());
                messageTracker.trackReceived(System.currentTimeMillis());
            }
            Thread.sleep(1);
        }

        assertEquals(messageTracker.peekSentTimestamp(), timestampSent);
        assertEquals(messageTracker.peekReceivedTimestamp(), timestampReceived);
    }

    @Test
    public void testDumpToLog() {
        long timestamp1 = System.currentTimeMillis();
        MessageTracker messageTracker = new MessageTracker(BUFFERED_MESSAGE_SIZE);
        String sid = "127.0.0.1";

        // MessageTracker is empty
        messageTracker.dumpToLog(sid);
        assertNull(messageTracker.peekSent());
        assertNull(messageTracker.peekReceived());

        // There is 1 sent and 0 received
        messageTracker.trackSent(timestamp1);
        assertEquals(messageTracker.peekSentTimestamp(), timestamp1);
        assertNull(messageTracker.peekReceived());
        messageTracker.dumpToLog(sid);
        assertNull(messageTracker.peekSent());
        assertNull(messageTracker.peekReceived());

        // There is 1 sent and 1 received
        messageTracker.trackSent(timestamp1);
        messageTracker.trackReceived(timestamp1);
        assertEquals(messageTracker.peekSentTimestamp(), timestamp1);
        assertEquals(messageTracker.peekReceivedTimestamp(), timestamp1);
        messageTracker.dumpToLog(sid);
        assertNull(messageTracker.peekSent());
        assertNull(messageTracker.peekReceived());
    }

    @Test
    public void testIPv6VerificationGood() {
        MessageTracker messageTracker = new MessageTracker(10);
        //see https://www.ibm.com/docs/en/ts4500-tape-library?topic=functionality-ipv4-ipv6-address-formats
        for (String serverAddr : new String[] {
                "2001:db8:3333:4444:5555:6666:7777:8888",
                "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF",
                "::", "2001:db8::", "2001:db8::1234:5678",
                "2001:0db8:0001:0000:0000:0ab9:C0A8:0102"
        }) {
            messageTracker.dumpToLog(serverAddr);
        }
    }

    @Test
    public void testIPv6TooManyColons() {
        final String serverAddr = "2001:db8:1234:0000:0000:0000:0000:0000:0000";
        MessageTracker messageTracker = new MessageTracker(10);
        IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> messageTracker.dumpToLog(serverAddr),
                "Expected dumpToLog to throw IllegalArgumentException, but it didn't"
        );
        assertTrue(thrown.getMessage().contains("too many colons=1"));
    }
}
