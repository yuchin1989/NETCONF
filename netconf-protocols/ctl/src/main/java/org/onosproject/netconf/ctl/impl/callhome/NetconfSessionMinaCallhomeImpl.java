/*
 * Copyright 2015-present Open Networking Foundation
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

package org.onosproject.netconf.ctl.impl.callhome;

import com.google.common.annotations.Beta;
import com.google.common.base.Objects;
import org.apache.sshd.client.session.ClientSession;
import org.onosproject.netconf.NetconfDeviceInfo;
import org.onosproject.netconf.NetconfException;
import org.onosproject.netconf.ctl.impl.AbstractNetconfSessionMina;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.List;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Implementation of a NETCONF session to talk to a device.
 */
public class NetconfSessionMinaCallhomeImpl extends AbstractNetconfSessionMina {

    private static final Logger log = getLogger(NetconfSessionMinaCallhomeImpl.class);

    public NetconfSessionMinaCallhomeImpl(NetconfDeviceInfo deviceInfo, ClientSession session) throws NetconfException {
        super(deviceInfo);
        this.session = session;
        // FIXME should not immediately start session on construction
        // setOnosCapabilities() is useless due to this behavior
        startConnection();
    }

    public NetconfSessionMinaCallhomeImpl(NetconfDeviceInfo deviceInfo, List<String> capabilities, ClientSession session) throws NetconfException {
        super(deviceInfo, capabilities);
        this.session = session;
        // FIXME should not immediately start session on construction
        // setOnosCapabilities() is useless due to this behavior
        startConnection();
    }

    @Override
    protected void startConnection() throws NetconfException {
        log.info("Connecting to {} with timeouts C:{}, R:{}, I:{}", deviceInfo,
                connectTimeout, replyTimeout, idleTimeout);

        try {
            openChannel();
        } catch (Exception e) {
            stopConnection();
            throw new NetconfException("Failed to establish SSH with device " + deviceInfo, e);
        }
    }

    @Beta
    @Override
    protected void startSubscriptionStream(String filterSchema) throws NetconfException {
        boolean openNewSession = false;
        if (!deviceCapabilities.contains(INTERLEAVE_CAPABILITY_STRING)) {
            log.info("Device {} doesn't support interleave, creating child session", deviceInfo);
            openNewSession = true;

        } else if (subscriptionConnected &&
                notificationFilterSchema != null &&
                !Objects.equal(filterSchema, notificationFilterSchema)) {
            // interleave supported and existing filter is NOT "no filtering"
            // and was requested with different filtering schema
            log.info("Cannot use existing session for subscription {} ({})",
                    deviceInfo, filterSchema);
            openNewSession = true;
        }

        if (openNewSession) {
            log.warn("Can't start subscription on callhome device without interleave capabilities {} ({})",
                    deviceInfo, filterSchema);
            throw new NetconfException("Can't start subscription on callhome device without interleave capabilities");
        }

        // request to start interleaved notification session
        String reply = sendRequest(createSubscriptionString(filterSchema));
        if (!checkReply(reply)) {
            throw new NetconfException("Subscription not successful with device "
                    + deviceInfo + " with reply " + reply);
        }
        subscriptionConnected = true;
    }

    @Override
    public void checkAndReestablish() throws NetconfException {
        if (disconnected) {
            log.warn("Can't reopen connection for device because of disconnected {}", deviceInfo.getDeviceId());
            throw new NetconfException("Can't reopen connection for device because of disconnected " + deviceInfo);
        }

        try {
            if (session.isClosed() || session.isClosing()) {
                throw new NetconfException("Cannot re-open the connection with device" + deviceInfo);
            } else if (channel.isClosed() || channel.isClosing()) {
                log.debug("Trying to reopen the channel with {}", deviceInfo.getDeviceId());
                cleanUp();
                openChannel();
            } else {
                return;
            }
            if (subscriptionConnected) {
                log.debug("Restarting subscription with {}", deviceInfo.getDeviceId());
                subscriptionConnected = false;
                startSubscription(notificationFilterSchema);
            }
        } catch (IOException | IllegalStateException e) {
            log.error("Can't reopen connection for device {}", e.getMessage());
            throw new NetconfException("Cannot re-open the connection with device" + deviceInfo, e);
        }
    }

    @Override
    public boolean close() throws NetconfException {
        try {
            return super.close();
        } catch (IOException ioe) {
            throw new NetconfException(ioe.getMessage());
        } finally {
            disconnected = true;
            stopConnection();
        }
    }
}
