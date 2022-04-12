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

package org.onosproject.netconf.ctl.impl;

import com.google.common.annotations.Beta;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableSet;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.onosproject.netconf.NetconfController;
import org.onosproject.netconf.NetconfDeviceInfo;
import org.onosproject.netconf.NetconfDeviceOutputEvent;
import org.onosproject.netconf.NetconfDeviceOutputEvent.Type;
import org.onosproject.netconf.NetconfDeviceOutputEventListener;
import org.onosproject.netconf.NetconfException;
import org.onosproject.netconf.NetconfSession;
import org.onosproject.netconf.NetconfSessionFactory;
import org.slf4j.Logger;

import java.io.CharArrayReader;
import java.io.IOException;
import java.security.KeyPair;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Implementation of a NETCONF session to talk to a device.
 */
public class NetconfSessionMinaImpl extends AbstractNetconfSessionMina {

    private static final Logger log = getLogger(NetconfSessionMinaImpl.class);

    private SshClient client = null;

    public NetconfSessionMinaImpl(NetconfDeviceInfo deviceInfo) throws NetconfException {
        super(deviceInfo);
        // FIXME should not immediately start session on construction
        // setOnosCapabilities() is useless due to this behavior
        startConnection();
    }

    public NetconfSessionMinaImpl(NetconfDeviceInfo deviceInfo, List<String> capabilities) throws NetconfException {
        super(deviceInfo, capabilities);
        // FIXME should not immediately start session on construction
        // setOnosCapabilities() is useless due to this behavior
        startConnection();
    }

    @Override
    protected void startConnection() throws NetconfException {
        log.info("Connecting to {} with timeouts C:{}, R:{}, I:{}", deviceInfo,
                connectTimeout, replyTimeout, idleTimeout);

        try {
            startClient();
        } catch (Exception e) {
            stopConnection();
            throw new NetconfException("Failed to establish SSH with device " + deviceInfo, e);
        }
    }


    private void startClient() throws IOException {
        log.info("Creating NETCONF session to {}",
                deviceInfo.getDeviceId());

        client = SshClient.setUpDefaultClient();
        if (idleTimeout != NetconfControllerImpl.netconfIdleTimeout) {
            client.getProperties().putIfAbsent(FactoryManager.IDLE_TIMEOUT,
                    TimeUnit.SECONDS.toMillis(idleTimeout));
            client.getProperties().putIfAbsent(FactoryManager.NIO2_READ_TIMEOUT,
                    TimeUnit.SECONDS.toMillis(idleTimeout + 15L));
        }
        client.start();
        client.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        startSession();

        disconnected = false;
    }

    //TODO: Remove the default methods already implemented in NetconfSession

    // FIXME blocking
    @Deprecated
    private void startSession() throws IOException {
        final ConnectFuture connectFuture;
        connectFuture = client.connect(deviceInfo.name(),
                deviceInfo.ip().toString(),
                deviceInfo.port())
                .verify(connectTimeout, TimeUnit.SECONDS);
        session = connectFuture.getSession();
        //Using the device ssh key if possible
        if (deviceInfo.getKey() != null) {
            try (PEMParser pemParser = new PEMParser(new CharArrayReader(deviceInfo.getKey()))) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                try {
                    KeyPair kp = converter.getKeyPair((PEMKeyPair) pemParser.readObject());
                    session.addPublicKeyIdentity(kp);
                } catch (IOException e) {
                    throw new NetconfException("Failed to authenticate session with device " +
                            deviceInfo + "check key to be a valid key", e);
                }
            }
        } else {
            session.addPasswordIdentity(deviceInfo.password());
        }
        session.auth().verify(connectTimeout, TimeUnit.SECONDS);
        Set<ClientSession.ClientSessionEvent> event = session.waitFor(
                ImmutableSet.of(ClientSession.ClientSessionEvent.WAIT_AUTH,
                        ClientSession.ClientSessionEvent.CLOSED,
                        ClientSession.ClientSessionEvent.AUTHED), 0);

        if (!event.contains(ClientSession.ClientSessionEvent.AUTHED)) {
            log.debug("Session closed {} {}", event, session.isClosed());
            throw new NetconfException("Failed to authenticate session with device " +
                    deviceInfo + "check the user/pwd or key");
        }
        openChannel();
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
            log.info("Creating notification session to {} with filter {}",
                    deviceInfo, filterSchema);
            NetconfSession child = new NotificationSession(deviceInfo);

            child.addDeviceOutputListener(new NotificationForwarder());

            child.startSubscription(filterSchema);
            children.add(child);
            return;
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
    protected void stopConnection() {
        super.stopConnection();

        if (client != null) {
            try {
                client.close();
            } catch (IOException ex) {
                log.warn("Cannot close client {} {}", sessionID, deviceInfo, ex);
            }
            client.stop();
        }
    }

    @Override
    public void checkAndReestablish() throws NetconfException {
        if (disconnected) {
            log.warn("Can't reopen connection for device because of disconnected {}", deviceInfo.getDeviceId());
            throw new NetconfException("Can't reopen connection for device because of disconnected " + deviceInfo);
        }

        try {
            if (client.isClosed() || client.isClosing()) {
                log.debug("Trying to restart the whole SSH connection with {}", deviceInfo.getDeviceId());
                cleanUp();
                startConnection();
            } else if (session.isClosed() || session.isClosing()) {
                log.debug("Trying to restart the session {} with {}", session, deviceInfo.getDeviceId());
                cleanUp();
                startSession();
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
            if (client != null && (client.isClosed() || client.isClosing())) {
                return true;
            }

            return super.close();
        } catch (IOException ioe) {
            throw new NetconfException(ioe.getMessage());
        } finally {
            disconnected = true;
            stopConnection();
        }
    }

    static class NotificationSession extends NetconfSessionMinaImpl {

        private String notificationFilter;

        NotificationSession(NetconfDeviceInfo deviceInfo)
                throws NetconfException {
            super(deviceInfo);
        }

        @Override
        protected void startSubscriptionStream(String filterSchema)
                throws NetconfException {

            notificationFilter = filterSchema;
            requestSync(createSubscriptionString(filterSchema));
        }

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(getClass())
                    .add("deviceInfo", deviceInfo)
                    .add("sessionID", getSessionId())
                    .add("notificationFilter", notificationFilter)
                    .toString();
        }
    }

    /**
     * Listener attached to child session for notification streaming.
     * <p>
     * Forwards all notification event from child session to primary session
     * listeners.
     */
    private final class NotificationForwarder
            implements NetconfDeviceOutputEventListener {

        @Override
        public boolean isRelevant(NetconfDeviceOutputEvent event) {
            return event.type() == Type.DEVICE_NOTIFICATION;
        }

        @Override
        public void event(NetconfDeviceOutputEvent event) {
            publishEvent(event);
        }
    }

    /**
     * @deprecated in 1.14.0
     */
    @Deprecated
    public static class MinaSshNetconfSessionFactory implements NetconfSessionFactory {

        @Override
        public NetconfSession createNetconfSession(NetconfDeviceInfo netconfDeviceInfo,
                                                   NetconfController netconfController) throws NetconfException {
            return new NetconfSessionMinaImpl(netconfDeviceInfo);
        }
    }
}
