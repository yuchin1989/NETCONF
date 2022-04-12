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
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.session.ClientSession;
import org.onlab.osgi.DefaultServiceDirectory;
import org.onlab.osgi.ServiceDirectory;
import org.onlab.util.ItemNotFoundException;
import org.onlab.util.SharedExecutors;
import org.onosproject.net.DeviceId;
import org.onosproject.net.driver.Driver;
import org.onosproject.net.driver.DriverService;
import org.onosproject.netconf.AbstractNetconfSession;
import org.onosproject.netconf.NetconfDeviceInfo;
import org.onosproject.netconf.NetconfDeviceOutputEvent;
import org.onosproject.netconf.NetconfDeviceOutputEventListener;
import org.onosproject.netconf.NetconfException;
import org.onosproject.netconf.NetconfSession;
import org.onosproject.netconf.NetconfTransportException;
import org.slf4j.Logger;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.slf4j.LoggerFactory.getLogger;

public abstract class AbstractNetconfSessionMina extends AbstractNetconfSession {
    private static final Logger log = getLogger(AbstractNetconfSessionMina.class);

        /**
     * NC 1.0, RFC4742 EOM sequence.
     */
    protected static final String ENDPATTERN = "]]>]]>";
    protected static final String MESSAGE_ID_STRING = "message-id";
    protected static final String HELLO = "<hello";
    protected static final String NEW_LINE = "\n";
    protected static final String END_OF_RPC_OPEN_TAG = "\">";
    protected static final String EQUAL = "=";
    protected static final String NUMBER_BETWEEN_QUOTES_MATCHER = "\"+([0-9]+)+\"";
    protected static final String SUBTREE_FILTER_CLOSE = "</filter>";
    // FIXME hard coded namespace nc
    protected static final String XML_HEADER =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

    // FIXME hard coded namespace base10
    protected static final String SUBSCRIPTION_SUBTREE_FILTER_OPEN =
            "<filter xmlns:base10=\"urn:ietf:params:xml:ns:netconf:base:1.0\" base10:type=\"subtree\">";

    protected static final String INTERLEAVE_CAPABILITY_STRING = "urn:ietf:params:netconf:capability:interleave:1.0";

    protected static final String CAPABILITY_REGEX = "<capability>\\s*(.*?)\\s*</capability>";
    protected static final Pattern CAPABILITY_REGEX_PATTERN = Pattern.compile(CAPABILITY_REGEX);

    protected static final String SESSION_ID_REGEX = "<session-id>\\s*(.*?)\\s*</session-id>";
    protected static final Pattern SESSION_ID_REGEX_PATTERN = Pattern.compile(SESSION_ID_REGEX);
    protected static final String HASH = "#";
    protected static final String LF = "\n";
    protected static final String MSGLEN_REGEX_PATTERN = "\n#\\d+\n";
    protected static final String NETCONF_10_CAPABILITY = "urn:ietf:params:netconf:base:1.0";
    protected static final String NETCONF_11_CAPABILITY = "urn:ietf:params:netconf:base:1.1";
    protected static final String NETCONF_CLIENT_CAPABILITY = "netconfClientCapability";
    protected static final String NOTIFICATION_STREAM = "notificationStream";

    protected static ServiceDirectory directory = new DefaultServiceDirectory();

    protected String sessionID;
    protected final AtomicInteger messageIdInteger = new AtomicInteger(1);
    protected final NetconfDeviceInfo deviceInfo;
    protected Iterable<String> onosCapabilities =
            ImmutableList.of(NETCONF_10_CAPABILITY, NETCONF_11_CAPABILITY);

    protected final Set<String> deviceCapabilities = new LinkedHashSet<>();
    protected NetconfStreamHandler streamHandler;
    // FIXME ONOS-7019 key type should be revised to a String, see RFC6241
    /**
     * Message-ID and corresponding Future waiting for response.
     */
    protected Map<Integer, CompletableFuture<String>> replies;
    protected List<String> errorReplies; // Not sure why we need this?
    protected boolean subscriptionConnected = false;
    protected String notificationFilterSchema = null;

    protected final Collection<NetconfDeviceOutputEventListener> primaryListeners =
            new CopyOnWriteArrayList<>();
    protected final Collection<NetconfSession> children =
            new CopyOnWriteArrayList<>();

    protected int connectTimeout;
    protected int replyTimeout;
    protected int idleTimeout;

    protected ClientChannel channel = null;
    protected ClientSession session = null;

    protected boolean disconnected = false;

    public AbstractNetconfSessionMina(NetconfDeviceInfo deviceInfo) throws NetconfException {
        this(deviceInfo, null);
    }

    public AbstractNetconfSessionMina(NetconfDeviceInfo deviceInfo, List<String> capabilities) throws NetconfException {
        this.deviceInfo = deviceInfo;
        replies = new ConcurrentHashMap<>();
        errorReplies = new ArrayList<>();
        connectTimeout = deviceInfo.getConnectTimeoutSec().orElse(
                NetconfControllerImpl.netconfConnectTimeout);
        replyTimeout = deviceInfo.getReplyTimeoutSec().orElse(
                NetconfControllerImpl.netconfReplyTimeout);
        idleTimeout = deviceInfo.getIdleTimeoutSec().orElse(
                NetconfControllerImpl.netconfIdleTimeout);

        if (capabilities == null) {
            Set<String> newCapabilities = getClientCapabilites(deviceInfo.getDeviceId());
            if (!newCapabilities.isEmpty()) {
                newCapabilities.addAll(Sets.newHashSet(onosCapabilities));
                setOnosCapabilities(newCapabilities);
            }
        }
        else {
            setOnosCapabilities(capabilities);
        }
    }

    /**
     * Get the list of the netconf client capabilities from device driver property.
     *
     * @param deviceId the deviceID for which to recover the capabilities from the driver.
     * @return the String list of clientCapability property, or null if it is not configured
     */
    public Set<String> getClientCapabilites(DeviceId deviceId) {
        Set<String> capabilities = new LinkedHashSet<>();
        DriverService driverService = directory.get(DriverService.class);
        try {
            Driver driver = driverService.getDriver(deviceId);
            if (driver == null) {
                return capabilities;
            }
            String clientCapabilities = driver.getProperty(NETCONF_CLIENT_CAPABILITY);
            if (clientCapabilities == null) {
                return capabilities;
            }
            String[] textStr = clientCapabilities.split("\\|");
            capabilities.addAll(Arrays.asList(textStr));
            return capabilities;
        } catch (ItemNotFoundException e) {
            log.warn("Driver for device {} currently not available", deviceId);
            return capabilities;
        }
    }


    protected abstract void startConnection() throws NetconfException;

    // FIXME unuse
    protected PublicKey getPublicKey(byte[] keyBytes, String type)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(type);
        return kf.generatePublic(spec);
    }

    // FIXME blocking
    @Deprecated
    protected void openChannel() throws IOException {
        channel = session.createSubsystemChannel("netconf");
        OpenFuture channelFuture = channel.open();
        if (channelFuture.await(connectTimeout, TimeUnit.SECONDS)) {
            if (channelFuture.isOpened()) {
                streamHandler = new NetconfStreamThread(channel.getInvertedOut(), channel.getInvertedIn(),
                        channel.getInvertedErr(), deviceInfo,
                        new NetconfSessionDelegateImpl(), replies);
                primaryListeners.forEach(l -> streamHandler.addDeviceEventListener(l));
            } else {
                throw new NetconfException("Failed to open channel with device " +
                        deviceInfo);
            }
            sendHello();
        }
    }

    protected abstract void startSubscriptionStream(String filterSchema) throws NetconfException;

    @Beta
    @Override
    public void startSubscription(String filterSchema) throws NetconfException {
        if (!subscriptionConnected) {
            notificationFilterSchema = filterSchema;
            startSubscriptionStream(filterSchema);
        }
        streamHandler.setEnableNotifications(true);
    }

    @Beta
    protected String createSubscriptionString(String filterSchema) {
        StringBuilder subscriptionbuffer = new StringBuilder();
        subscriptionbuffer.append("<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n");
        subscriptionbuffer.append("  <create-subscription\n");
        subscriptionbuffer.append("xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">\n");
        DriverService driverService = directory.get(DriverService.class);
        Driver driver = driverService.getDriver(deviceInfo.getDeviceId());
        if (driver != null) {
            String stream = driver.getProperty(NOTIFICATION_STREAM);
            if (stream != null) {
                subscriptionbuffer.append("    <stream>");
                subscriptionbuffer.append(stream);
                subscriptionbuffer.append("</stream>\n");
            }
        }
        // FIXME Only subtree filtering supported at the moment.
        if (filterSchema != null) {
            subscriptionbuffer.append("    ");
            subscriptionbuffer.append(SUBSCRIPTION_SUBTREE_FILTER_OPEN).append(NEW_LINE);
            subscriptionbuffer.append(filterSchema).append(NEW_LINE);
            subscriptionbuffer.append("    ");
            subscriptionbuffer.append(SUBTREE_FILTER_CLOSE).append(NEW_LINE);
        }
        subscriptionbuffer.append("  </create-subscription>\n");
        subscriptionbuffer.append("</rpc>\n");
        subscriptionbuffer.append(ENDPATTERN);
        return subscriptionbuffer.toString();
    }

    @Override
    public void endSubscription() throws NetconfException {
        if (subscriptionConnected) {
            streamHandler.setEnableNotifications(false);
        } else {
            throw new NetconfException("Subscription does not exist.");
        }
    }

    protected void stopConnection() {
        if (session != null) {
            try {
                session.close();
            } catch (IOException ex) {
                log.warn("Cannot close session {} {}", sessionID, deviceInfo, ex);
            }
        }

        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ex) {
                log.warn("Cannot close channel {} {}", sessionID, deviceInfo, ex);
            }
        }
    }

    protected void sendHello() throws NetconfException {
        String serverHelloResponse = sendRequest(createHelloString(), true);
        Matcher capabilityMatcher = CAPABILITY_REGEX_PATTERN.matcher(serverHelloResponse);
        while (capabilityMatcher.find()) {
            deviceCapabilities.add(capabilityMatcher.group(1));
        }
        sessionID = String.valueOf(-1);
        Matcher sessionIDMatcher = SESSION_ID_REGEX_PATTERN.matcher(serverHelloResponse);
        if (sessionIDMatcher.find()) {
            sessionID = sessionIDMatcher.group(1);
        } else {
            throw new NetconfException("Missing SessionID in server hello " +
                    "reponse.");
        }

    }

    protected String createHelloString() {
        StringBuilder hellobuffer = new StringBuilder();
        hellobuffer.append(XML_HEADER);
        hellobuffer.append("\n");
        hellobuffer.append("<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n");
        hellobuffer.append("  <capabilities>\n");
        onosCapabilities.forEach(
                cap -> hellobuffer.append("    <capability>")
                        .append(cap)
                        .append("</capability>\n"));
        hellobuffer.append("  </capabilities>\n");
        hellobuffer.append("</hello>\n");
        hellobuffer.append(ENDPATTERN);
        return hellobuffer.toString();

    }

    protected void cleanUp() {
        //makes sure everything is at a clean state.
        replies.clear();
        if (streamHandler != null) {
            streamHandler.close();
        }
    }

    @Override
    public String requestSync(String request) throws NetconfException {
        return requestSync(request, replyTimeout);
    }

    @Override
    public String requestSync(String request, int timeout) throws NetconfException {
        String reply = sendRequest(request, timeout);
        if (!checkReply(reply)) {
            throw new NetconfException("Request not successful with device "
                    + deviceInfo + " with reply " + reply);
        }
        return reply;
    }


    // FIXME rename to align with what it actually do

    /**
     * Validate and format netconf message.
     * - NC1.0 if no EOM sequence present on {@code message}, append.
     * - NC1.1 chunk-encode given message unless it already is chunk encoded
     *
     * @param message to format
     * @return formated message
     */
    protected String formatNetconfMessage(String message) {
        if (deviceCapabilities.contains(NETCONF_11_CAPABILITY)) {
            message = formatChunkedMessage(message);
        } else {
            if (!message.endsWith(ENDPATTERN)) {
                message = message + NEW_LINE + ENDPATTERN;
            }
        }
        return message;
    }

    /**
     * Validate and format message according to chunked framing mechanism.
     *
     * @param message to format
     * @return formated message
     */
    protected String formatChunkedMessage(String message) {
        if (message.endsWith(ENDPATTERN)) {
            // message given had Netconf 1.0 EOM pattern -> remove
            message = message.substring(0, message.length() - ENDPATTERN.length());
        }
        if (!message.startsWith(LF + HASH)) {
            // chunk encode message
            message = LF + HASH + message.getBytes(UTF_8).length + LF + message + LF + HASH + HASH + LF;
        }
        return message;
    }

    @Override
    @Deprecated
    public CompletableFuture<String> request(String request) {
        return streamHandler.sendMessage(request);
    }

    /**
     * {@inheritDoc}
     * <p>
     * FIXME Note: as of 1.12.0
     * {@code request} must not include message-id, this method will assign
     * and insert message-id on it's own.
     * Will require ONOS-7019 to remove this limitation.
     */
    @Override
    public CompletableFuture<String> rpc(String request) {

        String rpc = request;
        //  - assign message-id
        int msgId = messageIdInteger.incrementAndGet();
        //  - re-write request to insert message-id
        // FIXME avoid using formatRequestMessageId
        rpc = formatRequestMessageId(rpc, msgId);
        //  - ensure it contains XML header
        rpc = formatXmlHeader(rpc);
        //  - use chunked framing if talking to NC 1.1 device
        // FIXME avoid using formatNetconfMessage
        rpc = formatNetconfMessage(rpc);

        // TODO session liveness check & recovery

        log.debug("Sending {} to {}", rpc, this.deviceInfo.getDeviceId());
        return streamHandler.sendMessage(rpc, msgId)
                .handleAsync((reply, t) -> {
                    if (t != null) {
                        // secure transport-layer error
                        // cannot use NetconfException, which is
                        // checked Exception.
                        throw new NetconfTransportException(t);
                    } else {
                        // FIXME avoid using checkReply, error handling is weird
                        if (!checkReply(reply)) {
                            throw new NetconfTransportException("rpc-request not successful with device "
                                    + deviceInfo + " with reply " + reply);
                        }
                        return reply;
                    }
                }, SharedExecutors.getPoolThreadExecutor());
    }

    @Override
    public int timeoutConnectSec() {
        return connectTimeout;
    }

    @Override
    public int timeoutReplySec() {
        return replyTimeout;
    }

    @Override
    public int timeoutIdleSec() {
        return idleTimeout;
    }

    protected CompletableFuture<String> request(String request, int messageId) {
        return streamHandler.sendMessage(request, messageId);
    }

    protected String sendRequest(String request, boolean isHello) throws NetconfException {
        return sendRequest(request, isHello, replyTimeout);
    }

    protected String sendRequest(String request) throws NetconfException {
        // FIXME probably chunk-encoding too early
        request = formatNetconfMessage(request);
        return sendRequest(request, false, replyTimeout);
    }

    protected String sendRequest(String request, int timeout) throws NetconfException {
        // FIXME probably chunk-encoding too early
        request = formatNetconfMessage(request);
        return sendRequest(request, false, timeout);
    }

    protected String sendRequest(String request, boolean isHello, int timeout) throws NetconfException {
        checkAndReestablish();
        int messageId = -1;
        if (!isHello) {
            messageId = messageIdInteger.getAndIncrement();
        }
        // FIXME potentially re-writing chunked encoded String?
        request = formatXmlHeader(request);
        request = formatRequestMessageId(request, messageId);
        log.debug("Sending request to NETCONF with timeout {} for {}",
                replyTimeout, deviceInfo.name());
        CompletableFuture<String> futureReply = request(request, messageId);
        String rp;
        try {
            rp = futureReply.get(replyTimeout, TimeUnit.SECONDS);
            replies.remove(messageId); // Why here???
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NetconfException("Interrupted waiting for reply for request" + request, e);
        } catch (TimeoutException e) {
            throw new NetconfException("Timed out waiting for reply for request " +
                    request + " after " + replyTimeout + " sec.", e);
        } catch (ExecutionException e) {
            log.warn("Closing session {} for {} due to unexpected Error", sessionID, deviceInfo, e);
            stopConnection();
            NetconfDeviceOutputEvent event = new NetconfDeviceOutputEvent(
                    NetconfDeviceOutputEvent.Type.SESSION_CLOSED,
                    null, "Closed due to unexpected error " + e.getCause(),
                    Optional.of(-1), deviceInfo);
            publishEvent(event);
            errorReplies.clear(); // move to cleanUp()?
            cleanUp();

            throw new NetconfException("Closing session " + sessionID + " for " + deviceInfo +
                    " for request " + request, e);
        }
        log.debug("Result {} from request {} to device {}", rp, request, deviceInfo);
        return rp.trim();
    }

    protected String formatRequestMessageId(String request, int messageId) {
        if (request.contains(MESSAGE_ID_STRING)) {
            //FIXME if application provides his own counting of messages this fails that count
            // FIXME assumes message-id is integer. RFC6241 allows anything as long as it is allowed in XML
            request = request.replaceFirst(MESSAGE_ID_STRING + EQUAL + NUMBER_BETWEEN_QUOTES_MATCHER,
                    MESSAGE_ID_STRING + EQUAL + "\"" + messageId + "\"");
        } else if (!request.contains(MESSAGE_ID_STRING) && !request.contains(HELLO)) {
            //FIXME find out a better way to enforce the presence of message-id
            request = request.replaceFirst(END_OF_RPC_OPEN_TAG, "\" " + MESSAGE_ID_STRING + EQUAL + "\""
                    + messageId + "\"" + ">");
        }
        request = updateRequestLength(request);
        return request;
    }

    protected String updateRequestLength(String request) {
        if (request.contains(LF + HASH + HASH + LF)) {
            int oldLen = Integer.parseInt(request.split(HASH)[1].split(LF)[0]);
            String rpcWithEnding = request.substring(request.indexOf('<'));
            String firstBlock = request.split(MSGLEN_REGEX_PATTERN)[1].split(LF + HASH + HASH + LF)[0];
            int newLen = 0;
            newLen = firstBlock.getBytes(UTF_8).length;
            if (oldLen != newLen) {
                return LF + HASH + newLen + LF + rpcWithEnding;
            }
        }
        return request;
    }

    /**
     * Ensures xml start directive/declaration appears in the {@code request}.
     *
     * @param request RPC request message
     * @return XML RPC message
     */
    protected String formatXmlHeader(String request) {
        if (!request.contains(XML_HEADER)) {
            //FIXME if application provides his own XML header of different type there is a clash
            if (request.startsWith(LF + HASH)) {
                request = request.split("<")[0] + XML_HEADER + request.substring(request.split("<")[0].length());
            } else {
                request = XML_HEADER + "\n" + request;
            }
        }
        return request;
    }

    @Override
    public String getSessionId() {
        return sessionID;
    }

    @Override
    public Set<String> getDeviceCapabilitiesSet() {
        return Collections.unmodifiableSet(deviceCapabilities);
    }

    @Override
    public void setOnosCapabilities(Iterable<String> capabilities) {
        onosCapabilities = capabilities;
    }


    @Override
    public void addDeviceOutputListener(NetconfDeviceOutputEventListener listener) {
        streamHandler.addDeviceEventListener(listener);
        primaryListeners.add(listener);
    }

    @Override
    public void removeDeviceOutputListener(NetconfDeviceOutputEventListener listener) {
        primaryListeners.remove(listener);
        streamHandler.removeDeviceEventListener(listener);
    }

    @Override
    protected boolean checkReply(String reply) {
        // Overridden to record error logs
        if (reply != null) {
            if (!reply.contains("<rpc-error>")) {
                log.debug("Device {} sent reply {}", deviceInfo, reply);
                return true;
            } else if (reply.contains("<ok/>")
                    || (reply.contains("<rpc-error>")
                    && reply.contains("warning"))) {
                // FIXME rpc-error with a warning is considered same as Ok??
                log.debug("Device {} sent reply {}", deviceInfo, reply);
                return true;
            }
        }
        log.warn("Device {} has error in reply {}", deviceInfo, reply);
        return false;
    }

    protected void publishEvent(NetconfDeviceOutputEvent event) {
        primaryListeners.forEach(lsnr -> {
            if (lsnr.isRelevant(event)) {
                lsnr.event(event);
            }
        });
    }

    public class NetconfSessionDelegateImpl implements NetconfSessionDelegate {

        @Override
        public void notify(NetconfDeviceOutputEvent event) {
            Optional<Integer> messageId = event.getMessageID();
            log.debug("messageID {}, waiting replies messageIDs {}", messageId,
                    replies.keySet());
            if (!messageId.isPresent()) {
                errorReplies.add(event.getMessagePayload());
                log.error("Device {} sent error reply {}",
                        event.getDeviceInfo(), event.getMessagePayload());
                return;
            }
            // Remove the message as it has been processed.
            CompletableFuture<String> completedReply = replies.remove(messageId.get());
            if (completedReply != null) {
                completedReply.complete(event.getMessagePayload());
            }
        }
    }

}