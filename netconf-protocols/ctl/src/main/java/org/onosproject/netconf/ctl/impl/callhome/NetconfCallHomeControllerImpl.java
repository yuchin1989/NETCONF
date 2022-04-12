package org.onosproject.netconf.ctl.impl.callhome;

import java.io.CharArrayReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.onlab.packet.IpAddress;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.netconf.NetconfDeviceInfo;
import org.onosproject.netconf.NetconfSession;
import org.onosproject.netconf.callhome.CallHomeConfigBuilder;
import org.onosproject.netconf.callhome.NetconfCallHomeController;
import org.onosproject.netconf.callhome.NetconfCallHomeListener;
import org.onosproject.netconf.callhome.NetconfCallHomeDeviceConfig;
import org.onosproject.netconf.callhome.CallHomeSessionContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;

import static org.onlab.util.Tools.getIntegerProperty;
import static org.onosproject.netconf.NetconfDeviceInfo.extractIpPortPath;
import static org.onosproject.netconf.ctl.impl.callhome.OsgiPropertyConstants.CALL_HOME_SSH_SERVER_PORT;
import static org.onosproject.netconf.ctl.impl.callhome.OsgiPropertyConstants.DEFAULT_CALL_HOME_SSH_SERVER_PORT;

@Component(immediate = true, service = NetconfCallHomeController.class,
        property = {
                CALL_HOME_SSH_SERVER_PORT + ":Integer=" + DEFAULT_CALL_HOME_SSH_SERVER_PORT
        })
public class NetconfCallHomeControllerImpl implements CallHomeSessionFactory, NetconfCallHomeController {
    private static final Logger log = LoggerFactory.getLogger(NetconfCallHomeControllerImpl.class);

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService componentCfgService;

    protected final ConfigFactory<DeviceId, NetconfCallHomeDeviceConfig> configFactory =
            // TODO consider moving Config registration to NETCONF ctl bundle
            new ConfigFactory<>(
                    SubjectFactories.DEVICE_SUBJECT_FACTORY,
                    NetconfCallHomeDeviceConfig.class, NetconfCallHomeDeviceConfig.CONFIG_KEY) {
                @Override
                public NetconfCallHomeDeviceConfig createConfig() {
                    return new NetconfCallHomeDeviceConfig();
                }
            };

    protected static int callHomeSshServerPort = DEFAULT_CALL_HOME_SSH_SERVER_PORT;

    private final ConcurrentMap<DeviceId, CallHomeSessionContext> sessions = new ConcurrentHashMap<>();
    protected Set<NetconfCallHomeListener> listeners = new CopyOnWriteArraySet<>();

    private boolean isStarted = false;
    private NetconfCallHomeServer sshServer;

    @Activate
    protected void activate(ComponentContext context) {
        componentCfgService.registerProperties(getClass());
        cfgService.registerConfigFactory(configFactory);
        cfgService.addListener(cfgListener);

        modified(context);

        start();
        log.info("NetconfCallHomeController started");
    }

    @Deactivate
    protected void deactivate() {
        stop();

        listeners.clear();
        cfgService.addListener(cfgListener);
        cfgService.unregisterConfigFactory(configFactory);
        componentCfgService.unregisterProperties(getClass(), false);
        listeners.clear();
        sessions.clear();
        log.info("NetconfCallHomeController stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        if (context == null) {
            callHomeSshServerPort = DEFAULT_CALL_HOME_SSH_SERVER_PORT;
            return;
        }
        Dictionary<?, ?> properties = context.getProperties();
        int newSshServerPort = getIntegerProperty(
                properties, CALL_HOME_SSH_SERVER_PORT, callHomeSshServerPort);
        if (newSshServerPort <= 0 || newSshServerPort >= 65536) {
            log.warn("Invalid call home ssh server port {}", newSshServerPort);
            return;
        }
        callHomeSshServerPort = newSshServerPort;
        if (isStarted) {
            stop();
            start();
        }
    }

    public void start() {
        synchronized (this) {
            if (isStarted) {
                return;
            }
            isStarted = true;
            try {
                SshClient client = SshClient.setUpDefaultClient();
                sshServer = new NetconfCallHomeServer(
                        client, authenticationProvider, this,
                        new InetSocketAddress(callHomeSshServerPort));

                sshServer.bind();
                log.info("netconf call home ssh server started");
            } catch (IOException e) {
                log.error("netconf call home ssh server binding fail");
                isStarted = false;
            }
        }
    }

    public void stop() {
        synchronized (this) {
            if (!isStarted) {
                return;
            }
            isStarted = false;
            sshServer.close();
            sshServer = null;
        }
    }

    @Override
    public Optional<NetconfSession> createNetconfSession(NetconfDeviceInfo netconfDeviceInfo) {
        log.debug("Try to create netconf session for {}", netconfDeviceInfo.getDeviceId().toString());
        CallHomeSessionContext context = sessions.get(netconfDeviceInfo.getDeviceId());
        if (context == null) {
            log.warn("Create netconf session for {} fail", netconfDeviceInfo.getDeviceId().toString());
            return Optional.empty();
        }
        return Optional.of(context.createNetconfSession(netconfDeviceInfo));
    }

    @Override
    public void removeSession(DeviceId deviceId) {
        if (sessions.containsKey(deviceId)) {
            sessions.get(deviceId).terminate();
        }
    }

    @Override
    public Map<DeviceId, CallHomeSessionContext> getSessionMap() {
        return sessions;
    }

    @Override
    public boolean isCallHomeDeviceId(DeviceId deviceId) {

        if (deviceId.toString().startsWith("netconf")) {
            Triple<String, Integer, Optional<String>> info = extractIpPortPath(deviceId);
            return IpAddress.valueOf(info.getLeft()).toOctets()[0] == 0;
        }
        return false;
    }

    @Override
    public PublicKey decodePublicKeyString(String key) {
        try {
            AuthorizedKeyEntry entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(key);
            return entry.resolvePublicKey(PublicKeyEntryResolver.IGNORING);
        } catch (IOException | GeneralSecurityException e) {
            log.warn("Decode ssh server key fail", e);
            return null;
        }
    }

    @Override
    public void AddListener(NetconfCallHomeListener listener) {
        listeners.add(listener);
    }

    @Override
    public void removeListener(NetconfCallHomeListener listener) {
        listeners.remove(listener);
    }

    @Override
    public void register(CallHomeConfigBuilder builder) {
        Pair<DeviceId, JsonNode> pair = builder.build();
        cfgService.applyConfig("devices", pair.getLeft().toString(),
                               "netconf-ch", pair.getRight()
        );
    }

    @Override
    public void unregister(DeviceId deviceId) {
        cfgService.removeConfig(deviceId, NetconfCallHomeDeviceConfig.class);
    }

    @Override
    public void remove(final CallHomeSessionContext session) {
        String sessionId = session.getSessionId();
        log.debug("Remove session {}", sessionId);
        cfgService.removeConfig("devices", DeviceId.deviceId(sessionId), "netconf");
        sessions.remove(DeviceId.deviceId(session.getSessionId()), session);
        for (NetconfCallHomeListener l : listeners) {
            l.SessionRemoved(session);
        }
    }

    @Override
    public CallHomeSessionContext createIfNotExists(final ClientSession sshSession,
                                                    final CallHomeAuthorization authorization, final SocketAddress remoteAddress,
                                                    final PublicKey serverKey) {
        log.debug("Try to create session for {}", authorization.getSessionName());
        CallHomeSessionContext session = new CallHomeSessionContextImpl(sshSession, authorization, this, serverKey);
        CallHomeSessionContext preexisting = sessions.putIfAbsent(DeviceId.deviceId(session.getSessionId()), session);
        if (preexisting != null) {
            log.debug("Session for {} already existed", authorization.getSessionName());
        }
        // If preexisting is null - session does not exist, so we can safely create new
        // one, otherwise we return
        // null and incoming connection will be rejected.
        return preexisting == null ? session : null;
    }

    @Override
    public void onSessionAuthComplete(CallHomeSessionContext context) {
        String sessionId = context.getSessionId();
        log.debug("Auth for {} completed, start to trigger device discovery.", sessionId);

        NetconfCallHomeDeviceConfig config = cfgService.getConfig(DeviceId.deviceId(sessionId), NetconfCallHomeDeviceConfig.class);
        if (config == null) {
            log.error("Network cfg for {} not found, cancel device discovery", sessionId);
            return;
        }

        JsonNodeFactory jsonNodeFactory = JsonNodeFactory.instance;
        ObjectNode conf = jsonNodeFactory.objectNode();
        conf.put("username", context.getSshUsername());
        conf.put("ip", context.getRemoteAddress().getAddress().getHostAddress());
        conf.put("port", context.getRemoteAddress().getPort());

        if (config.connectTimeout().isPresent()) {
            conf.put(NetconfCallHomeDeviceConfig.CONNECT_TIMEOUT, config.connectTimeout().getAsInt());
        }
        if (config.replyTimeout().isPresent()) {
            conf.put(NetconfCallHomeDeviceConfig.REPLY_TIMEOUT, config.replyTimeout().getAsInt());
        }
        if (config.idleTimeout().isPresent()) {
            conf.put(NetconfCallHomeDeviceConfig.IDLE_TIMEOUT, config.idleTimeout().getAsInt());
        }
        if (!Objects.equals(config.password(), "")) {
            conf.put(NetconfCallHomeDeviceConfig.PASSWORD, config.password());
        }
        if (!Objects.equals(config.sshKey(), "")) {
            conf.put(NetconfCallHomeDeviceConfig.SSHKEY, config.sshKey());
        }
        if (config.path().isPresent()) {
            conf.put(NetconfCallHomeDeviceConfig.PATH, config.path().get());
        }
        cfgService.applyConfig("devices", DeviceId.deviceId(sessionId), "netconf", conf);

        for (NetconfCallHomeListener l : listeners) {
            l.SessionCreated(context);
        }
    }

    private final CallHomeAuthorizationProvider authenticationProvider = new CallHomeAuthorizationProvider() {
        @Override
        public CallHomeAuthorization provideAuth(SocketAddress remoteAddress, PublicKey serverKey) {
            List<DeviceId> subjects = new ArrayList<>(cfgService.getSubjects(DeviceId.class));
            List<NetconfCallHomeDeviceConfig> cfgs = subjects.stream()
                    .map(d -> cfgService.getConfig(d, NetconfCallHomeDeviceConfig.class))
                    .filter(cfg -> cfg != null && serverKey.equals(decodePublicKeyString(cfg.serverKey())))
                    .collect(Collectors.toList());
            if (cfgs.size() == 0) {
                for (NetconfCallHomeListener l : listeners) {
                    l.SessionAuthFailed(serverKey, (InetSocketAddress) remoteAddress);
                }
                return CallHomeAuthorization.rejected();
            } else {
                NetconfCallHomeDeviceConfig cfg = cfgs.get(0);
                log.debug("Authorization match for {}", cfg.subject().toString());
                CallHomeAuthorization.Builder builder = CallHomeAuthorization.serverAccepted(cfg.subject().toString(), cfg.username());
                KeyPair kp = decodeKeyPair(cfg.sshKey());
                if (kp != null) {
                    builder.addClientKeys(kp);
                }
                if (!Objects.equals(cfg.password(), "")) {
                    builder.addPassword(cfg.password());
                }
                return builder.build();
            }
        }

        private KeyPair decodeKeyPair(String key) {
            try (PEMParser pemParser = new PEMParser(new CharArrayReader(key.toCharArray()))) {
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                return converter.getKeyPair((PEMKeyPair) pemParser.readObject());
            } catch (IOException e) {
                return null;
            }
        }
    };

    protected final NetworkConfigListener cfgListener = new NetworkConfigListener() {
        @Override
        public void event(NetworkConfigEvent event) {
            switch (event.type()) {
                case CONFIG_UPDATED:
                case CONFIG_REMOVED:
                    // Let session reconnect to reload config
                    DeviceId deviceId = (DeviceId) event.subject();
                    removeSession(deviceId);
                    break;

                default:
                    break;
            }
        }

        @Override
        public boolean isRelevant(NetworkConfigEvent event) {
            return event.configClass().equals(NetconfCallHomeDeviceConfig.class);
        }
    };
}
