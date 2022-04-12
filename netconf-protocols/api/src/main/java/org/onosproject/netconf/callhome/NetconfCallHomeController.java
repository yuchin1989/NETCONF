package org.onosproject.netconf.callhome;

import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;

import org.onosproject.net.DeviceId;
import org.onosproject.netconf.NetconfDeviceInfo;
import org.onosproject.netconf.NetconfSession;

public interface NetconfCallHomeController {
    void start();

    void stop();

    Optional<NetconfSession> createNetconfSession(NetconfDeviceInfo netconfDeviceInfo);

    void removeSession(DeviceId deviceId);

    Map<DeviceId, CallHomeSessionContext> getSessionMap();

    boolean isCallHomeDeviceId(DeviceId deviceId);

    PublicKey decodePublicKeyString(String key);

    void AddListener(NetconfCallHomeListener listener);

    void removeListener(NetconfCallHomeListener listener);

    void register(CallHomeConfigBuilder builder);

    void unregister(DeviceId deviceId);
}
