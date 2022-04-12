package org.onosproject.netconf.callhome;

import java.net.InetSocketAddress;
import java.security.PublicKey;

import org.onosproject.netconf.NetconfDeviceInfo;
import org.onosproject.netconf.NetconfSession;


public interface CallHomeSessionContext {
    NetconfSession createNetconfSession(NetconfDeviceInfo deviceInfo);

    void terminate();

    PublicKey getRemoteServerKey();

    InetSocketAddress getRemoteAddress();

    String getSessionId();

    String getSshUsername();

    void removeSelf();
}
