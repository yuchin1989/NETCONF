package org.onosproject.netconf.ctl.impl.callhome;

import org.apache.sshd.client.session.ClientSession;
import org.onosproject.netconf.callhome.CallHomeSessionContext;

import java.net.SocketAddress;
import java.security.PublicKey;

public interface CallHomeSessionFactory {
    void remove(final CallHomeSessionContext session);

    CallHomeSessionContext createIfNotExists(
            final ClientSession sshSession, final CallHomeAuthorization authorization,
            final SocketAddress remoteAddress, final PublicKey serverKey);

    void onSessionAuthComplete(CallHomeSessionContext context);
}
