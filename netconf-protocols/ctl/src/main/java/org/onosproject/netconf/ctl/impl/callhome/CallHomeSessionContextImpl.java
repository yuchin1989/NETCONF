/*
 * Copyright (c) 2016 Brocade Communication Systems and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.onosproject.netconf.ctl.impl.callhome;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.PublicKey;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.client.future.AuthFuture;

import org.onosproject.netconf.NetconfSession;
import org.onosproject.netconf.NetconfDeviceInfo;
import org.onosproject.netconf.NetconfException;
import org.onosproject.netconf.callhome.CallHomeSessionContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class CallHomeSessionContextImpl implements CallHomeSessionContext {

    private static final Logger LOG = LoggerFactory.getLogger(CallHomeSessionContextImpl.class);
    static final Session.AttributeKey<CallHomeSessionContextImpl> SESSION_KEY = new Session.AttributeKey<>();

    private final ClientSession sshSession;
    private final CallHomeAuthorization authorization;
    private final CallHomeSessionFactory factory;

    private final InetSocketAddress remoteAddress;
    private final PublicKey serverKey;

    private Boolean netconfCreated = false;

    CallHomeSessionContextImpl(final ClientSession sshSession, final CallHomeAuthorization authorization,
            final CallHomeSessionFactory factory,             final PublicKey serverKey) {
        this.authorization = requireNonNull(authorization, "authorization");
        checkArgument(this.authorization.isServerAllowed(), "Server was not allowed.");
        this.factory = requireNonNull(factory, "factory");
        this.sshSession = requireNonNull(sshSession, "sshSession");
        this.sshSession.setAttribute(SESSION_KEY, this);
        this.remoteAddress = (InetSocketAddress) this.sshSession.getIoSession().getRemoteAddress();
        this.serverKey = serverKey;
    }

    static CallHomeSessionContextImpl getFrom(final ClientSession sshSession) {
        return sshSession.getAttribute(SESSION_KEY);
    }

    AuthFuture authorize() throws IOException {
        authorization.applyTo(sshSession);
        return sshSession.auth();
    }

    @Override
    public NetconfSession createNetconfSession(NetconfDeviceInfo deviceInfo) {
        synchronized(this) {
            try {
                if (netconfCreated) {
                    LOG.warn("Netconf session for {} context already created", deviceInfo.getDeviceId().toString());
                    return null;
                }
                netconfCreated = true;
                NetconfSession netconfSession = new NetconfSessionMinaCallhomeImpl(deviceInfo, sshSession);
                return netconfSession;
            }
            catch (NetconfException e) {
                LOG.error("Create callhome netconf session fail", e);
                return null;
            } 
        }
    }

    @Override
    public void terminate() {
        sshSession.close(false);
        removeSelf();
    }

    @Override
    public PublicKey getRemoteServerKey() {
        return serverKey;
    }

    @Override
    public InetSocketAddress getRemoteAddress() {
        return remoteAddress;
    }

    @Override
    public String getSessionId() {
        return authorization.getSessionName();
    }

    @Override
    public String getSshUsername() {
        return sshSession.getUsername();
    }

    @Override
    public void removeSelf() {
        factory.remove(this);
    }
}
