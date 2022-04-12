/*
 * Copyright (c) 2016 Brocade Communication Systems and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.onosproject.netconf.ctl.impl.callhome;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.PublicKey;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.SessionFactory;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.onosproject.netconf.callhome.CallHomeSessionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NetconfCallHomeServer implements AutoCloseable, ServerKeyVerifier {

    private static final Logger log = LoggerFactory.getLogger(NetconfCallHomeServer.class);

    private final CallHomeAuthorizationProvider authProvider;
    private final InetSocketAddress bindAddress;
    private final CallHomeSessionFactory sessionFactory;
    private final SshClient client;
    private IoServiceFactory serviceFactory;
    private IoAcceptor acceptor;

    public NetconfCallHomeServer(final SshClient sshClient, final CallHomeAuthorizationProvider authProvider,
            final CallHomeSessionFactory factory, final InetSocketAddress socketAddress) {
        this.client = requireNonNull(sshClient);
        this.authProvider = requireNonNull(authProvider);
        this.sessionFactory = requireNonNull(factory);
        this.bindAddress = socketAddress;
        sshClient.setServerKeyVerifier(this);
        sshClient.addSessionListener(createSessionListener());
    }

    public SshClient getClient() {
        return client;
    }

    SessionListener createSessionListener() {
        return new SessionListener() {
            @Override
            public void sessionEvent(final Session session, final Event event) {
                ClientSession clientSession = (ClientSession) session;
                log.debug("SSH session {} event {}", session, event);
                switch (event) {
                    case KeyEstablished:
                        doAuth(clientSession);
                        break;
                    case Authenticated:
                        sessionFactory.onSessionAuthComplete(CallHomeSessionContextImpl.getFrom(clientSession));
                        break;
                    default:
                        break;
                }
            }

            @Override
            public void sessionCreated(final Session session) {
                log.debug("SSH session {} created", session);
            }

            @Override
            public void sessionClosed(final Session session) {
                CallHomeSessionContextImpl ctx = CallHomeSessionContextImpl.getFrom((ClientSession) session);
                if (ctx != null) {
                    ctx.removeSelf();
                }
                log.debug("SSH Session {} closed", session);
            }

            private void doAuth(final ClientSession session) {
                try {
                    final AuthFuture authFuture = CallHomeSessionContextImpl.getFrom(session).authorize();
                    authFuture.addListener(newAuthSshFutureListener(session));
                } catch (IOException e) {
                    log.error("Failed to authorize session {}", session, e);
                }
            }
        };
    }

    private SshFutureListener<AuthFuture> newAuthSshFutureListener(final ClientSession session) {
        return new SshFutureListener<AuthFuture>() {
            @Override
            public void operationComplete(final AuthFuture authFuture) {
                if (authFuture.isSuccess()) {
                    onSuccess();
                } else if (authFuture.isFailure()) {
                    onFailure(authFuture.getException());
                } else if (authFuture.isCanceled()) {
                    onCanceled();
                }
                authFuture.removeListener(this);
            }

            private void onSuccess() {
                log.debug("Authorize success");
            }

            private void onFailure(final Throwable throwable) {
                log.error("Authorize failed for session {}", session, throwable);
                session.close(true);
            }

            private void onCanceled() {
                log.warn("Authorize cancelled");
                session.close(true);
            }
        };
    }

    @Override
    public boolean verifyServerKey(final ClientSession sshClientSession, final SocketAddress remoteAddress,
            final PublicKey serverKey) {
        final CallHomeAuthorization authorization = authProvider.provideAuth(remoteAddress, serverKey);
        // server is not authorized
        if (!authorization.isServerAllowed()) {
            log.info("Incoming session {} was rejected by Authorization Provider.", sshClientSession);
            return false;
        }
        CallHomeSessionContext session = sessionFactory.createIfNotExists(
                sshClientSession, authorization, remoteAddress, serverKey);
        // Session was created, session with same name does not exists
        if (session != null) {
            return true;
        }
        // Session was not created, session with same name exists
        log.info("Incoming session {} was rejected. Session with same name {} is already active.",
                 sshClientSession, authorization.getSessionName());
        return false;
    }

    public void bind() throws IOException {
        try {
            client.start();
            serviceFactory = client.getIoServiceFactory();
            acceptor = serviceFactory.createAcceptor(new SessionFactory(client));
            acceptor.bind(bindAddress);
        } catch (IOException e) {
            log.error("Unable to start NETCONF CallHome Service on {}", bindAddress, e);
            throw e;
        }
    }

    @Override
    public void close() {
        if (acceptor != null) {
            acceptor.close(true);
        }
        if (serviceFactory != null) {
            serviceFactory.close(true);
        }
    }
}
