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

package org.onosproject.netconf.callhome;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.onosproject.netconf.NetconfDeviceInfo.extractIpPortPath;
import static org.slf4j.LoggerFactory.getLogger;

import java.util.Optional;
import java.util.OptionalInt;

import com.google.common.annotations.Beta;

import org.onlab.packet.IpAddress;
import org.onosproject.net.config.Config;
import org.onosproject.net.DeviceId;
import org.slf4j.Logger;

/**
 * Configuration for Netconf call home device.
 *
 * The URI for a netconf call home device is of the format
 *
 * {@code netconf:<invalid_ip>[:<port>][/<path>]}
 *
 * The {@code ip} and {@code port} have no function only use to identify
 * device id. The {@code path} is an optional component that is not used
 * by the default netconf driver, but is leveragable by custom drivers.
 */
@Beta
public class NetconfCallHomeDeviceConfig extends Config<DeviceId> {

    private final Logger log = getLogger(getClass());

    /**
     * netcfg ConfigKey.
     */
    public static final String CONFIG_KEY = "netconf-ch";

    public static final String PATH = "path";
    public static final String SERVER_KEY = "server-key";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String SSHKEY = "sshkey";
    public static final String CONNECT_TIMEOUT = "connect-timeout";
    public static final String REPLY_TIMEOUT = "reply-timeout";
    public static final String IDLE_TIMEOUT = "idle-timeout";

    @Override
    public boolean isValid() {
        return hasOnlyFields(PATH, SERVER_KEY, USERNAME, PASSWORD, SSHKEY,
                CONNECT_TIMEOUT, REPLY_TIMEOUT, IDLE_TIMEOUT) &&
                IpAddress.valueOf(checkNotNull(extractIpPortPath(subject)).getLeft()).toOctets()[0] == 0
                && serverKey() != null;
    }

    /**
     * Gets the path of the NETCONF device.
     *
     * @return path
     */
    public Optional<String> path() {
        String val = get(PATH, "");
        if (val.isEmpty()) {
            return extractIpPortPath(subject).getRight();
        }
        return Optional.of(val);
    }

    public String serverKey() {
        return get(SERVER_KEY, "");
    }

    /**
     * Gets the username of the NETCONF device.
     *
     * @return usernamestoreDeviceKey
     */
    public String username() {
        return get(USERNAME, "");
    }

    /**
     * Gets the password of the NETCONF device.
     *
     * @return password
     */
    public String password() {
        return get(PASSWORD, "");
    }

    /**
     * Gets the sshKey of the NETCONF device.
     *
     * @return sshkey
     */
    public String sshKey() {
        return get(SSHKEY, "");
    }

    /**
     * Gets the connect timeout of the SSH connection.
     *
     * @return connectTimeout
     */
    public OptionalInt connectTimeout() {
        int connectTimeout = get(CONNECT_TIMEOUT, 0);
        return (connectTimeout == 0) ? OptionalInt.empty() : OptionalInt.of(connectTimeout);
    }

    /**
     * Gets the reply timeout of the SSH connection.
     *
     * @return replyTimeout
     */
    public OptionalInt replyTimeout() {
        int replyTimeout = get(REPLY_TIMEOUT, 0);
        return (replyTimeout == 0) ? OptionalInt.empty() : OptionalInt.of(replyTimeout);
    }

    /**
     * Gets the idle timeout of the SSH connection.
     *
     * @return idleTimeout
     */
    public OptionalInt idleTimeout() {
        int idleTimeout = get(IDLE_TIMEOUT, 0);
        return (idleTimeout == 0) ? OptionalInt.empty() : OptionalInt.of(idleTimeout);
    }

    /**
     * Sets the path for the device.
     *
     * @param path the path
     * @return instance for chaining
     */
    public NetconfCallHomeDeviceConfig setPath(String path) {
        return (NetconfCallHomeDeviceConfig) setOrClear(PATH, path);
    }

    /**
     * Sets the username for the Device.
     *
     * @param username username
     * @return instance for chaining
     */
    public NetconfCallHomeDeviceConfig setUsername(String username) {
        return (NetconfCallHomeDeviceConfig) setOrClear(USERNAME, username);
    }

    /**
     * Sets the password for the Device.
     *
     * @param password password
     * @return instance for chaining
     */
    public NetconfCallHomeDeviceConfig setPassword(String password) {
        return (NetconfCallHomeDeviceConfig) setOrClear(PASSWORD, password);
    }

    /**
     * Sets the SshKey for the Device.
     *
     * @param sshKey sshKey as string
     * @return instance for chaining
     */
    public NetconfCallHomeDeviceConfig setSshKey(String sshKey) {
        return (NetconfCallHomeDeviceConfig) setOrClear(SSHKEY, sshKey);
    }

    /**
     * Sets the NETCONF Connect Timeout for the Device.
     * This is the amount of time in seconds allowed for the SSH handshake to take
     * place
     * Minimum 1 second
     * When specified, overrides NetconfControllerImpl.netconfConnectTimeout for
     * this device
     *
     * @param connectTimeout connectTimeout as int
     * @return instance for chaining
     */
    public NetconfCallHomeDeviceConfig setConnectTimeout(Integer connectTimeout) {
        return (NetconfCallHomeDeviceConfig) setOrClear(CONNECT_TIMEOUT, connectTimeout);
    }

    /**
     * Sets the NETCONF Reply Timeout for the Device.
     * This is the amount of time in seconds allowed for the NETCONF Reply to a
     * command
     * Minimum 1 second
     * When specified, overrides NetconfControllerImpl.netconfReplyTimeout for this
     * device
     *
     * @param replyTimeout replyTimeout as int
     * @return instance for chaining
     */
    public NetconfCallHomeDeviceConfig setReplyTimeout(Integer replyTimeout) {
        return (NetconfCallHomeDeviceConfig) setOrClear(REPLY_TIMEOUT, replyTimeout);
    }

    /**
     * Sets the NETCONF Idle Timeout for the Device.
     * This is the amount of time in seconds after which the SSH connection will
     * close if no traffic is detected
     * Minimum 10 second
     * When specified, overrides NetconfControllerImpl.netconfIdleTimeout for this
     * device
     *
     * @param idleTimeout idleTimeout as int
     * @return instance for chaining
     */
    public NetconfCallHomeDeviceConfig setIdleTimeout(Integer idleTimeout) {
        return (NetconfCallHomeDeviceConfig) setOrClear(IDLE_TIMEOUT, idleTimeout);
    }
}
