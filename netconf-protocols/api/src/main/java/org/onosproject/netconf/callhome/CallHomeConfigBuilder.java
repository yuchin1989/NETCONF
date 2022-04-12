/*
 * Copyright 2022-present Open Networking Foundation
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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.lang3.tuple.Pair;
import org.onlab.packet.IpAddress;
import org.onosproject.net.DeviceId;

import java.util.Objects;

public class CallHomeConfigBuilder {
    private String ip;
    private Integer port;
    private String path;
    private String serverKey;
    private String username;
    private String password;
    private String sshKey;
    private Integer connectTimeout = null;
    private Integer replyTimeout = null;
    private Integer idleTimeout = null;

    private CallHomeConfigBuilder(IpAddress fakeIp, String serverKey, String username) {
        ip = fakeIp.toString();
        this.serverKey = serverKey;
        this.username = username;
    }

    public static CallHomeConfigBuilder builder(IpAddress fakeIp, String serverKey, String username) {
        return new CallHomeConfigBuilder(fakeIp, serverKey, username);
    }

    public String getIp() {
        return ip;
    }

    public CallHomeConfigBuilder setIp(String ip) {
        this.ip = ip;
        return this;
    }

    public Integer getPort() {
        return port;
    }

    public CallHomeConfigBuilder setPort(Integer port) {
        this.port = port;
        return this;
    }

    public String getPath() {
        return path;
    }

    public CallHomeConfigBuilder setPath(String path) {
        this.path = path;
        return this;
    }

    public String getServerKey() {
        return serverKey;
    }

    public CallHomeConfigBuilder setServerKey(String serverKey) {
        this.serverKey = serverKey;
        return this;
    }

    public String getUsername() {
        return username;
    }

    public CallHomeConfigBuilder setUsername(String username) {
        this.username = username;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public CallHomeConfigBuilder setPassword(String password) {
        this.password = password;
        return this;
    }

    public String getSshKey() {
        return sshKey;
    }

    public CallHomeConfigBuilder setSshKey(String sshKey) {
        this.sshKey = sshKey;
        return this;
    }

    public Integer getConnectTimeout() {
        return connectTimeout;
    }

    public CallHomeConfigBuilder setConnectTimeout(Integer connectTimeout) {
        this.connectTimeout = connectTimeout;
        return this;
    }

    public Integer getReplyTimeout() {
        return replyTimeout;
    }

    public CallHomeConfigBuilder setReplyTimeout(Integer replyTimeout) {
        this.replyTimeout = replyTimeout;
        return this;
    }

    public Integer getIdleTimeout() {
        return idleTimeout;
    }

    public void setIdleTimeout(Integer idleTimeout) {
        this.idleTimeout = idleTimeout;
    }

    public Pair<DeviceId, JsonNode> build() {
        JsonNodeFactory jsonNodeFactory = JsonNodeFactory.instance;
        ObjectNode conf = jsonNodeFactory.objectNode();
        conf.put(NetconfCallHomeDeviceConfig.SERVER_KEY, serverKey);
        conf.put(NetconfCallHomeDeviceConfig.USERNAME, username);

        if (connectTimeout != null) {
            conf.put(NetconfCallHomeDeviceConfig.CONNECT_TIMEOUT, connectTimeout);
        }
        if (replyTimeout != null) {
            conf.put(NetconfCallHomeDeviceConfig.REPLY_TIMEOUT, replyTimeout);
        }
        if (idleTimeout != null) {
            conf.put(NetconfCallHomeDeviceConfig.IDLE_TIMEOUT, idleTimeout);
        }
        if (!Objects.equals(password, "")) {
            conf.put(NetconfCallHomeDeviceConfig.PASSWORD, password);
        }
        if (!Objects.equals(sshKey, "")) {
            conf.put(NetconfCallHomeDeviceConfig.SSHKEY, sshKey);
        }
        if (!Objects.equals(path, "")) {
            conf.put(NetconfCallHomeDeviceConfig.PATH, path);
        }
        String id = "netconf-ch:" + ip;
        if (port != null) {
            id += ":" + port;
        }
        if (!Objects.equals(path, "")) {
            id += "/" + path;
        }

        return Pair.of(
                DeviceId.deviceId(id),
                conf
        );
    }
}
