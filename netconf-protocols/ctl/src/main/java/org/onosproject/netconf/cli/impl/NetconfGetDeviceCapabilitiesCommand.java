/*
 * Copyright 2016-present Open Networking Foundation
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
package org.onosproject.netconf.cli.impl;

import org.apache.karaf.shell.api.action.Argument;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.cli.net.DeviceIdCompleter;
import org.onosproject.net.DeviceId;
import org.onosproject.netconf.NetconfController;
import org.onosproject.netconf.NetconfDevice;
import org.onosproject.netconf.NetconfSession;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Command that retrieves running configuration and device state.
 * If configuration cannot be retrieved it prints an error string.
 */
@Service
@Command(scope = "onos", name = "netconf-get-cap",
        description = "Retrieve device capabilities ")
public class NetconfGetDeviceCapabilitiesCommand extends AbstractShellCommand {

    @Argument(name = "deviceId", description = "Device ID",
            required = true)
    @Completion(DeviceIdCompleter.class)
    String uri = null;

    @Override
    protected void doExecute() {
        DeviceId deviceId = DeviceId.deviceId(uri);

        NetconfController controller = get(NetconfController.class);
        checkNotNull(controller, "Netconf controller is null");

        NetconfDevice device = controller.getDevicesMap().get(deviceId);
        if (device == null) {
            print("Netconf device object not found for %s", deviceId);
            return;
        }

        NetconfSession session = device.getSession();
        if (session == null) {
            print("Netconf session not found for %s", deviceId);
            return;
        }

        session.getDeviceCapabilitiesSet().forEach(this::print);
    }

}
