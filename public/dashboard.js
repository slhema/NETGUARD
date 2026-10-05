// ==========================================
// LOAD NETWORK ACTIVITY
// ==========================================

async function loadNetworkActivity() {

    try {

        const response =
            await fetch("/api/network-activity");

        const data =
            await response.json();

        const activityList =
            document.getElementById("activityList");


        if (!data.success) {

            activityList.innerHTML = `
                <div class="empty-state">

                    <div class="empty-icon">
                        !
                    </div>

                    <h4>Unable to load activity</h4>

                    <p>
                        NETGUARD could not retrieve
                        network activity.
                    </p>

                </div>
            `;

            return;
        }


        if (data.activities.length === 0) {

            activityList.innerHTML = `
                <div class="empty-state">

                    <div class="empty-icon">
                        ◌
                    </div>

                    <h4>No network activity yet</h4>

                    <p>
                        Waiting for devices to communicate
                        with the protected server.
                    </p>

                </div>
            `;

            return;
        }


        activityList.innerHTML = "";


        data.activities.forEach((activity) => {

            const activityItem =
                document.createElement("div");

            activityItem.className =
                "activity-item";


            // ------------------------------------------
            // DETERMINE SECURITY STATE
            // ------------------------------------------

            let stateClass = "normal";
            let stateText = activity.status;

            if (
                activity.status === "UNAUTHORIZED" ||
                activity.activity_type === "Unauthorized Device"
            ) {

                stateClass = "unauthorized";
                stateText = "UNAUTHORIZED";

            } else if (
                activity.status === "SUSPICIOUS" ||
                activity.activity_type === "Suspicious Network Behavior"
            ) {

                stateClass = "suspicious";
                stateText = "SUSPICIOUS";

            } else if (
                activity.status === "AUTHORIZED"
            ) {

                stateClass = "authorized";
                stateText = "AUTHORIZED";

            }


            activityItem.classList.add(
                stateClass
            );


            activityItem.innerHTML = `

                <div class="activity-icon">
                    ⇄
                </div>

                <div class="activity-details">

                    <strong>
                        ${activity.activity_type}
                    </strong>

                    <span>
                        ${activity.method}
                        ${activity.endpoint}
                    </span>

                </div>

                <div class="activity-meta">

                    <span>
                        ${activity.ip_address}
                    </span>

                    <small class="activity-status ${stateClass}">
                        ${stateText}
                    </small>

                </div>

            `;


            activityList.appendChild(
                activityItem
            );

        });


        updateNetworkRequestCount(
            data.activities.length
        );


    } catch (error) {

        console.error(
            "Error loading network activity:",
            error
        );

    }

}


// ==========================================
// UPDATE NETWORK REQUEST COUNT
// ==========================================

function updateNetworkRequestCount(count) {

    const statValues =
        document.querySelectorAll(".stat-value");


    if (statValues.length >= 2) {

        statValues[1].textContent =
            count;

    }

}


// ==========================================
// LOAD AUTHORIZED DEVICES
// ==========================================

async function loadAuthorizedDevices() {

    try {

        const response =
            await fetch("/api/devices");

        const data =
            await response.json();


        const devicesContainer =
            document.querySelector(
                ".lower-grid .panel:nth-child(2)"
            );


        if (!devicesContainer) {
            return;
        }


        if (!data.success) {
            return;
        }


        const deviceList =
            data.devices;


        if (deviceList.length === 0) {

            devicesContainer.innerHTML = `

                <div class="panel-header">

                    <div>

                        <h3>
                            Authorized Devices
                        </h3>

                        <p>
                            Registered network devices
                        </p>

                    </div>

                </div>


                <div class="empty-state small">

                    <div class="empty-icon">
                        ◇
                    </div>

                    <h4>
                        No devices registered
                    </h4>

                    <p>
                        Authorized devices will appear here.
                    </p>

                </div>

            `;

            updateProtectedDeviceCount(0);

            return;
        }


        let deviceHTML = `

            <div class="panel-header">

                <div>

                    <h3>
                        Authorized Devices
                    </h3>

                    <p>
                        Registered network devices
                    </p>

                </div>

            </div>

            <div class="device-list">

        `;


        deviceList.forEach((device) => {

            deviceHTML += `

                <div class="device-item">

                    <div class="device-icon">
                        ◇
                    </div>

                    <div class="device-details">

                        <strong>
                            ${device.device_name}
                        </strong>

                        <span>
                            ${device.device_type}
                        </span>

                    </div>

                    <div class="device-meta">

                        <span>
                            ${device.ip_address}
                        </span>

                        <small>
                            ${device.status}
                        </small>

                    </div>

                </div>

            `;

        });


        deviceHTML += `

            </div>

        `;


        devicesContainer.innerHTML =
            deviceHTML;


        updateProtectedDeviceCount(
            deviceList.length
        );


    } catch (error) {

        console.error(
            "Error loading devices:",
            error
        );

    }

}


// ==========================================
// UPDATE PROTECTED DEVICE COUNT
// ==========================================

function updateProtectedDeviceCount(count) {

    const statValues =
        document.querySelectorAll(".stat-value");


    if (statValues.length >= 1) {

        statValues[0].textContent =
            count;

    }

}


// ==========================================
// LOAD SECURITY ALERTS
// ==========================================

async function loadSecurityAlerts() {

    try {

        const response =
            await fetch("/api/security-alerts");

        const data =
            await response.json();


        const alertsPanel =
            document.querySelector(
                ".lower-grid .panel:nth-child(1)"
            );


        if (!alertsPanel) {
            return;
        }


        if (!data.success) {
            return;
        }


        const alerts =
            data.alerts;


        // ------------------------------------------
        // NO ALERTS
        // ------------------------------------------

        if (alerts.length === 0) {

            alertsPanel.innerHTML = `

                <div class="panel-header">

                    <div>

                        <h3>
                            Security Alerts
                        </h3>

                        <p>
                            Recent detections
                        </p>

                    </div>

                </div>


                <div class="empty-state small">

                    <div class="empty-icon">
                        ✓
                    </div>

                    <h4>
                        No alerts
                    </h4>

                    <p>
                        Your network currently looks normal.
                    </p>

                </div>

            `;


            updateSecurityAlertCount(0);

            updateSystemStatus(false);

            return;
        }


        // ------------------------------------------
        // DISPLAY ALERTS
        // ------------------------------------------

        let alertHTML = `

            <div class="panel-header">

                <div>

                    <h3>
                        Security Alerts
                    </h3>

                    <p>
                        Recent detections
                    </p>

                </div>

                <span class="panel-badge alert-badge">
                    ${alerts.length}
                    ALERT${alerts.length === 1 ? "" : "S"}
                </span>

            </div>

            <div class="alert-list">

        `;


        alerts.forEach((alert) => {

            const isSuspicious =
                alert.status === "SUSPICIOUS" ||
                alert.activity_type ===
                "Suspicious Network Behavior";


            const alertTitle =
                alert.activity_type ||
                "Unauthorized Device";


            const alertStatus =
                alert.status ||
                "UNAUTHORIZED";


            const alertIP =
                alert.ip_address ||
                "Unknown IP";


            const alertMethod =
                alert.method ||
                "REQUEST";


            const alertEndpoint =
                alert.endpoint ||
                "/api/device-communication";


            const alertTime =
                alert.created_at ||
                "Recent";


            alertHTML += `

                <div class="alert-item ${
                    isSuspicious
                        ? "suspicious-alert"
                        : "unauthorized-alert"
                }">

                    <div class="alert-icon">
                        ${isSuspicious ? "~" : "!"}
                    </div>

                    <div class="alert-details">

                        <strong>
                            ${alertTitle}
                        </strong>

                        <span>
                            ${alertMethod}
                            ${alertEndpoint}
                        </span>

                        <small>
                            ${
                                isSuspicious
                                ? "Abnormal request pattern detected"
                                : "Device communication blocked"
                            }
                        </small>

                    </div>

                    <div class="alert-meta">

                        <span>
                            ${alertIP}
                        </span>

                        <small>
                            ${alertStatus}
                        </small>

                        <time>
                            ${alertTime}
                        </time>

                    </div>

                </div>

            `;

        });


        alertHTML += `

            </div>

        `;


        alertsPanel.innerHTML =
            alertHTML;


        updateSecurityAlertCount(
            alerts.length
        );


        updateSystemStatus(true);


    } catch (error) {

        console.error(
            "Error loading security alerts:",
            error
        );

    }

}


// ==========================================
// UPDATE SECURITY ALERT COUNT
// ==========================================

function updateSecurityAlertCount(count) {

    const statValues =
        document.querySelectorAll(".stat-value");


    if (statValues.length >= 3) {

        statValues[2].textContent =
            count;

    }

}


// ==========================================
// UPDATE SYSTEM STATUS
// ==========================================

function updateSystemStatus(hasAlerts) {

    const statValues =
        document.querySelectorAll(".stat-value");

    const descriptions =
        document.querySelectorAll(".stat-description");


    if (statValues.length >= 4) {

        if (hasAlerts) {

            statValues[3].textContent =
                "Alert";

        } else {

            statValues[3].textContent =
                "Secure";

        }

    }


    if (descriptions.length >= 4) {

        if (hasAlerts) {

            descriptions[3].textContent =
                "Security event detected";

        } else {

            descriptions[3].textContent =
                "No active threats";

        }

    }

}


// ==========================================
// INITIAL LOAD
// ==========================================

loadNetworkActivity();

loadAuthorizedDevices();

loadSecurityAlerts();


// ==========================================
// AUTOMATIC REFRESH
// ==========================================

setInterval(
    loadNetworkActivity,
    3000
);

setInterval(
    loadAuthorizedDevices,
    5000
);

setInterval(
    loadSecurityAlerts,
    3000
);