package com.security.demo.backend.model;

import javax.validation.constraints.NotBlank;

public class DeviceInfo {
    @NotBlank(message = "设备唯一标识不能为空")
    private String deviceId;
    // 设备UUID

    private String deviceModel; // 设备型号（可选）

    private String osVersion; // 系统版本（可选）

    // getter/setter
    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
    }

    public String getDeviceModel() {
        return deviceModel;
    }

    public void setDeviceModel(String deviceModel) {
        this.deviceModel = deviceModel;
    }

    public String getOsVersion() {
        return osVersion;
    }

    public void setOsVersion(String osVersion) {
        this.osVersion = osVersion;
    }
}
