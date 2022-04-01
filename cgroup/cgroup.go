package cgroup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/opencontainers/runc/libcontainer/devices"
	"golang.org/x/sys/unix"

	"github.com/docker/docker/client"

	logging "github.com/home-assistant/os-agent/utils/log"
)

const (
	useCGroup2             = true
	objectPath             = "/io/hass/os/CGroup"
	ifaceName              = "io.hass.os.CGroup"
	cgroupFSDockerDevices  = "/sys/fs/cgroup/devices/docker"
	cgroup2FSDockerDevices = "/sys/fs/cgroup/system.slice"
)

type cgroup struct {
	conn *dbus.Conn
}

var permissionCache = make(map[string][]string)

func (d cgroup) AddDevicesAllowed(containerID string, permission string) (bool, *dbus.Error) {
	if useCGroup2 {
		return AddDevicesAllowedCGroup2(containerID, permission)
	}

	// Make sure path is relative to cgroupFSDockerDevices
	allowedFile, err := securejoin.SecureJoin(cgroupFSDockerDevices, containerID+string(filepath.Separator)+"devices.allow")
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("Security issues with '%s': %s", containerID, err))
	}

	// Check if file/container exists
	_, err = os.Stat(allowedFile)
	if os.IsNotExist(err) {
		return false, dbus.MakeFailedError(fmt.Errorf("Can't find Container '%s' for adjust CGroup devices.", containerID))
	}

	// Write permission adjustments
	file, err := os.Create(allowedFile)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("Can't open CGroup devices '%s': %s", allowedFile, err))
	}
	defer file.Close()

	_, err = file.WriteString(permission + "\n")
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("Can't write CGroup permission '%s': %s", permission, err))
	}

	logging.Info.Printf("Permission '%s', granted for Container '%s'", permission, containerID)
	return true, nil
}

// Based of
// https://github.com/opencontainers/runc/blob/1515d936397083f6309e949ff13e868808a4f91b/libcontainer/cgroups/fs2/devices.go
func AddDevicesAllowedCGroup2(containerID string, permission string) (bool, *dbus.Error) {
	newRule := GetAllowRuleFromString(permission)

	// Or usage of direct docker API (seems to not work properly for some reason):
	// https://docs.docker.com/engine/api/v1.41/#operation/ContainerUpdate
	devices := []*devices.Rule{
		{
			// allow mknod for any device
			Type:        devices.CharDevice,
			Major:       devices.Wildcard,
			Minor:       devices.Wildcard,
			Permissions: "m",
			Allow:       true,
		},
		{
			Type:        devices.BlockDevice,
			Major:       devices.Wildcard,
			Minor:       devices.Wildcard,
			Permissions: "m",
			Allow:       true,
		},
		{
			// /dev/null
			Type:        devices.CharDevice,
			Major:       1,
			Minor:       3,
			Permissions: "rwm",
			Allow:       true,
		},
		{
			// /dev/random
			Type:        devices.CharDevice,
			Major:       1,
			Minor:       8,
			Permissions: "rwm",
			Allow:       true,
		},
		{
			// /dev/full
			Type:        devices.CharDevice,
			Major:       1,
			Minor:       7,
			Permissions: "rwm",
			Allow:       true,
		},
		{
			// /dev/tty
			Type:        devices.CharDevice,
			Major:       5,
			Minor:       0,
			Permissions: "rwm",
			Allow:       true,
		},
		{
			// /dev/zero",
			Type:        devices.CharDevice,
			Major:       1,
			Minor:       5,
			Permissions: "rwm",
			Allow:       true,
		},
		{
			// /dev/urandom",
			Type:        devices.CharDevice,
			Major:       1,
			Minor:       9,
			Permissions: "rwm",
			Allow:       true,
		},
		{
			// /dev/pts/ - pts namespaces are "coming soon"
			Type:        devices.CharDevice,
			Major:       136,
			Minor:       devices.Wildcard,
			Permissions: "rwm",
			Allow:       true,
		},
		{
			Type:        devices.CharDevice,
			Major:       5,
			Minor:       2,
			Permissions: "rwm",
			Allow:       true,
		},
		{
			// tuntap
			Type:        devices.CharDevice,
			Major:       10,
			Minor:       200,
			Permissions: "rwm",
			Allow:       true,
		},
	}

	// Append existing rukes from docker container
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("Can't create docker client connection: %s", err))
	}

	info, err := cli.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("Can't inspect container '%s': %s", containerID, err))
	}

	for _, existingPermission := range info.HostConfig.DeviceCgroupRules {
		devices = append(devices, GetAllowRuleFromString(existingPermission))
	}

	// Append existing rules from previous requests
	existingRules, found := permissionCache[containerID]
	if found {
		for _, existingPermission := range existingRules {
			devices = append(devices, GetAllowRuleFromString(existingPermission))
		}
	}

	devices = append(devices, newRule)
	permissionCache[containerID] = append(existingRules, permission)

	logging.Info.Printf("New ebpf filter: %s", devices)

	insts, license, err := DeviceFilter(devices)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("Can't create LinuxDeviceCgroup: %s", err))
	}

	// Make sure path is relative to cgroupFSDockerDevices
	path, err := securejoin.SecureJoin(cgroup2FSDockerDevices, "docker-"+containerID+".scope")
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("Security issues with '%s': %s", containerID, err))
	}

	dirFD, err := unix.Open(path, unix.O_DIRECTORY|unix.O_RDONLY, 0600)
	if err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("cannot get dir FD for %s", path))
	}
	defer unix.Close(dirFD)

	if _, err := LoadAttachCgroupDeviceFilter(insts, license, dirFD); err != nil {
		return false, dbus.MakeFailedError(fmt.Errorf("Can't attach bpf device filter: '%s': %s", containerID, err))
	}

	logging.Info.Printf("Permission '%s', granted for Container '%s'", permission, containerID)
	return true, nil
}

func InitializeDBus(conn *dbus.Conn) {
	d := cgroup{
		conn: conn,
	}

	err := conn.Export(d, objectPath, ifaceName)
	if err != nil {
		logging.Critical.Panic(err)
	}

	node := &introspect.Node{
		Name: objectPath,
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{
				Name:    ifaceName,
				Methods: introspect.Methods(d),
			},
		},
	}

	err = conn.Export(introspect.NewIntrospectable(node), objectPath, "org.freedesktop.DBus.Introspectable")
	if err != nil {
		logging.Critical.Panic(err)
	}

	logging.Info.Printf("Exposing object %s with interface %s ...", objectPath, ifaceName)
}

func GetAllowRuleFromString(permission string) *devices.Rule {
	fields := strings.Split(permission, " ")

	ids := strings.Split(fields[1], ":")
	major, _ := strconv.ParseInt(ids[0], 10, 64)
	minor, _ := strconv.ParseInt(ids[1], 10, 64)

	return &devices.Rule{
		Type:        devices.Type(fields[0][0]),
		Major:       major,
		Minor:       minor,
		Allow:       true,
		Permissions: devices.Permissions(fields[2]),
	}
}
