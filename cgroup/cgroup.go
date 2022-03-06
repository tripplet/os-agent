package cgroup

import (
	"fmt"
	"os"
	"path/filepath"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/opencontainers/runc/libcontainer/devices"
	"golang.org/x/sys/unix"

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

	logging.Info.Printf("Permission '%s', granted for Container '%s'", containerID, permission)
	return true, nil
}

// Based of
// https://github.com/opencontainers/runc/blob/1515d936397083f6309e949ff13e868808a4f91b/libcontainer/cgroups/fs2/devices.go
func AddDevicesAllowedCGroup2(containerID string, permission string) (bool, *dbus.Error) {
	//fields := strings.Split(permission, " ")

	//ids := strings.Split(fields[1], ":")
	//major, _ := strconv.ParseInt(ids[0], 10, 64)
	//minor, _ := strconv.ParseInt(ids[1], 10, 64)

	majorAll := int64(-1)
	minorAll := int64(-1)

	// Currently allows everything
	// TODO fix
	// Or usage of direct docker API (seems to not work properly for some reason):
	// https://docs.docker.com/engine/api/v1.41/#operation/ContainerUpdate
	devices := []*devices.Rule{
		{
			Allow:       true,
			Type:        devices.Type('a'),
			Major:       majorAll,
			Minor:       minorAll,
			Permissions: devices.Permissions("rwm"),
		},
		// {
		// 	Allow:  true,
		// 	Type:   fields[0],
		// 	Major:  &major,
		// 	Minor:  &minor,
		// 	Access: fields[2],
		// },
	}

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
