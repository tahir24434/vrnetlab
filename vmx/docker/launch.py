#!/usr/bin/env python3

import datetime
import logging
import os
import random
import re
import signal
import subprocess
import sys
import time
import vrnetlab
import shutil
import tarfile
from textwrap import dedent
from os import path
from tempfile import mkdtemp, mkstemp
from typing import Any, Dict, Iterable, List
from time import sleep

def handle_SIGCHLD(signal, frame):
    os.waitpid(-1, os.WNOHANG)

def handle_SIGTERM(signal, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, handle_SIGTERM)
signal.signal(signal.SIGTERM, handle_SIGTERM)
signal.signal(signal.SIGCHLD, handle_SIGCHLD)

TRACE_LEVEL_NUM = 9
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)
logging.Logger.trace = trace



class VMX_vcp(vrnetlab.VM):
    def __init__(self, username, password, image, install_mode=False, custom_config=False):
        super(VMX_vcp, self).__init__(username, password, disk_image=image, ram=2048)
        self.install_mode = install_mode
        self.num_nics = 0
        self.qemu_args.extend(["-drive", "if=ide,file=/vmx/vmxhdd.img"])
        self.smbios = ["type=0,vendor=Juniper",
                       "type=1,manufacturer=Juniper,product=VM-vcp_vmx2-161-re-0,version=0.1.0"]

        # If user has custom configuration file, present at given path inside docker container, we'll create our own
        # image so we can use a junos config file.
        if custom_config:
            logger.info("Creating custom config")
            custom_config_file = "/etc/config"
            boot_image_path = "/vmx/custom_config.img"
            if os.path.isfile(custom_config_file):
                self.create_config_drive(custom_config_file, boot_image_path)
                self.qemu_args.extend(
                    ["-usb", "-drive",
                     "id=custom_usb_disk,media=disk,format=raw,file=/vmx/custom_config.img,if=none",
                     "-device", "usb-storage,drive=custom_usb_disk"])
        # add metadata image if it exists
        elif os.path.exists("/vmx/metadata-usb-re.img"):
            self.qemu_args.extend(
                ["-usb", "-drive",
                 "id=vcp_usb_disk,media=disk,format=raw,file=/vmx/metadata-usb-re.img,if=none",
                 "-device", "usb-storage,drive=vcp_usb_disk"])

    def create_config_drive(self, custom_config_file: str, boot_image_path: str) -> None:
        """
        Creates an image holding custom junos config file.
        This image has a single gzip compressed tar file at /vmm-config.tgz.
        Inside the tgz are /boot/loader.conf, containing a static bootloader configuration,
        and /config/juniper.conf containing the input junos_config_file
        """
        temp_dir = mkdtemp("configdrive")
        temp_tgz = mkstemp(suffix=".tgz")[1]
        os.makedirs(path.join(temp_dir, "boot"))
        os.makedirs(path.join(temp_dir, "config"))

        # Generate a hardcoded bootloader configuration
        # This has been validated for  16.1 and 17.2
        # May need to be different for different versions
        # Bootload config can be found in vMX tarball within images/metadata-usb-re.img
        with open(path.join(temp_dir, "boot/loader.conf"), 'w') as f:
            f.write(dedent("""
                vmtype="0"
                vm_retype="RE-VMX"
                vm_i2cid="0xBAA"
                vm_chassis_i2cid="161"
                vm_instance="0"
                """))

        # Create a tarfile in the right format containing the user-provided config
        shutil.copyfile(custom_config_file, path.join(temp_dir, "config/juniper.conf"))
        with tarfile.open(temp_tgz, mode="w:gz") as tar:
            tar.add(temp_dir, arcname=".")

        self._exec_cmds([
            # Create the metadata image which'll hold the config, 10MB should be enough
            'dd if=/dev/zero of="{}" bs=1M count=10'.format(boot_image_path),
            '/sbin/mkfs.vfat "{}"'.format(boot_image_path),
        ])

        # Random sleep to avoid mount clashes between containers trying to mount at the same time
        sleep(random.randrange(0, 20))

        self._exec_cmds([
            # Copy our configs into the image
            'mount -o loop "{}" /mnt'.format(boot_image_path),
            'cp "{}" /mnt/vmm-config.tgz'.format(temp_tgz),
            'umount /mnt'
        ])

        # Only delete the files if we reach the end successfully.
        # Keep them around on errors for debugging.
        # Since this is all inside an ephemeral docker container (on an ephemeral host)
        # we don't need to worry about cluttering up the host with old file
        os.remove(temp_tgz)
        shutil.rmtree(temp_dir)

    def _exec_cmds(self, cmds: Iterable[str]) -> None:
        for cmd in cmds:
            self._exec_cmd(cmd)

    def _exec_cmd(self, cmd: str) -> str:
        """
        Execute shell command.
        Return the stdout if successful or raise exception otherwise
        :params cmd: shell command
        :return the output in bytes format
        """
        self.logger.info("Executing: %s", cmd)
        try:
            return str(subprocess.check_output(cmd, shell=True).decode("utf-8").strip())
        except Exception as ex:
            self.logger.error("Failed executing: %s, with exception: %s", cmd, ex)
            raise


    def start(self):
        # use parent class start() function
        super(VMX_vcp, self).start()
        # add interface to internal control plane bridge
        if not self.install_mode:
            vrnetlab.run_command(["brctl", "addif", "int_cp", "vcp-int"])
            vrnetlab.run_command(["ip", "link", "set", "vcp-int", "up"])


    def gen_mgmt(self):
        """ Generate mgmt interface(s)

            We override the default function since we want a virtio NIC to the
            vFPC
        """
        # call parent function to generate first mgmt interface (e1000)
        res = super(VMX_vcp, self).gen_mgmt()
        if not self.install_mode:
            # add virtio NIC for internal control plane interface to vFPC
            res.append("-device")
            res.append("virtio-net-pci,netdev=vcp-int,mac=%s" % vrnetlab.gen_mac(1))
            res.append("-netdev")
            res.append("tap,ifname=vcp-int,id=vcp-int,script=no,downscript=no")
        return res



    def bootstrap_spin(self):
        """ This function should be called periodically to do work.

            returns False when it has failed and given up, otherwise True
        """

        if self.spins > 300:
            # too many spins with no result -> restart
            self.logger.warning("no output from serial console, restarting VCP")
            self.stop()
            self.start()
            self.spins = 0
            return

        (ridx, match, res) = self.tn.expect([b"login:", b"root@(%|:~ #)"], 1)
        if match: # got a match!
            if ridx == 0: # matched login prompt, so should login
                self.logger.info("matched login prompt")
                self.wait_write("root", wait=None)
            if ridx == 1:
                if self.install_mode:
                    self.logger.info("requesting power-off")
                    self.wait_write("cli", None)
                    self.wait_write("request system power-off", '>')
                    self.wait_write("yes", 'Power Off the system')
                    self.running = True
                    return
                # run main config!
                self.bootstrap_config()
                self.running = True
                self.tn.close()
                # calc startup time
                startup_time = datetime.datetime.now() - self.start_time
                self.logger.info("Startup complete in: %s" % startup_time)
                return

        else:
            # no match, if we saw some output from the router it's probably
            # booting, so let's give it some more time
            if res != b'':
                self.logger.trace("OUTPUT VCP: %s" % res.decode())
                # reset spins if we saw some output
                self.spins = 0

        self.spins += 1



    def bootstrap_config(self):
        """ Do the actual bootstrap config
        """
        self.wait_write("cli", None)
        self.wait_write("configure", '>', 10)
        self.wait_write("set chassis fpc 0 pic 0 number-of-ports 96")
        self.wait_write("set system services ssh")
        self.wait_write("set system services netconf ssh")
        self.wait_write("set system services netconf rfc-compliant")
        self.wait_write("set system login user %s class super-user authentication plain-text-password" % self.username)
        self.wait_write(self.password, 'New password:')
        self.wait_write(self.password, 'Retype new password:')
        self.wait_write("set system root-authentication plain-text-password")
        self.wait_write(self.password, 'New password:')
        self.wait_write(self.password, 'Retype new password:')
        self.wait_write("set interfaces fxp0 unit 0 family inet address 10.0.0.15/24")
        self.wait_write("delete interfaces fxp0 unit 0 family inet dhcp")
        self.wait_write("delete system processes dhcp-service")
        self.wait_write("commit")
        self.wait_write("exit")


    def wait_write(self, cmd, wait='#', timeout=None):
        """ Wait for something and then send command
        """
        if wait:
            self.logger.trace("Waiting for %s" % wait)
            while True:
                (ridx, match, res) = self.tn.expect([wait.encode(), b"Retry connection attempts"], timeout=timeout)
                if match:
                    if ridx == 0:
                        break
                    if ridx == 1:
                        self.tn.write("yes\r".encode())
            self.logger.trace("Read: %s" % res.decode())
        self.logger.debug("writing to serial console: %s" % cmd)
        self.tn.write("{}\r".format(cmd).encode())





class VMX_vfpc(vrnetlab.VM):
    def __init__(self, version):
        super(VMX_vfpc, self).__init__(None, None, disk_image = "/vmx/vfpc.img", num=1)
        self.version = version
        self.num_nics = 96

        self.nic_type = "virtio-net-pci"
        self.qemu_args.extend(["-cpu", "SandyBridge", "-M", "pc", "-smp", "3"])
        # add metadata image if it exists
        if os.path.exists("/vmx/metadata-usb-fpc0.img"):
            self.qemu_args.extend(
                ["-usb", "-drive", "id=fpc_usb_disk,media=disk,format=raw,file=/vmx/metadata-usb-fpc0.img,if=none",
                 "-device", "usb-storage,drive=fpc_usb_disk"])



    def gen_mgmt(self):
        res = []
        # mgmt interface
        res.extend(["-device", "virtio-net-pci,netdev=mgmt,mac=%s" % vrnetlab.gen_mac(0)])
        res.extend(["-netdev", "user,id=mgmt,net=10.0.0.0/24"])
        # internal control plane interface to vFPC
        res.extend(["-device", "virtio-net-pci,netdev=vfpc-int,mac=%s" %
                    vrnetlab.gen_mac(0)])
        res.extend(["-netdev",
                    "tap,ifname=vfpc-int,id=vfpc-int,script=no,downscript=no"])

        if self.version in ('15.1F6.9', '16.1R2.11', '17.2R1.13'):
            # dummy interface for some vMX versions - not sure why vFPC wants
            # it but without it we get a misalignment
            res.extend(["-device", "virtio-net-pci,netdev=dummy,mac=%s" %
                                   vrnetlab.gen_mac(0)])
            res.extend(["-netdev", "tap,ifname=vfpc-dummy,id=dummy,script=no,downscript=no"])

        return res



    def start(self):
        # use parent class start() function
        super(VMX_vfpc, self).start()
        # add interface to internal control plane bridge
        vrnetlab.run_command(["brctl", "addif", "int_cp", "vfpc-int"])
        vrnetlab.run_command(["ip", "link", "set", "vfpc-int", "up"])



    def bootstrap_spin(self):
        (ridx, match, res) = self.tn.expect([b"localhost login", b"mounting /dev/sda2 on /mnt failed"], 1)
        if match:
            if ridx == 0: # got login - vFPC start succeeded!
                self.logger.info("vFPC successfully started")
                self.running = True
            if ridx == 1: # vFPC start failed - restart it
                self.logger.info("vFPC start failed, restarting")
                self.stop()
                self.start()
        if res != b'':
            pass
            #self.logger.trace("OUTPUT VFPC: %s" % res.decode())

        return



class VMX(vrnetlab.VR):
    """ Juniper vMX router
    """

    def __init__(self, username, password, custom_config=False):
        self.version = None
        self.version_info = []
        self.read_version()

        super(VMX, self).__init__(username, password)

        self.vms = [VMX_vcp(username, password, "/vmx/" + self.vcp_image, custom_config=custom_config),
                    VMX_vfpc(self.version)]

        # set up bridge for connecting VCP with vFPC
        vrnetlab.run_command(["brctl", "addbr", "int_cp"])
        vrnetlab.run_command(["ip", "link", "set", "int_cp", "up"])


    def read_version(self):
        for e in os.listdir("/vmx/"):
            m = re.search("-(([0-9][0-9])\.([0-9])([A-Z])([0-9]+)\.([0-9]+))", e)
            if m:
                self.vcp_image = e
                self.version = m.group(1)
                self.version_info = [int(m.group(2)), int(m.group(3)), m.group(4), int(m.group(5)), int(m.group(6))]


class VMX_installer(VMX):
    """ VMX installer

        Will start the VMX VCP and then shut it down. Booting the VCP for the
        first time requires the VCP itself to load some config and then it will
        restart. Subsequent boots will not require this restart. By running
        this "install" when building the docker image we can decrease the
        normal startup time of the vMX.
    """
    def __init__(self, username, password):
        self.version = None
        self.version_info = []
        self.read_version()

        super(VMX, self).__init__(username, password)

        self.vms = [ VMX_vcp(username, password, "/vmx/" + self.vcp_image, install_mode=True) ]

    def install(self):
        self.logger.info("Installing VMX")
        vcp = self.vms[0]
        while not vcp.running:
            vcp.work()

        # wait for system to shut down cleanly
        for i in range(0, 600):
            time.sleep(1)
            try:
                vcp.p.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            except Exception as exc:
                # assume it's dead
                self.logger.info("Can't communicate with qemu process, assuming VM has shut down properly." + str(exc))
                break

            try:
                (ridx, match, res) = vcp.tn.expect([b"Powering system off"], 1)
                if res != b'':
                    self.logger.trace("OUTPUT VCP: %s" % res.decode())
            except Exception as exc:
                # assume it's dead
                self.logger.info("Can't communicate over serial console, assuming VM has shut down properly." + str(exc))
                break

        vcp.stop()
        self.logger.info("Installation complete")



if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--trace', action='store_true', help='enable trace level logging')
    parser.add_argument('--username', default='vrnetlab', help='Username')
    parser.add_argument('--password', default='VR-netlab9', help='Password')
    parser.add_argument('--install', action='store_true', help='Install vMX')
    parser.add_argument('--custom_config', action='store_true', help='Does user have custom router configuration file')
    args = parser.parse_args()

    LOG_FORMAT = "%(asctime)s: %(module)-10s %(levelname)-8s %(message)s"
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger()

    logger.setLevel(logging.DEBUG)
    if args.trace:
        logger.setLevel(1)

    if args.install:
        vr = VMX_installer(args.username, args.password)
        vr.install()
    else:
        vr = VMX(args.username, args.password, custom_config=args.custom_config)
        vr.start()
