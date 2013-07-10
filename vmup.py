#!/usr/bin/env python2
import urllib
import json
import random
import subprocess
import hashlib
import os
import sys
import tempfile

from subprocess import check_call as call

MIRROR = 'http://user.zielm.com/vmup.json'
HOME = os.path.expanduser('~/.vmup')
VMUP_APT_PROXY = os.environ.get('VMUP_APT_PROXY')

def get_resource_meta(name):
    data = json.load(urllib.urlopen(MIRROR))
    return random.choice(data[name]['sources']), data[name]['sha256']

def fetch_resource(name, dest):
    url, sha256 = get_resource_meta(name)
    try:
        call(['wget', url, '-O', dest])
        if hash_file(dest, hashlib.sha256) != sha256:
            raise Exception('invalid hash of downloaded file (%r from %r)' % (dest, url))
    except:
        if os.path.exists(dest):
            os.remove(dest)
        raise

def hash_file(filename, func):
    state = func()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(8192), ''):
            state.update(block)
    return state.hexdigest()

def check_fetched(name):
    path = os.path.join(HOME, name)
    if not os.path.exists(path):
        fetch_resource(name, path)

def prepare():
    if not os.path.exists(HOME):
        os.mkdir(HOME)
    check_fetched('system')
    check_fetched('kernel')
    check_fetched('initrd')
    if not os.path.exists(HOME + '/system_custom'):
        setup_custom()

def setup_custom():
    if os.getuid() != 0:
        sys.exit('Run vmup as root (only once) to add your key to image, '
                 'but with HOME set to your home directory (preferably using sudo)')

    password = os.urandom(6).encode('hex')
    pass_path = HOME + '/password'
    with open(pass_path, 'w') as f:
        f.write('root:%s\n' % password)

    print 'decompressing system image...'
    call(['zcat', HOME + '/system'], stdout=open(HOME + '/system_making', 'wb'))

    mnt = tempfile.mkdtemp()
    call(['mount', HOME + '/system_making', mnt])

    chroot = ['unshare', '-ui', '--', 'chroot', mnt]
    print 'updating APT...'
    call(chroot + ['apt-get', 'update'])
    print 'installing SSH...'
    call(chroot + ['apt-get',
          '-y', '--force-yes', 'install', 'openssh-server', 'debian-keyring'])
    print 'adding your SSH public key and setting password...'
    os.mkdir(mnt + '/root/.ssh')
    with open(mnt + '/root/.ssh/authorized_keys', 'w') as f:
        f.write(open(os.path.expanduser('~/.ssh/id_rsa.pub')).read())
    call(chroot + ['chpasswd'], stdin=open(pass_path))
    print 'configuring...'
    with open(mnt + '/etc/network/interfaces', 'a') as f:
        f.write('\n\nauto eth0\niface eth0 inet dhcp\n')
    if VMUP_APT_PROXY:
        with open(mnt + '/etc/apt/apt.conf', 'w') as f:
            f.write('Acquire::http::proxy=%s' % VMUP_APT_PROXY)
    call(['umount', mnt])
    call(['rmdir', mnt])
    call(['mv', HOME + '/system_making', HOME + '/system_custom'])
    print 'setup done'

def help():
    sys.exit('''Usage: vmup <profile_name> <command> args
Commands:

    up - bring up all VMs from profile
    down - bring down all VMs from profile
    list - list VMs from profile
    dhcpd - create dhpcd config
    up <name> - bring up VM
    down <name> - bring down VM
    add <name> - create new VM
    del <name> - delete VM and all its data
    daemon <name> - run VM without forking
    fixhostname <name> - fixes /etc/hostname of VM''')

def accept_noarg(func):
    def wrapper(profile, arg=None):
        if not arg:
            path = prepare_profile(profile)
            for name, description in get_vms(path):
                func(profile, name)
        else:
            return func(profile, arg)

    return wrapper

def cmdline_add(profile, name):
    path = prepare_profile(profile)
    vm = path + '/' + name
    if os.path.exists(vm + '.json'):
        sys.exit('Error: machine %r already exists' % name)
    number = profile_get(path, 'counter', 0)
    profile_set(path, 'counter', number + 1)
    write_json(vm + '.json', {'mac': make_mac(), 'number': number})
    backing_file = os.path.abspath(HOME + '/system_custom')
    subprocess.check_call(['qemu-img', 'create', '-f', 'qcow2',
                           '-o', 'backing_file=' + backing_file,
                           vm + '.qcow2'])

def cmdline_dhcpd(profile, choose_name=None):
    path = prepare_profile(profile)
    tpl = 'host %(name)s {\n\thardware ethernet %(mac)s;\n\tfixed-address %(ip)s;\n}'

    for name, description in get_vms(path):
        if choose_name is None or name == choose_name:
            ip = get_ip(path, description['number'])
            print tpl % {'ip': ip, 'mac': description['mac'], 'name': name}

def get_ip(path, number):
    first_ip = profile_get(path, 'first_ip')
    first_ip_a, first_ip_b = first_ip.rsplit('.', 1)
    first_ip_b = int(first_ip_b)
    ip = '%s.%d' % (first_ip_a, first_ip_b + number)
    return ip

@accept_noarg
def cmdline_fixhostname(profile, name):
    path = prepare_profile(profile)
    data = json.load(open(path + '/' + name + '.json'))
    ip = get_ip(path, data['number'])
    print name
    call(['ssh', ip, '-l', 'root', '-o', 'StrictHostKeyChecking=no',
          'sh', '-c', 'echo %s > /etc/hostname; reboot' % name])

def cmdline_del(profile, name, really=None):
    path = prepare_profile(profile)
    vm = path + '/' + name
    if really != '--yes':
        sys.exit('Use: vmup %s del %s --yes' % (profile, name))
    os.remove(vm + '.json')
    os.remove(vm + '.qcow2')

def cmdline_list(profile):
    path = prepare_profile(profile)
    print '      name                 mac                  alive'
    for name, description in get_vms(path):
        mac = description['mac']
        alive = is_alive(path + '/' + name)
        print '% 5d %s %s %s' % (description['number'], name.ljust(20), mac.ljust(20), 'yes' if alive else 'no')

def is_alive(vm):
    return stop_daemon(vm, signal=0, user=False)

@accept_noarg
def cmdline_up(profile, name):
    check_br0()
    path = prepare_profile(profile)
    vm = path + '/' + name
    stop_daemon(vm)
    if os.fork() == 0:
        fd0 = open('/dev/null', 'w+')
        os.dup2(fd0.fileno(), 0)
        os.dup2(fd0.fileno(), 1)
        os.dup2(fd0.fileno(), 2)
        os.setsid()
        if os.fork() == 0:
            run_daemon(vm)
        else:
            os._exit(0)

@accept_noarg
def cmdline_down(profile, name):
    check_br0()
    path = prepare_profile(profile)
    vm = path + '/' + name
    stop_daemon(vm)

def cmdline_daemon(profile, name):
    check_br0()
    path = prepare_profile(profile)
    vm = path + '/' + name
    stop_daemon(vm)
    run_daemon(vm)

def check_br0():
    if subprocess.call('ip link | grep -q ": br0:"', shell=True) == 1:
        sys.exit('''You don't have bridge br0 configured.
Add the following to /etc/network/interfaces (Debian/Ubuntu, even if you use Network Manager)

iface eth0 inet manual
        up ifconfig eth1 promisc up
        down ifconfig eth1 promisc down

auto br0
iface br0 inet dhcp
        bridge_ports eth0

And restart network:

service networking restart''')

def stop_daemon(vm, signal=15, user=True):
    path = vm + '.pid'
    if os.path.exists(path):
        try:
            pid = open(path).read().strip()
            os.kill(int(pid), signal)
            if signal in (15, 9):
                os.remove(path)
            return True
        except (IOError, OSError) as err:
            if user:
                print 'cannot kill previous VM:', err
            else:
                return False
    else:
        return False

def run_daemon(vm):
    description = json.load(open(vm + '.json'))
    with open(vm + '.pid', 'w') as f:
        f.write('%d\n' % os.getpid())
    try:
        daemon(disk=vm + '.qcow2', mac=description['mac'])
    finally:
        os.remove(vm + '.pid')

def daemon(disk, mac):
    proc = subprocess.Popen(['qemu-system-x86_64', disk,
                             '-net', 'nic,macaddr=%s,model=virtio' % mac,
                             '-net', 'tap,name=br0',
                             '-kernel', HOME + '/kernel',
                             '-initrd', HOME + '/initrd',
                             '-machine', 'accel=kvm', '-enable-kvm', '-nographic',
                             '-append', 'root=/dev/sda quiet'])
    proc.wait()

def get_vms(path):
    vms = [ (name[:-5], json.load(open(path + '/' + name)))
              for name in os.listdir(path) if name.endswith('.json') ]
    return sorted( vms, key=lambda (name, description): description['number'] )

def write_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f)
        f.write('\n')

def make_mac():
    return '52:54:00:' + ':'.join( os.urandom(1).encode('hex') for i in xrange(3) )

def prepare_profile(name):
    path = HOME + '/' + name
    if not os.path.exists(path):
        os.mkdir(path)
        with open(path + '/profile', 'w') as f:
            f.write('{}')
        profile_set(path, 'counter', 0)
        profile_set(path, 'first_ip', '192.168.16.70')
    return path

def profile_get(path, name, default=None):
    return json.load(open(path + '/profile')).get(name, default)

def profile_set(path, name, val):
    conf = json.load(open(path + '/profile'))
    conf[name] = val
    write_json(path + '/profile', conf)

def main():
    if not sys.argv[2:]: return help()
    func = 'cmdline_' + sys.argv[2]
    if func not in globals():
        return help()
    globals()[func](sys.argv[1], *sys.argv[3:])
    return 0

if __name__ == '__main__':
    prepare()
    sys.exit(main())
