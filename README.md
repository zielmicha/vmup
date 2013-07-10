vmup
====

Easily create virtual machines with Debian.

Download system image:

    sudo ./vmup.py

Create VM vm1 in profile test:

    ./vmup.py test add vm1

Bring it up:

    sudo ./vmup.py test up vm1

Bring it down:

    ./vmup.py test down vm1

Show DHCP config for your machines:

    ./vmup.py test dhcpd
