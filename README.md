ka9q_hpsdr translates ka9q-radio channel data in to protocol2 hpsdr
data and sent via ethernet UDP packets. Protocol2 is defined in this
document: https://github.com/TAPR/OpenHPSDR-Firmware/blob/master/Protocol%202/Documentation/openHPSDR%20Ethernet%20Protocol%20v4.3.pdf

ka9q_hpsdr currently supports up to 8 receiver channels from ka9q-radio
defined by MAX_RCVRS. Could handle more depending on the host CPU.
I put this together to be able to use my RX-888Mk2 for CW skimming.

Hopefully this program will help RX888 owners run hpsdr friendly programs
that can handle multiple receiver slices for skimming cw, ft8, and other modes.

Examples:

https://www.sparksdr.com

https://www.dxatlas.com/SkimServer

https://www.dxatlas.com/RttySkimServ

https://github.com/g0orx/linhpsdr

https://github.com/ramdor/Thetis/releases

https://github.com/dl1ycf/pihpsdr

A sample configuration file 'radiod@rx888-hf.conf' is included for an RX888.

I run ka9q_hpsdr on the same PC as ka9q-radio and in a top level directory along
side ka9q-radio. If ka9q-radio isn't in an adjacent directory, needed source
code from ka9q-radio is used from the ALT_SRC directory.

I made a small patch that modifies rx888.c to write 16k of raw ADC samples
every 66ms to a ramdisk. That data is then used by ka9q_hpsdr to provide a
wideband spectrum for HPSDR programs which implement it. It would be much
better to send it in multicast once I figure out how to do that.

cd ../ka9q-radio

cat ../ka9q_hpsdr/ka9q-radio_wideband.patch | patch -p1

make; make install

I've been using the built-in tool 'tune' and 'pcmrecord --stdout' and executing
them in code from posix spawn, but recently I put in code to control and grab the
IQ data using sockets. It seems to be stable now but you can also build for using
the older method by:

make USE_INSTALLED_TOOLS=1

Issues:
Rarely I have seen that when initializing the channel, the high and low filters
get set to 5KHz and -5KHz. I'm guessing that the control packet with the proper
settings didn't make it to ka9q-radio.

If you can suggest improvements or find bugs please post something to the Issues
tab on https://github.com/n1gp/ka9q_hpsdr
