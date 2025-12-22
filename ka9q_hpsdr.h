#ifndef _KA9Q_HPSDR_H
#define _KA9Q_HPSDR_H

/* Copyright (C)
*
*   11/2025 - Rick Koch, N1GP
*
*   This program is free software: you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation, either version 3 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*
*/

#include <sched.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <termios.h>
#include <libgen.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <complex.h>
#include <sys/wait.h>

#ifndef USE_INSTALLED_TOOLS
#include "status.h"
#include "radio.h"
#else
#include <spawn.h>
#endif

#define HERMES_FW_VER 18
#define MAX_BUFFER_LEN 2048
#define HPSDR_FRAME_LEN 1032
#define IQ_FRAME_DATA_LEN 63
#define IQ_BUF_COUNT 1024
#define MAX_RCVRS 8
#define IQ_FRAME_DATA_LEN 63
#define MAXSTR 128
#define HERMES 1
#define HERMES_LITE 6
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

struct main_cb {
    u_int rcvrs_mask;
    int nsamps_packet;

    // the last array member is used to remember last settings
    int att;
    int gain;
    int wideband;
    int num_rxs;
    char data_maddr[128];
    char control_maddr[128];

    struct timespec freq_ltime[MAX_RCVRS];
    struct timespec freq_ttime[MAX_RCVRS];

    struct rcvr_cb {
        int rcvr_num;
        u_int err_count;
        int new_freq;
        int curr_freq;
        int output_rate;
        u_int ssrc;
        u_int rcvr_mask;
        float scale;
        struct main_cb* mcb;

        int iqSample_offset;
        int iqSamples_remaining;
        float complex iqSamples[IQ_BUF_COUNT + IQ_FRAME_DATA_LEN * 2];

#ifndef USE_INSTALLED_TOOLS
        int mStatus_sock;
        int mControl_sock;
        int mInput_fd;
        uint8_t mbuffer[PKTSIZE];
        uint8_t *mdp;
        int mbufferLen;
        int mbufferOffset;
#endif
    } rcb[MAX_RCVRS];
};

void load_packet(struct rcvr_cb* rcb);
void sdr_sighandler(int signum);
void hpsdrsim_stop_threads(void);
int new_protocol_running(void);
void new_protocol_general_packet(unsigned char *buffer);

//
// message printing
//
#include <stdarg.h>
void t_print(const char *format, ...);
void t_perror(const char *string);

#endif // _KA9Q_HPSDR_H
