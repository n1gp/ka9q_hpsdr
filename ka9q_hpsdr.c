/* Copyright (C)
*   11/2025 - Rick Koch, N1GP
*   Wrote ka9q_hpsdr with the help of various open sources on the internet.
*     Christoph v. Wüllen, https://github.com/dl1ycf/pihpsdr
*     John Melton, https://github.com/g0orx/linhpsdr
*     Phil Karn, https://github.com/ka9q/ka9q-radio
*
*   It uses HPSDR Protocol-2 defined here:
*     https://github.com/TAPR/OpenHPSDR-Firmware/blob/master/Protocol%202/Documentation/openHPSDR%20Ethernet%20Protocol%20v4.3.pdf
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

/*
 * This program simulates an HPSDR Hermes board with 8 receiver slices
 * using multicast data from ka9q-radio. Currently it expects ka9q-radio
 * to be setup and using an RX-888 (MkII) SDR but I've tested an RTL Blog V4
 * and it seems to work.
 */

#include "ka9q_hpsdr.h"

static int do_exit = 0;
struct main_cb mcb;
static int sock_udp;
static int hp_sock;
static int interface_offset = 0;

static u_int send_flags = 0;
static u_int done_send_flags = 0;
static pthread_mutex_t send_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t send_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t done_send_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t done_send_cond = PTHREAD_COND_INITIALIZER;

static int running = 0;
static bool gen_rcvd = false;
static bool wbenable = false;
static int wide_len;
static int wide_size;
static int wide_rate;
static int wide_ppf;

static struct sockaddr_in addr_new;

// protocol2 stuff
static int bits = -1;
static long rxfreq[MAX_RCVRS] = {0,};
static int ddcenable[MAX_RCVRS] = {0,};
static int rxrate[MAX_RCVRS] = {0,};
static int adcdither = -1;
static int adcrandom = -1;
static int stepatt0 = -1;
static int ddc_port = 1025;
static int mic_port = 1026;
static int hp_port = 1027; // also wb_port
static int ddc0_port = 1035;
static unsigned char pbuf[MAX_RCVRS][238*6];

static pthread_t sendiq_thread_id[MAX_RCVRS];
static pthread_t highprio_thread_id = 0;
static pthread_t ddc_specific_thread_id = 0;
static pthread_t mic_thread_id = 0;
static pthread_t wb_thread_id = 0;
static pthread_t rx_thread_id[MAX_RCVRS] = {0,};
static void   *highprio_thread(void*);
static void   *ddc_specific_thread(void*);
static void   *mic_thread(void *);
static void   *wb_thread(void *);
static void   *rx_thread(void *);

// using clock_nanosleep of librt
extern int clock_nanosleep(clockid_t __clock_id, int __flags,
                           __const struct timespec *__req,
                           struct timespec *__rem);

void send_tune(struct rcvr_cb *rcb)
{
    FILE *fp;
    char cmd[384];
    char buffer[384];
    char *bptr;
    bool retry = false;
    int i, number, retrycnt = 0;

    void extract_num(char *numstr) {
        char tempstr[64];
        number = 0;
        for (i = 0; i < strlen(numstr); i++) {
            if (numstr[i] == '.') {
                tempstr[number++] = '\0';
                break;
            }
            if (numstr[i] >= '0' && numstr[i] <= '9')
                tempstr[number++] = numstr[i];
        }
        tempstr[number] = '\0';
        number = atoi(tempstr);
    }

    // retry sending this cmd if ka9q-radio reports a mismatch
    do {
        sprintf (cmd, "tune -s %d -f %d -m iq -e F32LE -R %d -L %d -H %d --rfatten %d -g %d %s",
                 rcb->ssrc, rcb->curr_freq, rcb->output_rate+((rxrate[rcb->rcvr_num] > 192)?100:0),
                 (int)(rcb->output_rate * -0.49), (int)(rcb->output_rate * 0.49),
                 mcb.att, mcb.gain, mcb.control_maddr);

        t_print("Command: %s\n", cmd);

        fp = popen(cmd, "r");
        if (fp == NULL) {
            t_perror("popen failed");
            return;
        }

        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            if((bptr = strstr(buffer, "Preset")) != NULL) {
                if (strncmp(bptr+7, "iq", 2)) retry = true;
            }
            if((bptr = strstr(buffer, "Sample rate")) != NULL) {
                sscanf(bptr+12, "%s", cmd);
                extract_num(cmd);
                if (number != rcb->output_rate) retry = true;
            }
            if((bptr = strstr(buffer, "Encoding")) != NULL) {
                if (strncmp(bptr+9, "f32le", 5)) retry = true;
            }
            if((bptr = strstr(buffer, "Frequency")) != NULL) {
                sscanf(bptr+10, "%s", cmd);
                extract_num(cmd);
                if (number != rcb->curr_freq) retry = true;
            }
            if((bptr = strstr(buffer, "Channel Gain")) != NULL) {
                sscanf(bptr+13, "%s", cmd);
                extract_num(cmd);
                if (number != mcb.gain) retry = true;
            }
            if((bptr = strstr(buffer, "RF Atten")) != NULL) {
                sscanf(bptr+9, "%s", cmd);
                extract_num(cmd);
                if (number != mcb.att) retry = true;
            }
        }

        if (retry) {
            retry = false;
            retrycnt++;
            t_print("Retrying send_tune() for rx%d\n", rcb->rcvr_num);
        } else retrycnt--;

        int status = pclose(fp);
        if (status == -1) {
            t_perror("pclose failed");
        }
    } while (retrycnt > 0 && retrycnt < 3);
}

const char *App_path;

void setupStream(struct rcvr_cb *rcb)
{
    rcb->mInput_fd = setup_mcast_in(NULL, NULL,mcb.data_maddr, NULL, 0, 0);
    if (rcb->mInput_fd == -1) {
        t_print("mInput_fd == -1\n");
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    if (setsockopt(rcb->mInput_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        t_print("setsockopt() error\n");
    }
}

int readStream(float *buffs, const size_t numElems, struct rcvr_cb *rcb)
{
    int mbytesPerSample = 4; // floats

    char *out = (char *) &buffs[0];

    struct sockaddr sender;
    socklen_t socksize = sizeof(sender);

    int nRead = 0;

    while (nRead < numElems) {
        int toCopy = MIN((rcb->mbufferLen - rcb->mbufferOffset) / (2 * mbytesPerSample), (int)(numElems - nRead));
        if (toCopy > 0) {
            int copyBytes = 2 * toCopy * mbytesPerSample;
            memcpy(out, rcb->mdp, copyBytes);
            out += copyBytes;
            rcb->mdp += copyBytes;
            rcb->mbufferOffset += copyBytes;
            nRead += toCopy;
        } else {
            int size = recvfrom(rcb->mInput_fd, rcb->mbuffer, sizeof(rcb->mbuffer), 0, &sender, &socksize);
            if (size == -1 || size < RTP_MIN_SIZE) {
                continue;
            }

            struct rtp_header rtp;
            uint8_t *dp = (uint8_t *)ntoh_rtp(&rtp, rcb->mbuffer);

            if(rtp.ssrc != rcb->ssrc) {
                continue;
            }

            size -= dp - rcb->mbuffer;
            if (rtp.pad) {
                // Remove padding
                size -= dp[size-1];
                rtp.pad = 0;
            }

            if(size <= 0) {
                t_print("size <= 0\n");
                continue;
            }

            rcb->mdp = dp;
            rcb->mbufferLen = size;
            rcb->mbufferOffset = 0;
        }
    }
    return nRead;
}

uint64_t get_posix_clock_time_us()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)(ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
    } else {
        return 0; // Error handling
    }
}

void sdr_sighandler (int signum)
{
    t_print ("Signal:%d caught, exiting!\n", signum);
    do_exit = 1;
    running = 0;
    usleep(700000);
    for (int i = 0; i < mcb.num_rxs; i++) {
        mcb.rcb[i].curr_freq = 0;
        send_tune(&mcb.rcb[i]);
    }
}

char *time_stamp ()
{
    char *timestamp = (char *) malloc (sizeof (char) * 16);
    time_t ltime = time (NULL);
    struct tm *tm;

    tm = localtime (&ltime);
    sprintf (timestamp, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
    return timestamp;
}

void *sendiq_thread (void *arg)
{
    int samps_packet = 238;
    ssize_t num_samps = 0;
    struct rcvr_cb *rcb = (struct rcvr_cb *) arg;
    int count = 512;
    float data_buffer[2048];

    rcb->iqSample_offset = rcb->iqSamples_remaining = 0;
    rcb->err_count = 0;
    t_print("Starting sendiq_thread(%d)\n", rcb->rcvr_num);

    send_tune(rcb);
    setupStream(rcb);
    while (!do_exit) {
        if (!ddcenable[rcb->rcvr_num]) {
            usleep(50000);
            continue;
        }

        num_samps = readStream(data_buffer, count, rcb);
        if (num_samps != count) continue;
        num_samps = count;

        for (int i = 0; i < num_samps; ++i) {
            float real = data_buffer[2*i] * rcb->scale;
            float imag = data_buffer[2*i+1] * rcb->scale;
            rcb->iqSamples[rcb->iqSamples_remaining + i] = (real + imag*_Complex_I);
        }

        // can happen when switching between rcvr numbers
        if (rcb->iqSamples_remaining < 0)
            rcb->iqSamples_remaining = 0;

        rcb->iqSamples_remaining += num_samps;

        while (rcb->iqSamples_remaining > samps_packet) {
            load_packet(rcb);
            rcb->iqSamples_remaining -= samps_packet;
            rcb->iqSample_offset += samps_packet;
        }

        // move remaining samples to beginning of buffer
        if ((rcb->iqSample_offset > 0) && (rcb->iqSamples_remaining > 0)) {
            memcpy (&(rcb->iqSamples[0]),
                    &(rcb->iqSamples[rcb->iqSample_offset]),
                    rcb->iqSamples_remaining * sizeof (float complex));
            rcb->iqSample_offset = 0;
        }
    }

    t_print("Ending sendiq_thread(%d)\n", rcb->rcvr_num);
    pthread_exit (NULL);
}

int find_net(char *find)
{
    DIR* dir;
    struct dirent* ent;
    char* endptr;

    if (!(dir = opendir("/sys/class/net"))) {
        perror("can't open /sys/class/net");
        return 0;
    }

    while((ent = readdir(dir)) != NULL) {
        if (!strcmp("print", find) && strcmp(".", ent->d_name) && strcmp("..", ent->d_name)) {
            printf("%s ", ent->d_name);
        } else if (!strcmp(ent->d_name, find)) {
            return 1;
        }
        if (*endptr != '\0') {
            continue;
        }
    }
    return 0;
}

int proc_find(char name[][16], char *find)
{
    DIR* dir;
    struct dirent* ent;
    char* endptr;
    int i, name_found = 0;
    char buf[512];

    if (!(dir = opendir("/proc"))) {
        perror("can't open /proc");
        return 0;
    }

    while((ent = readdir(dir)) != NULL) {
        long lpid = strtol(ent->d_name, &endptr, 10);
        if (*endptr != '\0') {
            continue;
        }

        snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
        FILE* fp = fopen(buf, "r");

        if (fp) {
            if (fgets(buf, sizeof(buf), fp) != NULL) {
                // check the first token in the file, the program name
                char* first = strtok(buf, "\0");
                if (strstr(first, find) != NULL) {
                    for (i = 0; i < sizeof(buf); i++) {
                        if (!strcmp(&buf[i], "-i")) {
                            strcpy(name[name_found], &buf[i+3]);
                            if (++name_found > MAX_PRGMS)
                                goto finishup;
                            break;
                        }
                    }
                }
            }
            fclose(fp);
        }
    }

finishup:
    closedir(dir);
    return name_found;
}
int main (int argc, char *argv[])
{
    uint8_t id[4] = { 0xef, 0xfe, 1, 6 };
    struct sockaddr_in addr_udp;
    struct sockaddr_in addr_from;
    socklen_t lenaddr;
    struct timeval tv;
    int yes = 1;
    int bytes_read;
    uint32_t i, code;
    u_char buffer[MAX_BUFFER_LEN];
    uint32_t *code0;
    int CmdOption;
    struct sigaction sigact;

    code0 = (uint32_t *) buffer;
    memset(&mcb, 0, sizeof(mcb));
    // set defaults
    mcb.gain = 60;
    mcb.att = 0;
    mcb.num_rxs = MAX_RCVRS;
    mcb.wideband = false;
    strcpy(mcb.data_maddr, "hf-iq.local");
    strcpy(mcb.control_maddr, "hf.local");

    while((CmdOption = getopt(argc, argv, "a:c:d:g:i:n:hw:")) != -1) {
        switch(CmdOption) {
        case 'h':
            printf("Usage: %s <optional arguments>\n", basename(argv[0]));
            printf("optional arguments:\n");
            printf("-a attenuation in 1/10's dB (default 0))\n");
            printf("-d data maddr (default hf-iq.local)\n");
            printf("-c control maddr (default hf.local))\n");
            printf("-g tuner gain in 1/10's dB (default 60))\n");
            printf("-h help (prints this usage)\n");
            printf("-i net interface (required)\n");
            printf("-n number of receiver slices (defaults to 8 max)\n");
            printf("-w enable wideband 0/1 (default is 0, disabled)\n");
            return EXIT_SUCCESS;
            break;

        case 'a':
            mcb.att = atoi (optarg);
            break;
        case 'c':
            strcpy (mcb.control_maddr, optarg);
            break;
        case 'd':
            strcpy (mcb.data_maddr, optarg);
            break;
        case 'g':
            mcb.gain = atoi (optarg);
            break;
        case 'i':
            strcpy (mcb.interface, optarg);
            break;
        case 'n':
            mcb.num_rxs = atoi (optarg);
            break;
        case 'w':
            mcb.wideband = atoi (optarg);
            break;
        }
    }
    printf("\n");

    int same_int = 0, prgms_found = 0;
    char myproc[MAX_PRGMS][16] = {0,};
    prgms_found = proc_find(myproc, "ka9q_hpsdr");
    if (prgms_found > MAX_PRGMS) {
        printf("These are already max: %d ka9q_hpsdr programs running.\n", MAX_PRGMS);
        return EXIT_FAILURE;
    }

    if (strlen(mcb.interface) == 0) {
        printf("Must use -i for net interface selection.\n");
        printf("These are the available interfaces:\n\t");
        find_net("print");
        printf("\n");
        return EXIT_FAILURE;
    }

#if 0
    if (strlen(mcb.interface) == 0) {
        FILE *pfd = popen("ip route get 1.1.1.1|awk '{print $5}'|tr -dc '[:alnum:]'", "r");
        if(pfd == NULL) {
            t_perror("Could not open pipe.\n");
            return EXIT_FAILURE;
        }
        if (fgets(mcb.interface, 15, pfd) == NULL)
            return EXIT_FAILURE;
        if (prgms_found > 1) {
            printf("Must use -i for virtual net interface selection.\n");
            printf("These are the available interfaces:\n\t");
            find_net("print");
            printf("\n");
            return EXIT_FAILURE;
        } else {
            strcpy(myproc[0], mcb.interface);
        }
    }
#endif

    if (find_net(mcb.interface) == 0) {
        printf("%s not found\n", mcb.interface);
        return EXIT_FAILURE;
    }

    // see how many different net interfaces these prgm's are
    // using and check before using the same one
    for (i = 0; i < prgms_found; i++) {
        if (!strcmp(myproc[i], mcb.interface))
            same_int++;
    }

    if (same_int > 1) {
        printf("interface %s already in use\n", mcb.interface);
        return EXIT_FAILURE;
    }

    if ((sock_udp = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        t_perror("socket");
        return EXIT_FAILURE;
    }

    if (prgms_found > 1) {
        interface_offset++;
        mcb.wideband = 0;
        if (setsockopt(sock_udp, SOL_SOCKET, SO_BINDTODEVICE,
                       mcb.interface, sizeof(mcb.interface)) < 0) {
            perror ("SO_BINDTODEVICE");
        }
    }

    struct ifreq hwaddr;
    memset(&hwaddr, 0, sizeof(hwaddr));
    strncpy(hwaddr.ifr_name, mcb.interface, IFNAMSIZ - 1);
    ioctl(sock_udp, SIOCGIFHWADDR, &hwaddr);

    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;

    // get the IP address of the desired interface
    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET) {
            sa = (struct sockaddr_in *) ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);
            if (!strcmp(mcb.interface, ifa->ifa_name)) {
                strcpy(mcb.ip, addr);
            }
        }
    }
    freeifaddrs(ifap);

    setsockopt(sock_udp, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof(yes));
    setsockopt(sock_udp, SOL_SOCKET, SO_REUSEPORT, (void *)&yes, sizeof(yes));
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    setsockopt(sock_udp, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
    memset(&addr_udp, 0, sizeof(addr_udp));
    addr_udp.sin_family = AF_INET;
    addr_udp.sin_addr.s_addr = htonl(INADDR_ANY);
    addr_udp.sin_port = htons(1024);

    if (bind(sock_udp, (struct sockaddr *)&addr_udp, sizeof(addr_udp)) < 0) {
        t_perror("main ERROR: bind");
        return EXIT_FAILURE;
    }

    if (pthread_create(&highprio_thread_id, NULL, highprio_thread, NULL) < 0) {
        t_perror("***** ERROR: Create HighPrio thread");
    }

    if (pthread_create(&ddc_specific_thread_id, NULL, ddc_specific_thread, NULL) < 0) {
        t_perror("***** ERROR: Create DDC specific thread");
    }

    if (pthread_create(&mic_thread_id, NULL, mic_thread, NULL) < 0) {
        t_perror("***** ERROR: Create MIC thread");
    }

    if (mcb.wideband) {
        if (pthread_create(&wb_thread_id, NULL, wb_thread, NULL) < 0) {
            t_perror("***** ERROR: Create WB thread");
        }
    }

    sigact.sa_handler = sdr_sighandler;
    sigemptyset (&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction (SIGINT, &sigact, NULL);
    sigaction (SIGTERM, &sigact, NULL);
    sigaction (SIGQUIT, &sigact, NULL);
    sigaction (SIGPIPE, &sigact, NULL);

    pthread_mutex_init (&send_lock, NULL);
    pthread_cond_init (&send_cond, NULL);
    pthread_mutex_init (&done_send_lock, NULL);
    pthread_cond_init (&done_send_cond, NULL);

    for (i = 0; i < mcb.num_rxs; i++) {
        mcb.rcb[i].mcb = &mcb;
        mcb.rcb[i].new_freq = 0;
        mcb.rcb[i].curr_freq = 10000000;
        mcb.rcb[i].output_rate = 192000;
        mcb.rcb[i].ssrc = i + 1 + (interface_offset * MAX_RCVRS);
        mcb.rcb[i].scale = 700.0f;

        mcb.rcb[i].rcvr_num = i;
        mcb.rcvrs_mask |= 1 << i;
        mcb.rcb[i].rcvr_mask = 1 << i;
        // this sets up the mcast stream so fire it off before starting the rx's
        if (pthread_create(&sendiq_thread_id[i], NULL, sendiq_thread, &mcb.rcb[i]) < 0) {
            t_perror("***** ERROR: Create sendiq_thread");
        }
    }

    t_print("Waiting on Discovery...\n");

    while (!do_exit) {
        memcpy(buffer, id, 4);
        lenaddr = sizeof(addr_from);
        bytes_read = recvfrom(sock_udp, buffer, HPSDR_FRAME_LEN, 0, (struct sockaddr *)&addr_from, &lenaddr);

        if (bytes_read < 0 && errno != EAGAIN) {
            t_perror("recvfrom");
            continue;
        }

        if (bytes_read <= 0) {
            continue;
        }

        code = *code0;

        /*
         * Here we have to handle the following "non standard" cases:
         * NewProtocol "Discovery" packet   60 bytes starting with 00 00 00 00 02
         * NewProtocol "General"   packet   60 bytes starting with 00 00 00 00 00
         *                                  ==> this starts NewProtocol radio
         */
        if (code == 0 && buffer[4] == 0x02 && !running) {
            t_print("NewProtocol discovery packet received from %s\n", inet_ntoa(addr_from.sin_addr));
            // prepare response
            memset(buffer, 0, 60);
            buffer [4] = 0x02 + running;
            for (i = 0; i < 6; ++i) buffer[i + 5] = hwaddr.ifr_addr.sa_data[i];
            buffer[11] = HERMES;
            buffer[12] = 38;
            buffer[13] = 18;
            buffer[20] = mcb.num_rxs;
            buffer[21] = 1;
            buffer[22] = 3;

            sendto(sock_udp, buffer, 60, 0, (struct sockaddr *)&addr_from, sizeof(addr_from));
            continue;
        }

        if (bytes_read == 60 && buffer[4] == 0x00) {
            // handle "general packet" of the new protocol
            memset(&addr_new, 0, sizeof(addr_new));
            addr_new.sin_family = AF_INET;
            addr_new.sin_addr.s_addr = addr_from.sin_addr.s_addr;
            addr_new.sin_port = addr_from.sin_port;
            new_protocol_general_packet(buffer);
            continue;
        }
    }

    close(sock_udp);

    return EXIT_SUCCESS;
}

void t_print(const char *format, ...)
{
    va_list(args);
    va_start(args, format);
    struct timespec ts;
    double now;
    static double starttime;
    static int first = 1;
    char line[1024];
    clock_gettime(CLOCK_MONOTONIC, &ts);
    now = ts.tv_sec + 1E-9 * ts.tv_nsec;

    if (first) {
        first = 0;
        starttime = now;
    }

    //
    // After 11 days, the time reaches 999999.999 so we simply wrap around
    //
    if (now - starttime >= 999999.995) {
        starttime += 1000000.0;
    }

    //
    // We have to use vsnt_print to handle the varargs stuff
    // g_print() seems to be thread-safe but call it only ONCE.
    //
    vsnprintf(line, 1024, format, args);
    printf("%10.6f %s", now - starttime, line);
}

void t_perror(const char *string)
{
    t_print("%s: %s\n", string, strerror(errno));
}

void load_packet (struct rcvr_cb *rcb)
{
    float complex *out_buf = &rcb->iqSamples[rcb->iqSample_offset];
    int i, j, IQData;
    int k = rcb->rcvr_num;

    pthread_mutex_lock (&done_send_lock);
    while (!(done_send_flags & rcb->rcvr_mask) && running) {
        pthread_cond_wait (&done_send_cond, &done_send_lock);
    }
    done_send_flags &= ~rcb->rcvr_mask;
    pthread_mutex_unlock (&done_send_lock);

    for (i = 0, j = 0; i < 238; i++, j+=6) {
        IQData = (int)cimagf(out_buf[i]);
        pbuf[k][j] = IQData >> 16;
        pbuf[k][j+1] = IQData >> 8;
        pbuf[k][j+2] = IQData & 0xff;
        IQData = (int)crealf(out_buf[i]);
        pbuf[k][j+3] = IQData >> 16;
        pbuf[k][j+4] = IQData >> 8;
        pbuf[k][j+5] = IQData & 0xff;
    }

    pthread_mutex_lock (&send_lock);
    send_flags |= rcb->rcvr_mask;
    pthread_cond_broadcast (&send_cond);
    pthread_mutex_unlock (&send_lock);
}

void new_protocol_general_packet(unsigned char *buffer)
{
    static unsigned long seqnum = 0;
    unsigned long seqold;
    int rc;

    gen_rcvd = true;

    seqold = seqnum;
    seqnum = (buffer[0] >> 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3];

    if ((seqnum != 0 && seqnum != seqold + 1 ) && seqold != 0) {
        t_print("GP: SEQ ERROR, old=%lu new=%lu\n", seqold, seqnum);
    }

    if (mcb.wideband) {
        rc = buffer[23] & 1;
        if (rc != wbenable) {
            wbenable = rc;
            t_print("GP: Wideband Enable Flag is %d\n", wbenable);
        }

        rc = (buffer[24] << 8) + buffer[25];
        if (rc != wide_len) {
            wide_len = rc;
            t_print("GP: WideBand Length is %d\n", rc);
        }

        rc = buffer[26];
        if (rc != wide_size) {
            wide_size = rc;
            t_print("GP: Wideband sample size is %d\n", rc);
        }

        rc = buffer[27];
        if (rc != wide_rate) {
            wide_rate = rc;
            t_print("GP: Wideband sample rate is %d\n", rc);
        }

        rc = buffer[28];
        if (rc != wide_ppf) {
            wide_ppf = rc;
            t_print("GP: Wideband PPF is %d\n", rc);
        }
    }
}

void *highprio_thread(void *data)
{
    struct sockaddr_in addr;
    socklen_t lenaddr = sizeof(addr);
    unsigned long seqnum = 0, seqold;
    unsigned char hp_buffer[2000];
    struct timeval tv;
    int i, rc, yes = 1;
    long freq;

    hp_sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (hp_sock < 0) {
        t_perror("***** ERROR: HP: socket");
        return NULL;
    }

    setsockopt(hp_sock, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof(yes));
    setsockopt(hp_sock, SOL_SOCKET, SO_REUSEPORT, (void *)&yes, sizeof(yes));
    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    setsockopt(hp_sock, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = (interface_offset > 0) ? inet_addr(mcb.ip) : htonl(INADDR_ANY);
    addr.sin_port = htons(hp_port);

    if (bind(hp_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        t_perror("highprio_thread ERROR: bind");
        close(hp_sock);
        return NULL;
    }

    t_print("Starting highprio_thread()\n");
    while (!do_exit) {
        if (!running) seqnum = 0;

        rc = recvfrom(hp_sock, hp_buffer, 1444, 0, (struct sockaddr *)&addr, &lenaddr);

        if (rc < 0 && errno != EAGAIN) {
            t_perror("***** ERROR: HighPrio thread: recvmsg");
            break;
        }

        if (rc < 0) {
            continue;
        }

        if (rc != 1444) {
            t_print("Received HighPrio packet with incorrect length %d\n", rc);
            break;
        }

        seqold = seqnum;
        seqnum = (hp_buffer[0] >> 24) + (hp_buffer[1] << 16) + (hp_buffer[2] << 8) + hp_buffer[3];

        if ((seqnum != 0 && seqnum != seqold + 1 ) && seqold != 0) {
            t_print("HP: SEQ ERROR, old=%lu new=%lu\n", seqold, seqnum);
        }

        for (i = 0; i < mcb.num_rxs; i++) {
            freq = (hp_buffer[ 9 + 4 * i] << 24) + (hp_buffer[10 + 4 * i] << 16) + (hp_buffer[11 + 4 * i] << 8) + hp_buffer[12 + 4 * i];

            if (bits & 0x08) {
                freq = round(122880000.0 * (double) freq / 4294967296.0);
            }

            if (freq != rxfreq[i]) {
                mcb.rcb[i].new_freq = rxfreq[i] = freq;
                //t_print("HP: DDC%d freq: %lu\n", i, freq);
            }
        }

        rc = hp_buffer[5] & 0x01;
        if (rc != adcdither) {
            adcdither = rc;
            //t_print("RX: ADC dither=%d\n", adcdither);
        }

        rc = hp_buffer[6] & 0x01;
        if (rc != adcrandom) {
            adcrandom = rc;
            //t_print("RX: ADC random=%d\n", adcrandom);
        }

        rc = hp_buffer[1443];
        if (rc != stepatt0) {
            stepatt0 = rc;
            //t_print("HP: StepAtt0 = %d\n", stepatt0);
        }

        rc = hp_buffer[4] & 0x01;
        if (rc != running) {
            running = rc;
            t_print("HP: Running = %d\n", rc);
            if (!running) {
                for (i = 0; i < mcb.num_rxs; i++) {
                    ddcenable[i] = 0;
                    mcb.rcb[i].rcvr_mask = 0;
                    rxrate[i] = 0;
                    rxfreq[i] = 0;
                }
            } else {
                for (i = 0; i < mcb.num_rxs; i++) {
                    if (rx_thread_id[i] == 0) {
                        if (pthread_create(&rx_thread_id[i], NULL, rx_thread, (void *) (uintptr_t) i) < 0) {
                            t_perror("***** ERROR: Create RX thread");
                        }
                    }
                }
            }
        }
    }

    t_print("Ending highprio_thread()\n");
    close(hp_sock);
    return NULL;
}

void *ddc_specific_thread(void *data)
{
    int sock;
    struct sockaddr_in addr;
    socklen_t lenaddr = sizeof(addr);
    unsigned long seqnum, seqold;
    struct timeval tv;
    unsigned char ddc_buffer[2000];
    int yes = 1;
    int rc;
    int i;

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        t_perror("***** ERROR: ddc_specific_thread: socket");
        return NULL;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof(yes));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&yes, sizeof(yes));
    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = (interface_offset > 0) ? inet_addr(mcb.ip) : htonl(INADDR_ANY);
    addr.sin_port = htons(ddc_port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        t_perror("ddc_specific_thread ERROR: bind");
        close(sock);
        return NULL;
    }

    seqnum = 0;

    t_print("Starting ddc_specific_thread()\n");
    while (!do_exit) {
        if (!running) {
            seqnum = 0;
            usleep(50000);
            continue;
        }

        rc = recvfrom(sock, ddc_buffer, 1444, 0, (struct sockaddr *)&addr, &lenaddr);
        if (rc < 0 && errno != EAGAIN) {
            t_perror("***** ERROR: DDC specific thread: recvmsg");
            break;
        }

        if (rc < 0) {
            continue;
        }

        if (rc != 1444) {
            t_print("RXspec: Received DDC specific packet with incorrect length");
            break;
        }

        seqold = seqnum;
        seqnum = (ddc_buffer[0] >> 24) + (ddc_buffer[1] << 16) + (ddc_buffer[2] << 8) + ddc_buffer[3];

        if ((seqnum != 0 && seqnum != seqold + 1 ) && seqold != 0) {
            t_print("RXspec: SEQ ERROR, old=%lu new=%lu\n", seqold, seqnum);
        }

        for (i = 0; i < mcb.num_rxs; i++) {
            int modified = 0;
            struct rcvr_cb *rcb = &mcb.rcb[i];

            rc = (ddc_buffer[18 + 6 * i] << 8) + ddc_buffer[19 + 6 * i];
            if (rc != rxrate[i] && rc != 0) {
                rxrate[i] = rc;
                mcb.rcb[i].output_rate = (rxrate[i] * 1000);
                modified = 1;

                switch(rxrate[i]) {
                case 48:
                    mcb.rcb[i].scale = 8000.0f;
                    break;
                case 96:
                    mcb.rcb[i].scale = 6000.0f;
                    break;
                case 192:
                    mcb.rcb[i].scale = 4000.0f;
                    break;
                case 384:
                    mcb.rcb[i].scale = 3000.0f;
                    break;
                case 768:
                    mcb.rcb[i].scale = 1700.0f;
                    break;
                case 1536:
                    mcb.rcb[i].scale = 1000.0f;
                }

                send_tune(rcb);
            }

            rc = (ddc_buffer[7 + (i / 8)] >> (i % 8)) & 0x01;
            if (rc != ddcenable[i]) {
                modified = 1;
                ddcenable[i] = rc;
                mcb.rcb[i].rcvr_mask = 1 << i;
                if (ddcenable[i]) {
                    pthread_mutex_lock (&send_lock);
                    send_flags |= 1 << i;
                    pthread_cond_broadcast (&send_cond);
                    pthread_mutex_unlock (&send_lock);
                }
            }

            if (modified) {
                t_print("RX: DDC%d Enable=%d Rate=%d\n", i, ddcenable[i], rxrate[i]);
                rc = 0;
            }
        }
    }

    close(sock);
    ddc_specific_thread_id = 0;
    t_print("Ending ddc_specific_thread()\n");
    return NULL;
}

void *rx_thread(void *data)
{
    // One instance of this thread is started for each DDC
    int sock;
    struct sockaddr_in addr;
    unsigned long seqnum;
    unsigned char rx_buffer[1444];
    int myddc;
    int yes = 1;
    unsigned char *p;
    struct rcvr_cb *rcb;

    myddc = (int) (uintptr_t) data;
    rcb = &mcb.rcb[myddc];

    if (myddc < 0 || myddc >= mcb.num_rxs) {
        return NULL;
    }

    seqnum = 0;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        t_perror("***** ERROR: RXthread: socket");
        return NULL;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof(yes));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&yes, sizeof(yes));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = (interface_offset > 0) ? inet_addr(mcb.ip) : htonl(INADDR_ANY);
    addr.sin_port = htons(ddc0_port + myddc);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        t_perror("rx_thread ERROR: bind");
        close(sock);
        return NULL;
    }

    t_print("Starting rx_thread(%d)\n", myddc);
    while (!do_exit) {
        if (!gen_rcvd || ddcenable[myddc] <= 0 || rxrate[myddc] == 0 || rxfreq[myddc] == 0) {
            usleep(50000);
            seqnum = 0;
            continue;
        }

        p = rx_buffer;
        *(uint32_t*)p = htonl(seqnum++);
        p += 4;

        // no time stamps
        p += 9;

        *p++ = 24; // bits per sample
        *p++ = 0;
        *p++ = 238; // samps per packet

        pthread_mutex_lock (&send_lock);

        while (!(send_flags & rcb->rcvr_mask) && running) {
            pthread_cond_wait (&send_cond, &send_lock);
        }
        send_flags &= ~rcb->rcvr_mask;
        pthread_mutex_unlock (&send_lock);

        memcpy(p, &pbuf[myddc][0], 1428); // I-Q data

#if 0  // for debug
        if (seqnum > 1000 && myddc == 1) {
            t_print ("rcvrs_mask:%x send_flags:%d\n", mcb.rcvrs_mask, send_flags);

            for (int i = 0; i < 1444; i++) {
                printf("%4d:%2x ", i, rx_buffer[i]);

                if (!((i + 1) % 8))
                    printf("\n");
            }
            //exit(0);
        }
#endif

        if (sendto(sock, rx_buffer, 1444, 0, (struct sockaddr * )&addr_new, sizeof(addr_new)) < 0) {
            t_perror("***** ERROR: RX thread sendto");
            break;
        }

        pthread_mutex_lock (&done_send_lock);
        done_send_flags |= rcb->rcvr_mask;
        pthread_cond_broadcast (&done_send_cond);
        pthread_mutex_unlock (&done_send_lock);

        if (rcb->new_freq) {
            rcb->curr_freq = rcb->new_freq;
            send_tune(rcb);
            rcb->new_freq = 0;
        }
    }

    close(sock);
    t_print("Ending rx_thread(%d)\n", myddc);
    rx_thread_id[myddc] = 0;
    ddcenable[myddc] = 0;
    return NULL;
}

#define BIN_SAMPLE_CNT 32768

void *wb_thread(void *data)
{
    // NOTE: this thread reuses the hp_sock socket since two sockets
    //       can't send/recv on the same port/address (1027)
    unsigned long seqnum = 0;
    unsigned char wb_buffer[1028];
    uint8_t samples[BIN_SAMPLE_CNT];
    unsigned char *p;
    int i, j;
    FILE *bfile;
    char *filename = "/dev/shm/rx888wb.bin";
    size_t bytes_read;

    t_print("Starting wb_thread()\n");
    while (!do_exit) {
        if (!gen_rcvd || !running || !wbenable) {
            usleep(50000);
            continue;
        }

        bfile = fopen(filename, "rb");
        if (bfile != NULL) {
            bytes_read = fread(samples, 1, BIN_SAMPLE_CNT, bfile);
            if (bytes_read != 32768) {
                //t_print("%s, bytes_read:%ld bytes_wanted:%d\n",
                //       __FUNCTION__, bytes_read, BIN_SAMPLE_CNT);
                fclose(bfile);
                continue; // skip it and continue
            }
            seqnum = 0; // reset per frame
            fclose(bfile);

            // frame
            for (i = 0; i < 32; i++) {
                // update seq number
                p = wb_buffer;
                *(uint32_t*)p = htonl(seqnum++);
                p += 4;

                // packet
                for (j = 0; j < 1024; j+=2) { //swap bytes
                    wb_buffer[j+5] = samples[j + (i * 1024)];
                    wb_buffer[j+4] = samples[j + 1 + (i * 1024)];
                }

                if (sendto(hp_sock, wb_buffer, 1028, 0,
                           (struct sockaddr * )&addr_new, sizeof(addr_new)) < 0) {
                    t_perror("***** ERROR: WB thread sendto");
                    break;
                }
            }
            usleep(66000);
        } else {
            t_print("%s() filename: %s does not exist\n", __FUNCTION__, filename);
            break;
        }
    }

    t_print("Ending wb_thread()\n");
    return NULL;
}

//
// The microphone thread just sends silence, that is
// a "zeroed" mic frame every 1.333 msec and needs to
// be sent for some app's timing purposes.
//
void *mic_thread(void *data)
{
    int sock;
    unsigned long seqnum = 0;
    struct sockaddr_in addr;
    unsigned char mic_buffer[132];
    unsigned char *p;
    int yes = 1;
    struct timespec delay;
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0) {
        t_perror("***** ERROR: Mic thread: socket");
        return NULL;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof(yes));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (void *)&yes, sizeof(yes));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = (interface_offset > 0) ? inet_addr(mcb.ip) : htonl(INADDR_ANY);
    addr.sin_port = htons(mic_port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        t_perror("mic_thread ERROR: bind");
        close(sock);
        return NULL;
    }

    memset(mic_buffer, 0, 132);
    clock_gettime(CLOCK_MONOTONIC, &delay);

    t_print("Starting mic_thread()\n");
    while (!do_exit) {
        if (!gen_rcvd || !running) {
            usleep(500000);
            seqnum = 0;
            continue;
        }
        // update seq number
        p = mic_buffer;
        *(uint32_t*)p = htonl(seqnum++);
        p += 4;

        // 64 samples with 48000 kHz, makes 1333333 nsec
        delay.tv_nsec += 1333333;

        while (delay.tv_nsec >= 1000000000) {
            delay.tv_nsec -= 1000000000;
            delay.tv_sec++;
        }

        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &delay, NULL);

        if (sendto(sock, mic_buffer, 132, 0, (struct sockaddr * )&addr_new, sizeof(addr_new)) < 0) {
            t_perror("***** ERROR: Mic thread sendto");
            break;
        }
    }

    t_print("Ending mic_thread()\n");
    close(sock);
    return NULL;
}
