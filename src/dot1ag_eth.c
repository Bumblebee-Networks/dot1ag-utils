/*
 * Copyright (c) 2011
 * Author: Ronald van der Pol
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <fcntl.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>

#ifdef HAVE_NET_BPF_H
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if_dl.h>
#include <sys/types.h>
#else
#include <netpacket/packet.h>
#endif

#include "dot1ag_eth.h"
#include "ieee8021ag.h"

#ifdef HAVE_NET_BPF_H

char bpf_ifs[NR_BPF_IFS][BPF_IFS_MAXLEN] = {"/dev/bpf",  "/dev/bpf0",
                                            "/dev/bpf1", "/dev/bpf2",
                                            "/dev/bpf3", "/dev/bpf4"};

int get_local_mac(char *dev, uint8_t *ea) {
  struct ifaddrs *ifaddr, *ifa;
  struct sockaddr_dl *sdl;
  caddr_t addr;
  int i;

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) {
      continue;
    }
    if (strncmp(ifa->ifa_name, dev, sizeof(dev)) != 0) {
      continue; /* not the interface we are looking for */
    }
    sdl = (struct sockaddr_dl *)ifa->ifa_addr;
    if (sdl->sdl_family != AF_LINK) {
      continue; /* skip if this not a data link address */
    }
    addr = LLADDR(sdl);
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
      ea[i] = addr[i];
    }
    return 0;
  }
  freeifaddrs(ifaddr);
  /* interface not found, return -1 */
  return -1;
}

int send_packet(char *ifname, uint8_t *buf, int size) {
  int bpf;
  struct ifreq ifc;
  int complete_header = 1;
  int i;

  if (geteuid() != 0) {
    fprintf(stderr, "Execution requires superuser privilege.\n");
    exit(EXIT_FAILURE);
  }

  /* minimum size of Ethernet frames is ETHER_MIN_LEN octets */
  if (size < ETHER_MIN_LEN) {
    size = ETHER_MIN_LEN;
  }

  /* try to open BPF interfaces until it success */
  for (i = 0; i < NR_BPF_IFS; i++) {
    if ((bpf = open(bpf_ifs[i], O_RDWR)) == -1) {
      continue;
    } else {
      break;
    }
  }
  if (bpf == -1) {
    /* failed to open a BPF interface */
    return 0;
  }

  /* bind BPF to the outgoing interface */
  strncpy(ifc.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(bpf, BIOCSETIF, &ifc) > 0) {
    perror("BIOCSETIF");
    exit(EXIT_FAILURE);
  }
  /* tell BPF that frames contain an Ethernet header */
  if (ioctl(bpf, BIOCSHDRCMPLT, &complete_header) < 0) {
    perror("BIOCSHDRCMPLT");
    exit(EXIT_FAILURE);
  }
  if (write(bpf, buf, size) < 0) {
    perror("/dev/bpf");
    exit(EXIT_FAILURE);
  }
  close(bpf);
  return 0;
}

#else

int get_local_mac(char *dev, uint8_t *ea) {
  int s;
  int i;
  struct ifreq req;

  if (geteuid() != 0) {
    fprintf(stderr, "Execution requires superuser privilege.\n");
    exit(EXIT_FAILURE);
  }

  if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("opening socket");
    exit(EXIT_FAILURE);
  }

  /* get interface index */
  memset(&req, 0, sizeof(req));
  strncpy(req.ifr_name, dev, sizeof(req.ifr_name));

  /* get MAC address of interface */
  if (ioctl(s, SIOCGIFHWADDR, &req)) {
    perror(dev);
    exit(EXIT_FAILURE);
  }
  close(s);
  for (i = 0; i < ETH_ALEN; i++) {
    ea[i] = req.ifr_hwaddr.sa_data[i];
  }
  return 0;
}

int send_packet(char *ifname, uint8_t *buf, int size) {
  static int s = -1;
  static int ifindex = -1;
  static char current_ifname[IFNAMSIZ] = {0};
  struct ifreq req;
  struct sockaddr_ll addr_out;

  /* Ensure minimum Ethernet frame length */
  if (size < ETHER_MIN_LEN) {
    size = ETHER_MIN_LEN;
  }

  /* If socket not open or if interface changed, create a new socket */
  if (s < 0 || strncmp(current_ifname, ifname, IFNAMSIZ) != 0) {
    /* Close previously opened socket if necessary */
    if (s >= 0) {
      close(s);
    }
    s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
      perror("opening socket");
      exit(EXIT_FAILURE);
    }
    /* Cache the current interface name */
    strncpy(current_ifname, ifname, IFNAMSIZ);
    current_ifname[IFNAMSIZ - 1] = '\0';

    /* Get interface index once */
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    if (ioctl(s, SIOCGIFINDEX, &req) < 0) {
      perror(ifname);
      exit(EXIT_FAILURE);
    }
    ifindex = req.ifr_ifindex;
  }

  /* Set up the socket address parameters */
  memset(&addr_out, 0, sizeof(addr_out));
  addr_out.sll_family = AF_PACKET;
  addr_out.sll_protocol = htons(ETH_P_ALL);
  addr_out.sll_halen = ETH_ALEN;
  addr_out.sll_ifindex = ifindex;
  addr_out.sll_pkttype = PACKET_OTHERHOST;

  if (sendto(s, buf, size, 0, (struct sockaddr *)&addr_out, sizeof(addr_out)) <
      0) {
    perror("sendto");
    exit(EXIT_FAILURE);
  }
  return 0;
}

int send_packet_old(char *ifname, uint8_t *buf, int size) {
  int ifindex;
  int s;
  struct ifreq req;
  struct sockaddr_ll addr_out;

  if (geteuid() != 0) {
    fprintf(stderr, "Execution requires superuser privilege.\n");
    exit(EXIT_FAILURE);
  }

  /* minimum size of Ethernet frames is ETHER_MIN_LEN octets */
  if (size < ETHER_MIN_LEN) {
    size = ETHER_MIN_LEN;
  }

  /* open raw Ethernet socket for sending */
  if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("opening socket");
    exit(EXIT_FAILURE);
  }

  /* get interface index */
  memset(&req, 0, sizeof(req));
  strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
  if (ioctl(s, SIOCGIFINDEX, &req)) {
    perror(ifname);
    exit(EXIT_FAILURE);
  }
  ifindex = req.ifr_ifindex;

  /* set socket address parameters */
  memset(&addr_out, 0, sizeof(addr_out));
  addr_out.sll_family = AF_PACKET;
  addr_out.sll_protocol = htons(ETH_P_ALL);
  addr_out.sll_halen = ETH_ALEN;
  addr_out.sll_ifindex = ifindex;
  addr_out.sll_pkttype = PACKET_OTHERHOST;

  if ((sendto(s, buf, size, 0, (struct sockaddr *)&addr_out,
              sizeof(addr_out))) < 0) {
    perror("sendto");
    exit(EXIT_FAILURE);
  }
  close(s);
  return 0;
}

#endif

void print_ltr(uint8_t *buf) {
  struct cfmencap *encap;
  struct cfm_ltr *ltr;

  printf("\treply from ");
  encap = (struct cfmencap *)buf;
  eaprint(encap->srcmac);

  ltr = POS_CFM_LTR(buf);
  printf(", id=%d, ttl=%d", htonl(ltr->transID), ltr->ttl);
  switch (ltr->action) {
  case ACTION_RLYHIT:
    printf(", RlyHit\n");
    break;
  case ACTION_RLYFDB:
    printf(", RlyFDB\n");
    break;
  case ACTION_RLYMPDB:
    printf(", RlyMPDB\n");
    break;
  default:
    printf(", RlyUknown\n");
  }
}

/* Function to log a delay measurement packet fields to syslog */
void logDM_packet(uint8_t *dm_frame, int size, int opcode) {
  const char *pkt_type_str = (opcode == OAM_DMR) ? "DMR" : "DMM";
  struct ether_header *eth_hdr = (struct ether_header *)dm_frame;
  struct cfm_dm *dm;

  syslog(LOG_INFO, "=== %s Packet ===", pkt_type_str);
  syslog(LOG_INFO, "Ethernet Header:");
  syslog(LOG_INFO, "  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x",
         eth_hdr->ether_shost[0], eth_hdr->ether_shost[1],
         eth_hdr->ether_shost[2], eth_hdr->ether_shost[3],
         eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
  syslog(LOG_INFO, "  Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x",
         eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],
         eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3],
         eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

  /* Parse the common CFM header (immediately following the Ethernet header) */
  struct cfmhdr *cfm_hdr = (struct cfmhdr *)(dm_frame + ETHER_HDR_LEN);
  syslog(LOG_INFO, "CFM Header:");
  syslog(LOG_INFO, "  MD-L: %u", GET_MD_LEVEL(cfm_hdr));
  syslog(LOG_INFO, "  Version: %u", GET_VERSION(cfm_hdr));
  syslog(LOG_INFO, "  OpCode: %u", cfm_hdr->opcode);
  syslog(LOG_INFO, "  Reserved/Flags: %u", cfm_hdr->flags);
  syslog(LOG_INFO, "  Raw TLV Offset byte: %u", cfm_hdr->tlv_offset);

  /* Extract the T bit and First TLV Offset from the tlv_offset byte */
  uint8_t t_bit = cfm_hdr->tlv_offset >> 7;
  uint8_t first_tlv_offset = cfm_hdr->tlv_offset & 0x7F;
  syslog(LOG_INFO, "  T bit: %u", t_bit);
  syslog(LOG_INFO, "  First TLV Offset: %u", first_tlv_offset);

  dm = POS_CFM_DM(dm_frame);

  syslog(LOG_INFO, "Timestamp T1: %u seconds, %u nanoseconds",
         ntohl(dm->T1.seconds), ntohl(dm->T1.nanoseconds));
  syslog(LOG_INFO, "Timestamp T2: %u seconds, %u nanoseconds",
         ntohl(dm->T2.seconds), ntohl(dm->T2.nanoseconds));
  syslog(LOG_INFO, "Timestamp T3: %u seconds, %u nanoseconds",
         ntohl(dm->T3.seconds), ntohl(dm->T3.nanoseconds));
  syslog(LOG_INFO, "Timestamp T4: %u seconds, %u nanoseconds",
         ntohl(dm->T4.seconds), ntohl(dm->T4.nanoseconds));

  /* If TLVs are present, log their length and a hex dump of the raw TLV data */
  int header_len =
      ETHER_HDR_LEN + sizeof(struct cfmhdr) + sizeof(struct cfm_dm);
  if (size > header_len) {
    int tlv_len = size - header_len;
    syslog(LOG_INFO, "TLVs present: %d bytes", tlv_len);
    char tlv_buf[256] = {0};
    int pos = 0;
    uint8_t *tlv_ptr = dm_frame + header_len;
    for (int i = 0; i < tlv_len && pos < (int)(sizeof(tlv_buf) - 3); i++) {
      pos +=
          snprintf(tlv_buf + pos, sizeof(tlv_buf) - pos, "%02x ", tlv_ptr[i]);
    }
    syslog(LOG_INFO, "TLV Data: %s", tlv_buf);
  } else {
    syslog(LOG_INFO, "No TLVs present in the DMM packet");
  }
}

void process_dmm_frame(char *ifname, uint8_t md_level, uint16_t mep_id,
                       uint8_t *dmm_frame, int size, uint8_t *local_mac,
                       struct timeval capture_tv, int verbose) {

  struct cfmencap *encap;
  struct cfmhdr *cfmhdr;
  struct cfm_dm *dmr_hdr;
  uint8_t md_level_received;
  uint8_t dmr_frame[ETHER_MAX_LEN];
  struct ether_header *dmm_ehdr;
  struct ether_header *dmr_ehdr;
  int i;

  struct timespec ts;

  dmm_ehdr = (struct ether_header *)dmm_frame;
  dmr_ehdr = (struct ether_header *)dmr_frame;

  encap = (struct cfmencap *)dmm_frame;

  if (ETHER_IS_EQUAL(encap->srcmac, local_mac)) {
    return;
  }

  cfmhdr = CFMHDR(dmm_frame);
  md_level_received = GET_MD_LEVEL(cfmhdr);

  if (verbose) {
    logDM_packet(dmm_frame, size, OAM_DMM);
  }

  if (md_level_received != md_level) {
    syslog(LOG_ERR, "expected level %d, received level %d, discard frame\n",
           md_level, md_level_received);

    return;
  }

  memset(dmr_frame, 0, sizeof(dmr_frame));

  memcpy(dmr_frame, dmm_frame, size);

  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    dmr_ehdr->ether_shost[i] = local_mac[i];
    dmr_ehdr->ether_dhost[i] = dmm_ehdr->ether_shost[i];
  }
  cfmhdr = CFMHDR(dmr_frame);
  cfmhdr->opcode = OAM_DMR;
  dmr_hdr = POS_CFM_DM(dmr_frame);

  dmr_hdr->T2.seconds = htonl((uint32_t)capture_tv.tv_sec);
  dmr_hdr->T2.nanoseconds = htonl((uint32_t)(capture_tv.tv_usec));

  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }

  dmr_hdr->T3.seconds = htonl((uint32_t)ts.tv_sec);
  dmr_hdr->T3.nanoseconds = htonl((uint32_t)ts.tv_nsec);

  if (verbose) {
    logDM_packet(dmr_frame, size, OAM_DMR);
  }

  if (send_packet(ifname, dmr_frame, size) < 0) {
    perror("send_packet");
    exit(EXIT_FAILURE);
  }
}

int cfm_send_lbr(char *ifname, uint8_t *lbm_frame, int size,
                 uint8_t *local_mac) {
  uint8_t lbr_frame[ETHER_MAX_LEN];
  struct cfmhdr *cfmhdr;
  struct ether_header *lbm_ehdr;
  struct ether_header *lbr_ehdr;
  int i;

  lbm_ehdr = (struct ether_header *)lbm_frame;
  lbr_ehdr = (struct ether_header *)lbr_frame;

  /* check for valid source mac address */
  if (ETHER_IS_MCAST(lbm_ehdr->ether_shost)) {
    fprintf(stderr, "LBR received from multicast address\n");
    return 1;
  }

  /*
   * Destination mac address should be either our MAC address or the
   * CCM group address.
   */
  if (!(ETHER_IS_CCM_GROUP(lbm_ehdr->ether_dhost) ||
        ETHER_IS_EQUAL(lbm_ehdr->ether_dhost, local_mac))) {
    /* silently drop LBM */
    return 0;
  }

  /* clear outgoing packet buffer 'lbr_frame' */
  memset(lbr_frame, 0, sizeof(lbr_frame));

  /* copy received LBM to 'lbr_frame' */
  memcpy(lbr_frame, lbm_frame, size);

  /* set proper src and dst mac addresses */
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    lbr_ehdr->ether_shost[i] = local_mac[i];
    lbr_ehdr->ether_dhost[i] = lbm_ehdr->ether_shost[i];
  }

  cfmhdr = CFMHDR(lbr_frame);
  cfmhdr->opcode = CFM_LBR;

  if (send_packet(ifname, lbr_frame, size) < 0) {
    perror("send_packet");
    exit(1);
  }

  return 0;
}

int processLTM(char *ifname, uint8_t *ltm_frame, uint8_t *local_mac) {
  int i;
  uint8_t outbuf[ETHER_MAX_LEN];
  int size = 0;
  struct cfmencap *encap;
  struct ether_header *ltm_ehdr;
  uint8_t flags;
  uint8_t action;
  uint16_t vlan;
  uint8_t ttl;
  int pktsize = 0;
  struct cfmhdr *cfmhdr;
  uint8_t md_level = 0;
  uint32_t transid;
  struct cfm_ltm *cfm_ltm;

  ltm_ehdr = (struct ether_header *)ltm_frame;

  /* silently discard frame if it was sent by us */
  if (ETHER_IS_EQUAL(ltm_ehdr->ether_shost, local_mac)) {
    return 0;
  }

  /*
   * Destination mac address should be either our MAC address or the
   * LTM group address.
   */
  if (!(ETHER_IS_LTM_GROUP(ltm_ehdr->ether_dhost) ||
        ETHER_IS_EQUAL(ltm_ehdr->ether_dhost, local_mac))) {
    /* silently drop LTM */
    return 0;
  }

  encap = (struct cfmencap *)ltm_frame;
  if (IS_TAGGED(ltm_frame)) {
    vlan = ntohs(encap->tci) & 0x0fff;
  } else {
    vlan = 0;
  }
  cfmhdr = CFMHDR(ltm_frame);
  md_level = (cfmhdr->octet1.md_level >> 5) & 0x07;
  /* copy fields from LTM PDU */
  flags = cfmhdr->flags;
  /* clear FwdYes bit to indicate that we did not forward */
  flags &= ~DOT1AG_LTFLAGS_FWDYES;
  /* set TerminalMEP bit */
  flags |= DOT1AG_LTFLAGS_TERMINALMEP;

  cfm_ltm = POS_CFM_LTM(ltm_frame);
  transid = ntohl(cfm_ltm->transID);
  ttl = cfm_ltm->ttl;
  /* do not send LTR when TTL = 0 */
  if (ttl == 0) {
    return 0;
  }
  ttl--;

  /*
   * Below the outgoing LTR Ethernet frame is built
   */

  /* clear outgoing packet buffer 'outbuf' */
  memset(outbuf, 0, sizeof(outbuf));

  /* add CFM encapsulation header to packet */
  cfm_addencap(vlan, local_mac, cfm_ltm->orig_mac, outbuf, &size);
  pktsize += size;

  /* add CFM common header to packet */
  cfm_addhdr(md_level, flags, FIRST_TLV_LTR, CFM_LTR, outbuf + pktsize);
  pktsize += sizeof(struct cfmhdr);

  if (ETHER_IS_EQUAL(cfm_ltm->target_mac, local_mac)) {
    action = ACTION_RLYHIT;
  } else {
    action = ACTION_RLYFDB;
  }
  cfm_addltr(transid, ttl, action, outbuf + pktsize);
  pktsize += sizeof(struct cfm_ltr);

  /*
   *  finally add LTM Egress Identifier TLV
   */

  /* XXX code below needs cleanup */
  /* Type */
  *(uint8_t *)(outbuf + pktsize) = (uint8_t)TLV_LTR_EGRESS_IDENTIFIER;
  pktsize += sizeof(uint8_t);

  /* LTR Egress Identifier is 16 octets */
  *(uint16_t *)(outbuf + pktsize) = htons(16);
  pktsize += sizeof(uint16_t);

  /* add Last Egress Identifier TLV */
  /* Unique Identifier (set to 0) */
  *(uint16_t *)(outbuf + pktsize) = htons(0);
  pktsize += sizeof(uint16_t);
  /* MAC address of sender/forwarder of LTM */
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    *(outbuf + pktsize + i) = ltm_ehdr->ether_shost[i];
  }
  pktsize += ETHER_ADDR_LEN;

  /* add Next Egress Identifier TLV */
  /* Unique Identifier (set to 0) */
  *(uint16_t *)(outbuf + pktsize) = htons(0);
  pktsize += sizeof(uint16_t);
  /* our MAC address */
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    *(outbuf + pktsize + i) = local_mac[i];
  }
  pktsize += ETHER_ADDR_LEN;

  /* add Reply Ingress TLV */
  /* type */
  *(uint8_t *)(outbuf + pktsize) = (uint8_t)TLV_REPLY_INGRESS;
  pktsize += sizeof(uint8_t);

  /* length */
  *(uint16_t *)(outbuf + pktsize) = htons(7);
  pktsize += sizeof(uint16_t);

  /* action */
  *(uint16_t *)(outbuf + pktsize) = DOT1AG_IngOK;
  pktsize += sizeof(uint8_t);

  /* our MAC address */
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    *(outbuf + pktsize + i) = local_mac[i];
  }
  pktsize += ETHER_ADDR_LEN;

  /* end packet with End TLV field */
  *(uint8_t *)(outbuf + pktsize) = htons(TLV_END);
  pktsize += sizeof(uint8_t);

  /* Assembled Ethernet frame is 'outbuf', its size is 'pktsize' */

  if (send_packet(ifname, outbuf, pktsize) < 0) {
    perror("send_packet");
    exit(1);
  }

  return 0;
}

/* CCM sequence number */
static uint32_t CCIsentCCMs = 0;

void cfm_ccm_sender(char *ifname, uint16_t vlan, uint8_t md_level, char *md,
                    char *ma, uint16_t mepid, int interval,
                    uint8_t *local_mac) {
  uint8_t outbuf[ETHER_MAX_LEN];
  uint8_t remote_mac[ETHER_ADDR_LEN];
  uint8_t flags;
  int pktsize = 0;
  int size = 0;
  int CCMinterval = 4; /* default to 1 sec */
  struct cfm_cc *cfm_cc;
  uint8_t *p;
  int mdnl;
  int smanl;
  int max_smanl;

  /*
   * Below the outgoing Ethernet frame is built
   */

  /* clear outgoing packet buffer */
  memset(outbuf, 0, sizeof(outbuf));

  /* add CFM encapsulation header to packet */
  (void)eth_addr_parse(remote_mac, ETHER_CFM_GROUP);
  remote_mac[5] = 0x30 + (md_level & 0x0F);
  cfm_addencap(vlan, local_mac, remote_mac, outbuf, &size);
  pktsize += size;

  /* RDI in flag field is always set to 0 */
  flags = 0;
  /* least-significant three bits are the CCM Interval */
  switch (interval) {
  case 10:
    /* 10 ms */
    CCMinterval = 2;
    break;
  case 100:
    /* 100 ms */
    CCMinterval = 3;
    break;
  case 1000:
    /* 1 sec */
    CCMinterval = 4;
    break;
  case 10000:
    /* 10 sec */
    CCMinterval = 5;
    break;
  case 60000:
    /* 1 min */
    CCMinterval = 6;
    break;
  case 600000:
    /* 10 min */
    CCMinterval = 7;
    break;
  default:
    /* 1 sec */
    CCMinterval = 4;
    break;
  }
  flags |= (CCMinterval & 0x07);

  /* add CFM common header to packet */
  cfm_addhdr(md_level, flags, FIRST_TLV_CCM, CFM_CCM, outbuf + pktsize);
  pktsize += sizeof(struct cfmhdr);

  cfm_cc = (struct cfm_cc *)(outbuf + pktsize);
  /* add 4 octet Sequence Number to packet */
  cfm_cc->seqNumber = htonl(CCIsentCCMs);
  CCIsentCCMs++;
  cfm_cc->mepid = htons(mepid);
  /* XXX always assume character string format */
  /* use character string (4) as Maintenance Domain Name Format */
  cfm_cc->maid.format = 4;
  cfm_cc->maid.length = strlen(md);
  if (cfm_cc->maid.length > DOT1AG_MAX_MD_LENGTH) {
    cfm_cc->maid.length = DOT1AG_MAX_MD_LENGTH;
  }
  /* set p to start of variable part in MAID */
  p = cfm_cc->maid.var_p;
  /* fill variable part of MAID with 0 */
  memset(p, 0, sizeof(cfm_cc->maid.var_p));
  /* copy Maintenance Domain Name to MAID */
  mdnl = strlen(md);
  if (mdnl > DOT1AG_MAX_MD_LENGTH) {
    mdnl = DOT1AG_MAX_MD_LENGTH;
  }
  memcpy(p, md, mdnl);
  p += mdnl;
  /* XXX always assume character string format */
  /* set Short MA Name Format to character string (2) */
  *p = 2;
  p++;
  /* set Short MA Name Length */
  max_smanl = sizeof(struct cfm_maid) - 4 - mdnl;
  smanl = strlen(ma);
  if (smanl > max_smanl) {
    smanl = max_smanl;
  }
  *p = smanl;
  p++;
  /* copy Short MA Name to MAID */
  memcpy(p, ma, smanl);
  /* field defined by ITU-T Y.1731, transmit as 0 */
  memset(cfm_cc->y1731, 0, sizeof(cfm_cc->y1731));

  pktsize += sizeof(struct cfm_cc);

  /* add Sender ID TLV */
  /* Type */
  *(uint8_t *)(outbuf + pktsize) = TLV_SENDER_ID;
  pktsize += sizeof(uint8_t);
  /* minimal length of 1 */
  *(uint16_t *)(outbuf + pktsize) = htons(1);
  pktsize += sizeof(uint16_t);
  /* Chassis ID Length is 0 (no Chassis ID present) */
  *(uint8_t *)(outbuf + pktsize) = 0;
  pktsize += sizeof(uint8_t);

  /* add Port Status TLV */
  /* Type */
  *(uint8_t *)(outbuf + pktsize) = TLV_PORT_STATUS;
  pktsize += sizeof(uint8_t);
  /* minimal length of 1 */
  *(uint16_t *)(outbuf + pktsize) = htons(1);
  pktsize += sizeof(uint16_t);
  /* Port Status, XXX hard code to psUp */
  *(uint8_t *)(outbuf + pktsize) = DOT1AG_PS_UP;
  pktsize += sizeof(uint8_t);

  /* add Interface Status TLV */
  /* Type */
  *(uint8_t *)(outbuf + pktsize) = TLV_INTERFACE_STATUS;
  pktsize += sizeof(uint8_t);
  /* minimal length of 1 */
  *(uint16_t *)(outbuf + pktsize) = htons(1);
  pktsize += sizeof(uint16_t);
  /* Interface Status, XXX hard code to isUp */
  *(uint8_t *)(outbuf + pktsize) = DOT1AG_IS_UP;
  pktsize += sizeof(uint8_t);

  /* end packet with End TLV field */
  *(uint8_t *)(outbuf + pktsize) = htons(TLV_END);
  pktsize += sizeof(uint8_t);

  /* Assembled Ethernet frame is 'outbuf', its size is 'pktsize' */
  if (send_packet(ifname, outbuf, pktsize) < 0) {
    fprintf(stderr, "send_packet failed\n");
    return;
  }
}

/**
 * log_frame_info()
 *
 * Inspect an Ethernet frame (possibly 802.1Q-tagged and/or CFM/Y.1731)
 * and emit key fields to syslog(LOG_INFO) for debugging.
 *
 * @param frame  raw packet bytes
 * @param len    total length of the buffer
 */
void log_slm_frame(const uint8_t *sl_frame, size_t len, int opcode) {
  const char *pkt_type_str = (opcode == CFM_SLM) ? "SLM" : "SLR";
  const struct ether_header *eth = (const void *)sl_frame;
  uint16_t ethertype = ntohs(eth->ether_type);

  openlog("cfm-debug", LOG_PID | LOG_NDELAY, LOG_USER);
  syslog(LOG_INFO, "=== %s Packet ===", pkt_type_str);

  /* Ethernet header */
  syslog(LOG_INFO,
         "Ethernet: dst=%02x:%02x:%02x:%02x:%02x:%02x "
         "src=%02x:%02x:%02x:%02x:%02x:%02x "
         "ethertype=0x%04hx len=%zu",
         eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
         eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5],
         eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
         eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
         (unsigned short)ethertype, len);

  size_t offset = sizeof(*eth);
  if (ethertype == ETHERTYPE_VLAN) {
    const uint16_t *vlan_hdr = (const void *)(sl_frame + offset);
    uint16_t tci = ntohs(vlan_hdr[0]);
    uint16_t vid = tci & 0x0FFF;
    uint8_t pcp = (tci >> 13) & 0x07;
    uint8_t cfi = (tci >> 12) & 0x01;
    ethertype = ntohs(vlan_hdr[1]);
    offset += 4;
    syslog(LOG_INFO, "VLAN Tag: id=%u pcp=%u cfi=%u inner_eth=0x%04hx", vid,
           pcp, cfi, (unsigned short)ethertype);
  }

  /* CFM header */
  const struct cfmhdr *hdr = CFMHDR(sl_frame);
  const uint8_t *base = (const uint8_t *)hdr;

  uint8_t oct1 = hdr->octet1.md_level;
  uint8_t md_level = (oct1 >> 5) & 0x07;
  uint8_t version = oct1 & 0x1F;

  uint16_t sender_mep = ntohs(*(uint16_t *)(base + 4));
  uint16_t reflector_mep = ntohs(*(uint16_t *)(base + 6));
  uint32_t test_id = ntohl(*(uint32_t *)(base + 8));
  uint32_t counter_tx = ntohl(*(uint32_t *)(base + 12));
  uint32_t counter_trx = ntohl(*(uint32_t *)(base + 16));

  syslog(LOG_INFO,
         "CFM/Y.1731 Header: md_level=%u version=%u opcode=0x%02x "
         "flags=0x%02x tlv_offset=%u",
         md_level, version, hdr->opcode, hdr->flags, hdr->tlv_offset);

  syslog(LOG_INFO,
         "%s Fields: sender_mep=%u reflector_mep=%u test_id=%u "
         "counter_tx=%u counter_trx=%u",
         pkt_type_str, sender_mep, reflector_mep, test_id, counter_tx,
         counter_trx);
}

/*
 * Offsets (in bytes) relative to the start of the CFM header:
 *
 *   0..3    = struct cfmhdr (4 bytes: md_level/version, opcode, flags,
 * tlv_offset) 4..5    = Source MEP ID               (uint16_t, network order)
 *   6..7    = [Reserved in SLM] / Responder MEP ID in SLR (uint16_t, network
 * order) 8..11   = Test ID                     (uint32_t, network order) 12..15
 * = TxFCf (forward‐count from initiator)       (uint32_t, network order) 16..19
 * = TxFCb (backward‐count, only in SLR)        (uint32_t, network order) 20..
 * = (optional TLVs begin at offset = tlv_offset)
 */

/**
 * cfm_send_slr:
 *   Handle an incoming one‐way ETH-SLM (Opcode = CFM_SLM) and send back the
 *   corresponding ETH-SLR (Opcode = CFM_SLR). Uses CFMHDR() to locate the
 *   first 4 bytes of the CFM header (handling VLAN tags if present), then
 *   manually reads/writes the fields that follow.
 *
 * @param  ifname          Outgoing interface name (e.g., "ge-0/0/1")
 * @param  slm_frame       Pointer to the received Ethernet frame containing SLM
 * @param  size            Length in bytes of the received frame
 * @param  local_mac       This device’s MAC address (6 bytes)
 * @param  local_mep_id    This device’s MEP ID (13 LSB bits; host byte order)
 * @param  local_rx_count  RxFCl: number of SLM PDUs received so far for this
 * @param  verbose         Verbose output (0 or 1)
 * Test ID
 *
 * @return 0 on success (SLR sent or frame silently dropped if not for us),
 *         1 if the received frame was malformed (e.g., multicast source).
 */
int cfm_send_slr(char *ifname, uint8_t *slm_frame, int size, uint8_t *local_mac,
                 uint16_t local_mep_id, uint32_t local_rx_count, int verbose) {
  uint8_t slr_frame[ETHER_MAX_LEN];
  struct ether_header *slm_ehdr = (struct ether_header *)slm_frame;
  struct ether_header *slr_ehdr = (struct ether_header *)slr_frame;
  struct cfmhdr *cfm_req; /* pointer to CFM header in received frame */
  struct cfmhdr *cfm_rep; /* pointer to CFM header in reply */
  uint8_t *base_rep;      /* byte‐wise pointer to start of CFM header */
  int i;

  /* 1) Drop if source MAC is multicast (SLM must come from a unicast MEP). */
  if (ETHER_IS_MCAST(slm_ehdr->ether_shost)) {
    fprintf(stderr, "cfm_send_slr: received SLM from multicast source\n");
    return 1;
  }

  /* 2) If destination MAC ≠ our local MAC, silently drop */
  if (!ETHER_IS_EQUAL(slm_ehdr->ether_dhost, local_mac)) {
    return 0;
  }

  /* 3) Copy the entire incoming frame into our local buffer (preserve TLVs,
   * etc.) */
  memset(slr_frame, 0, sizeof(slr_frame));
  memcpy(slr_frame, slm_frame, size);

  /* 4) Swap Ethernet MACs in the reply */
  for (i = 0; i < ETHER_ADDR_LEN; i++) {
    slr_ehdr->ether_shost[i] = local_mac[i];
    slr_ehdr->ether_dhost[i] = slm_ehdr->ether_shost[i];
  }

  /*
   * 5) Locate the CFM header (handles tagged vs. untagged):
   *    CFMHDR() returns a (struct cfmhdr *) pointing to the first 4 bytes
   *    of the CFM header.
   */
  cfm_req = CFMHDR(slm_frame);
  cfm_rep = CFMHDR(slr_frame);

  /*
   * We'll also keep byte‐wise pointers, so we can address beyond the 4‐byte
   * struct:
   */
  base_rep = (uint8_t *)cfm_rep;

  /* 6) Ensure this is indeed an SLM PDU (opcode == CFM_SLM == 0x37) */
  if (cfm_req->opcode != CFM_SLM) {
    /* Not an SLM, drop silently */
    return 0;
  }

  /* 7) Change opcode from CFM_SLM → CFM_SLR */
  cfm_rep->opcode = CFM_SLR;

  /*
   * 8) Overwrite “Responder MEP ID” (bytes [6..7] relative to start of CFM
   * header) In the incoming SLM, bytes [6..7] are reserved (0). In the SLR we
   * set: base_rep[4]..base_rep[5] = Source MEP ID (copied automatically by
   * memcpy) base_rep[6]..base_rep[7] = Responder MEP ID = our local_mep_id
   * (nb‐order)
   */
  {
    uint16_t be_mep = htons(local_mep_id & 0x1FFF);
    memcpy(&base_rep[6], &be_mep, sizeof(be_mep));
  }

  /*
   * 9) Populate “TxFCb” (bytes [16..19] relative to start of CFM header)
   *    In the incoming SLM, bytes [12..15] = TxFCf (forward‐frame count from
   * initiator). We leave that unchanged (already copied by memcpy). Now set:
   *      base_rep[16..19] = TxFCb = local_rx_count (number of SLM PDUs we have
   * received).
   */
  {
    uint32_t be_rx_cnt = htonl(local_rx_count);
    memcpy(&base_rep[16], &be_rx_cnt, sizeof(be_rx_cnt));
  }

  /*
   * 10) All other fields remain as in the incoming SLM:
   *     – bytes [0..3] (mdlevel_version, opcode, flags, tlv_offset)
   *     – bytes [4..5] Source MEP ID (unchanged)
   *     – bytes [ 8..11 ] Test ID (unchanged)
   *     – bytes [12..15] TxFCf  (unchanged)
   *     – any TLVs starting at offset = cfm_rep->tlv_offset  (unchanged)
   */

  /* 11) Transmit the SLR frame */
  if (send_packet(ifname, slr_frame, size) < 0) {
    perror("cfm_send_slr: send_packet failed");
    exit(1);
  }

  if (verbose) {
    log_slm_frame(slr_frame, size, CFM_SLR);
  }

  return 0;
}

static session_t *sessions = NULL;

//------------------------------------------------------------------------------
// Lookup-or-create session for (peer_mep, test_id)
//------------------------------------------------------------------------------
static session_t *get_session(uint16_t peer_mep, uint32_t test_id,
                              int verbose) {
  session_key_t key = {peer_mep, test_id};
  session_t *s;

  HASH_FIND(hh, sessions, &key, sizeof(key), s);
  if (!s) {
    s = malloc(sizeof(*s));
    if (!s) {
      syslog(LOG_ERR, "Failed to allocate memory for session: peer %u test %u",
             peer_mep, test_id);
      return NULL;
    }
    if (verbose) {
      syslog(LOG_INFO, "Creating new session for peer_mep=%u, test_id=%u",
             peer_mep, test_id);
    }
    s->key = key;
    s->rx_count = 0;
    s->last_seen = time(NULL);
    HASH_ADD(hh, sessions, key, sizeof(key), s);
  } else {
    if (verbose) {
      syslog(LOG_INFO, "Found existing session for peer_mep=%u, test_id=%u",
             peer_mep, test_id);
    }
  }
  return s;
}

static time_t last_eviction = 0;

static void maybe_evict_stale_sessions(time_t max_age_sec, time_t interval_sec,
                                       int verbose) {
  time_t now = time(NULL);
  if (now - last_eviction < interval_sec) {
    return;
  }
  last_eviction = now;

  session_t *s, *tmp;
  HASH_ITER(hh, sessions, s, tmp) {
    if (now - s->last_seen > max_age_sec) {
      if (verbose) {
        syslog(LOG_INFO, "Evicting stale session: peer_mep=%u, test_id=%u",
               s->key.peer_mep, s->key.test_id);
      }
      HASH_DEL(sessions, s);
      free(s);
    }
  }
}

void process_slm_frame(char *ifname, uint8_t *frame, int size,
                       uint8_t *local_mac, uint16_t local_mep_id, int verbose) {
  struct cfmhdr *hdr = CFMHDR(frame);
  uint8_t *base = (uint8_t *)hdr;

  maybe_evict_stale_sessions(EVICT_MAX_AGE, EVICT_INTERVAL, verbose);

  if (verbose) {
    log_slm_frame(frame, size, CFM_SLM);
  }

  uint16_t peer_mep_raw;
  memcpy(&peer_mep_raw, &base[4], sizeof(peer_mep_raw));
  uint16_t peer_mep = ntohs(peer_mep_raw);

  uint32_t test_id_raw;
  memcpy(&test_id_raw, &base[8], sizeof(test_id_raw));
  uint32_t test_id = ntohl(test_id_raw);

  session_t *s = get_session(peer_mep, test_id, verbose);
  if (!s) {
    syslog(LOG_ERR,
           "process_slm_frame: failed to create session for peer_mep=%u, "
           "test_id=%u",
           peer_mep, test_id);
    return;
  }

  s->rx_count += 1;
  s->last_seen = time(NULL);

  cfm_send_slr(ifname, frame, size, local_mac, local_mep_id, s->rx_count,
               verbose);
}
