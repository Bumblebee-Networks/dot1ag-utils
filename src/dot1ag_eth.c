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

void processDMM(char *ifname, uint8_t md_level, uint16_t mep_id,
                uint8_t *data) {

  uint8_t local_mac[ETHER_ADDR_LEN];
  struct cfmencap *encap;
  struct cfmhdr *cfmhdr;
  struct cfm_dmm *dmm_frame;
  uint8_t md_level_received;

  if (get_local_mac(ifname, local_mac) != 0) {
    fprintf(stderr, "Cannot determine local MAC address\n");
    exit(EXIT_FAILURE);
  }

  encap = (struct cfmencap *)data;

  if (ETHER_IS_EQUAL(encap->srcmac, local_mac)) {
    return;
  }

  cfmhdr = CFMHDR(data);
  md_level_received = GET_MD_LEVEL(cfmhdr);

  syslog(LOG_INFO,
         "rcvd DMM: "
         "%02x:%02x:%02x:%02x:%02x:%02x, level %d",
         encap->srcmac[0], encap->srcmac[1], encap->srcmac[2], encap->srcmac[3],
         encap->srcmac[4], encap->srcmac[5], md_level_received);

  if (md_level_received != md_level) {
    syslog(LOG_ERR, "expected level %d, received level %d, discard frame\n",
           md_level, md_level_received);

    return;
  }

  dmm_frame = POS_CFM_DMM(data);

  /* Convert timestamps from network byte order and log them */
  uint32_t ts_T1 = ntohl(dmm_frame->timestamp_T1);
  uint32_t ts_T2 = ntohl(dmm_frame->timestamp_T2);
  uint32_t ts_T3 = ntohl(dmm_frame->timestamp_T3);
  uint32_t ts_reserved = ntohl(dmm_frame->reserved);

  syslog(LOG_INFO, "DMM Timestamps:");
  syslog(LOG_INFO, "  Timestamp T1: %u", ts_T1);
  syslog(LOG_INFO, "  Timestamp T2: %u", ts_T2);
  syslog(LOG_INFO, "  Timestamp T3: %u", ts_T3);
  syslog(LOG_INFO, "  Reserved for DMR receiving equipment: %u", ts_reserved);
}

int processDMMOld(char *ifname, char *md, uint8_t *dmm_frame) {
  uint8_t local_mac[ETHER_ADDR_LEN];
  struct ether_header *eth_hdr;
  uint8_t *msg; // Pointer to the DMM message header within the frame

  /* Retrieve the local MAC address */
  if (get_local_mac(ifname, local_mac) != 0) {
    syslog(LOG_ERR, "Cannot determine local MAC address for interface %s",
           ifname);
    exit(EXIT_FAILURE);
  }

  /* Parse Ethernet header and log Ethernet addresses */
  eth_hdr = (struct ether_header *)dmm_frame;
  syslog(LOG_INFO,
         "Processing DMM message on interface: %s, Maintenance Domain: %s",
         ifname, md);
  syslog(LOG_INFO, "Local MAC: %02x:%02x:%02x:%02x:%02x:%02x", local_mac[0],
         local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
  syslog(LOG_INFO, "Ethernet Source MAC: %02x:%02x:%02x:%02x:%02x:%02x",
         eth_hdr->ether_shost[0], eth_hdr->ether_shost[1],
         eth_hdr->ether_shost[2], eth_hdr->ether_shost[3],
         eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
  syslog(LOG_INFO, "Ethernet Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x",
         eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],
         eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3],
         eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

  /* The DMM message header follows after the Ethernet header */
  msg = dmm_frame + ETHER_HDR_LEN;

  /* Extract fields from the first 4 bytes */
  uint8_t md_level = msg[0] >> 4;  // Upper 4 bits of byte 0
  uint8_t version = msg[0] & 0x0F; // Lower 4 bits of byte 0
  uint8_t opcode = msg[1];         // Byte 1: OpCode
  uint8_t reserved = msg[2];       // Byte 2: Reserved (should be 0)
  uint8_t t_bit = msg[3] >> 7;     // Bit 7 of byte 3: T bit
  uint8_t first_tlv_offset =
      msg[3] & 0x7F; // Bits 0-6 of byte 3: First TLV Offset

  /* Extract 32-bit values from the subsequent bytes.
     Use ntohl() to convert from network byte order to host byte order. */
  uint32_t timestamp_T1 =
      ntohl(*(uint32_t *)(msg + 4)); // Bytes 4-7: Timestamp T1
  uint32_t timestamp_T2 =
      ntohl(*(uint32_t *)(msg + 8)); // Bytes 8-11: Reserved for DMM receiving
                                     // (Timestamp T2)
  uint32_t timestamp_T3 = ntohl(
      *(uint32_t *)(msg + 12)); // Bytes 12-15: Reserved for DMR (Timestamp T3)
  uint32_t reserved_dmr_recv = ntohl(
      *(uint32_t *)(msg +
                    16)); // Bytes 16-19: Reserved for DMR receiving equipment

  /* Log the parsed DMM header fields via syslog */
  syslog(LOG_INFO, "DMM Header Fields:");
  syslog(LOG_INFO, "  MD-L (Maintenance Domain Level): %u", md_level);
  syslog(LOG_INFO, "  Version: %u", version);
  syslog(LOG_INFO, "  OpCode: %u", opcode);
  syslog(LOG_INFO, "  Reserved (byte 2): %u", reserved);
  syslog(LOG_INFO, "  T Bit: %u", t_bit);
  syslog(LOG_INFO, "  First TLV Offset: %u", first_tlv_offset);
  syslog(LOG_INFO, "  Timestamp T1: %u", timestamp_T1);
  syslog(LOG_INFO, "  Timestamp T2 (Reserved for DMM receiving): %u",
         timestamp_T2);
  syslog(LOG_INFO, "  Timestamp T3 (Reserved for DMR): %u", timestamp_T3);
  syslog(LOG_INFO, "  Reserved for DMR receiving equipment: %u",
         reserved_dmr_recv);

  /* Additional processing of TLVs could be added here */

  return 0;
}

int cfm_send_lbr(char *ifname, uint8_t *lbm_frame, int size) {
  uint8_t lbr_frame[ETHER_MAX_LEN];
  struct cfmhdr *cfmhdr;
  uint8_t local_mac[ETHER_ADDR_LEN];
  struct ether_header *lbm_ehdr;
  struct ether_header *lbr_ehdr;
  int i;

  if (get_local_mac(ifname, local_mac) != 0) {
    fprintf(stderr, "Cannot determine local MAC address\n");
    exit(EXIT_FAILURE);
  }
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

int processLTM(char *ifname, uint8_t *ltm_frame) {
  int i;
  uint8_t outbuf[ETHER_MAX_LEN];
  int size = 0;
  struct cfmencap *encap;
  struct ether_header *ltm_ehdr;
  uint8_t local_mac[ETHER_ADDR_LEN];
  uint8_t flags;
  uint8_t action;
  uint16_t vlan;
  uint8_t ttl;
  int pktsize = 0;
  struct cfmhdr *cfmhdr;
  uint8_t md_level = 0;
  uint32_t transid;
  struct cfm_ltm *cfm_ltm;

  if (get_local_mac(ifname, local_mac) != 0) {
    fprintf(stderr, "Cannot determine local MAC address\n");
    return 0;
  }
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
                    char *ma, uint16_t mepid, int interval) {
  uint8_t outbuf[ETHER_MAX_LEN];
  uint8_t local_mac[ETHER_ADDR_LEN];
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

  if (get_local_mac(ifname, local_mac) != 0) {
    fprintf(stderr, "Cannot determine local MAC address\n");
    exit(EXIT_FAILURE);
  }

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
