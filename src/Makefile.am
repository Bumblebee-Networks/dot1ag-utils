AM_CFLAGS = -Wall -Werror -ggdb

bin_PROGRAMS = ethping ethtrace dot1agd dot1ag_ccd

ethping_SOURCES = \
	ethping.c \
	ieee8021ag.c \
	ieee8021ag.h \
	dot1ag_eth.c \
	dot1ag_eth.h
ethping_LDADD = -lpcap


ethtrace_SOURCES = \
	ethtrace.c \
	ieee8021ag.c \
	ieee8021ag.h \
	dot1ag_eth.c \
	dot1ag_eth.h
ethtrace_LDADD = -lpcap

dot1agd_SOURCES = \
	dot1agd.c \
	ieee8021ag.c \
	ieee8021ag.h \
	dot1ag_eth.c \
	dot1ag_eth.h
dot1agd_LDADD = -lpcap

dot1ag_ccd_SOURCES = \
	dot1ag_ccd.c \
	ieee8021ag.c \
	ieee8021ag.h \
	dot1ag_eth.c \
	dot1ag_eth.h
dot1ag_ccd_LDADD = -lpcap
